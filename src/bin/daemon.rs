//! Syntriass v2 user-space control daemon.
//!
//! Consumes kernel connection events and drives each through the hybrid PQC
//! handshake + kTLS bridge ([`kernel_native::complete_kernel_upcall`], which on
//! any failure tears the socket down — fail closed).
//!
//! ## Event sources
//! The daemon is transport-agnostic over *records*. Two sources exist:
//!   * a Unix-socket transport (used today; testable without privileges), which
//!     accepts either a JSON [`KernelUpcall`] line or a raw binary
//!     [`KernelSockEvent`] RingBuf record;
//!   * the eBPF RingBuf (`ebpf/src/main.rs`), wired with the `aya` loader. That
//!     path needs the BPF object built (out-of-tree, see `ebpf/`), a loaded
//!     program, and CAP_BPF, so it is documented below rather than compiled into
//!     this sandbox build. The record format ([`KernelSockEvent::from_bytes`]) is
//!     the stable contract, so only the transport differs.
//!
//! ```ignore
//! // Aya RingBuf consumer (requires `aya` + a loaded BPF program):
//! use aya::{maps::ring_buf::RingBuf, Ebpf};
//! let mut bpf = Ebpf::load_file("syntriass_bpf.o")?;
//! let ring = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
//! let mut poll = tokio::io::unix::AsyncFd::new(ring)?;
//! loop {
//!     let mut guard = poll.readable_mut().await?;
//!     let ring = guard.get_inner_mut();
//!     while let Some(item) = ring.next() {
//!         // `item` is the raw KernelSockEvent bytes the eBPF program submitted.
//!         let resp = process_event_record(&item, /* fd from sockmap */ None);
//!         // ... act on resp ...
//!     }
//!     guard.clear_ready();
//! }
//! ```

use serde::Serialize;
use std::env;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use syntriass_overlay::kernel_native::{
    self, configured_suite, KernelSockEvent, KernelUpcall, DEFAULT_UPCALL_SOCKET,
};
use syntriass_overlay::over_socket::{establish_and_bridge, HandshakeRole};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

#[derive(Debug, Serialize)]
struct UpcallResponse {
    socket_id: u64,
    status: &'static str,
    message: String,
}

/// Run one upcall through the handshake + kTLS bridge and classify the outcome.
fn run_upcall(upcall: &KernelUpcall) -> UpcallResponse {
    match kernel_native::complete_kernel_upcall(upcall) {
        Ok(()) => UpcallResponse {
            socket_id: upcall.socket_id,
            status: "ok",
            message: "kernel-native enforcement completed (kTLS installed)".to_string(),
        },
        Err(e) => UpcallResponse {
            socket_id: upcall.socket_id,
            status: "fail_closed",
            message: e.to_string(),
        },
    }
}

/// Decode and process one binary `KernelSockEvent` RingBuf record. This is the
/// function an Aya RingBuf consumer calls per record; it is also exercised by
/// the Unix-socket transport when a record is delivered as raw bytes.
fn process_event_record(record: &[u8], fd: Option<RawFd>) -> UpcallResponse {
    match KernelSockEvent::from_bytes(record) {
        Some(ev) => run_upcall(&ev.to_upcall(fd)),
        None => UpcallResponse {
            socket_id: 0,
            status: "bad_request",
            message: format!("short RingBuf record ({} bytes)", record.len()),
        },
    }
}

/// Run the real over-socket hybrid handshake on a paused connection, then hand
/// the live socket to kernel TLS. In a live v2 deployment the eBPF layer supplies
/// the connection (the paused target socket); here the daemon's listener mode
/// accepts it directly and plays the responder role.
async fn serve_over_socket(stream: TcpStream, role: HandshakeRole) {
    let suite = match configured_suite() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("syntriass daemon: no policy suite: {e}");
            return;
        }
    };
    let identity = match syntriass_overlay::crypto::resolve_identity() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("syntriass daemon: no identity: {e:?} (fail closed)");
            return;
        }
    };
    match establish_and_bridge(stream, &identity, suite, role).await {
        Ok(()) => eprintln!("syntriass daemon: over-socket handshake -> kTLS installed"),
        Err(e) => eprintln!("syntriass daemon: over-socket session failed closed: {e}"),
    }
}

/// Over-socket responder mode: accept connections and establish kTLS on each.
async fn run_over_socket_server(
    addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("syntriass daemon over-socket responder listening on {addr}");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(serve_over_socket(stream, HandshakeRole::Responder));
    }
}

/// fd-passing mode: accept SCM_RIGHTS-injected sockets and protect each.
///
/// The injector (eBPF orchestration / a mock) connects to this UDS and passes the
/// paused connection's fd as ancillary `SCM_RIGHTS` data. The daemon takes
/// ownership, binds it into Tokio, and drives the over-socket responder handshake.
async fn run_fd_passing_server(path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    eprintln!("syntriass daemon fd-passing (SCM_RIGHTS) listening on {path}");
    loop {
        let (channel, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_passed_fd(channel).await {
                eprintln!("syntriass daemon: fd-passing channel error: {e}");
            }
        });
    }
}

async fn run_kernel_visibility(
    bpf_object: &str,
    cgroup_path: &str,
    map_pin_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config =
        syntriass_overlay::kernel::loader::KernelVisibilityConfig::new(bpf_object, cgroup_path)
            .with_map_pin_path(map_pin_path);
    let mut runtime = syntriass_overlay::kernel::loader::KernelVisibilityRuntime::load(&config)?;
    let mut sink = syntriass_overlay::audit::sink::JsonStdoutSink;
    eprintln!(
        "syntriass daemon kernel visibility attached: object={bpf_object} cgroup={cgroup_path} map_pin_path={map_pin_path}"
    );
    runtime.run(&mut sink).await
}

#[cfg(target_os = "linux")]
fn run_session_establisher(
    socket_cookie: u64,
    ttl_secs: u64,
    map_pin_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let suite = configured_suite()?;
    let session_id =
        syntriass_overlay::session::run_authenticated_pqc_session(socket_cookie, suite)
            .map_err(|e| format!("PQC handshake failed: {e:?}"))?;
    let store = syntriass_overlay::session::linux::BpfSessionStore::open_pinned(
        &std::path::PathBuf::from(map_pin_path),
    )?;
    let mut manager = syntriass_overlay::session::SessionManager::new(store);
    let entry = manager.insert_state(
        socket_cookie,
        session_id,
        syntriass_overlay::session::SessionState::PqcEstablished,
        syntriass_overlay::session::monotonic_expiry_after(std::time::Duration::from_secs(
            ttl_secs,
        )),
    )?;
    println!("{}", serde_json::to_string(&entry)?);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_session_establisher(
    _socket_cookie: u64,
    _ttl_secs: u64,
    _map_pin_path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("session establishment requires Linux and pinned SESSION_MAP".into())
}

/// Receive one `SCM_RIGHTS` fd from `channel`, bind it into Tokio, and run the
/// responder handshake. Any missing / invalid descriptor aborts the channel
/// (fail closed) without ever touching application bytes.
async fn handle_passed_fd(
    channel: UnixStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // recvmsg is blocking; run it on a blocking thread with the UDS in blocking
    // mode, and close the control channel as soon as the fd is consumed.
    let std_channel = channel.into_std()?;
    std_channel.set_nonblocking(false)?;
    let uds_fd = std_channel.as_raw_fd();
    let (_data, maybe_fd) = tokio::task::spawn_blocking(move || {
        let result = syntriass_overlay::fd_passing::recv_fd(uds_fd);
        drop(std_channel); // closes the control UDS
        result
    })
    .await??;

    let Some(fd) = maybe_fd else {
        eprintln!("syntriass daemon: no SCM_RIGHTS fd in message -> abort (fail closed)");
        return Ok(());
    };

    // Take ownership of the passed socket and feed it to the negotiation engine.
    let std_tcp = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    std_tcp.set_nonblocking(true)?;
    let stream = TcpStream::from_std(std_tcp)?;
    serve_over_socket(stream, HandshakeRole::Responder).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // fd-passing mode takes SCM_RIGHTS-injected sockets; over-socket mode drives
    // the PQC exchange across a connection it accepts itself; the default mode
    // consumes kernel upcalls.
    if let Ok(path) = env::var("SYNTRIASS_FD_PASSING_UDS") {
        return run_fd_passing_server(&path).await;
    }
    if let Ok(addr) = env::var("SYNTRIASS_OVERSOCKET_LISTEN") {
        return run_over_socket_server(&addr).await;
    }
    // Transparent proxy mode: redirected application connections are accepted
    // here, tunneled to the remote peer over a real PQC handshake, and kTLS-
    // encrypted in-kernel. This is the data path that makes interception
    // *encrypt* unmodified apps, not merely gate them.
    if let Ok(addr) = env::var("SYNTRIASS_PROXY_LISTEN") {
        let suite = configured_suite()?;
        let identity = syntriass_overlay::crypto::resolve_identity()
            .map_err(|e| format!("transparent proxy: no identity: {e:?} (fail closed)"))?;
        return syntriass_overlay::proxy::run_proxy(&addr, identity, suite)
            .await
            .map_err(Into::into);
    }
    if let Ok(cookie) = env::var("SYNTRIASS_SESSION_COOKIE") {
        let socket_cookie = cookie.parse::<u64>()?;
        let ttl_secs = env::var("SYNTRIASS_SESSION_TTL_SECS")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()?;
        let map_pin_path = env::var("SYNTRIASS_MAP_PIN_PATH")
            .unwrap_or_else(|_| "/sys/fs/bpf/syntriass".to_string());
        run_session_establisher(socket_cookie, ttl_secs, &map_pin_path)?;
        return Ok(());
    }
    if let Ok(bpf_object) = env::var("SYNTRIASS_EBPF_OBJECT") {
        let cgroup_path =
            env::var("SYNTRIASS_CGROUP_PATH").unwrap_or_else(|_| "/sys/fs/cgroup".to_string());
        let map_pin_path = env::var("SYNTRIASS_MAP_PIN_PATH")
            .unwrap_or_else(|_| "/sys/fs/bpf/syntriass".to_string());
        return run_kernel_visibility(&bpf_object, &cgroup_path, &map_pin_path).await;
    }

    let socket_path =
        env::var("SYNTRIASS_UPCALL_SOCKET").unwrap_or_else(|_| DEFAULT_UPCALL_SOCKET.to_string());
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("syntriass daemon listening on {socket_path}");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream).await {
                eprintln!("syntriass daemon connection failed: {e}");
            }
        });
    }
}

/// Accept one record. A `KernelSockEvent::WIRE_LEN` binary payload is treated as
/// a RingBuf record; anything else is parsed as a JSON `KernelUpcall` line.
async fn handle_stream(stream: UnixStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    if buf.is_empty() {
        return Ok(());
    }

    let response = if buf.len() == KernelSockEvent::WIRE_LEN {
        process_event_record(&buf, None)
    } else {
        match serde_json::from_slice::<KernelUpcall>(&buf) {
            Ok(upcall) => run_upcall(&upcall),
            Err(e) => UpcallResponse {
                socket_id: 0,
                status: "bad_request",
                message: e.to_string(),
            },
        }
    };

    let mut stream = reader.into_inner();
    let mut body = serde_json::to_vec(&response)?;
    body.push(b'\n');
    stream.write_all(&body).await?;
    Ok(())
}
