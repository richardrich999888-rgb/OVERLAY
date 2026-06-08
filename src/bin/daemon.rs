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
use std::os::unix::io::RawFd;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Over-socket responder mode drives the real PQC exchange across the live
    // connection socket; the default mode consumes kernel upcalls.
    if let Ok(addr) = env::var("SYNTRIASS_OVERSOCKET_LISTEN") {
        return run_over_socket_server(&addr).await;
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
