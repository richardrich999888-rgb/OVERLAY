//! Transparent egress proxy: the user-space data path that turns kernel
//! interception into an actual PQC + kTLS-encrypted tunnel for **unmodified**
//! applications.
//!
//! ## Why this exists
//! The eBPF `cgroup/connect` hook (`ebpf/src/cgroup_connect.rs`) *gates* a
//! connection (allow/deny) but never sees the application's payload, so it cannot
//! encrypt it. This module is the missing data path: it owns the application's
//! redirected connection, runs the real over-socket hybrid handshake to the
//! remote Syntriass peer, installs kTLS on the **outbound** socket, and splices
//! the two — so an app that issues a plain `connect()`/`send()` ends up with its
//! bytes AES-256-GCM-encrypted on the wire without a single application change.
//!
//! ## Data path
//! ```text
//!  app ──connect(dst)──▶ [redirect] ──▶ proxy listener (this module)
//!                                          │ resolve ORIGINAL dst
//!                                          ▼
//!                          dial dst ──▶ remote Syntriass peer (responder)
//!                          over-socket initiator handshake (X25519+ML-KEM)
//!                          install kTLS on the OUTBOUND socket
//!                          splice app ⇄ peer (copy_bidirectional)
//! ```
//! The `app ⇄ proxy` hop is loopback plaintext (confine to `lo`/netns); the
//! `proxy ⇄ peer` hop is kTLS ciphertext on the wire. **Fail closed:** any error
//! before/at the kTLS stage returns early, dropping both sockets (closing them)
//! before a single application byte is relayed.
//!
//! ## Redirect mechanism
//! Resolution of the original destination uses `SO_ORIGINAL_DST`, the standard
//! transparent-proxy contract populated by an iptables `REDIRECT`/`TPROXY` rule
//! (the same mechanism Envoy/Istio sidecars use). Example, scoped to the
//! enforced cgroup so only governed workloads are redirected:
//! ```text
//! iptables -t nat -A OUTPUT -p tcp -m cgroup --path syntriass.slice \
//!          -j REDIRECT --to-ports 18443
//! ```
//! An eBPF `connect`-rewrite (writing `ctx->user_ip4` + an `ORIGINAL_DST` map) is
//! an equivalent, iptables-free alternative; see `docs/UNIVERSAL_INTERCEPTION.md`.

use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

use tokio::net::TcpStream;

use crate::crypto::{CipherSuite, IdentityMaterial};
use crate::kernel_native::{install_session_ktls, KernelNativeError};
use crate::over_socket::{initiator_handshake, OverSocketError};

/// Errors from one proxied connection. Every variant ends in the same outcome —
/// both sockets dropped, no plaintext relayed — but the tag pinpoints the stage.
#[derive(Debug)]
pub enum ProxyError {
    /// Could not recover the original destination (no `SO_ORIGINAL_DST`: the
    /// redirect rule is missing, or this was a direct connection to the proxy).
    Resolve(io::Error),
    /// Could not dial the resolved destination (remote peer unreachable).
    Dial(io::Error),
    /// The over-socket PQC handshake failed (auth, protocol, or transport).
    Handshake(OverSocketError),
    /// kTLS could not be installed on the outbound socket -> fail closed.
    Ktls(KernelNativeError),
    /// The bidirectional relay ended in an I/O error.
    Relay(io::Error),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Resolve(e) => write!(f, "original-destination resolution failed: {e}"),
            ProxyError::Dial(e) => write!(f, "dial to original destination failed: {e}"),
            ProxyError::Handshake(e) => write!(f, "PQC handshake failed: {e}"),
            ProxyError::Ktls(e) => write!(f, "kTLS install failed (fail closed): {e}"),
            ProxyError::Relay(e) => write!(f, "relay I/O error: {e}"),
        }
    }
}

impl std::error::Error for ProxyError {}

/// Strategy for recovering the destination an application *intended* to reach,
/// before the kernel redirected its connection to this proxy.
pub trait OriginalDest {
    fn resolve(&self, app_fd: i32) -> io::Result<SocketAddr>;
}

/// `getsockopt(SOL_IP, SO_ORIGINAL_DST)` — the destination an iptables
/// `REDIRECT`/`TPROXY` (or netfilter) rule recorded before bouncing the
/// connection here. IPv4 today; IPv6 (`IP6T_SO_ORIGINAL_DST`) is the analogous
/// `SOL_IPV6` option (left for the IPv6 redirect lane).
#[cfg(target_os = "linux")]
pub struct SoOriginalDst;

#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(target_os = "linux")]
impl OriginalDest for SoOriginalDst {
    fn resolve(&self, app_fd: i32) -> io::Result<SocketAddr> {
        use std::net::{IpAddr, Ipv4Addr};
        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // SO_ORIGINAL_DST is read at the SOL_IP level (numerically IPPROTO_IP).
        let rc = unsafe {
            libc::getsockopt(
                app_fd,
                libc::IPPROTO_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    }
}

/// A fixed destination, for tests and for explicit (non-redirect) deployments.
pub struct FixedDest(pub SocketAddr);

impl OriginalDest for FixedDest {
    fn resolve(&self, _app_fd: i32) -> io::Result<SocketAddr> {
        Ok(self.0)
    }
}

/// Splice two connected streams until either side closes. Returns
/// `(app→peer, peer→app)` byte counts. After kTLS is installed on `peer`, the
/// `app→peer` bytes are AES-256-GCM-encrypted by the kernel on write and the
/// `peer→app` bytes are decrypted on read — transparently.
pub async fn splice(app: &mut TcpStream, peer: &mut TcpStream) -> io::Result<(u64, u64)> {
    tokio::io::copy_bidirectional(app, peer).await
}

/// Proxy one redirected application connection through the PQC + kTLS tunnel.
///
/// Fail-closed by construction: an early `return Err(..)` drops `app` and `peer`
/// (closing both fds) before any payload is relayed, so a connection that cannot
/// be encrypted is never carried in clear.
#[cfg(unix)]
pub async fn proxy_connection<R: OriginalDest>(
    mut app: TcpStream,
    resolver: &R,
    identity: &IdentityMaterial,
    suite: CipherSuite,
) -> Result<(u64, u64), ProxyError> {
    let dst = resolver
        .resolve(app.as_raw_fd())
        .map_err(ProxyError::Resolve)?;
    let mut peer = TcpStream::connect(dst).await.map_err(ProxyError::Dial)?;

    // Real two-party hybrid handshake across the OUTBOUND socket (no self-loop).
    let keys = initiator_handshake(&mut peer, identity, suite)
        .await
        .map_err(ProxyError::Handshake)?;

    // Encrypt the outbound leg in-kernel. Borrowed-fd install: on failure we do
    // NOT close here — dropping `peer`/`app` on the `?` return closes them, and
    // no bytes have been spliced yet, so this is fail-closed.
    install_session_ktls(peer.as_raw_fd(), &keys).map_err(ProxyError::Ktls)?;

    // Hand the byte stream to the kernel TLS layer via a plain bidirectional copy.
    splice(&mut app, &mut peer).await.map_err(ProxyError::Relay)
}

/// Accept loop: redirect-aware transparent proxy listener. Linux-only because it
/// relies on `SO_ORIGINAL_DST`.
#[cfg(target_os = "linux")]
pub async fn run_proxy(
    addr: &str,
    identity: std::sync::Arc<IdentityMaterial>,
    suite: CipherSuite,
) -> io::Result<()> {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind(addr).await?;
    eprintln!("syntriass proxy (transparent, SO_ORIGINAL_DST) listening on {addr}");
    loop {
        let (app, _peer) = listener.accept().await?;
        let id = std::sync::Arc::clone(&identity);
        tokio::spawn(async move {
            match proxy_connection(app, &SoOriginalDst, &id, suite).await {
                Ok((up, down)) => {
                    eprintln!("syntriass proxy: tunnel closed (app→peer {up}B, peer→app {down}B)")
                }
                Err(e) => eprintln!("syntriass proxy: connection failed closed: {e}"),
            }
        });
    }
}

/// Non-Linux stub: the transparent proxy needs `SO_ORIGINAL_DST`, so it is a
/// Linux-only runtime mode. The daemon binary still compiles on dev hosts.
#[cfg(not(target_os = "linux"))]
pub async fn run_proxy(
    _addr: &str,
    _identity: std::sync::Arc<IdentityMaterial>,
    _suite: CipherSuite,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "transparent proxy requires Linux (SO_ORIGINAL_DST + iptables REDIRECT)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_identity_public_keys, IdentityMaterial};
    use crate::over_socket::responder_handshake;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SUITE: CipherSuite = CipherSuite::NistStandard768;

    fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
        let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
        let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
        let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
        let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
        let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
        let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
        (client, server)
    }

    /// The splice primitive relays bytes in both directions independently.
    #[tokio::test]
    async fn splice_relays_bidirectionally() {
        // Two independent loopback pairs; splice the inner ends together.
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a1 = l1.local_addr().unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a2 = l2.local_addr().unwrap();

        let mut outer_a = TcpStream::connect(a1).await.unwrap();
        let (inner_a, _) = l1.accept().await.unwrap();
        let mut outer_b = TcpStream::connect(a2).await.unwrap();
        let (inner_b, _) = l2.accept().await.unwrap();

        let mut inner_a = inner_a;
        let mut inner_b = inner_b;
        let splicer = tokio::spawn(async move { splice(&mut inner_a, &mut inner_b).await });

        // outer_a -> inner_a -> inner_b -> outer_b
        outer_a.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        outer_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // outer_b -> inner_b -> inner_a -> outer_a
        outer_b.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        outer_a.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");

        drop(outer_a);
        drop(outer_b);
        let _ = splicer.await.unwrap();
    }

    /// On a host without the kTLS ULP (e.g. this macOS dev box), the proxy must
    /// complete the handshake and then FAIL CLOSED at the kTLS install — never
    /// relaying application plaintext. (On a kTLS-capable kernel the success path
    /// is covered by the privileged enforcement matrix, so skip there.)
    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_fails_closed_when_ktls_unavailable() {
        if crate::kernel_native::ktls_supported() {
            return; // success path is exercised by the Linux enforcement matrix
        }
        let (client_id, server_id) = trusting_identities();

        // Stand-in remote peer: completes the responder handshake, then waits.
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = peer_listener.accept().await.unwrap();
            let _ = responder_handshake(&mut s, &server_id, SUITE).await;
            // Hold the socket so the initiator reaches the kTLS stage.
            let mut sink = [0u8; 16];
            let _ = s.read(&mut sink).await;
        });

        // A throwaway "application" connection to feed the proxy.
        let app_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app_addr = app_listener.local_addr().unwrap();
        let app_client = TcpStream::connect(app_addr).await.unwrap();
        let (app_server_side, _) = app_listener.accept().await.unwrap();

        let res = proxy_connection(app_server_side, &FixedDest(peer_addr), &client_id, SUITE).await;

        assert!(
            matches!(res, Err(ProxyError::Ktls(_))),
            "proxy must fail closed at kTLS when the ULP is unavailable, got {res:?}"
        );
        drop(app_client);
        server.abort();
    }
}
