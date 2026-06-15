//! Over-socket hybrid PQC handshake for the v2 control daemon.
//!
//! Replaces the local dual-role stand-in: the daemon runs the real X25519 +
//! ML-KEM exchange **across the paused connection's socket**, then hands the
//! derived keys to the kernel via [`kernel_native::bridge_session_to_ktls`].
//!
//! Wire framing (handshake only): each message is a `u32` big-endian length
//! prefix followed by that many bytes. Exactly two messages are exchanged —
//! `ClientHello` then `ServerHello` — after which user-space I/O stops and the
//! kernel TLS layer owns the byte stream. This cleanly delineates handshake
//! framing from application payload (which never crosses user space).

use std::os::unix::io::IntoRawFd;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{CipherSuite, CryptoError, IdentityMaterial, SessionKeys};
use crate::handshake_guard::{
    monotonic_secs, AdmissionError, Cookie, HandshakeGuard, COOKIE_WIRE_LEN,
};
use crate::kernel_native::{bridge_session_to_ktls, KernelNativeError};

/// Cap on a single handshake frame (a NIST-1024 hello is ~7 KB; 1 MiB is slack).
const MAX_HANDSHAKE_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

#[derive(Debug)]
pub enum OverSocketError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Protocol(&'static str),
    Ktls(KernelNativeError),
    /// The anti-DoS admission gate rejected this connection *before* any PQC work
    /// (mitigation for finding C6). Carries the precise reason.
    Admission(AdmissionError),
}

impl std::fmt::Display for OverSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverSocketError::Io(e) => write!(f, "over-socket I/O error: {e}"),
            OverSocketError::Crypto(e) => write!(f, "handshake crypto error: {e:?}"),
            OverSocketError::Protocol(m) => write!(f, "handshake protocol error: {m}"),
            OverSocketError::Ktls(e) => write!(f, "kTLS handoff failed: {e}"),
            OverSocketError::Admission(e) => write!(f, "admission gate rejected (no PQC): {e:?}"),
        }
    }
}

impl std::error::Error for OverSocketError {}

impl From<std::io::Error> for OverSocketError {
    fn from(e: std::io::Error) -> Self {
        OverSocketError::Io(e)
    }
}

async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), OverSocketError> {
    if payload.len() > MAX_HANDSHAKE_FRAME {
        return Err(OverSocketError::Protocol("handshake frame too large"));
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, OverSocketError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > MAX_HANDSHAKE_FRAME {
        return Err(OverSocketError::Protocol("bad handshake frame length"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Initiator: write our ML-KEM public key block (ClientHello), await ServerHello,
/// finish key agreement.
pub async fn initiator_handshake(
    stream: &mut TcpStream,
    identity: &IdentityMaterial,
    suite: CipherSuite,
) -> Result<SessionKeys, OverSocketError> {
    let engine = suite.engine();
    let (state, client_hello) = engine
        .begin_initiator(identity)
        .map_err(OverSocketError::Crypto)?;
    write_frame(stream, &client_hello).await?;
    let server_hello = read_frame(stream).await?;
    state
        .finish(identity, &server_hello)
        .map_err(OverSocketError::Crypto)
}

/// Responder: read the ClientHello public key block, encapsulate to derive the
/// shared secret, write the ServerHello (ciphertext) back.
pub async fn responder_handshake(
    stream: &mut TcpStream,
    identity: &IdentityMaterial,
    suite: CipherSuite,
) -> Result<SessionKeys, OverSocketError> {
    let engine = suite.engine();
    let client_hello = read_frame(stream).await?;
    let (keys, server_hello) = engine
        .respond(identity, &client_hello)
        .map_err(OverSocketError::Crypto)?;
    write_frame(stream, &server_hello).await?;
    Ok(keys)
}

/// Run the over-socket handshake for `role`, then hand the live socket + derived
/// keys to kernel TLS.
///
/// On success the kernel owns the (now-encrypted) stream. On ANY error — a
/// malformed handshake, a dropped connection, or a kTLS failure — the socket is
/// dropped/closed and no plaintext is ever exchanged in user space.
pub async fn establish_and_bridge(
    mut stream: TcpStream,
    identity: &IdentityMaterial,
    suite: CipherSuite,
    role: HandshakeRole,
) -> Result<(), OverSocketError> {
    let keys = match role {
        HandshakeRole::Initiator => initiator_handshake(&mut stream, identity, suite).await?,
        HandshakeRole::Responder => responder_handshake(&mut stream, identity, suite).await?,
    };

    // Handshake done: stop ALL user-space I/O and hand the fd to the kernel.
    // `into_std` + `into_raw_fd` extracts the live descriptor WITHOUT closing it;
    // ownership transfers to the bridge, which closes it only on failure.
    let std_stream = stream.into_std().map_err(OverSocketError::Io)?;
    let fd = std_stream.into_raw_fd();
    bridge_session_to_ktls(fd, &keys).map_err(OverSocketError::Ktls)
}

// ---------------------------------------------------------------------------
// Anti-DoS admission gate on the live handshake path (finding C6).
//
// The gated responder adds one cheap round-trip *in front of* the existing
// two-message exchange:
//
//   1. S -> C : Cookie                (stateless; one HMAC; NO PQC)
//   2. C -> S : Cookie || ClientHello (echoed cookie proves return-routability)
//   3. S -> C : ServerHello           (sent ONLY after the gate admits)
//
// The cookie is bound to the kernel-observed peer address (requirement 2): the
// client cannot forge it on an established connection. `respond()` — the
// expensive PQC — runs only after the per-source cookie check *and* the global
// rate/concurrency gate both pass.
// ---------------------------------------------------------------------------

/// RAII reservation for one in-flight PQC handshake. Releasing the concurrency
/// slot in `Drop` guarantees the count is restored on every path — success,
/// early `?` return, or panic.
struct PqcPermit {
    guard: Arc<Mutex<HandshakeGuard>>,
}

impl Drop for PqcPermit {
    fn drop(&mut self) {
        if let Ok(mut g) = self.guard.lock() {
            g.release_pqc();
        }
    }
}

/// Initiator side of the gated handshake: receive the server cookie, then send
/// `Cookie || ClientHello`, then finish on the ServerHello.
pub async fn gated_initiator_handshake(
    stream: &mut TcpStream,
    identity: &IdentityMaterial,
    suite: CipherSuite,
) -> Result<SessionKeys, OverSocketError> {
    let cookie_bytes = read_frame(stream).await?;
    if cookie_bytes.len() != COOKIE_WIRE_LEN {
        return Err(OverSocketError::Protocol("malformed cookie reply"));
    }
    let engine = suite.engine();
    let (state, client_hello) = engine
        .begin_initiator(identity)
        .map_err(OverSocketError::Crypto)?;
    let mut frame = Vec::with_capacity(COOKIE_WIRE_LEN + client_hello.len());
    frame.extend_from_slice(&cookie_bytes);
    frame.extend_from_slice(&client_hello);
    write_frame(stream, &frame).await?;
    let server_hello = read_frame(stream).await?;
    state
        .finish(identity, &server_hello)
        .map_err(OverSocketError::Crypto)
}

/// Run the over-socket handshake under the anti-DoS admission gate, then bridge
/// the live socket to kernel TLS. This is the responder path the daemon uses.
///
/// On every rejection (`Throttled`, `Expired`, `BadMac`, `Replay`,
/// `GlobalRateLimited`, `AtCapacity`) the connection is dropped having cost the
/// responder at most a couple of HMACs — never an ML-KEM/ML-DSA operation.
pub async fn establish_and_bridge_gated(
    mut stream: TcpStream,
    identity: &IdentityMaterial,
    suite: CipherSuite,
    guard: &Arc<Mutex<HandshakeGuard>>,
) -> Result<(), OverSocketError> {
    // Requirement 2: bind the cookie (and the rate-limit key) to the actual peer
    // identity in the live connection path — the kernel-reported peer **IP**.
    // Unforgeable by the client over an established TCP connection. We key on the
    // IP, not ip:port, so an attacker cannot bypass per-source rate limiting or
    // replay detection simply by opening connections from fresh ephemeral ports.
    let source = stream
        .peer_addr()
        .map_err(OverSocketError::Io)?
        .ip()
        .to_string()
        .into_bytes();

    // Phase 0 (cheap): per-source rate limit + issue a stateless cookie. No PQC.
    // The lock is held only for the synchronous gate call, never across an await.
    let now = monotonic_secs();
    let cookie = {
        let mut g = guard
            .lock()
            .map_err(|_| OverSocketError::Protocol("admission guard poisoned"))?;
        g.request(&source, now)
            .map_err(OverSocketError::Admission)?
    };
    write_frame(&mut stream, &cookie.to_bytes()).await?;

    // Phase 1: the client must echo the cookie ahead of its ClientHello.
    let frame = read_frame(&mut stream).await?;
    if frame.len() < COOKIE_WIRE_LEN {
        return Err(OverSocketError::Protocol("gated client hello too short"));
    }
    let (cookie_bytes, client_hello) = frame.split_at(COOKIE_WIRE_LEN);
    let echoed = Cookie::from_bytes(cookie_bytes)
        .ok_or(OverSocketError::Protocol("malformed echoed cookie"))?;

    // Admit (per-source cookie + replay) and then the global gate (aggregate rate
    // + concurrency). Only on success do we hold a PQC permit and spend PQC.
    let now2 = monotonic_secs();
    let permit = {
        let mut g = guard
            .lock()
            .map_err(|_| OverSocketError::Protocol("admission guard poisoned"))?;
        g.admit(&source, &echoed, now2)
            .map_err(OverSocketError::Admission)?;
        g.try_acquire_pqc(now2)
            .map_err(OverSocketError::Admission)?;
        PqcPermit {
            guard: Arc::clone(guard),
        }
    };

    // --- Past the gate: the expensive hybrid-PQC responder runs exactly here. ---
    let engine = suite.engine();
    let (keys, server_hello) = engine
        .respond(identity, client_hello)
        .map_err(OverSocketError::Crypto)?;
    write_frame(&mut stream, &server_hello).await?;
    drop(permit); // PQC done; free the concurrency slot before the kTLS handoff.

    let std_stream = stream.into_std().map_err(OverSocketError::Io)?;
    let fd = std_stream.into_raw_fd();
    bridge_session_to_ktls(fd, &keys).map_err(OverSocketError::Ktls)
}
