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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::{CipherSuite, CryptoError, IdentityMaterial, SessionKeys};
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
}

impl std::fmt::Display for OverSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverSocketError::Io(e) => write!(f, "over-socket I/O error: {e}"),
            OverSocketError::Crypto(e) => write!(f, "handshake crypto error: {e:?}"),
            OverSocketError::Protocol(m) => write!(f, "handshake protocol error: {m}"),
            OverSocketError::Ktls(e) => write!(f, "kTLS handoff failed: {e}"),
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
