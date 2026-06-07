//! Per-file-descriptor session state. No crypto math here; this is the state
//! machine and the buffers that make a byte stream behave like a framed channel.
//!
//! The handshake now carries a runtime-negotiated suite. Initiator state and the
//! established session are trait objects, so the active cipher suite is dynamic.

use crate::crypto::{CipherSuite, InitiatorState, SessionKeys};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroize;

pub const MAX_WIRE_RX_BUFFER: usize = 16 * 1024 * 1024;
pub const MAX_WRITE_BACKLOG: usize = 16 * 1024 * 1024;
pub const MAX_PLAIN_RX_BUFFER: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    LimitExceeded,
}

/// Handshake phase for a tracked socket.
pub enum FdPhase {
    /// connect(2) succeeded; we are the initiator. We hold the boxed initiator
    /// state for the suite we proposed until ServerHello arrives.
    InitiatorAwaitingServerHello(Box<dyn InitiatorState>),
    /// We accepted on this fd and expect a ClientHello first.
    ResponderAwaitingClientHello,
    /// Key agreement complete; application data flows encrypted.
    Active(SessionKeys),
    /// Terminal: framing/crypto/negotiation failure. Fail closed.
    Failed,
}

/// All mutable state for one socket fd.
pub struct FdState {
    pub phase: FdPhase,
    /// Suite this process is configured to use (policy-pinned at startup).
    pub policy_suite: CipherSuite,
    /// Bytes framed and waiting to go out on the real socket.
    pub tx_backlog: Vec<u8>,
    /// Raw bytes pulled off the wire, awaiting frame reassembly.
    pub rx_wire: Vec<u8>,
    /// Decrypted plaintext ready to hand back to the application.
    pub rx_plain: Vec<u8>,
}

impl FdState {
    pub fn responder(policy_suite: CipherSuite) -> Self {
        Self {
            phase: FdPhase::ResponderAwaitingClientHello,
            policy_suite,
            tx_backlog: Vec::new(),
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
        }
    }

    pub fn initiator(
        policy_suite: CipherSuite,
        state: Box<dyn InitiatorState>,
        client_hello_frame: Vec<u8>,
    ) -> Self {
        Self {
            phase: FdPhase::InitiatorAwaitingServerHello(state),
            policy_suite,
            tx_backlog: client_hello_frame,
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
        }
    }

    pub fn failed(policy_suite: CipherSuite) -> Self {
        Self {
            phase: FdPhase::Failed,
            policy_suite,
            tx_backlog: Vec::new(),
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
        }
    }

    pub fn append_tx(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.tx_backlog, bytes, MAX_WRITE_BACKLOG)
    }

    pub fn append_rx_wire(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.rx_wire, bytes, MAX_WIRE_RX_BUFFER)
    }

    pub fn append_rx_plain(&mut self, bytes: &[u8]) -> Result<(), BufferError> {
        append_bounded(&mut self.rx_plain, bytes, MAX_PLAIN_RX_BUFFER)
    }
}

impl Drop for FdState {
    fn drop(&mut self) {
        self.tx_backlog.zeroize();
        self.rx_wire.zeroize();
        self.rx_plain.zeroize();
    }
}

fn append_bounded(buf: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), BufferError> {
    if bytes.len() > limit.saturating_sub(buf.len()) {
        return Err(BufferError::LimitExceeded);
    }
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Global fd -> state registry. Single Mutex is intentional for a PoC.
pub static REGISTRY: Lazy<Mutex<HashMap<i32, FdState>>> = Lazy::new(|| Mutex::new(HashMap::new()));
