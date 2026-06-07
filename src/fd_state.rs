//! Per-file-descriptor session state. No crypto math here; this is the state
//! machine and the buffers that make a byte stream behave like a framed channel.
//!
//! The handshake now carries a runtime-negotiated suite. Initiator state and the
//! established session are trait objects, so the active cipher suite is dynamic.

use crate::crypto::{CipherSuite, InitiatorState, SessionKeys};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

/// Handshake phase for a tracked socket.
pub enum Phase {
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
    pub phase: Phase,
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
            phase: Phase::ResponderAwaitingClientHello,
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
            phase: Phase::InitiatorAwaitingServerHello(state),
            policy_suite,
            tx_backlog: client_hello_frame,
            rx_wire: Vec::new(),
            rx_plain: Vec::new(),
        }
    }
}

/// Global fd -> state registry. Single Mutex is intentional for a PoC.
pub static REGISTRY: Lazy<Mutex<HashMap<i32, FdState>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
