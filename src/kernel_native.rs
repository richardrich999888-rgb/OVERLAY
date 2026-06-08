//! User-space control-plane types for the kernel-native Syntriass architecture.
//!
//! The eBPF program is responsible for detecting sockets that need enforcement.
//! This module owns the stable daemon-side contract: parse the up-call, run the
//! configured hybrid PQC handshake, and fail closed unless kTLS configuration
//! succeeds. Real kTLS installation requires a kernel-passed socket reference;
//! a plain numeric fd from another process is not sufficient.

use crate::crypto::{self, CipherSuite, CryptoError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::os::unix::io::RawFd;

pub const DEFAULT_UPCALL_SOCKET: &str = "/var/run/syntriass.sock";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KernelUpcall {
    pub socket_id: u64,
    pub local_port: u16,
    pub remote_port: u16,
    pub remote_addr: String,
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub fd: Option<RawFd>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDecision {
    Enforce,
    Ignore,
}

#[derive(Debug)]
pub enum KernelNativeError {
    Config,
    Crypto(CryptoError),
    MissingSocketReference,
    KtlsUnavailable,
}

impl fmt::Display for KernelNativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelNativeError::Config => {
                write!(f, "kernel-native policy or identity is unavailable")
            }
            KernelNativeError::Crypto(e) => write!(f, "hybrid PQC handshake failed: {e:?}"),
            KernelNativeError::MissingSocketReference => {
                write!(
                    f,
                    "kernel upcall did not include an installable socket reference"
                )
            }
            KernelNativeError::KtlsUnavailable => {
                write!(f, "kTLS key installation is not implemented")
            }
        }
    }
}

impl std::error::Error for KernelNativeError {}

pub fn classify_upcall(upcall: &KernelUpcall) -> EnforcementDecision {
    if upcall.local_port == 0 || upcall.remote_port == 0 {
        EnforcementDecision::Ignore
    } else {
        EnforcementDecision::Enforce
    }
}

pub fn configured_suite() -> Result<CipherSuite, KernelNativeError> {
    crypto::resolve_policy().map_err(|_| KernelNativeError::Config)
}

pub fn execute_local_handshake_probe(suite: CipherSuite) -> Result<(), KernelNativeError> {
    let identity = crypto::resolve_identity().map_err(KernelNativeError::Crypto)?;
    let engine = suite.engine();
    let (_initiator_state, client_hello) = engine
        .begin_initiator(&identity)
        .map_err(KernelNativeError::Crypto)?;
    let (_keys, _server_hello) = engine
        .respond(&identity, &client_hello)
        .map_err(KernelNativeError::Crypto)?;
    Ok(())
}

pub fn install_ktls_keys(_fd: RawFd) -> Result<(), KernelNativeError> {
    Err(KernelNativeError::KtlsUnavailable)
}

pub fn complete_kernel_upcall(upcall: &KernelUpcall) -> Result<(), KernelNativeError> {
    if classify_upcall(upcall) == EnforcementDecision::Ignore {
        return Ok(());
    }
    let suite = configured_suite()?;
    execute_local_handshake_probe(suite)?;
    let fd = upcall.fd.ok_or(KernelNativeError::MissingSocketReference)?;
    install_ktls_keys(fd)
}
