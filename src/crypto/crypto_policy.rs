//! Cryptographic policy enforcement — eBPF Policy Engine v2, Phase 3.
//!
//! The eBPF data plane (`ebpf/c/policy_v2.bpf.c`) enforces the *consequence* it
//! can observe at `connect` time — whether a fallback connection is permitted —
//! but the kernel cannot see the negotiated cipher suite, whether ML-KEM was
//! actually exercised, or whether the identity key is hardware-backed. Those
//! requirements are enforced **here**, at handshake time, by the daemon, which
//! does see the negotiated [`ConnectionProfile`].
//!
//! The five named policies map to a flag set that is bit-compatible with the
//! kernel `crypto_flags` (see [`CryptoPolicy::to_kernel_flags`]); the kernel and
//! userspace therefore agree on what each flag means, and a single profile or
//! deployment can be expressed once and enforced at both layers.
//!
//! **Fail-closed:** [`CryptoPolicy::enforce`] returns `Err` on any violation, and
//! a caller MUST treat `Err` as *deny*. An under-determined profile (an attribute
//! the policy depends on is `Unknown`) is a violation, not a pass — there is no
//! "benefit of the doubt" on a security path.

use crate::crypto::CipherSuite;

/// Kernel `crypto_flags` bits — kept identical to the `CRYPTO_*` defines in
/// `ebpf/c/policy_v2.bpf.c` so the two layers cannot drift.
pub mod kernel_flags {
    pub const FULL_PQC_ONLY: u32 = 1 << 0;
    pub const HYBRID_ONLY: u32 = 1 << 1;
    pub const FALLBACK_ALLOWED: u32 = 1 << 2;
    pub const HARDWARE_KEY_REQ: u32 = 1 << 3;
    pub const NO_CLASSICAL_FB: u32 = 1 << 4;
}

/// How the long-term identity key is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyBacking {
    /// Sealed in software (passphrase-derived KEK). Not hardware.
    Software,
    /// Sealed to a hardware root of trust (TPM2 / PKCS#11 / HSM).
    Hardware,
    /// Backing could not be determined — treated as *not* hardware (fail closed).
    Unknown,
}

impl KeyBacking {
    fn is_hardware(self) -> bool {
        matches!(self, KeyBacking::Hardware)
    }
}

/// A tri-state attribute of a negotiated connection. `Unknown` is never treated
/// as satisfying a requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attr {
    Yes,
    No,
    Unknown,
}

impl Attr {
    fn is_yes(self) -> bool {
        matches!(self, Attr::Yes)
    }
}

/// What was actually negotiated for a connection — the input to enforcement.
#[derive(Clone, Copy, Debug)]
pub struct ConnectionProfile {
    /// The negotiated suite (all current suites are hybrid X25519+ML-KEM).
    pub suite: CipherSuite,
    /// ML-KEM (post-quantum KEM) was exercised in the handshake.
    pub pqc_active: Attr,
    /// Both a classical (X25519) and a PQC (ML-KEM) primitive were combined.
    pub hybrid: Attr,
    /// This connection is the encrypted PSK fallback, not the PQC handshake.
    pub is_fallback: bool,
    /// The fallback (if engaged) relies on classical public-key crypto. The
    /// Syntriass fallback is a *symmetric* PSK (AES-256), so this is normally
    /// `No`; the flag exists so a classical fallback can never slip through.
    pub fallback_is_classical: Attr,
    /// Protection of the identity key used to authenticate.
    pub key_backing: KeyBacking,
}

impl ConnectionProfile {
    /// A healthy full-PQC, hybrid, software-keyed, non-fallback connection.
    pub fn full_pqc(suite: CipherSuite) -> Self {
        ConnectionProfile {
            suite,
            pqc_active: Attr::Yes,
            hybrid: Attr::Yes,
            is_fallback: false,
            fallback_is_classical: Attr::No,
            key_backing: KeyBacking::Software,
        }
    }

    /// The encrypted PSK fallback (symmetric; no PQC KEM, not classical PK).
    pub fn encrypted_fallback(suite: CipherSuite) -> Self {
        ConnectionProfile {
            suite,
            pqc_active: Attr::No,
            hybrid: Attr::No,
            is_fallback: true,
            fallback_is_classical: Attr::No,
            key_backing: KeyBacking::Software,
        }
    }

    pub fn with_hardware_key(mut self) -> Self {
        self.key_backing = KeyBacking::Hardware;
        self
    }
}

/// Why a connection was rejected. Each maps to exactly one required policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoViolation {
    /// FullPqcOnly: a non-PQC or fallback connection was offered.
    FullPqcRequired,
    /// HybridOnly: the connection was not a classical+PQC hybrid.
    HybridRequired,
    /// Fallback engaged but FallbackAllowed was not set.
    FallbackForbidden,
    /// NoClassicalFallback: a classical-only fallback was offered.
    ClassicalFallbackForbidden,
    /// HardwareKeyRequired: the identity key is not hardware-backed.
    HardwareKeyRequired,
}

/// A cryptographic policy: the requirements a connection must meet to be allowed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CryptoPolicy {
    pub require_full_pqc: bool,
    pub require_hybrid: bool,
    pub fallback_allowed: bool,
    pub hardware_key_required: bool,
    pub no_classical_fallback: bool,
}

impl CryptoPolicy {
    /// FullPqcOnly — only full post-quantum handshakes; no fallback at all.
    pub fn full_pqc_only() -> Self {
        CryptoPolicy {
            require_full_pqc: true,
            require_hybrid: true,
            fallback_allowed: false,
            no_classical_fallback: true,
            ..Default::default()
        }
    }

    /// HybridOnly — require a classical+PQC hybrid suite.
    pub fn hybrid_only() -> Self {
        CryptoPolicy {
            require_hybrid: true,
            ..Default::default()
        }
    }

    /// FallbackAllowed — full PQC preferred, the encrypted PSK fallback permitted,
    /// but a *classical* fallback is still forbidden.
    pub fn fallback_allowed() -> Self {
        CryptoPolicy {
            require_hybrid: true,
            fallback_allowed: true,
            no_classical_fallback: true,
            ..Default::default()
        }
    }

    /// HardwareKeyRequired — the identity key must be hardware-backed.
    pub fn hardware_key_required() -> Self {
        CryptoPolicy {
            hardware_key_required: true,
            ..Default::default()
        }
    }

    /// NoClassicalFallback — fallback is permitted, but a classical-only fallback
    /// is never acceptable (the symmetric PSK fallback is fine; a classical
    /// public-key fallback is denied). `FallbackAllowed` is implied.
    pub fn no_classical_fallback() -> Self {
        CryptoPolicy {
            fallback_allowed: true,
            no_classical_fallback: true,
            ..Default::default()
        }
    }

    /// The bit-compatible kernel `crypto_flags` for this policy.
    pub fn to_kernel_flags(self) -> u32 {
        use kernel_flags::*;
        let mut f = 0;
        if self.require_full_pqc {
            f |= FULL_PQC_ONLY;
        }
        if self.require_hybrid {
            f |= HYBRID_ONLY;
        }
        if self.fallback_allowed {
            f |= FALLBACK_ALLOWED;
        }
        if self.hardware_key_required {
            f |= HARDWARE_KEY_REQ;
        }
        if self.no_classical_fallback {
            f |= NO_CLASSICAL_FB;
        }
        f
    }

    /// Enforce the policy against a negotiated connection. `Ok(())` = allow;
    /// `Err(_)` = deny (fail closed). Checks run most-fundamental first so the
    /// returned violation is the most security-relevant one.
    pub fn enforce(&self, p: &ConnectionProfile) -> Result<(), CryptoViolation> {
        // FullPqcOnly: PQC must be active and this must not be a fallback.
        if self.require_full_pqc && (!p.pqc_active.is_yes() || p.is_fallback) {
            return Err(CryptoViolation::FullPqcRequired);
        }
        // HybridOnly: a classical+PQC hybrid must have been negotiated. A fallback
        // is not a hybrid handshake, so it only passes when explicitly allowed.
        if self.require_hybrid {
            let hybrid_ok = p.hybrid.is_yes() && !p.is_fallback;
            let permitted_fallback = p.is_fallback && self.fallback_allowed;
            if !hybrid_ok && !permitted_fallback {
                return Err(CryptoViolation::HybridRequired);
            }
        }
        // Fallback engaged but not permitted.
        if p.is_fallback && !self.fallback_allowed {
            return Err(CryptoViolation::FallbackForbidden);
        }
        // NoClassicalFallback: a classical fallback is never acceptable. `Unknown`
        // classicality on a fallback is treated as classical (fail closed).
        if self.no_classical_fallback && p.is_fallback && !p.fallback_is_classical.is_no() {
            return Err(CryptoViolation::ClassicalFallbackForbidden);
        }
        // HardwareKeyRequired: software / unknown backing is rejected.
        if self.hardware_key_required && !p.key_backing.is_hardware() {
            return Err(CryptoViolation::HardwareKeyRequired);
        }
        Ok(())
    }

    /// Convenience: a boolean allow/deny.
    pub fn permits(&self, p: &ConnectionProfile) -> bool {
        self.enforce(p).is_ok()
    }
}

impl Attr {
    fn is_no(self) -> bool {
        matches!(self, Attr::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> CipherSuite {
        CipherSuite::NistStandard768
    }

    #[test]
    fn full_pqc_only_accepts_full_pqc_rejects_fallback() {
        let pol = CryptoPolicy::full_pqc_only();
        assert!(pol.permits(&ConnectionProfile::full_pqc(s())));
        assert_eq!(
            pol.enforce(&ConnectionProfile::encrypted_fallback(s())),
            Err(CryptoViolation::FullPqcRequired)
        );
    }

    #[test]
    fn fallback_allowed_accepts_encrypted_fallback() {
        let pol = CryptoPolicy::fallback_allowed();
        assert!(pol.permits(&ConnectionProfile::full_pqc(s())));
        assert!(pol.permits(&ConnectionProfile::encrypted_fallback(s())));
    }

    #[test]
    fn no_fallback_policy_rejects_fallback() {
        // hybrid_only does not permit fallback
        let pol = CryptoPolicy::hybrid_only();
        assert_eq!(
            pol.enforce(&ConnectionProfile::encrypted_fallback(s())),
            Err(CryptoViolation::HybridRequired)
        );
    }

    #[test]
    fn no_classical_fallback_rejects_classical_fallback() {
        let pol = CryptoPolicy::fallback_allowed(); // allows the PSK fallback
        let mut classical = ConnectionProfile::encrypted_fallback(s());
        classical.fallback_is_classical = Attr::Yes;
        assert_eq!(
            pol.enforce(&classical),
            Err(CryptoViolation::ClassicalFallbackForbidden)
        );
        // the symmetric PSK fallback (classical = No) is still accepted
        assert!(pol.permits(&ConnectionProfile::encrypted_fallback(s())));
    }

    #[test]
    fn hardware_key_required_rejects_software() {
        let pol = CryptoPolicy::hardware_key_required();
        assert_eq!(
            pol.enforce(&ConnectionProfile::full_pqc(s())),
            Err(CryptoViolation::HardwareKeyRequired)
        );
        assert!(pol.permits(&ConnectionProfile::full_pqc(s()).with_hardware_key()));
    }

    #[test]
    fn unknown_attributes_fail_closed() {
        // FullPqcOnly with an unknown pqc_active must reject (no benefit of doubt).
        let pol = CryptoPolicy::full_pqc_only();
        let mut p = ConnectionProfile::full_pqc(s());
        p.pqc_active = Attr::Unknown;
        assert!(pol.enforce(&p).is_err());

        // HardwareKeyRequired with Unknown backing must reject.
        let polh = CryptoPolicy::hardware_key_required();
        let mut ph = ConnectionProfile::full_pqc(s());
        ph.key_backing = KeyBacking::Unknown;
        assert_eq!(polh.enforce(&ph), Err(CryptoViolation::HardwareKeyRequired));

        // NoClassicalFallback with Unknown classicality on a fallback must reject.
        let polc = CryptoPolicy::no_classical_fallback();
        let mut pc = ConnectionProfile::encrypted_fallback(s());
        pc.fallback_is_classical = Attr::Unknown;
        assert_eq!(
            polc.enforce(&pc),
            Err(CryptoViolation::ClassicalFallbackForbidden)
        );
    }

    #[test]
    fn kernel_flags_match_defines() {
        // Mirror of the CRYPTO_* defines in ebpf/c/policy_v2.bpf.c.
        assert_eq!(kernel_flags::FULL_PQC_ONLY, 1 << 0);
        assert_eq!(kernel_flags::HYBRID_ONLY, 1 << 1);
        assert_eq!(kernel_flags::FALLBACK_ALLOWED, 1 << 2);
        assert_eq!(kernel_flags::HARDWARE_KEY_REQ, 1 << 3);
        assert_eq!(kernel_flags::NO_CLASSICAL_FB, 1 << 4);

        // full_pqc_only sets FULL_PQC_ONLY | HYBRID_ONLY | NO_CLASSICAL_FB and
        // crucially NOT FALLBACK_ALLOWED — the kernel will deny a fallback.
        let f = CryptoPolicy::full_pqc_only().to_kernel_flags();
        assert_ne!(f & kernel_flags::FULL_PQC_ONLY, 0);
        assert_eq!(f & kernel_flags::FALLBACK_ALLOWED, 0);

        // fallback_allowed sets FALLBACK_ALLOWED (kernel permits the PSK fallback).
        let g = CryptoPolicy::fallback_allowed().to_kernel_flags();
        assert_ne!(g & kernel_flags::FALLBACK_ALLOWED, 0);
        assert_eq!(g & kernel_flags::FULL_PQC_ONLY, 0);
    }
}
