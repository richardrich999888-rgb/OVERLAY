//! Deployable defence policy profiles — eBPF Policy Engine v2, Phase 6.
//!
//! A *profile* is a named, deployable bundle that pins a complete operational
//! policy: the normal posture, the cryptographic policy ([`CryptoPolicy`],
//! Phase 3), the hierarchy priority it installs at (Phase 2), and the degradation
//! behaviour (does it fall back, or fail closed?). An operator selects one
//! profile per deployment; applying it pushes a single policy object into the
//! kernel maps (measured in `scripts/ebpf_profile_validate.sh`).
//!
//! The three profiles span the assurance↔resilience axis:
//!
//! | Profile | Normal posture | Crypto | On degradation |
//! |---|---|---|---|
//! | **StrategicCommand** | FullPqc | FullPqcOnly + HardwareKeyRequired | **FailClosed** (never falls back) |
//! | **TacticalComms** | FullPqc | FullPqc + FallbackAllowed | EncryptedFallback |
//! | **LegacyMigration** | FullPqc | HybridOnly + controlled fallback | EncryptedFallback |
//!
//! The `crypto_flags()` of each profile are bit-compatible with the kernel
//! `crypto_flags` (`ebpf/c/policy_v2.bpf.c`), cross-checked in tests, so a profile
//! is enforced identically at the daemon and the kernel data plane.

use crate::crypto::crypto_policy::CryptoPolicy;
use crate::kinetic::{KineticConfig, OperationMode};

/// The deployable defence profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DefenceProfile {
    /// Highest assurance: full PQC only, hardware-backed key, no fallback — a
    /// degradation fails closed rather than weakening the channel.
    StrategicCommand,
    /// Resilient field operation: full PQC preferred, the encrypted PSK fallback
    /// permitted so a degraded link stays up (never plaintext).
    TacticalComms,
    /// Controlled interop during migration: hybrid required, controlled
    /// (audited, non-classical) fallback permitted, lowest priority.
    LegacyMigration,
}

/// The concrete settings a profile installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileSpec {
    pub profile: DefenceProfile,
    /// The posture installed in steady state.
    pub normal_posture: OperationMode,
    /// The cryptographic policy enforced at both layers.
    pub crypto: CryptoPolicy,
    /// The hierarchy priority this profile installs at (higher = harder to
    /// override; Strategic pins the highest).
    pub priority: u32,
    /// Whether the fallback path is provisioned (drives the kinetic supervisor:
    /// Strategic degrades straight to FailClosed, never EncryptedFallback).
    pub fallback_available: bool,
}

impl DefenceProfile {
    pub fn spec(self) -> ProfileSpec {
        match self {
            DefenceProfile::StrategicCommand => ProfileSpec {
                profile: self,
                normal_posture: OperationMode::FullPqc,
                crypto: CryptoPolicy {
                    require_full_pqc: true,
                    require_hybrid: true,
                    fallback_allowed: false,
                    hardware_key_required: true,
                    no_classical_fallback: true,
                },
                priority: 1000,
                fallback_available: false, // never falls back — fails closed
            },
            DefenceProfile::TacticalComms => ProfileSpec {
                profile: self,
                normal_posture: OperationMode::FullPqc,
                crypto: CryptoPolicy {
                    require_full_pqc: false,
                    require_hybrid: true,
                    fallback_allowed: true,
                    hardware_key_required: false,
                    no_classical_fallback: true,
                },
                priority: 500,
                fallback_available: true,
            },
            DefenceProfile::LegacyMigration => ProfileSpec {
                profile: self,
                normal_posture: OperationMode::FullPqc,
                crypto: CryptoPolicy {
                    require_full_pqc: false,
                    require_hybrid: true,
                    fallback_allowed: true,
                    hardware_key_required: false,
                    // "controlled" fallback: permitted, but never a classical one.
                    no_classical_fallback: true,
                },
                priority: 100,
                fallback_available: true,
            },
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            DefenceProfile::StrategicCommand => "strategic-command",
            DefenceProfile::TacticalComms => "tactical-comms",
            DefenceProfile::LegacyMigration => "legacy-migration",
        }
    }

    /// The kernel `crypto_flags` this profile installs.
    pub fn crypto_flags(self) -> u32 {
        self.spec().crypto.to_kernel_flags()
    }

    /// The kinetic supervisor configuration this profile implies — in particular
    /// whether a degradation may move to EncryptedFallback or must fail closed.
    pub fn kinetic_config(self) -> KineticConfig {
        KineticConfig {
            fallback_available: self.spec().fallback_available,
            ..KineticConfig::default()
        }
    }

    pub fn all() -> [DefenceProfile; 3] {
        [
            DefenceProfile::StrategicCommand,
            DefenceProfile::TacticalComms,
            DefenceProfile::LegacyMigration,
        ]
    }
}

impl ProfileSpec {
    /// The eBPF `operation_mode`/posture flag this profile installs (0/1/2).
    pub fn posture_flag(&self) -> u32 {
        self.normal_posture.flag()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::crypto_policy::kernel_flags;

    #[test]
    fn strategic_is_highest_assurance() {
        let s = DefenceProfile::StrategicCommand.spec();
        assert!(s.crypto.require_full_pqc);
        assert!(s.crypto.hardware_key_required);
        assert!(
            !s.crypto.fallback_allowed,
            "Strategic must not allow fallback"
        );
        assert!(
            !s.fallback_available,
            "Strategic degrades to FailClosed, never fallback"
        );
        // highest priority — cannot be overridden by a lower-tier profile
        assert!(s.priority > DefenceProfile::TacticalComms.spec().priority);
        // kernel flags: FULL_PQC_ONLY + HARDWARE_KEY_REQ set, FALLBACK_ALLOWED clear
        let f = DefenceProfile::StrategicCommand.crypto_flags();
        assert_ne!(f & kernel_flags::FULL_PQC_ONLY, 0);
        assert_ne!(f & kernel_flags::HARDWARE_KEY_REQ, 0);
        assert_eq!(f & kernel_flags::FALLBACK_ALLOWED, 0);
    }

    #[test]
    fn tactical_allows_fallback_never_plaintext() {
        let t = DefenceProfile::TacticalComms.spec();
        assert!(t.crypto.fallback_allowed);
        assert!(t.fallback_available);
        assert!(
            t.crypto.no_classical_fallback,
            "fallback must never be classical/plaintext"
        );
        let f = DefenceProfile::TacticalComms.crypto_flags();
        assert_ne!(f & kernel_flags::FALLBACK_ALLOWED, 0);
        assert_eq!(f & kernel_flags::FULL_PQC_ONLY, 0);
    }

    #[test]
    fn legacy_is_hybrid_with_controlled_fallback_lowest_priority() {
        let l = DefenceProfile::LegacyMigration.spec();
        assert!(l.crypto.require_hybrid);
        assert!(l.crypto.fallback_allowed);
        assert!(
            l.crypto.no_classical_fallback,
            "controlled = non-classical fallback"
        );
        // lowest priority of the three
        for p in DefenceProfile::all() {
            if p != DefenceProfile::LegacyMigration {
                assert!(l.priority < p.spec().priority);
            }
        }
    }

    #[test]
    fn no_profile_ever_permits_plaintext() {
        // Every profile's normal posture is an encrypted posture, and every
        // fallback-allowing profile forbids a classical fallback.
        for p in DefenceProfile::all() {
            let s = p.spec();
            assert_ne!(
                s.normal_posture,
                OperationMode::FailClosed,
                "{} normal posture should be operational",
                p.name()
            );
            if s.crypto.fallback_allowed {
                assert!(
                    s.crypto.no_classical_fallback,
                    "{} fallback must be non-classical",
                    p.name()
                );
            }
        }
    }

    #[test]
    fn kinetic_config_reflects_fallback_availability() {
        assert!(
            !DefenceProfile::StrategicCommand
                .kinetic_config()
                .fallback_available
        );
        assert!(
            DefenceProfile::TacticalComms
                .kinetic_config()
                .fallback_available
        );
        assert!(
            DefenceProfile::LegacyMigration
                .kinetic_config()
                .fallback_available
        );
    }
}
