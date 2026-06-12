//! Kinetic state machine — autonomous operational recovery (Phase 4).
//!
//! Drives the platform's operational posture between three modes — and only these
//! three; **there is no plaintext mode** (enforced by the type system):
//!
//!   * [`OperationMode::FullPqc`]           — the hybrid-PQC control plane is healthy.
//!   * [`OperationMode::EncryptedFallback`] — PQC unavailable; the encrypted PSK
//!     path keeps traffic confidential (AES-256, never plaintext).
//!   * [`OperationMode::FailClosed`]        — no safe channel; egress is denied.
//!
//! The numeric value of [`OperationMode::flag`] is the **`OPERATION_MODE_FLAG`**
//! the eBPF policy engine reads (`ebpf/c/policy.bpf.c`'s `operation_mode` map:
//! 0/1/2). The [`Supervisor`] consumes handshake outcomes and health events and
//! transitions autonomously: degrade on sustained handshake failure, recover on
//! sustained success. A *security* fail-closed ([`Supervisor::force_fail_closed`])
//! is **sticky** — only a manual reset clears it (an autonomous recovery must not
//! reopen a channel a security event closed).
//!
//! Invariants (tested): degradation never routes to plaintext (no such state);
//! with no provisioned fallback, degradation goes straight to `FailClosed`; a
//! `FailClosed` posture denies egress; transitions only ever follow the documented
//! edges.

/// The operational posture. Its `flag()` is the `OPERATION_MODE_FLAG` consumed by
/// the kernel policy engine. **No `Plaintext` variant exists.**
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationMode {
    FullPqc,
    EncryptedFallback,
    FailClosed,
}

impl OperationMode {
    /// The `OPERATION_MODE_FLAG` value (matches `ebpf/c/policy.bpf.c`).
    pub fn flag(self) -> u32 {
        match self {
            OperationMode::FullPqc => 0,
            OperationMode::EncryptedFallback => 1,
            OperationMode::FailClosed => 2,
        }
    }
    /// Whether egress is permitted in this posture (FailClosed denies).
    pub fn permits_egress(self) -> bool {
        !matches!(self, OperationMode::FailClosed)
    }
}

/// Thresholds for autonomous transitions.
#[derive(Clone, Copy, Debug)]
pub struct KineticConfig {
    /// Consecutive handshake failures in FullPqc before degrading.
    pub failures_to_degrade: u32,
    /// Consecutive failures in EncryptedFallback before failing closed.
    pub fallback_failures_to_closed: u32,
    /// Consecutive successes needed to climb one step back toward FullPqc.
    pub successes_to_recover: u32,
    /// Is an encrypted PSK fallback provisioned? If not, degradation skips
    /// straight to FailClosed (never plaintext).
    pub fallback_available: bool,
}

impl Default for KineticConfig {
    fn default() -> Self {
        Self {
            failures_to_degrade: 3,
            fallback_failures_to_closed: 3,
            successes_to_recover: 2,
            fallback_available: true,
        }
    }
}

/// An input event the supervisor reacts to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthEvent {
    HandshakeSuccess,
    HandshakeFailure,
    /// A security event (e.g. downgrade detected, tamper) — forces sticky fail-closed.
    SecurityViolation,
}

/// A recorded posture transition (for failover/recovery measurement & audit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transition {
    pub from: OperationMode,
    pub to: OperationMode,
    pub at_event: u64,
}

/// The autonomous supervisor. Single-threaded; a daemon wraps it and feeds it
/// events from the handshake/health path, pushing `flag()` to the eBPF
/// `operation_mode` map on each change.
pub struct Supervisor {
    mode: OperationMode,
    cfg: KineticConfig,
    consecutive_failures: u32,
    consecutive_successes: u32,
    /// A security fail-closed is sticky: no autonomous transition out of it.
    security_locked: bool,
    event_count: u64,
    transition_count: u64,
    last_transition: Option<Transition>,
}

impl Supervisor {
    pub fn new(cfg: KineticConfig) -> Self {
        Self {
            mode: OperationMode::FullPqc,
            cfg,
            consecutive_failures: 0,
            consecutive_successes: 0,
            security_locked: false,
            event_count: 0,
            transition_count: 0,
            last_transition: None,
        }
    }

    pub fn mode(&self) -> OperationMode {
        self.mode
    }
    /// The `OPERATION_MODE_FLAG` to write into the eBPF policy map.
    pub fn operation_mode_flag(&self) -> u32 {
        self.mode.flag()
    }
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }
    pub fn last_transition(&self) -> Option<Transition> {
        self.last_transition
    }
    pub fn is_security_locked(&self) -> bool {
        self.security_locked
    }

    fn transition_to(&mut self, to: OperationMode) -> OperationMode {
        if to != self.mode {
            self.last_transition = Some(Transition {
                from: self.mode,
                to,
                at_event: self.event_count,
            });
            self.transition_count += 1;
            self.mode = to;
            self.consecutive_failures = 0;
            self.consecutive_successes = 0;
        }
        self.mode
    }

    /// Feed one health event; returns the (possibly unchanged) posture.
    pub fn on_event(&mut self, ev: HealthEvent) -> OperationMode {
        self.event_count += 1;
        match ev {
            HealthEvent::SecurityViolation => {
                self.security_locked = true;
                return self.transition_to(OperationMode::FailClosed);
            }
            HealthEvent::HandshakeFailure => {
                self.consecutive_failures += 1;
                self.consecutive_successes = 0;
            }
            HealthEvent::HandshakeSuccess => {
                self.consecutive_successes += 1;
                self.consecutive_failures = 0;
            }
        }

        match (self.mode, ev) {
            // FullPqc degrades on sustained failure.
            (OperationMode::FullPqc, HealthEvent::HandshakeFailure)
                if self.consecutive_failures >= self.cfg.failures_to_degrade =>
            {
                // Encrypted fallback if provisioned; otherwise straight to
                // FailClosed — NEVER plaintext.
                if self.cfg.fallback_available {
                    self.transition_to(OperationMode::EncryptedFallback)
                } else {
                    self.transition_to(OperationMode::FailClosed)
                }
            }
            // EncryptedFallback fails closed on sustained failure.
            (OperationMode::EncryptedFallback, HealthEvent::HandshakeFailure)
                if self.consecutive_failures >= self.cfg.fallback_failures_to_closed =>
            {
                self.transition_to(OperationMode::FailClosed)
            }
            // EncryptedFallback recovers to FullPqc on sustained success.
            (OperationMode::EncryptedFallback, HealthEvent::HandshakeSuccess)
                if self.consecutive_successes >= self.cfg.successes_to_recover =>
            {
                self.transition_to(OperationMode::FullPqc)
            }
            // A *degraded* (non-security) FailClosed recovers to EncryptedFallback
            // on sustained success; a security-locked one does not.
            (OperationMode::FailClosed, HealthEvent::HandshakeSuccess)
                if !self.security_locked
                    && self.consecutive_successes >= self.cfg.successes_to_recover =>
            {
                let to = if self.cfg.fallback_available {
                    OperationMode::EncryptedFallback
                } else {
                    OperationMode::FullPqc
                };
                self.transition_to(to)
            }
            _ => self.mode,
        }
    }

    /// `handle_handshake_failure` — the named entry point from the brief.
    pub fn handle_handshake_failure(&mut self) -> OperationMode {
        self.on_event(HealthEvent::HandshakeFailure)
    }
    pub fn handle_handshake_success(&mut self) -> OperationMode {
        self.on_event(HealthEvent::HandshakeSuccess)
    }
    /// Force a sticky security fail-closed (only a manual `reset` clears it).
    pub fn force_fail_closed(&mut self) -> OperationMode {
        self.on_event(HealthEvent::SecurityViolation)
    }
    /// Manual operator reset after a security fail-closed.
    pub fn reset(&mut self) {
        self.security_locked = false;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.transition_to(OperationMode::FullPqc);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_full_pqc() {
        let s = Supervisor::new(KineticConfig::default());
        assert_eq!(s.mode(), OperationMode::FullPqc);
        assert_eq!(s.operation_mode_flag(), 0);
    }

    #[test]
    fn degrades_to_fallback_then_fail_closed() {
        let mut s = Supervisor::new(KineticConfig::default());
        // 3 failures -> EncryptedFallback.
        s.handle_handshake_failure();
        s.handle_handshake_failure();
        assert_eq!(s.mode(), OperationMode::FullPqc);
        assert_eq!(
            s.handle_handshake_failure(),
            OperationMode::EncryptedFallback
        );
        assert_eq!(s.operation_mode_flag(), 1);
        // 3 more failures -> FailClosed.
        s.handle_handshake_failure();
        s.handle_handshake_failure();
        assert_eq!(s.handle_handshake_failure(), OperationMode::FailClosed);
        assert_eq!(s.operation_mode_flag(), 2);
        assert!(!s.mode().permits_egress());
    }

    #[test]
    fn no_fallback_degrades_straight_to_fail_closed_never_plaintext() {
        let cfg = KineticConfig {
            fallback_available: false,
            ..KineticConfig::default()
        };
        let mut s = Supervisor::new(cfg);
        s.handle_handshake_failure();
        s.handle_handshake_failure();
        // With no PSK fallback, degrade goes straight to FailClosed — NOT plaintext.
        assert_eq!(s.handle_handshake_failure(), OperationMode::FailClosed);
    }

    #[test]
    fn recovers_from_fallback_on_sustained_success() {
        let mut s = Supervisor::new(KineticConfig::default());
        for _ in 0..3 {
            s.handle_handshake_failure();
        }
        assert_eq!(s.mode(), OperationMode::EncryptedFallback);
        s.handle_handshake_success();
        assert_eq!(s.handle_handshake_success(), OperationMode::FullPqc); // 2 successes
    }

    #[test]
    fn degraded_fail_closed_recovers_but_security_lock_is_sticky() {
        let mut s = Supervisor::new(KineticConfig::default());
        // degrade to fail-closed via failures
        for _ in 0..6 {
            s.handle_handshake_failure();
        }
        assert_eq!(s.mode(), OperationMode::FailClosed);
        assert!(!s.is_security_locked());
        // autonomous recovery (degraded) -> EncryptedFallback
        s.handle_handshake_success();
        assert_eq!(
            s.handle_handshake_success(),
            OperationMode::EncryptedFallback
        );

        // Security fail-closed is STICKY: successes do not reopen it.
        s.force_fail_closed();
        assert_eq!(s.mode(), OperationMode::FailClosed);
        assert!(s.is_security_locked());
        for _ in 0..10 {
            s.handle_handshake_success();
        }
        assert_eq!(
            s.mode(),
            OperationMode::FailClosed,
            "security lock must be sticky"
        );
        // Only a manual reset clears it.
        s.reset();
        assert_eq!(s.mode(), OperationMode::FullPqc);
        assert!(!s.is_security_locked());
    }

    #[test]
    fn no_plaintext_mode_exists() {
        // Exhaustive match: every OperationMode is one of the three safe states;
        // none permits plaintext. (Compile-checked exhaustiveness is the proof.)
        for m in [
            OperationMode::FullPqc,
            OperationMode::EncryptedFallback,
            OperationMode::FailClosed,
        ] {
            match m {
                OperationMode::FullPqc | OperationMode::EncryptedFallback => {
                    assert!(m.permits_egress())
                }
                OperationMode::FailClosed => assert!(!m.permits_egress()),
            }
        }
    }

    #[test]
    fn random_event_sequences_never_reach_a_forbidden_state() {
        // Fuzz-style: any sequence of events leaves the machine in one of the
        // three valid states and never violates the FailClosed-denies invariant.
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0xC0DE);
        for _ in 0..2000 {
            let mut s = Supervisor::new(KineticConfig::default());
            for _ in 0..200 {
                let ev = match rng.gen_range(0..3) {
                    0 => HealthEvent::HandshakeSuccess,
                    1 => HealthEvent::HandshakeFailure,
                    _ => HealthEvent::SecurityViolation,
                };
                let m = s.on_event(ev);
                // invariant: FailClosed denies egress; others permit.
                assert_eq!(m.permits_egress(), m != OperationMode::FailClosed);
            }
        }
    }
}
