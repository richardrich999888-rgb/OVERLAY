//! Anti-DoS admission gate for the PQC handshake (mitigation for finding **C6**:
//! CPU exhaustion via handshake flooding).
//!
//! ## The problem (C6)
//!
//! The responder's `respond()` performs the expensive half of the hybrid
//! handshake — ML-KEM encapsulation, X25519, **and** generating an ML-DSA-65
//! signature (3309 bytes) plus verifying the initiator's ML-DSA-65 signature —
//! the moment a ClientHello arrives. An attacker who sprays ClientHello messages
//! (even garbage ones, even with a spoofed source address) forces the responder
//! to burn CPU on asymmetric crypto before it has learned anything about the
//! peer. That is a classic asymmetric-work DoS.
//!
//! ## The mitigation
//!
//! A two-phase, **stateless-cookie** admission gate (the same idea as WireGuard's
//! cookie reply and QUIC's Retry token): the responder will not perform *any*
//! PQC work until the initiator echoes a cookie that the responder issued and
//! bound to the initiator's source address. Phase 0 costs one HMAC; only after a
//! cookie validates (Phase 1) does the caller proceed to `respond()`.
//!
//! ```text
//!   Initiator                          Responder (this gate)
//!   ---------                          ---------------------
//!   (initial contact) --------------->  request(source, now):
//!                                          per-source rate-limit (token bucket)
//!                                          issue stateless cookie (1 HMAC, no state)
//!                     <--- Cookie -----
//!   ClientHello + Cookie ------------>  admit(source, cookie, now):
//!                                          freshness window  (Expired?)
//!                                          HMAC verify, constant-time (BadMac?)
//!                                          anti-replay consume (Replay?)
//!                                        -- only now --> respond()  [expensive PQC]
//! ```
//!
//! ### Why this is stateless
//!
//! Issuing a cookie creates **no per-connection state**. The cookie is
//! `issued_at || server_nonce || HMAC(secret_epoch, "…" || source || issued_at ||
//! server_nonce)`. The secret rotates on a fixed period (current + previous epoch
//! retained), so validation needs only the two rotating secrets — not a table of
//! outstanding challenges. The single piece of bounded state is a short-lived
//! anti-replay set of *consumed* cookie tags, pruned to the validity window and
//! capped.
//!
//! ### Return-routability
//!
//! The cookie travels to the claimed source address. An attacker who spoofs a
//! source address never receives it, so cannot produce a valid Phase-1 message —
//! spoofed floods are stopped at Phase 0 having cost the responder only an HMAC,
//! never a PQC operation.
//!
//! Everything here is pure-CPU and deterministic under an injected clock, so it
//! is fully testable in this environment (`tests/handshake_dos_tests.rs`).

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Cookie domain-separation label (bound under the HMAC).
const COOKIE_LABEL: &[u8] = b"syntriass-overlay cookie v1";
/// Source-key domain-separation label.
const SOURCE_LABEL: &[u8] = b"syntriass-overlay source v1";

const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 32;
/// Wire length of a serialized [`Cookie`]: `issued_at(8) || nonce(16) || mac(32)`.
pub const COOKIE_WIRE_LEN: usize = 8 + NONCE_LEN + TAG_LEN;

/// Tunable admission policy. All durations are in whole seconds to match the
/// coarse, monotonic clock the caller supplies.
#[derive(Clone, Copy, Debug)]
pub struct GuardConfig {
    /// Cookie-signing secret rotation period (seconds). Current + previous kept.
    pub rotation_secs: u64,
    /// How long an issued cookie remains valid (seconds). Should be ≤ one
    /// rotation period so a cookie never outlives the previous-epoch secret.
    pub validity_secs: u64,
    /// Token-bucket burst capacity per source.
    pub rate_capacity: u32,
    /// Token-bucket refill rate per source (tokens per second).
    pub rate_refill_per_sec: u32,
    /// Maximum distinct sources tracked by the rate limiter (bounds memory under
    /// a spoofed-source flood). Oldest idle source is evicted past this.
    pub max_sources: usize,
    /// Maximum consumed-cookie tags retained for replay detection (bounds memory).
    pub max_replay_entries: usize,
    /// **Global** admitted-PQC rate, summed across *all* sources (per second).
    /// Complements the per-source bucket: caps aggregate responder work even
    /// under a distributed (many-source) flood. 0 disables the global rate gate.
    pub global_pqc_per_sec: u32,
    /// Global admitted-PQC burst capacity (token-bucket depth). 0 disables.
    pub global_pqc_burst: u32,
    /// Maximum number of PQC handshakes allowed *in flight* at once (concurrency
    /// cap / load-shed). 0 disables the concurrency gate.
    pub max_in_flight_pqc: u32,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            rotation_secs: 120,
            validity_secs: 60,
            rate_capacity: 20,
            rate_refill_per_sec: 10,
            max_sources: 4096,
            max_replay_entries: 8192,
            // Aggregate ceiling: at most 200 admitted PQC handshakes/sec sustained
            // (burst 400), and at most 256 in flight at once. These bound total
            // responder work irrespective of how many distinct sources attack.
            global_pqc_per_sec: 200,
            global_pqc_burst: 400,
            max_in_flight_pqc: 256,
        }
    }
}

/// A stateless return-routability cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cookie {
    pub issued_at: u64,
    pub server_nonce: [u8; NONCE_LEN],
    pub mac: [u8; TAG_LEN],
}

impl Cookie {
    /// Serialize to the fixed [`COOKIE_WIRE_LEN`]-byte wire form.
    pub fn to_bytes(&self) -> [u8; COOKIE_WIRE_LEN] {
        let mut out = [0u8; COOKIE_WIRE_LEN];
        out[0..8].copy_from_slice(&self.issued_at.to_be_bytes());
        out[8..8 + NONCE_LEN].copy_from_slice(&self.server_nonce);
        out[8 + NONCE_LEN..].copy_from_slice(&self.mac);
        out
    }

    /// Parse a cookie from the wire. Returns `None` on a length mismatch (the
    /// caller maps that to [`AdmissionError::Malformed`]).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != COOKIE_WIRE_LEN {
            return None;
        }
        let mut issued = [0u8; 8];
        issued.copy_from_slice(&bytes[0..8]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[8..8 + NONCE_LEN]);
        let mut mac = [0u8; TAG_LEN];
        mac.copy_from_slice(&bytes[8 + NONCE_LEN..]);
        Some(Self {
            issued_at: u64::from_be_bytes(issued),
            server_nonce: nonce,
            mac,
        })
    }
}

/// Why an admission attempt was rejected. None of these variants carry secret or
/// plaintext material; the caller drops the connection on any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Per-source rate limit exceeded (cheap drop, no cookie issued).
    Throttled,
    /// Cookie is outside its validity window (or from a future time).
    Expired,
    /// HMAC did not verify under the current or previous secret.
    BadMac,
    /// Cookie already consumed (replay).
    Replay,
    /// Cookie failed to parse.
    Malformed,
    /// The global admitted-PQC rate ceiling was hit (aggregate across all
    /// sources). The caller sheds this connection; a legitimate peer simply
    /// reconnects to obtain a fresh cookie and retry.
    GlobalRateLimited,
    /// The in-flight PQC concurrency cap was hit (load-shed). As with
    /// `GlobalRateLimited`, the peer reconnects for a fresh cookie to retry.
    AtCapacity,
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: u64,
}

/// The admission gate. Not `Sync` on its own; a daemon wraps it in a `Mutex`.
pub struct HandshakeGuard {
    cfg: GuardConfig,
    current_secret: Zeroizing<[u8; 32]>,
    prev_secret: Zeroizing<[u8; 32]>,
    current_epoch: u64,
    have_prev: bool,
    buckets: HashMap<[u8; 16], Bucket>,
    /// consumed cookie tag -> issued_at (for time-based pruning).
    consumed: HashMap<[u8; TAG_LEN], u64>,
    /// Global (all-sources) admitted-PQC rate bucket.
    global_bucket: Bucket,
    /// PQC handshakes currently in flight (concurrency gate).
    in_flight: u32,
    // Lifetime counters (observability; no timing, just counts).
    issued: u64,
    admitted: u64,
    rejected: u64,
    /// Connections shed by the global rate or concurrency gate.
    global_shed: u64,
}

impl HandshakeGuard {
    /// Create a guard seeded for the given wall-clock second `now`.
    pub fn new(cfg: GuardConfig, now: u64) -> Self {
        let mut current = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(current.as_mut());
        Self {
            cfg,
            current_secret: current,
            prev_secret: Zeroizing::new([0u8; 32]),
            current_epoch: now / cfg.rotation_secs.max(1),
            have_prev: false,
            buckets: HashMap::new(),
            consumed: HashMap::new(),
            global_bucket: Bucket {
                tokens: cfg.global_pqc_burst as f64,
                last: now,
            },
            in_flight: 0,
            issued: 0,
            admitted: 0,
            rejected: 0,
            global_shed: 0,
        }
    }

    /// (issued, admitted, rejected) lifetime counters.
    pub fn counters(&self) -> (u64, u64, u64) {
        (self.issued, self.admitted, self.rejected)
    }

    /// Number of distinct sources currently tracked (bounded by `max_sources`).
    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }

    /// Number of consumed cookies currently retained (bounded by validity +
    /// `max_replay_entries`).
    pub fn replay_entries(&self) -> usize {
        self.consumed.len()
    }

    fn source_key(source: &[u8]) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(SOURCE_LABEL);
        h.update(source);
        let digest = h.finalize();
        let mut k = [0u8; 16];
        k.copy_from_slice(&digest[..16]);
        k
    }

    fn rotate_if_needed(&mut self, now: u64) {
        let epoch = now / self.cfg.rotation_secs.max(1);
        if epoch == self.current_epoch {
            return;
        }
        // If exactly one epoch advanced, the old current becomes the previous so
        // cookies issued moments ago still validate. A larger jump discards the
        // previous (those cookies are past their validity window anyway).
        if epoch == self.current_epoch + 1 {
            self.prev_secret = self.current_secret.clone();
            self.have_prev = true;
        } else {
            self.have_prev = false;
        }
        let mut next = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(next.as_mut());
        self.current_secret = next;
        self.current_epoch = epoch;
    }

    fn compute_mac(
        secret: &[u8; 32],
        source: &[u8],
        issued_at: u64,
        nonce: &[u8],
    ) -> [u8; TAG_LEN] {
        let mut m = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        m.update(COOKIE_LABEL);
        m.update(source);
        m.update(&issued_at.to_be_bytes());
        m.update(nonce);
        let out = m.finalize().into_bytes();
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&out);
        tag
    }

    /// Token-bucket admission for `source`. Returns `true` if a token was spent.
    fn take_token(&mut self, source_key: [u8; 16], now: u64) -> bool {
        let cap = self.cfg.rate_capacity as f64;
        let refill = self.cfg.rate_refill_per_sec as f64;
        // Opportunistically evict a full, idle bucket if we are at the cap and
        // this is a new source — keeps the map bounded under a spoof flood.
        if !self.buckets.contains_key(&source_key) && self.buckets.len() >= self.cfg.max_sources {
            if let Some(victim) = self
                .buckets
                .iter()
                .filter(|(_, b)| b.tokens >= cap && b.last < now)
                .map(|(k, _)| *k)
                .next()
                .or_else(|| {
                    // Fall back to the oldest-touched bucket.
                    self.buckets
                        .iter()
                        .min_by_key(|(_, b)| b.last)
                        .map(|(k, _)| *k)
                })
            {
                self.buckets.remove(&victim);
            }
        }
        let bucket = self.buckets.entry(source_key).or_insert(Bucket {
            tokens: cap,
            last: now,
        });
        let elapsed = now.saturating_sub(bucket.last) as f64;
        bucket.tokens = (bucket.tokens + elapsed * refill).min(cap);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// **Phase 0** — cheap. Apply the per-source rate limit; if the source is
    /// within budget, issue a stateless cookie (one HMAC, no per-connection
    /// state). No PQC is performed here under any circumstances.
    pub fn request(&mut self, source: &[u8], now: u64) -> Result<Cookie, AdmissionError> {
        self.rotate_if_needed(now);
        let sk = Self::source_key(source);
        if !self.take_token(sk, now) {
            self.rejected += 1;
            return Err(AdmissionError::Throttled);
        }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let mac = Self::compute_mac(&self.current_secret, source, now, &nonce);
        self.issued += 1;
        Ok(Cookie {
            issued_at: now,
            server_nonce: nonce,
            mac,
        })
    }

    fn prune_consumed(&mut self, now: u64) {
        let horizon = now.saturating_sub(self.cfg.validity_secs);
        self.consumed.retain(|_, &mut issued| issued >= horizon);
        // Hard cap as a backstop against a same-second burst that outruns
        // time-pruning: drop the oldest entries until under the cap.
        while self.consumed.len() > self.cfg.max_replay_entries {
            if let Some(oldest) = self
                .consumed
                .iter()
                .min_by_key(|(_, &v)| v)
                .map(|(k, _)| *k)
            {
                self.consumed.remove(&oldest);
            } else {
                break;
            }
        }
    }

    /// **Phase 1** — the admission decision that gates the expensive PQC path.
    ///
    /// On `Ok(())` the caller MAY proceed to `respond()`. On any `Err` the caller
    /// MUST drop the connection and perform no PQC. Validation order is chosen so
    /// the cheapest checks reject first:
    ///   1. freshness window (`Expired`),
    ///   2. HMAC verify, constant-time, current then previous secret (`BadMac`),
    ///   3. anti-replay consume (`Replay`).
    pub fn admit(
        &mut self,
        source: &[u8],
        cookie: &Cookie,
        now: u64,
    ) -> Result<(), AdmissionError> {
        self.rotate_if_needed(now);

        // 1. Freshness: not from the future (allow tiny skew), not past validity.
        if cookie.issued_at > now.saturating_add(2) {
            self.rejected += 1;
            return Err(AdmissionError::Expired);
        }
        if now.saturating_sub(cookie.issued_at) > self.cfg.validity_secs {
            self.rejected += 1;
            return Err(AdmissionError::Expired);
        }

        // 2. Authenticity: HMAC under whichever secret matches the cookie's epoch,
        //    compared in constant time.
        let want_current = Self::compute_mac(
            &self.current_secret,
            source,
            cookie.issued_at,
            &cookie.server_nonce,
        );
        let mut ok: bool = want_current.ct_eq(&cookie.mac).into();
        if !ok && self.have_prev {
            let want_prev = Self::compute_mac(
                &self.prev_secret,
                source,
                cookie.issued_at,
                &cookie.server_nonce,
            );
            ok |= bool::from(want_prev.ct_eq(&cookie.mac));
        }
        if !ok {
            self.rejected += 1;
            return Err(AdmissionError::BadMac);
        }

        // 3. Anti-replay: a given cookie tag may be consumed exactly once.
        self.prune_consumed(now);
        if self.consumed.contains_key(&cookie.mac) {
            self.rejected += 1;
            return Err(AdmissionError::Replay);
        }
        self.consumed.insert(cookie.mac, cookie.issued_at);
        self.admitted += 1;
        Ok(())
    }

    /// **Global gate** — reserve a slot for one PQC handshake, enforcing the
    /// aggregate (all-sources) rate ceiling and the in-flight concurrency cap.
    ///
    /// Call this *after* [`admit`](Self::admit) returns `Ok` and *before* running
    /// the expensive `respond()`. On `Ok` a concurrency slot is reserved and the
    /// caller MUST later call [`release_pqc`](Self::release_pqc) (the over-socket
    /// path uses an RAII permit so this happens even on error/panic). On `Err`
    /// the caller sheds the connection without doing PQC; nothing is reserved.
    ///
    /// This is the control that bounds a *distributed* flood: per-source limiting
    /// caps each attacker, but only this aggregate gate caps the responder's total
    /// PQC work when the sources are numerous and individually under budget.
    pub fn try_acquire_pqc(&mut self, now: u64) -> Result<(), AdmissionError> {
        // Concurrency cap first (cheapest), then the aggregate rate.
        if self.cfg.max_in_flight_pqc != 0 && self.in_flight >= self.cfg.max_in_flight_pqc {
            self.global_shed += 1;
            return Err(AdmissionError::AtCapacity);
        }
        if self.cfg.global_pqc_burst != 0 {
            let cap = self.cfg.global_pqc_burst as f64;
            let refill = self.cfg.global_pqc_per_sec as f64;
            let elapsed = now.saturating_sub(self.global_bucket.last) as f64;
            self.global_bucket.tokens = (self.global_bucket.tokens + elapsed * refill).min(cap);
            self.global_bucket.last = now;
            if self.global_bucket.tokens < 1.0 {
                self.global_shed += 1;
                return Err(AdmissionError::GlobalRateLimited);
            }
            self.global_bucket.tokens -= 1.0;
        }
        self.in_flight += 1;
        Ok(())
    }

    /// Release a slot reserved by [`try_acquire_pqc`](Self::try_acquire_pqc).
    pub fn release_pqc(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// PQC handshakes currently in flight.
    pub fn in_flight_pqc(&self) -> u32 {
        self.in_flight
    }

    /// Connections shed by the global rate or concurrency gate (lifetime).
    pub fn pqc_shed(&self) -> u64 {
        self.global_shed
    }
}

/// Coarse, monotonic wall-clock seconds for the live daemon path.
///
/// Derived from a process-start `Instant`, so it never goes backwards (immune to
/// system-clock adjustments) — the property the cookie freshness window needs.
/// Tests inject explicit `now` values instead of calling this.
pub fn monotonic_secs() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    // Offset by 1 so the very first second is non-zero (keeps `issued_at != 0`).
    START.get_or_init(Instant::now).elapsed().as_secs() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> HandshakeGuard {
        HandshakeGuard::new(GuardConfig::default(), 1_000)
    }

    #[test]
    fn happy_path_request_then_admit() {
        let mut g = guard();
        let src = b"10.0.0.5:51000";
        let cookie = g.request(src, 1_000).unwrap();
        assert_eq!(g.admit(src, &cookie, 1_001), Ok(()));
        let (issued, admitted, rejected) = g.counters();
        assert_eq!((issued, admitted, rejected), (1, 1, 0));
    }

    #[test]
    fn cookie_round_trips_through_wire() {
        let mut g = guard();
        let src = b"src";
        let c = g.request(src, 1_000).unwrap();
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), COOKIE_WIRE_LEN);
        let parsed = Cookie::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, c);
        assert_eq!(g.admit(src, &parsed, 1_000), Ok(()));
    }

    #[test]
    fn forged_cookie_is_rejected_without_pqc() {
        let mut g = guard();
        let src = b"attacker";
        // A cookie the server never issued (random mac).
        let forged = Cookie {
            issued_at: 1_000,
            server_nonce: [0xAB; NONCE_LEN],
            mac: [0xCD; TAG_LEN],
        };
        assert_eq!(g.admit(src, &forged, 1_000), Err(AdmissionError::BadMac));
    }

    #[test]
    fn cookie_bound_to_source_does_not_transfer() {
        let mut g = guard();
        let cookie = g.request(b"source-A", 1_000).unwrap();
        // Same cookie, different source: MAC covers the source, so it fails.
        assert_eq!(
            g.admit(b"source-B", &cookie, 1_000),
            Err(AdmissionError::BadMac)
        );
    }

    #[test]
    fn replayed_cookie_is_rejected() {
        let mut g = guard();
        let src = b"peer";
        let cookie = g.request(src, 1_000).unwrap();
        assert_eq!(g.admit(src, &cookie, 1_000), Ok(()));
        assert_eq!(g.admit(src, &cookie, 1_000), Err(AdmissionError::Replay));
        assert_eq!(g.admit(src, &cookie, 1_001), Err(AdmissionError::Replay));
    }

    #[test]
    fn expired_cookie_is_rejected() {
        let mut g = guard();
        let src = b"slow-peer";
        let cookie = g.request(src, 1_000).unwrap();
        let too_late = 1_000 + GuardConfig::default().validity_secs + 1;
        assert_eq!(
            g.admit(src, &cookie, too_late),
            Err(AdmissionError::Expired)
        );
    }

    #[test]
    fn future_dated_cookie_is_rejected() {
        let mut g = guard();
        let forged = Cookie {
            issued_at: 2_000,
            server_nonce: [0; NONCE_LEN],
            mac: [0; TAG_LEN],
        };
        assert_eq!(g.admit(b"x", &forged, 1_000), Err(AdmissionError::Expired));
    }

    #[test]
    fn malformed_cookie_bytes_rejected() {
        assert!(Cookie::from_bytes(&[]).is_none());
        assert!(Cookie::from_bytes(&[0u8; COOKIE_WIRE_LEN - 1]).is_none());
        assert!(Cookie::from_bytes(&[0u8; COOKIE_WIRE_LEN + 1]).is_none());
        assert!(Cookie::from_bytes(&[0u8; COOKIE_WIRE_LEN]).is_some());
    }

    #[test]
    fn rate_limiter_throttles_a_single_source_burst() {
        let cfg = GuardConfig {
            rate_capacity: 5,
            rate_refill_per_sec: 1,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        let src = b"flooder";
        let mut ok = 0;
        let mut throttled = 0;
        for _ in 0..100 {
            match g.request(src, 1_000) {
                Ok(_) => ok += 1,
                Err(AdmissionError::Throttled) => throttled += 1,
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        // Exactly the burst capacity is served in one second; the rest throttled.
        assert_eq!(ok, 5);
        assert_eq!(throttled, 95);
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let cfg = GuardConfig {
            rate_capacity: 2,
            rate_refill_per_sec: 1,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        let src = b"steady";
        assert!(g.request(src, 1_000).is_ok());
        assert!(g.request(src, 1_000).is_ok());
        assert_eq!(g.request(src, 1_000), Err(AdmissionError::Throttled));
        // One second later: one token refilled.
        assert!(g.request(src, 1_001).is_ok());
        assert_eq!(g.request(src, 1_001), Err(AdmissionError::Throttled));
    }

    #[test]
    fn secret_rotation_keeps_previous_epoch_valid() {
        let cfg = GuardConfig {
            rotation_secs: 100,
            validity_secs: 60,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        let src = b"peer";
        // Issued near the end of epoch 10 (1000..1099 -> epoch 10).
        let cookie = g.request(src, 1_090).unwrap();
        // Validated early in epoch 11 (1100), within the 60s validity window.
        assert_eq!(g.admit(src, &cookie, 1_100), Ok(()));
    }

    #[test]
    fn source_map_stays_bounded_under_spoofed_flood() {
        let cfg = GuardConfig {
            max_sources: 64,
            rate_capacity: 1,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        // 10k distinct spoofed sources, one packet each.
        for i in 0..10_000u32 {
            let src = format!("198.51.100.{}:{}", i % 256, i);
            let _ = g.request(src.as_bytes(), 1_000);
        }
        assert!(
            g.tracked_sources() <= 64,
            "source map exceeded cap: {}",
            g.tracked_sources()
        );
    }

    #[test]
    fn global_rate_gate_caps_aggregate_pqc_across_sources() {
        // Per-source budget is generous, but the GLOBAL ceiling is small: even a
        // distributed flood from many distinct sources cannot exceed it.
        let cfg = GuardConfig {
            rate_capacity: 1000,
            rate_refill_per_sec: 1000,
            global_pqc_per_sec: 10,
            global_pqc_burst: 10,
            max_in_flight_pqc: 0, // isolate the rate gate
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        let mut acquired = 0u32;
        let mut shed = 0u32;
        // 500 distinct sources, each with a valid cookie, all in one second.
        for i in 0..500u32 {
            let src = format!("src-{i}");
            let cookie = g.request(src.as_bytes(), 1_000).unwrap();
            g.admit(src.as_bytes(), &cookie, 1_000).unwrap();
            match g.try_acquire_pqc(1_000) {
                Ok(()) => {
                    acquired += 1;
                    g.release_pqc();
                }
                Err(AdmissionError::GlobalRateLimited) => shed += 1,
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        assert_eq!(acquired, 10, "global burst must cap aggregate admits");
        assert_eq!(shed, 490);
        assert_eq!(g.pqc_shed(), 490);
    }

    #[test]
    fn global_rate_gate_refills_over_time() {
        let cfg = GuardConfig {
            global_pqc_per_sec: 5,
            global_pqc_burst: 5,
            max_in_flight_pqc: 0,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        for _ in 0..5 {
            assert_eq!(g.try_acquire_pqc(1_000), Ok(()));
            g.release_pqc();
        }
        assert_eq!(
            g.try_acquire_pqc(1_000),
            Err(AdmissionError::GlobalRateLimited)
        );
        // One second later, 5 tokens refill.
        assert_eq!(g.try_acquire_pqc(1_001), Ok(()));
    }

    #[test]
    fn concurrency_gate_caps_in_flight_pqc() {
        let cfg = GuardConfig {
            max_in_flight_pqc: 4,
            global_pqc_burst: 0, // isolate the concurrency gate
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg, 1_000);
        // Reserve up to the cap without releasing.
        for _ in 0..4 {
            assert_eq!(g.try_acquire_pqc(1_000), Ok(()));
        }
        assert_eq!(g.in_flight_pqc(), 4);
        assert_eq!(g.try_acquire_pqc(1_000), Err(AdmissionError::AtCapacity));
        // Releasing one frees exactly one slot.
        g.release_pqc();
        assert_eq!(g.in_flight_pqc(), 3);
        assert_eq!(g.try_acquire_pqc(1_000), Ok(()));
        assert_eq!(g.in_flight_pqc(), 4);
    }

    #[test]
    fn release_pqc_is_saturating() {
        let mut g = guard();
        // Releasing with nothing in flight must not underflow.
        g.release_pqc();
        assert_eq!(g.in_flight_pqc(), 0);
    }
}
