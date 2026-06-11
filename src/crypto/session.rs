//! Hardened application-record layer over an established hybrid-PQC session.
//!
//! The handshake (`crypto::generic`) yields a [`SessionKeys`] with two AEAD
//! directions and per-session forward secrecy (ephemeral X25519 + ML-KEM). That
//! is sufficient for a strictly in-order, lossless transport (e.g. the kTLS
//! bridge, where the kernel owns record sequencing). For a long-lived session
//! over a **lossy, reorderable, hostile tactical link** it is not enough:
//!
//!   * lost or reordered records must not permanently desynchronise the channel
//!     (the in-order counter in [`SessionKeys::open`] cannot tolerate a gap);
//!   * a captured ciphertext must not be replayable;
//!   * a session that runs for hours/days must not encrypt unbounded traffic
//!     under one key (key-wear) and must bound the blast radius of a future key
//!     compromise (intra-session forward secrecy);
//!   * a session must have an explicit, enforced lifecycle (it expires).
//!
//! [`SecureSession`] adds exactly these four properties on top of the existing
//! keys, with **no new dependencies** and **no change to the handshake or the
//! kTLS export path**:
//!
//!   1. **Explicit sequencing.** Every record carries a 12-byte cleartext header
//!      `epoch(u32 BE) || seq(u64 BE)`, bound into the AEAD tag as associated
//!      data. The 96-bit GCM nonce is derived from `seq`.
//!   2. **Sliding-window anti-replay.** An IPsec/DTLS-style 64-record window
//!      ([`AntiReplayWindow`]) rejects replays and stale records while tolerating
//!      reordering and loss inside the window. The window is only advanced
//!      *after* the AEAD tag verifies, so a forged header cannot poison it.
//!   3. **Forward-secret rekey ratchet.** [`SecureSession::rekey`] advances both
//!      directions via a one-way HKDF ratchet ([`Direction::ratchet`]); the old
//!      keys are zeroized. The previous receive epoch is retained for exactly one
//!      step so records already in flight still open across the boundary.
//!   4. **Lifecycle limits.** [`SessionLimits`] sets soft rekey thresholds and
//!      hard caps (records, bytes, wall-clock age). Past a hard cap the session
//!      is `Expired` and both `seal` and `open` fail closed.
//!
//! Every failure path returns an `Err` — there is no path that yields plaintext
//! from an unauthenticated, replayed, stale, or expired record.

use std::time::{Duration, Instant};

use super::generic::Direction;
use super::{CryptoError, SessionKeys};

/// `epoch(u32 BE)` width in the record header.
const EPOCH_LEN: usize = 4;
/// `seq(u64 BE)` width in the record header.
const SEQ_LEN: usize = 8;
/// Cleartext per-record header, also used verbatim as the AEAD associated data.
pub const RECORD_HEADER_LEN: usize = EPOCH_LEN + SEQ_LEN;

/// IPsec/DTLS-style sliding-window replay detector (RFC 6479 in spirit).
///
/// `highest` is the largest accepted sequence number; `bitmap` bit `i` records
/// whether `highest - i` has been accepted (bit 0 == `highest`). A record is
/// fresh iff it is newer than `highest`, or within `WIDTH` of it and not yet
/// seen. Anything `>= WIDTH` below `highest` is rejected as too old.
#[derive(Debug, Clone)]
pub struct AntiReplayWindow {
    highest: u64,
    bitmap: u64,
    seen_any: bool,
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl AntiReplayWindow {
    /// Window width in records (one `u64` bitmap).
    pub const WIDTH: u64 = 64;

    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            seen_any: false,
        }
    }

    /// Non-mutating freshness test: would `seq` be accepted right now?
    pub fn is_fresh(&self, seq: u64) -> bool {
        if !self.seen_any {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        let diff = self.highest - seq;
        if diff >= Self::WIDTH {
            return false;
        }
        self.bitmap & (1u64 << diff) == 0
    }

    /// Record `seq` as accepted. Returns `false` (without mutating) if `seq` is a
    /// replay or too old. Call this only **after** the record's AEAD tag has been
    /// verified, so a forged sequence number can never advance the window.
    pub fn commit(&mut self, seq: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= Self::WIDTH {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = seq;
            true
        } else {
            let diff = self.highest - seq;
            if diff >= Self::WIDTH {
                return false;
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                false
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

/// Lifecycle thresholds for a [`SecureSession`].
///
/// Soft thresholds (`rekey_after_*`) flip the session to [`SessionState::NeedsRekey`]
/// so the operator/daemon initiates a ratchet. Hard caps (`max_*`) expire the
/// session: once any is reached, `seal`/`open` fail closed.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    pub rekey_after_records: u64,
    pub rekey_after_bytes: u64,
    pub max_records: u64,
    pub max_bytes: u64,
    pub max_age: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            // Soft: ratchet roughly every ~1M records or ~1 GiB of plaintext.
            rekey_after_records: 1 << 20,
            rekey_after_bytes: 1 << 30,
            // Hard: a generous but finite ceiling well under AES-GCM's safe
            // single-key data limit, and a 24h wall-clock expiry.
            max_records: 1 << 34,
            max_bytes: 1 << 40,
            max_age: Duration::from_secs(24 * 3600),
        }
    }
}

/// Coarse session health, derived from [`SessionLimits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Healthy; under all thresholds.
    Active,
    /// A soft threshold was crossed; the caller should [`SecureSession::rekey`].
    NeedsRekey,
    /// A hard cap was reached; the session is dead and fails closed.
    Expired,
}

/// Record-layer failure. Never carries plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// A hard lifecycle cap was reached; the session is closed.
    Expired,
    /// The record's epoch is neither the current nor the retained previous one.
    EpochMismatch,
    /// The sequence number is a replay or older than the replay window.
    Replay,
    /// The record is shorter than the header.
    Malformed,
    /// The AEAD tag did not verify (forgery/corruption) or another crypto error.
    Crypto(CryptoError),
}

/// A hardened, sequenced, replay-protected, rekeyable record channel.
pub struct SecureSession {
    tx: Direction,
    rx: Direction,
    /// Previous-epoch receive direction, retained for one rekey step so records
    /// already in flight when we ratcheted still open. Dropped (zeroized) at the
    /// next rekey.
    rx_prev: Option<Direction>,
    epoch: u32,
    tx_seq: u64,
    rx_window: AntiReplayWindow,
    rx_prev_window: AntiReplayWindow,
    /// Counters since the last rekey (drive the soft thresholds).
    records_this_epoch: u64,
    bytes_this_epoch: u64,
    /// Lifetime totals (drive the hard caps).
    records_total: u64,
    bytes_total: u64,
    created: Instant,
    limits: SessionLimits,
    expired: bool,
}

impl std::fmt::Debug for SecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSession")
            .field("epoch", &self.epoch)
            .field("tx_seq", &self.tx_seq)
            .field("records_total", &self.records_total)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl SecureSession {
    /// Wrap an established [`SessionKeys`] in the hardened record layer.
    pub fn new(keys: SessionKeys, limits: SessionLimits) -> Self {
        let (tx, rx) = keys.into_directions();
        Self {
            tx,
            rx,
            rx_prev: None,
            epoch: 0,
            tx_seq: 0,
            rx_window: AntiReplayWindow::new(),
            rx_prev_window: AntiReplayWindow::new(),
            records_this_epoch: 0,
            bytes_this_epoch: 0,
            records_total: 0,
            bytes_total: 0,
            created: Instant::now(),
            limits,
            expired: false,
        }
    }

    /// Current key epoch (number of completed rekeys).
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Total application records sealed over the session's lifetime.
    pub fn records_sent(&self) -> u64 {
        self.records_total
    }

    fn header(epoch: u32, seq: u64) -> [u8; RECORD_HEADER_LEN] {
        let mut h = [0u8; RECORD_HEADER_LEN];
        h[..EPOCH_LEN].copy_from_slice(&epoch.to_be_bytes());
        h[EPOCH_LEN..].copy_from_slice(&seq.to_be_bytes());
        h
    }

    /// Whether any hard cap has been reached. Once true it stays true.
    fn refresh_expiry(&mut self) {
        if self.expired {
            return;
        }
        if self.records_total >= self.limits.max_records
            || self.bytes_total >= self.limits.max_bytes
            || self.created.elapsed() >= self.limits.max_age
        {
            self.expired = true;
        }
    }

    /// Coarse health. `Expired` dominates `NeedsRekey` dominates `Active`.
    pub fn state(&self) -> SessionState {
        if self.expired
            || self.records_total >= self.limits.max_records
            || self.bytes_total >= self.limits.max_bytes
            || self.created.elapsed() >= self.limits.max_age
        {
            SessionState::Expired
        } else if self.records_this_epoch >= self.limits.rekey_after_records
            || self.bytes_this_epoch >= self.limits.rekey_after_bytes
        {
            SessionState::NeedsRekey
        } else {
            SessionState::Active
        }
    }

    /// True once a soft rekey threshold has been crossed (still operable).
    pub fn needs_rekey(&self) -> bool {
        matches!(self.state(), SessionState::NeedsRekey)
    }

    /// Seal one application record: `epoch || seq || AEAD(seq, aad=header, pt)`.
    /// Fails closed if the session has expired.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.refresh_expiry();
        if self.expired {
            return Err(SessionError::Expired);
        }
        // Per-epoch sequence space is u64; a rekey resets it long before this,
        // but guard the boundary anyway and fail closed.
        if self.tx_seq == u64::MAX {
            self.expired = true;
            return Err(SessionError::Expired);
        }
        let header = Self::header(self.epoch, self.tx_seq);
        let ct = self
            .tx
            .seal_at(self.tx_seq, &header, plaintext)
            .map_err(SessionError::Crypto)?;
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + ct.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&ct);

        self.tx_seq += 1;
        self.records_this_epoch += 1;
        self.bytes_this_epoch = self.bytes_this_epoch.saturating_add(plaintext.len() as u64);
        self.records_total += 1;
        self.bytes_total = self.bytes_total.saturating_add(plaintext.len() as u64);
        Ok(record)
    }

    /// Open one record. Verifies the AEAD tag, then enforces anti-replay. A
    /// record from the immediately previous epoch (in flight across a rekey) is
    /// accepted via the retained `rx_prev` direction; anything older is rejected.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, SessionError> {
        self.refresh_expiry();
        if self.expired {
            return Err(SessionError::Expired);
        }
        if record.len() < RECORD_HEADER_LEN {
            return Err(SessionError::Malformed);
        }
        let (header, ct) = record.split_at(RECORD_HEADER_LEN);
        let mut epoch_bytes = [0u8; EPOCH_LEN];
        let mut seq_bytes = [0u8; SEQ_LEN];
        epoch_bytes.copy_from_slice(&header[..EPOCH_LEN]);
        seq_bytes.copy_from_slice(&header[EPOCH_LEN..]);
        let epoch = u32::from_be_bytes(epoch_bytes);
        let seq = u64::from_be_bytes(seq_bytes);

        if epoch == self.epoch {
            // Cheap replay pre-check before spending a decryption, but the window
            // is only *committed* after the tag verifies.
            if !self.rx_window.is_fresh(seq) {
                return Err(SessionError::Replay);
            }
            let pt = self
                .rx
                .open_at(seq, header, ct)
                .map_err(SessionError::Crypto)?;
            if !self.rx_window.commit(seq) {
                return Err(SessionError::Replay);
            }
            Ok(pt)
        } else if self.epoch > 0 && epoch == self.epoch - 1 {
            // In-flight record from the previous epoch (one-step grace).
            // NB: compare against our OWN (trusted, bounded) epoch minus one —
            // never `epoch + 1`, since `epoch` is attacker-controlled and
            // `0xFFFF_FFFF + 1` would overflow-panic (a fuzzer-found fail-open).
            let prev = self.rx_prev.as_ref().ok_or(SessionError::EpochMismatch)?;
            if !self.rx_prev_window.is_fresh(seq) {
                return Err(SessionError::Replay);
            }
            let pt = prev
                .open_at(seq, header, ct)
                .map_err(SessionError::Crypto)?;
            if !self.rx_prev_window.commit(seq) {
                return Err(SessionError::Replay);
            }
            Ok(pt)
        } else {
            Err(SessionError::EpochMismatch)
        }
    }

    /// Advance both directions one forward-secret ratchet step.
    ///
    /// Retains the pre-ratchet receive direction (and its replay window) as the
    /// one-step grace epoch, ratchets `tx`/`rx` to `epoch + 1`, resets the send
    /// sequence and per-epoch counters, and starts a fresh receive window. The
    /// previous grace epoch (two epochs back) is dropped here and its key
    /// zeroized — that is the point at which forward secrecy for the older epoch
    /// becomes unconditional.
    pub fn rekey(&mut self) -> Result<(), SessionError> {
        self.refresh_expiry();
        if self.expired {
            return Err(SessionError::Expired);
        }
        let next = self.epoch.checked_add(1).ok_or(SessionError::Expired)?;
        // Stash the current rx as the grace epoch (drops the older grace epoch).
        self.rx_prev = Some(self.rx.clone());
        self.rx_prev_window = std::mem::take(&mut self.rx_window);

        self.tx.ratchet(next);
        self.rx.ratchet(next);
        self.epoch = next;
        self.tx_seq = 0;
        self.records_this_epoch = 0;
        self.bytes_this_epoch = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a connected pair of sessions directly from raw directional keys so
    /// the record layer can be tested without standing up a full handshake.
    /// (End-to-end coverage over the real handshake lives in
    /// `tests/session_hardening_tests.rs`.)
    fn paired(limits: SessionLimits) -> (SecureSession, SecureSession) {
        // Two independent sessions that share key material: we derive a single
        // SessionKeys for each side via the fallback schedule (symmetric, no
        // identity needed) with mirrored roles, exactly like the PQC path.
        let psk = [0x5au8; super::super::FALLBACK_PSK_LEN];
        let cn = [0x01u8; super::super::FALLBACK_NONCE_LEN];
        let sn = [0x02u8; super::super::FALLBACK_NONCE_LEN];
        let client = super::super::derive_fallback_session(&psk, &cn, &sn, true).unwrap();
        let server = super::super::derive_fallback_session(&psk, &cn, &sn, false).unwrap();
        (
            SecureSession::new(client, limits),
            SecureSession::new(server, limits),
        )
    }

    #[test]
    fn in_order_roundtrip() {
        let (mut a, mut b) = paired(SessionLimits::default());
        for i in 0..1000u32 {
            let msg = format!("record-{i}");
            let rec = a.seal(msg.as_bytes()).unwrap();
            assert_eq!(b.open(&rec).unwrap(), msg.as_bytes());
        }
    }

    #[test]
    fn header_is_authenticated_aad() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let mut rec = a.seal(b"mission").unwrap();
        // Flip a bit in the cleartext sequence header. The header is the AEAD
        // associated data and also drives the nonce, so a moved/forged header
        // cannot authenticate: the tag fails closed.
        rec[RECORD_HEADER_LEN - 1] ^= 0x01;
        assert_eq!(
            b.open(&rec),
            Err(SessionError::Crypto(CryptoError::Decrypt))
        );
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let mut rec = a.seal(b"mission").unwrap();
        let last = rec.len() - 1;
        rec[last] ^= 0x01;
        assert_eq!(
            b.open(&rec),
            Err(SessionError::Crypto(CryptoError::Decrypt))
        );
    }

    #[test]
    fn replay_is_rejected() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let rec = a.seal(b"once").unwrap();
        assert_eq!(b.open(&rec).unwrap(), b"once");
        // Byte-identical replay of an already-accepted record.
        assert_eq!(b.open(&rec), Err(SessionError::Replay));
    }

    #[test]
    fn reordering_within_window_is_tolerated() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let r0 = a.seal(b"0").unwrap();
        let r1 = a.seal(b"1").unwrap();
        let r2 = a.seal(b"2").unwrap();
        // Deliver out of order: 2, 0, 1 — all must open exactly once.
        assert_eq!(b.open(&r2).unwrap(), b"2");
        assert_eq!(b.open(&r0).unwrap(), b"0");
        assert_eq!(b.open(&r1).unwrap(), b"1");
        // And none may be replayed.
        assert_eq!(b.open(&r0), Err(SessionError::Replay));
    }

    #[test]
    fn record_older_than_window_is_rejected() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let first = a.seal(b"old").unwrap();
        // Advance the receiver past the window without delivering `first`.
        for _ in 0..(AntiReplayWindow::WIDTH + 2) {
            let r = a.seal(b"x").unwrap();
            assert!(b.open(&r).is_ok());
        }
        // `first` (seq 0) is now older than the window -> rejected, not replayed.
        assert_eq!(b.open(&first), Err(SessionError::Replay));
    }

    #[test]
    fn rekey_gives_fresh_keys_and_in_order_continues() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let r = a.seal(b"pre").unwrap();
        assert_eq!(b.open(&r).unwrap(), b"pre");
        a.rekey().unwrap();
        b.rekey().unwrap();
        assert_eq!(a.epoch(), 1);
        let r = a.seal(b"post").unwrap();
        assert_eq!(b.open(&r).unwrap(), b"post");
    }

    #[test]
    fn in_flight_record_opens_across_one_rekey() {
        let (mut a, mut b) = paired(SessionLimits::default());
        // `a` sealed under epoch 0 but the record is delayed.
        let delayed = a.seal(b"in-flight").unwrap();
        // Both peers rekey; `b` retains epoch-0 rx for one step.
        a.rekey().unwrap();
        b.rekey().unwrap();
        // A fresh epoch-1 record arrives first.
        let fresh = a.seal(b"fresh").unwrap();
        assert_eq!(b.open(&fresh).unwrap(), b"fresh");
        // The delayed epoch-0 record still opens via the grace epoch.
        assert_eq!(b.open(&delayed).unwrap(), b"in-flight");
    }

    #[test]
    fn record_two_epochs_old_is_rejected() {
        let (mut a, mut b) = paired(SessionLimits::default());
        let ancient = a.seal(b"ancient").unwrap();
        a.rekey().unwrap();
        b.rekey().unwrap();
        a.rekey().unwrap();
        b.rekey().unwrap();
        // `b` only retains one previous epoch; epoch 0 is now unreachable.
        assert_eq!(b.open(&ancient), Err(SessionError::EpochMismatch));
    }

    #[test]
    fn hard_record_cap_expires_session() {
        let limits = SessionLimits {
            max_records: 3,
            ..SessionLimits::default()
        };
        let (mut a, mut _b) = paired(limits);
        assert!(a.seal(b"1").is_ok());
        assert!(a.seal(b"2").is_ok());
        assert!(a.seal(b"3").is_ok());
        assert_eq!(a.state(), SessionState::Expired);
        assert_eq!(a.seal(b"4"), Err(SessionError::Expired));
    }

    #[test]
    fn soft_threshold_flags_needs_rekey_without_failing() {
        let limits = SessionLimits {
            rekey_after_records: 2,
            ..SessionLimits::default()
        };
        let (mut a, mut b) = paired(limits);
        assert_eq!(a.state(), SessionState::Active);
        let r = a.seal(b"1").unwrap();
        assert!(b.open(&r).is_ok());
        let r = a.seal(b"2").unwrap();
        assert!(b.open(&r).is_ok());
        // Soft threshold crossed: flagged, but still fully operable.
        assert!(a.needs_rekey());
        let r = a.seal(b"3").unwrap();
        assert!(b.open(&r).is_ok());
    }

    #[test]
    fn age_cap_expires_session() {
        let limits = SessionLimits {
            max_age: Duration::from_millis(30),
            ..SessionLimits::default()
        };
        let (mut a, _b) = paired(limits);
        assert!(a.seal(b"early").is_ok());
        std::thread::sleep(Duration::from_millis(45));
        assert_eq!(a.state(), SessionState::Expired);
        assert_eq!(a.seal(b"late"), Err(SessionError::Expired));
    }

    /// Regression (fuzzer-found): a record whose attacker-controlled epoch field
    /// is `u32::MAX` must fail closed, not overflow-panic on the grace-epoch
    /// comparison (`epoch + 1`). See `tests/fuzz` / session.rs:open.
    #[test]
    fn max_epoch_record_fails_closed_without_overflow() {
        let (_a, mut b) = paired(SessionLimits::default());
        // header = epoch(0xFFFFFFFF) || seq(0) || (no ciphertext needed)
        let mut record = vec![0xFFu8; RECORD_HEADER_LEN];
        for byte in record.iter_mut().take(EPOCH_LEN) {
            *byte = 0xFF;
        }
        // seq bytes = 0
        for byte in record.iter_mut().skip(EPOCH_LEN) {
            *byte = 0x00;
        }
        record.extend_from_slice(&[0u8; 16]); // arbitrary "ciphertext"
                                              // Must return an Err, never panic.
        assert!(matches!(
            b.open(&record),
            Err(SessionError::EpochMismatch) | Err(SessionError::Crypto(_))
        ));
    }

    #[test]
    fn anti_replay_window_unit() {
        let mut w = AntiReplayWindow::new();
        assert!(w.commit(0));
        assert!(!w.commit(0)); // replay
        assert!(w.commit(1));
        assert!(w.commit(5));
        assert!(w.commit(3));
        assert!(!w.commit(3)); // replay
                               // jump far ahead, then an in-window-but-old fresh seq
        assert!(w.commit(100));
        assert!(w.commit(99));
        assert!(!w.commit(100)); // replay
        assert!(!w.commit(0)); // way too old
    }
}
