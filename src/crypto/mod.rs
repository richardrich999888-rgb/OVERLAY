//! Cryptographic core for the Syntriass overlay, with runtime cipher agility.
//!
//! Late binding: the active `CipherSuite` is resolved once at process start from
//! `SYNTRIASS_SUITE` (env) or `/etc/syntriass/policy.toml`, and pinned. Suites
//! are negotiated over the wire only within what local policy permits; there is
//! no legacy/no-PQC fallback and no silent downgrade (fail closed).
//!
//! Submodules:
//!   * `generic`  - the shared X25519+ML-KEM construction, generic over KemCore.
//!   * `nist768`  - X25519 + ML-KEM-768  (suite id 0x01).
//!   * `nist1024` - X25519 + ML-KEM-1024 (suite id 0x02).

mod generic;
pub mod nist1024;
pub mod nist768;

use generic::Direction;

/// X25519 public-key length, shared by all suites.
pub const X25519_LEN: usize = 32;

/// Errors that never panic the host process.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    BadHelloLength,
    MlKemDecode,
    Decapsulate,
    Hkdf,
    Encrypt,
    Decrypt,
    NonceExhausted,
}

/// Established bidirectional session keys. Owns both directions' counters; the
/// raw key material never leaves this struct.
pub struct SessionKeys {
    tx: Direction,
    rx: Direction,
}

impl SessionKeys {
    /// Encrypt one outbound application record.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.tx.seal(plaintext)
    }
    /// Decrypt one inbound application record.
    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rx.open(ciphertext)
    }
}

/// Retained initiator handshake state. Consumed by `finish`.
pub trait InitiatorState {
    fn finish(self: Box<Self>, server_hello: &[u8]) -> Result<SessionKeys, CryptoError>;
}

/// A negotiable cryptographic suite. Trait objects are stored per-fd so the
/// active suite is chosen at runtime (dynamic dispatch).
pub trait SovereignCryptoEngine: Send + Sync {
    /// Wire identifier for this suite.
    fn suite_id(&self) -> u8;
    /// Initiator: produce retained state + ClientHello body.
    fn begin_initiator(&self) -> (Box<dyn InitiatorState>, Vec<u8>);
    /// Responder: consume ClientHello body -> session keys + ServerHello body.
    fn respond(&self, client_hello: &[u8]) -> Result<(SessionKeys, Vec<u8>), CryptoError>;
}

/// The set of suites this build knows about. No legacy/no-PQC variant exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherSuite {
    NistStandard768,
    NistStandard1024,
}

impl CipherSuite {
    pub fn id(self) -> u8 {
        match self {
            CipherSuite::NistStandard768 => nist768::SUITE_ID,
            CipherSuite::NistStandard1024 => nist1024::SUITE_ID,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            x if x == nist768::SUITE_ID => Some(CipherSuite::NistStandard768),
            x if x == nist1024::SUITE_ID => Some(CipherSuite::NistStandard1024),
            _ => None,
        }
    }

    /// Construct the engine for this suite.
    pub fn engine(self) -> Box<dyn SovereignCryptoEngine> {
        match self {
            CipherSuite::NistStandard768 => Box::new(nist768::Nist768Engine),
            CipherSuite::NistStandard1024 => Box::new(nist1024::Nist1024Engine),
        }
    }
}

// ----------------------- Late-binding policy resolution -----------------------

/// Resolve the process-wide active suite ONCE, from env then config file.
/// Order: `SYNTRIASS_SUITE` env var wins; else `/etc/syntriass/policy.toml`;
/// else a safe default of NistStandard768.
///
/// Accepted values (env or file): `0x01`/`1`/`768`/`nist768`, and
/// `0x02`/`2`/`1024`/`nist1024` (case-insensitive). Anything else -> error,
/// and the caller fails closed rather than guessing.
pub fn resolve_policy() -> Result<CipherSuite, &'static str> {
    if let Ok(val) = std::env::var("SYNTRIASS_SUITE") {
        return parse_suite_token(val.trim());
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/syntriass/policy.toml") {
        if let Some(tok) = parse_policy_file(&contents) {
            return parse_suite_token(&tok);
        }
    }
    Ok(CipherSuite::NistStandard768)
}

/// Minimal zero-dependency reader for a single `suite = "<value>"` line.
/// Ignores comments (`#`), blank lines, and surrounding quotes/whitespace.
/// We do NOT pull in a TOML crate for one key (dependency-minimization rule).
fn parse_policy_file(contents: &str) -> Option<String> {
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("suite") {
            let v = value.trim().trim_matches('"').trim_matches('\'').trim();
            return Some(v.to_string());
        }
    }
    None
}

fn parse_suite_token(tok: &str) -> Result<CipherSuite, &'static str> {
    let t = tok.trim().to_ascii_lowercase();
    match t.as_str() {
        "0x01" | "1" | "768" | "nist768" | "niststandard768" => Ok(CipherSuite::NistStandard768),
        "0x02" | "2" | "1024" | "nist1024" | "niststandard1024" => {
            Ok(CipherSuite::NistStandard1024)
        }
        _ => Err("unrecognized SYNTRIASS suite policy value"),
    }
}

// ----------------------------------- tests -----------------------------------

#[cfg(test)]
mod verification_tests {
    use super::*;

    /// Run a full handshake for one suite and return the two key sets.
    fn handshake(suite: CipherSuite) -> (SessionKeys, SessionKeys) {
        let engine = suite.engine();
        let (init_state, client_hello) = engine.begin_initiator();
        let (server_keys, server_hello) =
            engine.respond(&client_hello).expect("responder accepts hello");
        let client_keys = init_state.finish(&server_hello).expect("initiator finishes");
        (client_keys, server_keys)
    }

    /// Agility: cycle every suite in one run; each yields a working channel.
    #[test]
    fn agility_loop_all_suites() {
        for suite in [CipherSuite::NistStandard768, CipherSuite::NistStandard1024] {
            let (mut ck, mut sk) = handshake(suite);

            // client -> server
            let m1 = b"CONFIDENTIAL_MISSION_DATA_STREAM";
            let f1 = ck.seal(m1).unwrap();
            assert_ne!(&f1[..], &m1[..], "{suite:?}: ciphertext must differ");
            assert_eq!(sk.open(&f1).unwrap(), m1, "{suite:?}: c2s roundtrip");

            // server -> client
            let m2 = b"ACK 200 OK";
            let f2 = sk.seal(m2).unwrap();
            assert_eq!(ck.open(&f2).unwrap(), m2, "{suite:?}: s2c roundtrip");

            // multiple records: nonce counters advance, identical pt -> distinct ct
            let a = ck.seal(b"AAAA").unwrap();
            let b = ck.seal(b"AAAA").unwrap();
            assert_ne!(a, b, "{suite:?}: nonce counter must advance");
        }
    }

    /// Suite ids are distinct and round-trip through from_id.
    #[test]
    fn suite_id_mapping() {
        assert_eq!(CipherSuite::from_id(0x01), Some(CipherSuite::NistStandard768));
        assert_eq!(CipherSuite::from_id(0x02), Some(CipherSuite::NistStandard1024));
        assert_eq!(CipherSuite::from_id(0xFF), None);
    }

    /// Cross-session / cross-suite keys must never interoperate. This is the
    /// observable consequence of (a) ephemeral per-session keys and (b) the
    /// suite id being folded into the HKDF info. A client that established a
    /// 768 session cannot decrypt a 1024 session's records, and vice versa.
    /// (Direct unit coverage of the HKDF-info binding lives in `generic` via
    /// the handshake path; here we assert the end-to-end non-interop property.)
    #[test]
    fn cross_suite_keys_do_not_interoperate() {
        let (mut ck_768, _sk_768) = handshake(CipherSuite::NistStandard768);
        let (_ck_1024, mut sk_1024) = handshake(CipherSuite::NistStandard1024);

        let frame = ck_768.seal(b"x").unwrap();
        assert!(
            sk_1024.open(&frame).is_err(),
            "keys from different suites/sessions must not interoperate"
        );
    }

    /// MITM tamper: a flipped ciphertext byte fails authentication (fail closed).
    #[test]
    fn tampered_record_rejected() {
        let (mut ck, mut sk) = handshake(CipherSuite::NistStandard768);
        let mut f = ck.seal(b"secret").unwrap();
        let last = f.len() - 1;
        f[last] ^= 0x01;
        assert_eq!(sk.open(&f).unwrap_err(), CryptoError::Decrypt);
    }

    /// Malformed ClientHello length is rejected, not panicked.
    #[test]
    fn malformed_hello_rejected() {
        let engine = CipherSuite::NistStandard768.engine();
        assert_eq!(engine.respond(&[0u8; 10]).unwrap_err(), CryptoError::BadHelloLength);
    }

    /// Policy parsing: env tokens and file lines map to the right suites.
    #[test]
    fn policy_token_parsing() {
        assert_eq!(parse_suite_token("0x01").unwrap(), CipherSuite::NistStandard768);
        assert_eq!(parse_suite_token("1024").unwrap(), CipherSuite::NistStandard1024);
        assert_eq!(parse_suite_token("NIST768").unwrap(), CipherSuite::NistStandard768);
        assert!(parse_suite_token("legacy-aes").is_err());

        let file = "# policy\n\nsuite = \"nist1024\"\n";
        assert_eq!(parse_policy_file(file).as_deref(), Some("nist1024"));
        assert_eq!(parse_policy_file("# nothing here\n"), None);
    }
}
