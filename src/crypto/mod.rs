//! Cryptographic core for the Syntriass overlay, with runtime cipher agility.
//!
//! Late binding: the active `CipherSuite` is resolved from `SYNTRIASS_SUITE`
//! (env) or `/etc/syntriass/policy.toml`, cached, and refreshed by the runtime
//! hot-reload worker. Suites are negotiated over the wire only within what local
//! policy permits; there is no legacy/no-PQC fallback and no silent downgrade
//! (fail closed).
//!
//! Submodules:
//!   * `generic`  - the shared X25519+ML-KEM construction, generic over KemCore.
//!   * `nist768`  - X25519 + ML-KEM-768  (suite id 0x01).
//!   * `nist1024` - X25519 + ML-KEM-1024 (suite id 0x02).

pub mod crypto_policy;
pub mod fallback;
mod generic;
pub mod nist1024;
pub mod nist768;
pub mod oob;
pub mod session;

pub use session::{
    AntiReplayWindow, SecureSession, SessionError, SessionLimits, SessionState, RECORD_HEADER_LEN,
};

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use generic::Direction;
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Signature as MlDsaSignature, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use once_cell::sync::Lazy;
use std::fmt;
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// X25519 public-key length, shared by all suites.
pub const X25519_LEN: usize = 32;
/// This build authenticates handshakes with ML-DSA-65.
pub const MLDSA65_PUBLIC_LEN: usize = 1952;
pub const MLDSA65_SIGNATURE_LEN: usize = 3309;
pub const MLDSA65_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_LEN: usize = PUBLIC_KEY_LENGTH;
pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LENGTH;
pub const ED25519_SEED_LEN: usize = SECRET_KEY_LENGTH;
pub const IDENTITY_PUBLIC_LEN: usize = ED25519_PUBLIC_LEN + MLDSA65_PUBLIC_LEN;
pub const IDENTITY_SIGNATURE_LEN: usize = ED25519_SIGNATURE_LEN + MLDSA65_SIGNATURE_LEN;

/// Degraded-fallback pre-shared key + nonce sizes (quantum-safe symmetric path).
pub const FALLBACK_PSK_LEN: usize = 32;
pub const FALLBACK_NONCE_LEN: usize = 16;

/// Errors that never panic the host process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    BadHelloLength,
    BadIdentityConfig,
    Authentication,
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

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys").finish_non_exhaustive()
    }
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

    /// Consume the keys into their two raw AEAD directions.
    ///
    /// This is how [`session::SecureSession`] takes ownership of the established
    /// key material to build the hardened (sequenced, replay-protected,
    /// rekeyable) record layer on top of the handshake. Crate-internal: the
    /// directions still never expose their key bytes.
    pub(crate) fn into_directions(self) -> (Direction, Direction) {
        (self.tx, self.rx)
    }

    /// Wrap these keys in the hardened record layer ([`session::SecureSession`]).
    pub fn into_secure_session(self, limits: SessionLimits) -> SecureSession {
        SecureSession::new(self, limits)
    }

    /// Export TLS-1.3 AES-256-GCM traffic material for the kernel-TLS bridge.
    ///
    /// This is the *only* way raw key bytes leave `SessionKeys`, and it exists
    /// solely so the v2 daemon can hand the keys to the kernel via
    /// `setsockopt(SOL_TLS, ...)`. Each direction's 32-byte AEAD key is the one
    /// already derived for that direction; the 4-byte salt + 8-byte IV (the
    /// 96-bit implicit nonce) are HKDF-expanded from that key, so both peers
    /// derive identical material for the matching direction (initiator TX ==
    /// responder RX). The returned secrets zeroize on drop.
    pub fn export_ktls(&self) -> KtlsTrafficKeys {
        KtlsTrafficKeys {
            tx: self.tx.ktls_secret(),
            rx: self.rx.ktls_secret(),
        }
    }
}

/// TLS-1.3 AES-256-GCM traffic material for one direction, for the kTLS bridge.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KtlsTrafficSecret {
    pub key: [u8; 32],
    pub salt: [u8; 4],
    pub iv: [u8; 8],
}

impl fmt::Debug for KtlsTrafficSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KtlsTrafficSecret").finish_non_exhaustive()
    }
}

/// Both directions exported from an established session.
#[derive(Clone, Debug)]
pub struct KtlsTrafficKeys {
    pub tx: KtlsTrafficSecret,
    pub rx: KtlsTrafficSecret,
}

/// Retained initiator handshake state. Consumed by `finish`.
pub trait InitiatorState: Send {
    fn finish(
        self: Box<Self>,
        identity: &IdentityMaterial,
        server_hello: &[u8],
    ) -> Result<SessionKeys, CryptoError>;
}

/// A negotiable cryptographic suite. Trait objects are stored per-fd so the
/// active suite is chosen at runtime (dynamic dispatch).
pub trait SovereignCryptoEngine: Send + Sync {
    /// Wire identifier for this suite.
    fn suite_id(&self) -> u8;
    /// Initiator: produce retained state + ClientHello body.
    fn begin_initiator(
        &self,
        identity: &IdentityMaterial,
    ) -> Result<(Box<dyn InitiatorState>, Vec<u8>), CryptoError>;
    /// Responder: consume ClientHello body -> session keys + ServerHello body.
    fn respond(
        &self,
        identity: &IdentityMaterial,
        client_hello: &[u8],
    ) -> Result<(SessionKeys, Vec<u8>), CryptoError>;
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

/// Long-term local identity plus the exact peer identity this process trusts.
///
/// The constructed material (with expanded Ed25519/ML-DSA-65 signing keys) is
/// built once and cached process-wide behind an `Arc` in `RUNTIME_CONFIG`;
/// handshakes clone the `Arc` instead of re-expanding the keys, which is the
/// dominant per-handshake cost. The root seeds are *not* retained after
/// construction (they are zeroized when the transient `CachedIdentityConfig`
/// drops), so caching the derived keys does not widen secret residency beyond
/// what holding the seeds already implied. All key material zeroizes on drop,
/// and the cache is rebuilt on config hot-reload.
pub struct IdentityMaterial {
    own_ed25519: Ed25519SigningKey,
    own_mldsa65: MlDsaSigningKey<MlDsa65>,
    own_ed25519_public: [u8; ED25519_PUBLIC_LEN],
    own_mldsa65_public: Vec<u8>,
    peer_ed25519: Ed25519VerifyingKey,
    peer_mldsa65: MlDsaVerifyingKey<MlDsa65>,
    peer_ed25519_public: [u8; ED25519_PUBLIC_LEN],
    peer_mldsa65_public: Vec<u8>,
}

impl fmt::Debug for IdentityMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityMaterial")
            .field("own_ed25519_public", &hex_preview(&self.own_ed25519_public))
            .field("own_mldsa65_public_len", &self.own_mldsa65_public.len())
            .field(
                "peer_ed25519_public",
                &hex_preview(&self.peer_ed25519_public),
            )
            .field("peer_mldsa65_public_len", &self.peer_mldsa65_public.len())
            .finish()
    }
}

pub struct IdentitySignatures {
    pub ed25519: [u8; ED25519_SIGNATURE_LEN],
    pub mldsa65: Vec<u8>,
}

struct CachedIdentityConfig {
    own_ed25519_seed: [u8; ED25519_SEED_LEN],
    own_mldsa65_seed: [u8; MLDSA65_SEED_LEN],
    peer_ed25519_public: [u8; ED25519_PUBLIC_LEN],
    peer_mldsa65_public: Vec<u8>,
}

impl CachedIdentityConfig {
    fn to_material(&self) -> Result<IdentityMaterial, CryptoError> {
        IdentityMaterial::from_bytes(
            self.own_ed25519_seed,
            self.own_mldsa65_seed,
            self.peer_ed25519_public,
            self.peer_mldsa65_public.clone(),
        )
    }
}

impl Drop for CachedIdentityConfig {
    fn drop(&mut self) {
        self.own_ed25519_seed.zeroize();
        self.own_mldsa65_seed.zeroize();
        self.peer_ed25519_public.zeroize();
        self.peer_mldsa65_public.zeroize();
    }
}

struct RuntimeConfig {
    policy: Result<CipherSuite, &'static str>,
    /// Fully-constructed identity, shared by reference across handshakes so the
    /// Ed25519/ML-DSA key expansion happens once per config epoch, not per
    /// handshake.
    identity: Result<Arc<IdentityMaterial>, CryptoError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigError {
    Poisoned,
}

static RUNTIME_CONFIG: Lazy<RwLock<RuntimeConfig>> =
    Lazy::new(|| RwLock::new(load_runtime_config()));

impl IdentityMaterial {
    pub fn from_bytes(
        mut own_ed25519_seed: [u8; ED25519_SEED_LEN],
        mut own_mldsa65_seed: [u8; MLDSA65_SEED_LEN],
        peer_ed25519_public: [u8; ED25519_PUBLIC_LEN],
        peer_mldsa65_public: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        if peer_mldsa65_public.len() != MLDSA65_PUBLIC_LEN {
            return Err(CryptoError::BadIdentityConfig);
        }

        let own_ed25519 = Ed25519SigningKey::from_bytes(&own_ed25519_seed);
        let own_ed25519_public = own_ed25519.verifying_key().to_bytes();

        let mut mldsa_seed = ml_dsa::Seed::try_from(&own_mldsa65_seed[..])
            .map_err(|_| CryptoError::BadIdentityConfig)?;
        let own_mldsa65 = MlDsaSigningKey::<MlDsa65>::from_seed(&mldsa_seed);
        mldsa_seed.zeroize();
        let own_mldsa65_public = own_mldsa65.verifying_key().encode().as_slice().to_vec();
        own_ed25519_seed.zeroize();
        own_mldsa65_seed.zeroize();

        let peer_ed25519 = Ed25519VerifyingKey::from_bytes(&peer_ed25519_public)
            .map_err(|_| CryptoError::BadIdentityConfig)?;
        let peer_mldsa65_enc =
            EncodedVerifyingKey::<MlDsa65>::try_from(peer_mldsa65_public.as_slice())
                .map_err(|_| CryptoError::BadIdentityConfig)?;
        let peer_mldsa65 = MlDsaVerifyingKey::<MlDsa65>::decode(&peer_mldsa65_enc);

        Ok(Self {
            own_ed25519,
            own_mldsa65,
            own_ed25519_public,
            own_mldsa65_public,
            peer_ed25519,
            peer_mldsa65,
            peer_ed25519_public,
            peer_mldsa65_public,
        })
    }

    pub fn own_ed25519_public(&self) -> &[u8; ED25519_PUBLIC_LEN] {
        &self.own_ed25519_public
    }

    pub fn own_mldsa65_public(&self) -> &[u8] {
        &self.own_mldsa65_public
    }

    pub fn sign(&self, transcript: &[u8]) -> Result<IdentitySignatures, CryptoError> {
        let ed_sig: Ed25519Signature = self
            .own_ed25519
            .try_sign(transcript)
            .map_err(|_| CryptoError::Authentication)?;
        let ml_sig: MlDsaSignature<MlDsa65> = self
            .own_mldsa65
            .try_sign(transcript)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(IdentitySignatures {
            ed25519: ed_sig.to_bytes(),
            mldsa65: ml_sig.encode().as_slice().to_vec(),
        })
    }

    pub fn verify_peer_public_keys(
        &self,
        ed25519_public: &[u8],
        mldsa65_public: &[u8],
    ) -> Result<(), CryptoError> {
        if ed25519_public != self.peer_ed25519_public
            || mldsa65_public != self.peer_mldsa65_public.as_slice()
        {
            return Err(CryptoError::Authentication);
        }
        Ok(())
    }

    pub fn verify_peer_signatures(
        &self,
        transcript: &[u8],
        ed25519_signature: &[u8],
        mldsa65_signature: &[u8],
    ) -> Result<(), CryptoError> {
        let ed_sig = Ed25519Signature::try_from(ed25519_signature)
            .map_err(|_| CryptoError::Authentication)?;
        self.peer_ed25519
            .verify_strict(transcript, &ed_sig)
            .map_err(|_| CryptoError::Authentication)?;

        let ml_sig = MlDsaSignature::<MlDsa65>::try_from(mldsa65_signature)
            .map_err(|_| CryptoError::Authentication)?;
        self.peer_mldsa65
            .verify(transcript, &ml_sig)
            .map_err(|_| CryptoError::Authentication)?;
        Ok(())
    }
}

impl Drop for IdentityMaterial {
    fn drop(&mut self) {
        self.own_ed25519_public.zeroize();
        self.own_mldsa65_public.zeroize();
    }
}

// ----------------------- Late-binding policy resolution -----------------------

fn load_runtime_config() -> RuntimeConfig {
    // Build the identity (expand signing keys) once here; the transient
    // `CachedIdentityConfig` carrying the raw seeds is dropped (and zeroized)
    // as soon as the material is constructed.
    let identity = read_identity_config_from_sources()
        .and_then(|cfg| cfg.to_material())
        .map(Arc::new);
    RuntimeConfig {
        policy: read_policy_from_sources(),
        identity,
    }
}

pub fn reload_runtime_config() -> Result<(), RuntimeConfigError> {
    let next = load_runtime_config();
    let mut guard = RUNTIME_CONFIG
        .write()
        .map_err(|_| RuntimeConfigError::Poisoned)?;
    *guard = next;
    Ok(())
}

/// Resolve the process-wide active suite from the reloadable runtime cache.
/// Order: `SYNTRIASS_SUITE` env var wins; else `/etc/syntriass/policy.toml`;
/// else a safe default of NistStandard768.
///
/// Accepted values (env or file): `0x01`/`1`/`768`/`nist768`, and
/// `0x02`/`2`/`1024`/`nist1024` (case-insensitive). Anything else -> error,
/// and the caller fails closed rather than guessing.
pub fn resolve_policy() -> Result<CipherSuite, &'static str> {
    let guard = RUNTIME_CONFIG
        .read()
        .map_err(|_| "SYNTRIASS runtime config lock poisoned")?;
    guard.policy
}

fn read_policy_from_sources() -> Result<CipherSuite, &'static str> {
    if let Ok(val) = std::env::var("SYNTRIASS_SUITE") {
        return parse_suite_token(val.trim());
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/syntriass/policy.toml") {
        match parse_policy_file(&contents)? {
            Some(tok) => return parse_suite_token(&tok),
            None => return Ok(CipherSuite::NistStandard768),
        }
    }
    Ok(CipherSuite::NistStandard768)
}

/// Return the process-wide identity, cloning the cached `Arc` (cheap) rather
/// than re-expanding the signing keys (expensive). The cache is refreshed by
/// `reload_runtime_config` on config hot-reload.
pub fn resolve_identity() -> Result<Arc<IdentityMaterial>, CryptoError> {
    let guard = RUNTIME_CONFIG
        .read()
        .map_err(|_| CryptoError::BadIdentityConfig)?;
    match &guard.identity {
        Ok(identity) => Ok(Arc::clone(identity)),
        Err(e) => Err(*e),
    }
}

/// Derive a quantum-safe degraded-fallback session from a pre-shared key and a
/// fresh nonce pair. Used only when the full PQC path is unavailable; it keeps
/// traffic **encrypted** (never plaintext) at the cost of forward secrecy. Both
/// peers must share the PSK and agree on the same nonces (initiator/responder
/// roles mirror the key directions, as in the PQC path).
pub fn derive_fallback_session(
    psk: &[u8; FALLBACK_PSK_LEN],
    client_nonce: &[u8; FALLBACK_NONCE_LEN],
    server_nonce: &[u8; FALLBACK_NONCE_LEN],
    is_initiator: bool,
) -> Result<SessionKeys, CryptoError> {
    generic::derive_fallback(psk, client_nonce, server_nonce, is_initiator)
}

/// Load the optional degraded-fallback PSK from `SYNTRIASS_FALLBACK_PSK_HEX`
/// (64 hex chars = 32 bytes). Returns `None` when unset or malformed — the
/// caller then has no fallback and must fail closed (never plaintext).
pub fn resolve_fallback_psk() -> Option<[u8; FALLBACK_PSK_LEN]> {
    let token = std::env::var("SYNTRIASS_FALLBACK_PSK_HEX").ok()?;
    decode_hex_exact::<FALLBACK_PSK_LEN>(&token).ok()
}

/// Whether the asymmetric (PQC) control path is currently healthy.
///
/// This is a *local* signal — it is read from local configuration, never from
/// the wire — which is what makes the fallback decision downgrade-resistant: an
/// on-path attacker cannot flip it to force a healthy node into fallback. A v2
/// deployment wires this to the daemon heartbeat; here it is driven by
/// `SYNTRIASS_PQC_DEGRADED` (truthy => degraded) so the path is testable.
pub fn pqc_control_available() -> bool {
    match std::env::var("SYNTRIASS_PQC_DEGRADED") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v == "1" || v == "true" || v == "yes" || v == "on")
        }
        Err(_) => true,
    }
}

/// Derive the Ed25519 + ML-DSA-65 public keys from local signing seeds.
///
/// The same derivation the `syntriass-identity` helper performs, exposed so a
/// daemon (or test) can compute the peer public keys it must trust without
/// re-implementing the key expansion.
pub fn derive_identity_public_keys(
    ed25519_seed: &[u8; ED25519_SEED_LEN],
    mldsa65_seed: &[u8; MLDSA65_SEED_LEN],
) -> Result<([u8; ED25519_PUBLIC_LEN], Vec<u8>), CryptoError> {
    let ed_pub = Ed25519SigningKey::from_bytes(ed25519_seed)
        .verifying_key()
        .to_bytes();
    let ml_seed =
        ml_dsa::Seed::try_from(&mldsa65_seed[..]).map_err(|_| CryptoError::BadIdentityConfig)?;
    let ml_pub = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_seed)
        .verifying_key()
        .encode()
        .as_slice()
        .to_vec();
    Ok((ed_pub, ml_pub))
}

fn read_identity_config_from_sources() -> Result<CachedIdentityConfig, CryptoError> {
    let file = std::fs::read_to_string("/etc/syntriass/identity.toml").ok();
    let own_ed_seed = read_identity_hex::<ED25519_SEED_LEN>(
        "SYNTRIASS_ED25519_SEED_HEX",
        "ed25519_seed",
        file.as_deref(),
    )?;
    let own_ml_seed = read_identity_hex::<MLDSA65_SEED_LEN>(
        "SYNTRIASS_MLDSA65_SEED_HEX",
        "mldsa65_seed",
        file.as_deref(),
    )?;
    let peer_ed_public = read_identity_hex::<ED25519_PUBLIC_LEN>(
        "SYNTRIASS_PEER_ED25519_PUB_HEX",
        "peer_ed25519_public",
        file.as_deref(),
    )?;
    let peer_ml_public = read_identity_hex_vec(
        "SYNTRIASS_PEER_MLDSA65_PUB_HEX",
        "peer_mldsa65_public",
        file.as_deref(),
        MLDSA65_PUBLIC_LEN,
    )?;
    Ok(CachedIdentityConfig {
        own_ed25519_seed: own_ed_seed,
        own_mldsa65_seed: own_ml_seed,
        peer_ed25519_public: peer_ed_public,
        peer_mldsa65_public: peer_ml_public,
    })
}

/// Minimal zero-dependency reader for a single `suite = "<value>"` line.
/// Ignores comments (`#`), blank lines, and surrounding quotes/whitespace.
/// We do NOT pull in a TOML crate for one key (dependency-minimization rule).
fn parse_policy_file(contents: &str) -> Result<Option<String>, &'static str> {
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("malformed SYNTRIASS policy line")?;
        if key.trim().eq_ignore_ascii_case("suite") {
            let v = value.trim().trim_matches('"').trim_matches('\'').trim();
            return Ok(Some(v.to_string()));
        }
    }
    Ok(None)
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

fn read_identity_hex<const N: usize>(
    env_key: &str,
    file_key: &str,
    file: Option<&str>,
) -> Result<[u8; N], CryptoError> {
    let token = std::env::var(env_key)
        .ok()
        .or_else(|| file.and_then(|contents| parse_policy_value(contents, file_key)))
        .ok_or(CryptoError::BadIdentityConfig)?;
    decode_hex_exact::<N>(&token)
}

fn read_identity_hex_vec(
    env_key: &str,
    file_key: &str,
    file: Option<&str>,
    expected_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let token = std::env::var(env_key)
        .ok()
        .or_else(|| file.and_then(|contents| parse_policy_value(contents, file_key)))
        .ok_or(CryptoError::BadIdentityConfig)?;
    decode_hex_vec(&token, expected_len)
}

fn parse_policy_value(contents: &str, wanted_key: &str) -> Option<String> {
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=')?;
        if key.trim().eq_ignore_ascii_case(wanted_key) {
            let v = value.trim().trim_matches('"').trim_matches('\'').trim();
            return Some(v.to_string());
        }
    }
    None
}

fn decode_hex_exact<const N: usize>(token: &str) -> Result<[u8; N], CryptoError> {
    let mut bytes = decode_hex_vec(token, N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

fn decode_hex_vec(token: &str, expected_len: usize) -> Result<Vec<u8>, CryptoError> {
    let compact: String = token.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let hex = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);
    if hex.len() != expected_len * 2 {
        return Err(CryptoError::BadIdentityConfig);
    }
    let mut out = vec![0u8; expected_len];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(CryptoError::BadIdentityConfig)?;
        let low = hex_nibble(chunk[1]).ok_or(CryptoError::BadIdentityConfig)?;
        out[idx] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(16);
    for b in bytes.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

// ----------------------------------- tests -----------------------------------

#[cfg(test)]
mod verification_tests {
    use super::*;

    /// Run a full handshake for one suite and return the two key sets.
    fn handshake(suite: CipherSuite) -> (SessionKeys, SessionKeys) {
        let (client_identity, server_identity) = identities();
        let engine = suite.engine();
        let (init_state, client_hello) = engine
            .begin_initiator(&client_identity)
            .expect("client hello");
        let (server_keys, server_hello) = engine
            .respond(&server_identity, &client_hello)
            .expect("responder accepts hello");
        let client_keys = init_state
            .finish(&client_identity, &server_hello)
            .expect("initiator finishes");
        (client_keys, server_keys)
    }

    fn identities() -> (IdentityMaterial, IdentityMaterial) {
        let client_ed = [0x11u8; ED25519_SEED_LEN];
        let client_ml = [0x22u8; MLDSA65_SEED_LEN];
        let server_ed = [0x33u8; ED25519_SEED_LEN];
        let server_ml = [0x44u8; MLDSA65_SEED_LEN];
        identity_pair(client_ed, client_ml, server_ed, server_ml)
    }

    fn identity_pair(
        client_ed_seed: [u8; ED25519_SEED_LEN],
        client_ml_seed: [u8; MLDSA65_SEED_LEN],
        server_ed_seed: [u8; ED25519_SEED_LEN],
        server_ml_seed: [u8; MLDSA65_SEED_LEN],
    ) -> (IdentityMaterial, IdentityMaterial) {
        let client_ed_key = Ed25519SigningKey::from_bytes(&client_ed_seed);
        let client_ml_arr = ml_dsa::Seed::try_from(&client_ml_seed[..]).unwrap();
        let client_ml_key = MlDsaSigningKey::<MlDsa65>::from_seed(&client_ml_arr);
        let server_ed_key = Ed25519SigningKey::from_bytes(&server_ed_seed);
        let server_ml_arr = ml_dsa::Seed::try_from(&server_ml_seed[..]).unwrap();
        let server_ml_key = MlDsaSigningKey::<MlDsa65>::from_seed(&server_ml_arr);

        let client_ed_pub = client_ed_key.verifying_key().to_bytes();
        let client_ml_pub = client_ml_key.verifying_key().encode().as_slice().to_vec();
        let server_ed_pub = server_ed_key.verifying_key().to_bytes();
        let server_ml_pub = server_ml_key.verifying_key().encode().as_slice().to_vec();

        let client = IdentityMaterial::from_bytes(
            client_ed_seed,
            client_ml_seed,
            server_ed_pub,
            server_ml_pub,
        )
        .unwrap();
        let server = IdentityMaterial::from_bytes(
            server_ed_seed,
            server_ml_seed,
            client_ed_pub,
            client_ml_pub,
        )
        .unwrap();
        (client, server)
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
        assert_eq!(
            CipherSuite::from_id(0x01),
            Some(CipherSuite::NistStandard768)
        );
        assert_eq!(
            CipherSuite::from_id(0x02),
            Some(CipherSuite::NistStandard1024)
        );
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
        let (_client_identity, server_identity) = identities();
        let engine = CipherSuite::NistStandard768.engine();
        assert_eq!(
            engine.respond(&server_identity, &[0u8; 10]).unwrap_err(),
            CryptoError::BadHelloLength
        );
    }

    #[test]
    fn unauthenticated_client_hello_rejected() {
        let (client_identity, server_identity) = identities();
        let engine = CipherSuite::NistStandard768.engine();
        let (_state, mut client_hello) = engine
            .begin_initiator(&client_identity)
            .expect("client hello");
        let last = client_hello.len() - 1;
        client_hello[last] ^= 0x01;
        assert_eq!(
            engine.respond(&server_identity, &client_hello).unwrap_err(),
            CryptoError::Authentication
        );
    }

    #[test]
    fn untrusted_client_identity_rejected() {
        let (client_identity, _server_identity) = identities();
        let (_trusted_client, server_identity) = identity_pair(
            [0x55; ED25519_SEED_LEN],
            [0x66; MLDSA65_SEED_LEN],
            [0x33; ED25519_SEED_LEN],
            [0x44; MLDSA65_SEED_LEN],
        );
        let engine = CipherSuite::NistStandard768.engine();
        let (_state, client_hello) = engine
            .begin_initiator(&client_identity)
            .expect("client hello");
        assert_eq!(
            engine.respond(&server_identity, &client_hello).unwrap_err(),
            CryptoError::Authentication
        );
    }

    /// Policy parsing: env tokens and file lines map to the right suites.
    #[test]
    fn policy_token_parsing() {
        assert_eq!(
            parse_suite_token("0x01").unwrap(),
            CipherSuite::NistStandard768
        );
        assert_eq!(
            parse_suite_token("1024").unwrap(),
            CipherSuite::NistStandard1024
        );
        assert_eq!(
            parse_suite_token("NIST768").unwrap(),
            CipherSuite::NistStandard768
        );
        assert!(parse_suite_token("legacy-aes").is_err());

        let file = "# policy\n\nsuite = \"nist1024\"\n";
        assert_eq!(
            parse_policy_file(file).unwrap().as_deref(),
            Some("nist1024")
        );
        assert_eq!(parse_policy_file("# nothing here\n").unwrap(), None);
        assert!(parse_policy_file("not toml").is_err());
    }

    #[test]
    fn identity_wire_lengths_match_fips_204_mldsa65() {
        let (client_identity, _server_identity) = identities();
        assert_eq!(
            client_identity.own_ed25519_public().len(),
            ED25519_PUBLIC_LEN
        );
        assert_eq!(
            client_identity.own_mldsa65_public().len(),
            MLDSA65_PUBLIC_LEN
        );
        let sigs = client_identity.sign(b"length-test").unwrap();
        assert_eq!(sigs.ed25519.len(), ED25519_SIGNATURE_LEN);
        assert_eq!(sigs.mldsa65.len(), MLDSA65_SIGNATURE_LEN);
    }
}
