//! Identity lifecycle for the Syntriass overlay: enrollment, issuance, rotation,
//! revocation, expiry, and offline (air-gap) provisioning — built on the same
//! hybrid Ed25519 + ML-DSA-65 signatures the handshake already uses.
//!
//! ## Model
//!
//! Today a node's peer trust is *static*: peer public keys are pinned in
//! `/etc/syntriass/identity.toml` and never rotate, revoke, or expire. For a
//! fielded fleet that is unworkable — keys must be enrolled, rotated on a
//! schedule, revoked on compromise, and expire on their own.
//!
//! This module adds a minimal, **fully verifiable** credential system:
//!
//! ```text
//!   node                         Issuing Authority (CA)            relying peer
//!   ----                         ----------------------            ------------
//!   generate hybrid keypair
//!   EnrollmentRequest{pub, PoP}  --->  verify proof-of-possession
//!                                      issue IdentityCredential{...,
//!                                        not_before, not_after, serial,
//!                                        CA hybrid-signature}
//!                                <---  (credential)
//!   present credential in band ---------------------------------> TrustStore.verify():
//!                                                                   CA sig (Ed25519+ML-DSA)
//!                                                                   now in [nbf, naf]   (expiry)
//!                                                                   serial not on CRL   (revocation)
//!                                                                   => VerifiedIdentity{pubkeys}
//! ```
//!
//! Everything is pure-CPU and deterministic under an injected clock, so the whole
//! lifecycle is testable here (`tests/identity_lifecycle_tests.rs`). Credentials,
//! enrollment requests, and revocation lists are self-contained signed byte
//! blobs (`to_bytes`/`from_bytes`) that need **no network** to verify — only the
//! CA's pinned public keys — which is exactly the air-gap provisioning property.
//!
//! ## Hardware key protection (TPM2 / PKCS#11 / HSM)
//!
//! The private-key operation is abstracted behind [`HybridSigner`]. The
//! [`SoftwareSigner`] implementation (keys in zeroizing memory) is implemented and
//! validated here. Hardware backends slot in behind the same trait; their honest
//! status and required infrastructure are documented in `docs/IDENTITY_LIFECYCLE.md`.
//! Note the PQC caveat: current TPM2 / most HSMs do **not** implement ML-DSA, so a
//! hardware backend protects the *classical* Ed25519 key while the ML-DSA key
//! stays software-protected — the hybrid still requires forging *both*.

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as Ed25519Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use ml_dsa::{
    EncodedVerifyingKey, Keypair, MlDsa65, Signature as MlDsaSignature, Signer as MlDsaSigner,
    SigningKey as MlDsaSigningKey, Verifier as MlDsaVerifier, VerifyingKey as MlDsaVerifyingKey,
};
use rand_core::{OsRng, RngCore};

use crate::crypto::{
    ED25519_PUBLIC_LEN, ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, MLDSA65_PUBLIC_LEN,
    MLDSA65_SEED_LEN, MLDSA65_SIGNATURE_LEN,
};

const CRED_DOMAIN: &[u8] = b"syntriass-overlay identity-credential v1";
const REQ_DOMAIN: &[u8] = b"syntriass-overlay enrollment-request v1";
const CRL_DOMAIN: &[u8] = b"syntriass-overlay revocation-list v1";

/// Node identifier (opaque 16 bytes; e.g. a UUID or a hashed hostname).
pub type NodeId = [u8; 16];

/// Every lifecycle failure. None carries secret material; the caller fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// A signature (CA, CRL, or proof-of-possession) did not verify.
    BadSignature,
    /// Proof-of-possession on an enrollment request did not verify.
    BadProofOfPossession,
    /// `now` is before the credential's `not_before`.
    NotYetValid,
    /// `now` is at/after the credential's `not_after`.
    Expired,
    /// The credential's serial is on a valid revocation list.
    Revoked,
    /// The revocation list is past its `next_update` (stale).
    StaleRevocationList,
    /// A field had the wrong length or the blob was truncated/corrupt.
    Malformed,
    /// Key material could not be loaded (bad seed).
    BadKey,
}

// --------------------------- low-level hybrid sign/verify ---------------------------

fn load_ed_signing(seed: &[u8; ED25519_SEED_LEN]) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(seed)
}

fn load_mldsa_signing(
    seed: &[u8; MLDSA65_SEED_LEN],
) -> Result<MlDsaSigningKey<MlDsa65>, IdentityError> {
    let s = ml_dsa::Seed::try_from(&seed[..]).map_err(|_| IdentityError::BadKey)?;
    Ok(MlDsaSigningKey::<MlDsa65>::from_seed(&s))
}

fn ed_sign(
    key: &Ed25519SigningKey,
    msg: &[u8],
) -> Result<[u8; ED25519_SIGNATURE_LEN], IdentityError> {
    key.try_sign(msg)
        .map(|s| s.to_bytes())
        .map_err(|_| IdentityError::BadSignature)
}

fn mldsa_sign(key: &MlDsaSigningKey<MlDsa65>, msg: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let sig: MlDsaSignature<MlDsa65> =
        key.try_sign(msg).map_err(|_| IdentityError::BadSignature)?;
    Ok(sig.encode().as_slice().to_vec())
}

fn ed_verify(pubk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let arr: [u8; ED25519_PUBLIC_LEN] = pubk.try_into().map_err(|_| IdentityError::Malformed)?;
    let vk = Ed25519VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::Malformed)?;
    let sig = Ed25519Signature::try_from(sig).map_err(|_| IdentityError::Malformed)?;
    vk.verify_strict(msg, &sig)
        .map_err(|_| IdentityError::BadSignature)
}

fn mldsa_verify(pubk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), IdentityError> {
    let enc =
        EncodedVerifyingKey::<MlDsa65>::try_from(pubk).map_err(|_| IdentityError::Malformed)?;
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&enc);
    let sig = MlDsaSignature::<MlDsa65>::try_from(sig).map_err(|_| IdentityError::Malformed)?;
    vk.verify(msg, &sig)
        .map_err(|_| IdentityError::BadSignature)
}

// ------------------------------- signer abstraction -------------------------------

/// The private-key operation, abstracted so the key can live in software, a TPM,
/// a PKCS#11 token, or an HSM. Only the public keys and the signing op are
/// exposed; raw private material never crosses this boundary.
pub trait HybridSigner {
    fn ed25519_public(&self) -> [u8; ED25519_PUBLIC_LEN];
    fn mldsa65_public(&self) -> Vec<u8>;
    /// Hybrid sign: returns `(ed25519_sig[64], mldsa65_sig[3309])`.
    fn sign_hybrid(
        &self,
        msg: &[u8],
    ) -> Result<([u8; ED25519_SIGNATURE_LEN], Vec<u8>), IdentityError>;
}

/// Software-resident hybrid signer (keys in zeroizing memory). The reference
/// implementation, fully validated here.
pub struct SoftwareSigner {
    ed: Ed25519SigningKey,
    mldsa: MlDsaSigningKey<MlDsa65>,
    ed_pub: [u8; ED25519_PUBLIC_LEN],
    mldsa_pub: Vec<u8>,
}

impl SoftwareSigner {
    pub fn from_seeds(
        ed_seed: [u8; ED25519_SEED_LEN],
        mldsa_seed: [u8; MLDSA65_SEED_LEN],
    ) -> Result<Self, IdentityError> {
        let ed = load_ed_signing(&ed_seed);
        let mldsa = load_mldsa_signing(&mldsa_seed)?;
        let ed_pub = ed.verifying_key().to_bytes();
        let mldsa_pub = mldsa.verifying_key().encode().as_slice().to_vec();
        Ok(Self {
            ed,
            mldsa,
            ed_pub,
            mldsa_pub,
        })
    }

    /// Generate a fresh hybrid keypair from the OS CSPRNG (enrollment).
    pub fn generate() -> Self {
        let mut ed_seed = [0u8; ED25519_SEED_LEN];
        let mut mldsa_seed = [0u8; MLDSA65_SEED_LEN];
        OsRng.fill_bytes(&mut ed_seed);
        OsRng.fill_bytes(&mut mldsa_seed);
        // Infallible: a 32-byte ML-DSA seed is always a valid seed.
        Self::from_seeds(ed_seed, mldsa_seed).expect("32-byte seeds are always valid")
    }
}

impl HybridSigner for SoftwareSigner {
    fn ed25519_public(&self) -> [u8; ED25519_PUBLIC_LEN] {
        self.ed_pub
    }
    fn mldsa65_public(&self) -> Vec<u8> {
        self.mldsa_pub.clone()
    }
    fn sign_hybrid(
        &self,
        msg: &[u8],
    ) -> Result<([u8; ED25519_SIGNATURE_LEN], Vec<u8>), IdentityError> {
        Ok((ed_sign(&self.ed, msg)?, mldsa_sign(&self.mldsa, msg)?))
    }
}

// --------------------------------- serialization helpers --------------------------------

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
/// Length-prefixed (u32 BE) variable field.
fn put_var(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], IdentityError> {
        let end = self.pos.checked_add(n).ok_or(IdentityError::Malformed)?;
        if end > self.b.len() {
            return Err(IdentityError::Malformed);
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, IdentityError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, IdentityError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn var(&mut self) -> Result<&'a [u8], IdentityError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn finish(self) -> Result<(), IdentityError> {
        if self.pos == self.b.len() {
            Ok(())
        } else {
            Err(IdentityError::Malformed)
        }
    }
}

// ----------------------------------- enrollment -----------------------------------

/// A node's request to be certified: its public keys plus a proof it holds the
/// matching private keys (a self-signature over the request body).
pub struct EnrollmentRequest {
    pub node_id: NodeId,
    pub ed25519_pub: [u8; ED25519_PUBLIC_LEN],
    pub mldsa65_pub: Vec<u8>,
    ed_pop: [u8; ED25519_SIGNATURE_LEN],
    mldsa_pop: Vec<u8>,
}

fn enrollment_body(node_id: &NodeId, ed_pub: &[u8], mldsa_pub: &[u8]) -> Vec<u8> {
    let mut m =
        Vec::with_capacity(REQ_DOMAIN.len() + 16 + ED25519_PUBLIC_LEN + 4 + mldsa_pub.len());
    m.extend_from_slice(REQ_DOMAIN);
    m.extend_from_slice(node_id);
    m.extend_from_slice(ed_pub);
    put_var(&mut m, mldsa_pub);
    m
}

impl EnrollmentRequest {
    /// Build a request for `node_id` signed (proof-of-possession) by `signer`.
    pub fn create(node_id: NodeId, signer: &dyn HybridSigner) -> Result<Self, IdentityError> {
        let ed_pub = signer.ed25519_public();
        let mldsa_pub = signer.mldsa65_public();
        let body = enrollment_body(&node_id, &ed_pub, &mldsa_pub);
        let (ed_pop, mldsa_pop) = signer.sign_hybrid(&body)?;
        Ok(Self {
            node_id,
            ed25519_pub: ed_pub,
            mldsa65_pub: mldsa_pub,
            ed_pop,
            mldsa_pop,
        })
    }

    /// Verify the proof-of-possession (the requester controls both private keys).
    pub fn verify_proof_of_possession(&self) -> Result<(), IdentityError> {
        if self.mldsa65_pub.len() != MLDSA65_PUBLIC_LEN {
            return Err(IdentityError::Malformed);
        }
        let body = enrollment_body(&self.node_id, &self.ed25519_pub, &self.mldsa65_pub);
        ed_verify(&self.ed25519_pub, &body, &self.ed_pop)
            .map_err(|_| IdentityError::BadProofOfPossession)?;
        mldsa_verify(&self.mldsa65_pub, &body, &self.mldsa_pop)
            .map_err(|_| IdentityError::BadProofOfPossession)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.ed25519_pub);
        put_var(&mut out, &self.mldsa65_pub);
        out.extend_from_slice(&self.ed_pop);
        put_var(&mut out, &self.mldsa_pop);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(b);
        let node_id: NodeId = r.take(16)?.try_into().unwrap();
        let ed25519_pub: [u8; ED25519_PUBLIC_LEN] = r.take(ED25519_PUBLIC_LEN)?.try_into().unwrap();
        let mldsa65_pub = r.var()?.to_vec();
        let ed_pop: [u8; ED25519_SIGNATURE_LEN] =
            r.take(ED25519_SIGNATURE_LEN)?.try_into().unwrap();
        let mldsa_pop = r.var()?.to_vec();
        r.finish()?;
        Ok(Self {
            node_id,
            ed25519_pub,
            mldsa65_pub,
            ed_pop,
            mldsa_pop,
        })
    }
}

// ----------------------------------- credential -----------------------------------

/// The signed body of an identity credential (everything the CA signs over).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialBody {
    pub node_id: NodeId,
    pub serial: u64,
    pub epoch: u32,
    pub not_before: u64,
    pub not_after: u64,
    pub ed25519_pub: [u8; ED25519_PUBLIC_LEN],
    pub mldsa65_pub: Vec<u8>,
}

impl CredentialBody {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(CRED_DOMAIN);
        m.extend_from_slice(&self.node_id);
        put_u64(&mut m, self.serial);
        put_u32(&mut m, self.epoch);
        put_u64(&mut m, self.not_before);
        put_u64(&mut m, self.not_after);
        m.extend_from_slice(&self.ed25519_pub);
        put_var(&mut m, &self.mldsa65_pub);
        m
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node_id);
        put_u64(out, self.serial);
        put_u32(out, self.epoch);
        put_u64(out, self.not_before);
        put_u64(out, self.not_after);
        out.extend_from_slice(&self.ed25519_pub);
        put_var(out, &self.mldsa65_pub);
    }
    fn decode(r: &mut Reader) -> Result<Self, IdentityError> {
        let node_id: NodeId = r.take(16)?.try_into().unwrap();
        let serial = r.u64()?;
        let epoch = r.u32()?;
        let not_before = r.u64()?;
        let not_after = r.u64()?;
        let ed25519_pub: [u8; ED25519_PUBLIC_LEN] = r.take(ED25519_PUBLIC_LEN)?.try_into().unwrap();
        let mldsa65_pub = r.var()?.to_vec();
        Ok(Self {
            node_id,
            serial,
            epoch,
            not_before,
            not_after,
            ed25519_pub,
            mldsa65_pub,
        })
    }
}

/// A CA-signed identity credential. Self-contained: verifiable offline with only
/// the CA's public keys.
pub struct IdentityCredential {
    pub body: CredentialBody,
    ca_ed_sig: [u8; ED25519_SIGNATURE_LEN],
    ca_mldsa_sig: Vec<u8>,
}

impl IdentityCredential {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.body.encode(&mut out);
        out.extend_from_slice(&self.ca_ed_sig);
        put_var(&mut out, &self.ca_mldsa_sig);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(b);
        let body = CredentialBody::decode(&mut r)?;
        let ca_ed_sig: [u8; ED25519_SIGNATURE_LEN] =
            r.take(ED25519_SIGNATURE_LEN)?.try_into().unwrap();
        let ca_mldsa_sig = r.var()?.to_vec();
        r.finish()?;
        Ok(Self {
            body,
            ca_ed_sig,
            ca_mldsa_sig,
        })
    }
}

/// The verified result a relying peer feeds into the handshake's peer-pinning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub node_id: NodeId,
    pub epoch: u32,
    pub ed25519_pub: [u8; ED25519_PUBLIC_LEN],
    pub mldsa65_pub: Vec<u8>,
}

// ------------------------------- issuing authority --------------------------------

/// The offline (air-gappable) Certificate/credential Authority.
pub struct IssuingAuthority<S: HybridSigner> {
    signer: S,
}

impl<S: HybridSigner> IssuingAuthority<S> {
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    /// The CA's public keys — the only thing a relying peer must be provisioned
    /// with to verify credentials offline.
    pub fn public(&self) -> AuthorityPublic {
        AuthorityPublic {
            ed25519_pub: self.signer.ed25519_public(),
            mldsa65_pub: self.signer.mldsa65_public(),
        }
    }

    /// Issue a credential for a verified enrollment request. Fails closed if the
    /// proof-of-possession does not verify.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        req: &EnrollmentRequest,
        serial: u64,
        epoch: u32,
        not_before: u64,
        not_after: u64,
    ) -> Result<IdentityCredential, IdentityError> {
        req.verify_proof_of_possession()?;
        if not_after <= not_before {
            return Err(IdentityError::Malformed);
        }
        let body = CredentialBody {
            node_id: req.node_id,
            serial,
            epoch,
            not_before,
            not_after,
            ed25519_pub: req.ed25519_pub,
            mldsa65_pub: req.mldsa65_pub.clone(),
        };
        let (ed_sig, mldsa_sig) = self.signer.sign_hybrid(&body.signing_bytes())?;
        Ok(IdentityCredential {
            body,
            ca_ed_sig: ed_sig,
            ca_mldsa_sig: mldsa_sig,
        })
    }

    /// Issue a signed revocation list covering `serials`, valid until `next_update`.
    pub fn revoke(
        &self,
        serials: &[u64],
        issued_at: u64,
        next_update: u64,
    ) -> Result<RevocationList, IdentityError> {
        let mut sorted = serials.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let body = revocation_body(issued_at, next_update, &sorted);
        let (ed_sig, mldsa_sig) = self.signer.sign_hybrid(&body)?;
        Ok(RevocationList {
            issued_at,
            next_update,
            serials: sorted,
            ca_ed_sig: ed_sig,
            ca_mldsa_sig: mldsa_sig,
        })
    }
}

/// The CA public keys a relying peer pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityPublic {
    pub ed25519_pub: [u8; ED25519_PUBLIC_LEN],
    pub mldsa65_pub: Vec<u8>,
}

// ------------------------------- revocation list ----------------------------------

fn revocation_body(issued_at: u64, next_update: u64, serials: &[u64]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CRL_DOMAIN.len() + 20 + serials.len() * 8);
    m.extend_from_slice(CRL_DOMAIN);
    put_u64(&mut m, issued_at);
    put_u64(&mut m, next_update);
    put_u32(&mut m, serials.len() as u32);
    for s in serials {
        put_u64(&mut m, *s);
    }
    m
}

/// A CA-signed, freshness-bounded list of revoked credential serials.
pub struct RevocationList {
    pub issued_at: u64,
    pub next_update: u64,
    serials: Vec<u64>,
    ca_ed_sig: [u8; ED25519_SIGNATURE_LEN],
    ca_mldsa_sig: Vec<u8>,
}

impl RevocationList {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u64(&mut out, self.issued_at);
        put_u64(&mut out, self.next_update);
        put_u32(&mut out, self.serials.len() as u32);
        for s in &self.serials {
            put_u64(&mut out, *s);
        }
        out.extend_from_slice(&self.ca_ed_sig);
        put_var(&mut out, &self.ca_mldsa_sig);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(b);
        let issued_at = r.u64()?;
        let next_update = r.u64()?;
        let count = r.u32()? as usize;
        let mut serials = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            serials.push(r.u64()?);
        }
        let ca_ed_sig: [u8; ED25519_SIGNATURE_LEN] =
            r.take(ED25519_SIGNATURE_LEN)?.try_into().unwrap();
        let ca_mldsa_sig = r.var()?.to_vec();
        r.finish()?;
        Ok(Self {
            issued_at,
            next_update,
            serials,
            ca_ed_sig,
            ca_mldsa_sig,
        })
    }
    fn verify(&self, ca: &AuthorityPublic, now: u64) -> Result<(), IdentityError> {
        let body = revocation_body(self.issued_at, self.next_update, &self.serials);
        ed_verify(&ca.ed25519_pub, &body, &self.ca_ed_sig)?;
        mldsa_verify(&ca.mldsa65_pub, &body, &self.ca_mldsa_sig)?;
        if now >= self.next_update {
            return Err(IdentityError::StaleRevocationList);
        }
        Ok(())
    }
    fn contains(&self, serial: u64) -> bool {
        self.serials.binary_search(&serial).is_ok()
    }
}

// -------------------------------- relying-party trust -----------------------------

/// What a relying peer is provisioned with (offline): the CA public keys and,
/// optionally, the current revocation list.
pub struct TrustStore {
    ca: AuthorityPublic,
}

impl TrustStore {
    pub fn new(ca: AuthorityPublic) -> Self {
        Self { ca }
    }

    /// Verify a credential at time `now`, optionally against a revocation list.
    /// Order is cheapest-meaningful-first: CA signature, then validity window,
    /// then revocation. Any failure is fail-closed (`Err`).
    pub fn verify(
        &self,
        cred: &IdentityCredential,
        now: u64,
        crl: Option<&RevocationList>,
    ) -> Result<VerifiedIdentity, IdentityError> {
        if cred.body.mldsa65_pub.len() != MLDSA65_PUBLIC_LEN
            || cred.ca_mldsa_sig.len() != MLDSA65_SIGNATURE_LEN
        {
            return Err(IdentityError::Malformed);
        }
        // 1. CA hybrid signature over the body.
        let msg = cred.body.signing_bytes();
        ed_verify(&self.ca.ed25519_pub, &msg, &cred.ca_ed_sig)?;
        mldsa_verify(&self.ca.mldsa65_pub, &msg, &cred.ca_mldsa_sig)?;

        // 2. Validity window (expiry).
        if now < cred.body.not_before {
            return Err(IdentityError::NotYetValid);
        }
        if now >= cred.body.not_after {
            return Err(IdentityError::Expired);
        }

        // 3. Revocation (if a CRL is supplied, it must be valid + fresh).
        if let Some(crl) = crl {
            crl.verify(&self.ca, now)?;
            if crl.contains(cred.body.serial) {
                return Err(IdentityError::Revoked);
            }
        }

        Ok(VerifiedIdentity {
            node_id: cred.body.node_id,
            epoch: cred.body.epoch,
            ed25519_pub: cred.body.ed25519_pub,
            mldsa65_pub: cred.body.mldsa65_pub.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> IssuingAuthority<SoftwareSigner> {
        IssuingAuthority::new(SoftwareSigner::from_seeds([7u8; 32], [9u8; 32]).unwrap())
    }

    fn enroll(node: u8) -> (SoftwareSigner, EnrollmentRequest) {
        let signer = SoftwareSigner::generate();
        let req = EnrollmentRequest::create([node; 16], &signer).unwrap();
        (signer, req)
    }

    #[test]
    fn enrollment_proof_of_possession_round_trips() {
        let (_s, req) = enroll(1);
        assert_eq!(req.verify_proof_of_possession(), Ok(()));
        // wire round-trip preserves verifiability.
        let parsed = EnrollmentRequest::from_bytes(&req.to_bytes()).unwrap();
        assert_eq!(parsed.verify_proof_of_possession(), Ok(()));
    }

    #[test]
    fn forged_proof_of_possession_is_rejected() {
        let (_s, mut req) = enroll(1);
        // Swap in a different node's public key without re-signing.
        let (_s2, other) = enroll(2);
        req.ed25519_pub = other.ed25519_pub;
        assert_eq!(
            req.verify_proof_of_possession(),
            Err(IdentityError::BadProofOfPossession)
        );
    }

    #[test]
    fn issue_then_verify_happy_path() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 1, 0, 1_000, 2_000).unwrap();
        let store = TrustStore::new(ca.public());
        let v = store.verify(&cred, 1_500, None).unwrap();
        assert_eq!(v.ed25519_pub, req.ed25519_pub);
        assert_eq!(v.node_id, [1u8; 16]);
    }

    #[test]
    fn expiry_is_enforced() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 1, 0, 1_000, 2_000).unwrap();
        let store = TrustStore::new(ca.public());
        assert_eq!(
            store.verify(&cred, 999, None),
            Err(IdentityError::NotYetValid)
        );
        assert_eq!(
            store.verify(&cred, 2_000, None),
            Err(IdentityError::Expired)
        );
        assert!(store.verify(&cred, 1_999, None).is_ok());
    }

    #[test]
    fn tampered_credential_fails_ca_signature() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 1, 0, 1_000, 2_000).unwrap();
        let mut bytes = cred.to_bytes();
        // Flip a bit in the not_after field region (inside the signed body).
        bytes[16 + 8 + 4 + 8] ^= 0x01;
        let tampered = IdentityCredential::from_bytes(&bytes).unwrap();
        let store = TrustStore::new(ca.public());
        assert_eq!(
            store.verify(&tampered, 1_500, None),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn wrong_authority_is_rejected() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 1, 0, 1_000, 2_000).unwrap();
        let other_ca = IssuingAuthority::new(SoftwareSigner::generate());
        let store = TrustStore::new(other_ca.public());
        assert_eq!(
            store.verify(&cred, 1_500, None),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn rotation_overlap_then_old_expires() {
        let ca = authority();
        let (_s1, req1) = enroll(1);
        // First credential valid [1000, 2000).
        let c1 = ca.issue(&req1, 1, 0, 1_000, 2_000).unwrap();
        // Rotated credential (new keys, new serial/epoch) valid [1500, 3000):
        // the windows overlap so there is no gap in trust.
        let signer2 = SoftwareSigner::generate();
        let req2 = EnrollmentRequest::create([1u8; 16], &signer2).unwrap();
        let c2 = ca.issue(&req2, 2, 1, 1_500, 3_000).unwrap();
        let store = TrustStore::new(ca.public());
        // During overlap both verify.
        assert!(store.verify(&c1, 1_600, None).is_ok());
        assert!(store.verify(&c2, 1_600, None).is_ok());
        // After old expiry only the rotated credential verifies.
        assert_eq!(store.verify(&c1, 2_500, None), Err(IdentityError::Expired));
        assert!(store.verify(&c2, 2_500, None).is_ok());
    }

    #[test]
    fn revocation_blocks_a_credential() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 42, 0, 1_000, 9_000).unwrap();
        let store = TrustStore::new(ca.public());
        // Before revocation: valid.
        assert!(store.verify(&cred, 1_500, None).is_ok());
        // CA revokes serial 42 with a CRL fresh until 5000.
        let crl = ca.revoke(&[42], 1_400, 5_000).unwrap();
        assert_eq!(
            store.verify(&cred, 1_500, Some(&crl)),
            Err(IdentityError::Revoked)
        );
        // A different serial on the same CRL is unaffected.
        let (_s2, req2) = enroll(2);
        let cred2 = ca.issue(&req2, 43, 0, 1_000, 9_000).unwrap();
        assert!(store.verify(&cred2, 1_500, Some(&crl)).is_ok());
    }

    #[test]
    fn stale_revocation_list_is_rejected() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 1, 0, 1_000, 9_000).unwrap();
        let store = TrustStore::new(ca.public());
        let crl = ca.revoke(&[999], 1_400, 2_000).unwrap();
        // Past next_update -> the CRL is stale, so we cannot trust "not revoked".
        assert_eq!(
            store.verify(&cred, 2_001, Some(&crl)),
            Err(IdentityError::StaleRevocationList)
        );
    }

    #[test]
    fn forged_revocation_list_is_rejected() {
        let ca = authority();
        let (_s, req) = enroll(1);
        let cred = ca.issue(&req, 7, 0, 1_000, 9_000).unwrap();
        // CRL signed by a DIFFERENT authority must not be honoured.
        let evil = IssuingAuthority::new(SoftwareSigner::generate());
        let crl = evil.revoke(&[7], 1_400, 5_000).unwrap();
        let store = TrustStore::new(ca.public());
        assert_eq!(
            store.verify(&cred, 1_500, Some(&crl)),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn offline_provisioning_round_trip() {
        // "Air-gap": the authority side produces only bytes; the relying side has
        // only the CA public keys + those bytes. No shared state, no network.
        let ca = authority();
        let ca_pub = ca.public();
        let (_s, req) = enroll(1);
        let cred_bytes = ca.issue(&req, 100, 0, 1_000, 9_000).unwrap().to_bytes();
        let crl_bytes = ca.revoke(&[200], 1_000, 9_000).unwrap().to_bytes();

        // ... transported across the gap as opaque bytes ...

        let store = TrustStore::new(ca_pub);
        let cred = IdentityCredential::from_bytes(&cred_bytes).unwrap();
        let crl = RevocationList::from_bytes(&crl_bytes).unwrap();
        assert!(store.verify(&cred, 1_500, Some(&crl)).is_ok());
    }

    #[test]
    fn malformed_blobs_never_panic() {
        // Arbitrary truncations of a real credential must Err, not panic.
        let ca = authority();
        let (_s, req) = enroll(1);
        let full = ca.issue(&req, 1, 0, 1_000, 2_000).unwrap().to_bytes();
        for len in 0..full.len() {
            let _ = IdentityCredential::from_bytes(&full[..len]);
        }
        assert!(IdentityCredential::from_bytes(&full).is_ok());
    }
}
