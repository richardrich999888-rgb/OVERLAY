//! End-to-end identity lifecycle: a credential issued by the authority, verified
//! by a relying peer, and **used to drive the real hybrid-PQC handshake**. This
//! closes the loop — lifecycle-managed identities (not statically pinned hex
//! seeds) become the peer trust the handshake enforces.
//!
//! Also exercises the air-gap (offline, bytes-only) provisioning path and the
//! fail-closed behaviour when a peer's credential is expired or revoked.

use syntriass_overlay::crypto::{
    CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::identity::{
    EnrollmentRequest, HybridSigner, IdentityCredential, IdentityError, IssuingAuthority,
    RevocationList, SoftwareSigner, TrustStore,
};

struct Node {
    ed_seed: [u8; ED25519_SEED_LEN],
    mldsa_seed: [u8; MLDSA65_SEED_LEN],
    signer: SoftwareSigner,
    node_id: [u8; 16],
}

impl Node {
    fn new(tag: u8) -> Self {
        let ed_seed = [tag; ED25519_SEED_LEN];
        let mldsa_seed = [tag.wrapping_add(0x80); MLDSA65_SEED_LEN];
        let signer = SoftwareSigner::from_seeds(ed_seed, mldsa_seed).unwrap();
        Self {
            ed_seed,
            mldsa_seed,
            signer,
            node_id: [tag; 16],
        }
    }
    fn request(&self) -> EnrollmentRequest {
        EnrollmentRequest::create(self.node_id, &self.signer).unwrap()
    }
    /// Build the handshake identity: our own seeds + the peer's CA-verified keys.
    fn identity_trusting(
        &self,
        peer: &syntriass_overlay::identity::VerifiedIdentity,
    ) -> IdentityMaterial {
        IdentityMaterial::from_bytes(
            self.ed_seed,
            self.mldsa_seed,
            peer.ed25519_pub,
            peer.mldsa65_pub.clone(),
        )
        .unwrap()
    }
}

/// Run the real X25519+ML-KEM / Ed25519+ML-DSA handshake and a sealed round-trip.
fn handshake_ok(client: &IdentityMaterial, server: &IdentityMaterial) -> bool {
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = match engine.begin_initiator(client) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let (mut sk, sh) = match engine.respond(server, &ch) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut ck = match state.finish(client, &sh) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let ct = ck.seal(b"lifecycle-verified channel").unwrap();
    sk.open(&ct)
        .map(|p| p == b"lifecycle-verified channel")
        .unwrap_or(false)
}

#[test]
fn credential_verified_identity_drives_real_handshake() {
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let store = TrustStore::new(ca.public());

    let client = Node::new(0x33);
    let server = Node::new(0x55);

    // Enroll both nodes; the CA issues credentials valid [1000, 5000).
    let client_cred = ca.issue(&client.request(), 10, 0, 1_000, 5_000).unwrap();
    let server_cred = ca.issue(&server.request(), 11, 0, 1_000, 5_000).unwrap();

    // Each peer verifies the OTHER's credential to obtain trusted public keys.
    let now = 1_500;
    let verified_server = store.verify(&server_cred, now, None).unwrap();
    let verified_client = store.verify(&client_cred, now, None).unwrap();

    // The verified keys must equal what each node actually holds.
    assert_eq!(verified_client.ed25519_pub, client.signer.ed25519_public());
    assert_eq!(verified_server.ed25519_pub, server.signer.ed25519_public());

    // Build handshake identities from the CA-verified peer keys and connect.
    let client_im = client.identity_trusting(&verified_server);
    let server_im = server.identity_trusting(&verified_client);
    assert!(
        handshake_ok(&client_im, &server_im),
        "a handshake between two CA-verified identities must succeed"
    );
}

#[test]
fn expired_peer_credential_blocks_trust_and_handshake() {
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let store = TrustStore::new(ca.public());
    let client = Node::new(0x33);
    let server = Node::new(0x55);
    let client_cred = ca.issue(&client.request(), 10, 0, 1_000, 2_000).unwrap();
    let server_cred = ca.issue(&server.request(), 11, 0, 1_000, 5_000).unwrap();

    // At t=3000 the client credential has expired: the server cannot derive
    // trusted client keys, so no channel is even attempted.
    let now = 3_000;
    assert_eq!(
        store.verify(&client_cred, now, None),
        Err(IdentityError::Expired)
    );
    // The server credential is still valid; trust is one-directional and fails
    // closed on the expired side.
    assert!(store.verify(&server_cred, now, None).is_ok());
}

#[test]
fn revoked_peer_credential_blocks_trust() {
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let store = TrustStore::new(ca.public());
    let client = Node::new(0x33);
    let client_cred = ca.issue(&client.request(), 77, 0, 1_000, 9_000).unwrap();

    // Compromise reported: CA revokes serial 77.
    let crl = ca.revoke(&[77], 1_400, 8_000).unwrap();
    assert_eq!(
        store.verify(&client_cred, 1_500, Some(&crl)),
        Err(IdentityError::Revoked)
    );
}

#[test]
fn rotation_gives_uninterrupted_trust_through_a_handshake() {
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let store = TrustStore::new(ca.public());
    let server = Node::new(0x55);
    let server_cred = ca.issue(&server.request(), 11, 0, 1_000, 9_000).unwrap();
    let verified_server = store.verify(&server_cred, 2_000, None).unwrap();

    // The client rotates its key mid-deployment: old cred [1000,2500), new
    // cred [2000,4000) with fresh keys. During the overlap a handshake using the
    // *new* credential's identity succeeds.
    let client_old = Node::new(0x33);
    let _old_cred = ca
        .issue(&client_old.request(), 20, 0, 1_000, 2_500)
        .unwrap();

    let client_new_seed_ed = [0x34u8; ED25519_SEED_LEN];
    let client_new_seed_ml = [0xB4u8; MLDSA65_SEED_LEN];
    let client_new_signer =
        SoftwareSigner::from_seeds(client_new_seed_ed, client_new_seed_ml).unwrap();
    let req = EnrollmentRequest::create([0x33u8; 16], &client_new_signer).unwrap();
    let new_cred = ca.issue(&req, 21, 1, 2_000, 4_000).unwrap();

    // At t=2200 (overlap) the rotated credential verifies and drives a handshake.
    let verified_client_new = store.verify(&new_cred, 2_200, None).unwrap();
    assert_eq!(verified_client_new.epoch, 1);

    let client_im = IdentityMaterial::from_bytes(
        client_new_seed_ed,
        client_new_seed_ml,
        verified_server.ed25519_pub,
        verified_server.mldsa65_pub.clone(),
    )
    .unwrap();
    let server_im = server.identity_trusting(&verified_client_new);
    assert!(handshake_ok(&client_im, &server_im));
}

#[test]
fn air_gapped_bytes_only_provisioning() {
    // The CA runs on a disconnected machine and emits only bytes; the relying
    // peer is provisioned out-of-band with the CA public keys only.
    let ca = IssuingAuthority::new(SoftwareSigner::from_seeds([1u8; 32], [2u8; 32]).unwrap());
    let ca_public = ca.public();

    let node = Node::new(0x33);
    let req_bytes = node.request().to_bytes();

    // --- transported to the air-gapped CA as bytes ---
    let req = EnrollmentRequest::from_bytes(&req_bytes).unwrap();
    let cred_bytes = ca.issue(&req, 1, 0, 1_000, 9_000).unwrap().to_bytes();
    let crl_bytes = ca.revoke(&[2, 3, 4], 1_000, 9_000).unwrap().to_bytes();

    // --- transported back to the relying peer as bytes ---
    let store = TrustStore::new(ca_public);
    let cred = IdentityCredential::from_bytes(&cred_bytes).unwrap();
    let crl = RevocationList::from_bytes(&crl_bytes).unwrap();
    let verified = store.verify(&cred, 1_500, Some(&crl)).unwrap();
    assert_eq!(verified.node_id, [0x33u8; 16]);
}
