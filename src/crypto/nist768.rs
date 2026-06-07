//! NIST-768 suite: X25519 + ML-KEM-768. Suite id 0x01.

use ml_kem::MlKem768;

use super::generic::{self, GenericInitiatorState};
use super::{CryptoError, IdentityMaterial, InitiatorState, SessionKeys, SovereignCryptoEngine};

/// FIPS 203 ML-KEM-768 wire sizes (verified on docs.rs).
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
pub const SUITE_ID: u8 = 0x01;

pub struct Nist768Engine;

struct Nist768Init(GenericInitiatorState<MlKem768>);

impl InitiatorState for Nist768Init {
    fn finish(
        self: Box<Self>,
        identity: &IdentityMaterial,
        server_hello: &[u8],
    ) -> Result<SessionKeys, CryptoError> {
        generic::finish::<MlKem768>(self.0, CT_LEN, identity, server_hello)
    }
}

impl SovereignCryptoEngine for Nist768Engine {
    fn suite_id(&self) -> u8 {
        SUITE_ID
    }

    fn begin_initiator(
        &self,
        identity: &IdentityMaterial,
    ) -> Result<(Box<dyn InitiatorState>, Vec<u8>), CryptoError> {
        let (state, hello) = generic::client_hello::<MlKem768>(SUITE_ID, identity)?;
        Ok((Box::new(Nist768Init(state)), hello))
    }

    fn respond(
        &self,
        identity: &IdentityMaterial,
        client_hello: &[u8],
    ) -> Result<(SessionKeys, Vec<u8>), CryptoError> {
        generic::respond::<MlKem768>(SUITE_ID, EK_LEN, identity, client_hello)
    }
}
