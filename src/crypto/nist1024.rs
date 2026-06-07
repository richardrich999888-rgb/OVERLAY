//! NIST-1024 suite: X25519 + ML-KEM-1024. Suite id 0x02.

use ml_kem::MlKem1024;

use super::generic::{self, GenericInitiatorState};
use super::{CryptoError, InitiatorState, SessionKeys, SovereignCryptoEngine};

/// FIPS 203 ML-KEM-1024 wire sizes (verified on docs.rs: pk 1568, ct 1568).
const EK_LEN: usize = 1568;
const CT_LEN: usize = 1568;
pub const SUITE_ID: u8 = 0x02;

pub struct Nist1024Engine;

struct Nist1024Init(GenericInitiatorState<MlKem1024>);

impl InitiatorState for Nist1024Init {
    fn finish(self: Box<Self>, server_hello: &[u8]) -> Result<SessionKeys, CryptoError> {
        generic::finish::<MlKem1024>(self.0, CT_LEN, server_hello)
    }
}

impl SovereignCryptoEngine for Nist1024Engine {
    fn suite_id(&self) -> u8 {
        SUITE_ID
    }

    fn begin_initiator(&self) -> (Box<dyn InitiatorState>, Vec<u8>) {
        let (state, hello) = generic::client_hello::<MlKem1024>(SUITE_ID);
        (Box::new(Nist1024Init(state)), hello)
    }

    fn respond(&self, client_hello: &[u8]) -> Result<(SessionKeys, Vec<u8>), CryptoError> {
        generic::respond::<MlKem1024>(SUITE_ID, EK_LEN, client_hello)
    }
}
