use crate::{
    crypto::{self, CipherSuite, CryptoError, SessionKeys},
    kernel::maps::{
        SessionValue, SESSION_EXPIRED, SESSION_PENDING, SESSION_PQC_ESTABLISHED,
        SESSION_PQC_NEGOTIATING,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Pending,
    PqcNegotiating,
    PqcEstablished,
    Expired,
}

impl SessionState {
    pub fn as_u32(self) -> u32 {
        match self {
            SessionState::Pending => SESSION_PENDING,
            SessionState::PqcNegotiating => SESSION_PQC_NEGOTIATING,
            SessionState::PqcEstablished => SESSION_PQC_ESTABLISHED,
            SessionState::Expired => SESSION_EXPIRED,
        }
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            SESSION_PENDING => Some(SessionState::Pending),
            SESSION_PQC_NEGOTIATING => Some(SessionState::PqcNegotiating),
            SESSION_PQC_ESTABLISHED => Some(SessionState::PqcEstablished),
            SESSION_EXPIRED => Some(SessionState::Expired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionEntry {
    pub socket_cookie: u64,
    pub session_id: String,
    pub session_state: SessionState,
    pub expires_at_ns: u64,
}

pub trait SessionStore {
    fn insert(&mut self, socket_cookie: u64, value: SessionValue) -> Result<(), String>;
    fn remove(&mut self, socket_cookie: &u64) -> Result<(), String>;
    fn get(&mut self, socket_cookie: &u64) -> Result<Option<SessionValue>, String>;
    fn list(&mut self) -> Result<Vec<(u64, SessionValue)>, String>;
}

pub struct SessionManager<S> {
    store: S,
}

impl<S: SessionStore> SessionManager<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn insert_state(
        &mut self,
        socket_cookie: u64,
        session_id: [u8; 32],
        state: SessionState,
        expires_at_ns: u64,
    ) -> Result<SessionEntry, String> {
        if socket_cookie == 0 {
            return Err("socket cookie must be non-zero".to_string());
        }
        let mut value = unsafe { core::mem::zeroed::<SessionValue>() };
        value.session_id = session_id;
        value.session_state = state.as_u32();
        value.expires_at = expires_at_ns;
        self.store.insert(socket_cookie, value)?;
        entry_from_value(socket_cookie, value)
    }

    pub fn remove(&mut self, socket_cookie: u64) -> Result<SessionEntry, String> {
        let old = self
            .store
            .get(&socket_cookie)?
            .ok_or_else(|| "session not found".to_string())?;
        self.store.remove(&socket_cookie)?;
        entry_from_value(socket_cookie, old)
    }

    pub fn list(&mut self) -> Result<Vec<SessionEntry>, String> {
        self.store
            .list()?
            .into_iter()
            .map(|(cookie, value)| entry_from_value(cookie, value))
            .collect()
    }
}

#[derive(Default)]
pub struct MemorySessionStore {
    entries: std::collections::HashMap<u64, SessionValue>,
}

impl SessionStore for MemorySessionStore {
    fn insert(&mut self, socket_cookie: u64, value: SessionValue) -> Result<(), String> {
        self.entries.insert(socket_cookie, value);
        Ok(())
    }

    fn remove(&mut self, socket_cookie: &u64) -> Result<(), String> {
        self.entries.remove(socket_cookie);
        Ok(())
    }

    fn get(&mut self, socket_cookie: &u64) -> Result<Option<SessionValue>, String> {
        Ok(self.entries.get(socket_cookie).copied())
    }

    fn list(&mut self) -> Result<Vec<(u64, SessionValue)>, String> {
        Ok(self.entries.iter().map(|(k, v)| (*k, *v)).collect())
    }
}

pub fn entry_from_value(socket_cookie: u64, value: SessionValue) -> Result<SessionEntry, String> {
    Ok(SessionEntry {
        socket_cookie,
        session_id: hex32(&value.session_id),
        session_state: SessionState::from_u32(value.session_state)
            .ok_or_else(|| format!("invalid session state {}", value.session_state))?,
        expires_at_ns: value.expires_at,
    })
}

pub fn derive_session_id(socket_cookie: u64, keys: &SessionKeys) -> [u8; 32] {
    let traffic = keys.export_ktls();
    let mut h = Sha256::new();
    h.update(b"syntriass/session-map/v1");
    h.update(socket_cookie.to_ne_bytes());
    h.update(traffic.tx.key);
    h.update(traffic.tx.salt);
    h.update(traffic.tx.iv);
    h.update(traffic.rx.key);
    h.update(traffic.rx.salt);
    h.update(traffic.rx.iv);
    h.finalize().into()
}

pub fn run_authenticated_pqc_session(
    socket_cookie: u64,
    suite: CipherSuite,
) -> Result<[u8; 32], CryptoError> {
    let identity = crypto::resolve_identity()?;
    let engine = suite.engine();
    let (state, client_hello) = engine.begin_initiator(&identity)?;
    let (_server_keys, server_hello) = engine.respond(&identity, &client_hello)?;
    let client_keys = state.finish(&identity, &server_hello)?;
    Ok(derive_session_id(socket_cookie, &client_keys))
}

pub fn monotonic_expiry_after(ttl: Duration) -> u64 {
    let now = monotonic_now_ns();
    now.saturating_add(ttl.as_nanos().min(u128::from(u64::MAX)) as u64)
}

#[cfg(target_os = "linux")]
fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

#[cfg(not(target_os = "linux"))]
fn monotonic_now_ns() -> u64 {
    1
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{SessionStore, SessionValue};
    use crate::kernel::maps::SESSION_MAP;
    use aya::maps::HashMap;
    use std::{convert::TryFrom, path::Path};

    pub struct BpfSessionStore {
        map: HashMap<aya::maps::MapData, u64, SessionValue>,
    }

    impl BpfSessionStore {
        pub fn open_pinned(pin_dir: &Path) -> Result<Self, String> {
            let map_path = pin_dir.join(SESSION_MAP);
            let map_data = aya::maps::MapData::from_pin(&map_path).map_err(|e| e.to_string())?;
            // aya 0.12: wrap the pinned `MapData` in the `Map::HashMap` variant;
            // `HashMap: TryFrom<Map>` (not `TryFrom<MapData>`).
            let map =
                HashMap::try_from(aya::maps::Map::HashMap(map_data)).map_err(|e| e.to_string())?;
            Ok(Self { map })
        }
    }

    impl SessionStore for BpfSessionStore {
        fn insert(&mut self, socket_cookie: u64, value: SessionValue) -> Result<(), String> {
            self.map
                .insert(socket_cookie, value, 0)
                .map_err(|e| e.to_string())
        }

        fn remove(&mut self, socket_cookie: &u64) -> Result<(), String> {
            self.map.remove(socket_cookie).map_err(|e| e.to_string())
        }

        fn get(&mut self, socket_cookie: &u64) -> Result<Option<SessionValue>, String> {
            match self.map.get(socket_cookie, 0) {
                Ok(v) => Ok(Some(v)),
                Err(aya::maps::MapError::KeyNotFound) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }

        fn list(&mut self) -> Result<Vec<(u64, SessionValue)>, String> {
            self.map
                .iter()
                .map(|item| item.map_err(|e| e.to_string()))
                .collect()
        }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
