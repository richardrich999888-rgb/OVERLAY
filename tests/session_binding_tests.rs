use syntriass_overlay::{
    kernel::maps::SESSION_PQC_ESTABLISHED,
    session::{
        entry_from_value, monotonic_expiry_after, MemorySessionStore, SessionManager, SessionState,
    },
};

#[test]
fn session_state_values_are_stable() {
    assert_eq!(SessionState::Pending.as_u32(), 1);
    assert_eq!(SessionState::PqcNegotiating.as_u32(), 2);
    assert_eq!(SessionState::PqcEstablished.as_u32(), 3);
    assert_eq!(SessionState::Expired.as_u32(), 4);
    assert_eq!(
        SessionState::from_u32(SESSION_PQC_ESTABLISHED),
        Some(SessionState::PqcEstablished)
    );
}

#[test]
fn established_session_can_be_inserted_listed_and_removed() {
    let mut manager = SessionManager::new(MemorySessionStore::default());
    let session_id = [7u8; 32];
    let entry = manager
        .insert_state(42, session_id, SessionState::PqcEstablished, 99)
        .unwrap();
    assert_eq!(entry.socket_cookie, 42);
    assert_eq!(entry.session_state, SessionState::PqcEstablished);
    assert_eq!(entry.expires_at_ns, 99);
    assert_eq!(manager.list().unwrap().len(), 1);
    let removed = manager.remove(42).unwrap();
    assert_eq!(removed.session_state, SessionState::PqcEstablished);
    assert!(manager.list().unwrap().is_empty());
}

#[test]
fn zero_socket_cookie_is_rejected() {
    let mut manager = SessionManager::new(MemorySessionStore::default());
    assert!(manager
        .insert_state(0, [0u8; 32], SessionState::PqcEstablished, 99)
        .is_err());
}

#[test]
fn invalid_session_state_rejected_by_entry_decode() {
    let value = syntriass_overlay::kernel::maps::SessionValue {
        session_id: [0u8; 32],
        session_state: 99,
        expires_at: 0,
    };
    assert!(entry_from_value(1, value).is_err());
}

#[test]
fn monotonic_expiry_is_in_future() {
    let expires = monotonic_expiry_after(std::time::Duration::from_secs(1));
    assert!(expires > 0);
}
