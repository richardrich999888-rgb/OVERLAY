use std::net::{IpAddr, Ipv4Addr};

use syntriass_overlay::policy::{
    engine::{MemoryPolicyStore, PolicyEngine},
    maps::PolicyAction,
};

fn deny_by_default_engine() -> PolicyEngine<MemoryPolicyStore> {
    PolicyEngine::new(MemoryPolicyStore::default())
}

#[test]
fn ld_preload_disabled_still_has_no_policy() {
    std::env::remove_var("LD_PRELOAD");
    let mut engine = deny_by_default_engine();
    assert!(engine
        .lookup(777, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443)
        .unwrap()
        .is_none());
}

#[test]
fn direct_syscall_connect_subject_to_same_policy_key() {
    let mut engine = deny_by_default_engine();
    assert!(engine
        .lookup(777, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)), 443)
        .unwrap()
        .is_none());
}

#[test]
fn static_binary_client_subject_to_same_policy_key() {
    let mut engine = deny_by_default_engine();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
    assert!(engine.lookup(777, ip, 443).unwrap().is_none());
    engine.add(777, ip, 443, PolicyAction::Allow).unwrap();
    assert_eq!(
        engine.lookup(777, ip, 443).unwrap().unwrap().action,
        "allow"
    );
}

#[test]
fn forked_child_process_in_same_cgroup_subject_to_policy() {
    let mut engine = deny_by_default_engine();
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
    engine.add(888, ip, 8443, PolicyAction::Deny).unwrap();
    assert_eq!(
        engine.lookup(888, ip, 8443).unwrap().unwrap().action,
        "deny"
    );
}
