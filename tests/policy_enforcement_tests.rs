use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use syntriass_overlay::{
    audit::events::{
        KernelFlowEvent, ACTION_ALLOW, ACTION_DENY, AUDIT_DECISION_ALLOW, AUDIT_DECISION_DENY,
        AUDIT_EVENT_CONNECT4, AUDIT_EVENT_CONNECT6, REASON_NO_POLICY, REASON_POLICY_ALLOW,
        REASON_POLICY_DENY,
    },
    policy::{
        engine::{MemoryPolicyStore, PolicyEngine},
        maps::PolicyAction,
    },
};

#[test]
fn allowed_destination_succeeds() {
    let mut engine = PolicyEngine::new(MemoryPolicyStore::default());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 50));
    engine.add(123, ip, 5432, PolicyAction::Allow).unwrap();
    let entry = engine.lookup(123, ip, 5432).unwrap().unwrap();
    assert_eq!(entry.action, "allow");
}

#[test]
fn explicit_deny_fails() {
    let mut engine = PolicyEngine::new(MemoryPolicyStore::default());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 50));
    engine.add(123, ip, 5432, PolicyAction::Deny).unwrap();
    let entry = engine.lookup(123, ip, 5432).unwrap().unwrap();
    assert_eq!(entry.action, "deny");
}

#[test]
fn missing_policy_fails() {
    let mut engine = PolicyEngine::new(MemoryPolicyStore::default());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 50));
    assert!(engine.lookup(123, ip, 5432).unwrap().is_none());
}

#[test]
fn ipv4_enforcement_key_path() {
    let mut engine = PolicyEngine::new(MemoryPolicyStore::default());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 50));
    let entry = engine.add(123, ip, 5432, PolicyAction::Allow).unwrap();
    assert_eq!(entry.family, 2);
    assert_eq!(entry.ip, "10.1.1.50");
}

#[test]
fn ipv6_enforcement_key_path() {
    let mut engine = PolicyEngine::new(MemoryPolicyStore::default());
    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let entry = engine.add(123, ip, 443, PolicyAction::Deny).unwrap();
    assert_eq!(entry.family, 10);
    assert_eq!(entry.ip, "::1");
}

#[test]
fn audit_events_distinguish_allow_deny_and_missing_policy() {
    let allow = KernelFlowEvent {
        event_type: AUDIT_EVENT_CONNECT4,
        decision: AUDIT_DECISION_ALLOW,
        pid: 1,
        tgid: 1,
        cgroup_id: 123,
        socket_cookie: 9,
        family: 2,
        protocol: 6,
        dst_addr: [10, 1, 1, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        dst_port: 5432,
        action: ACTION_ALLOW,
        reason: REASON_POLICY_ALLOW,
    };
    assert_eq!(allow.to_audit_record().action, "allow");
    assert_eq!(allow.to_audit_record().reason, "policy_allow");

    let deny = KernelFlowEvent {
        event_type: AUDIT_EVENT_CONNECT6,
        decision: AUDIT_DECISION_DENY,
        action: ACTION_DENY,
        reason: REASON_POLICY_DENY,
        ..allow
    };
    assert_eq!(deny.to_audit_record().action, "deny");
    assert_eq!(deny.to_audit_record().reason, "policy_deny");

    let missing = KernelFlowEvent {
        reason: REASON_NO_POLICY,
        ..deny
    };
    assert_eq!(missing.to_audit_record().reason, "no_policy");
}
