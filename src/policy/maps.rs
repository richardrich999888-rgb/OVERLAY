use crate::kernel::maps::{PolicyKey, PolicyValue, POLICY_ALLOW, POLICY_DENY};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Deny,
}

impl PolicyAction {
    pub fn as_u8(self) -> u8 {
        match self {
            PolicyAction::Allow => POLICY_ALLOW,
            PolicyAction::Deny => POLICY_DENY,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Deny => "deny",
        }
    }

    pub fn from_value(value: PolicyValue) -> Result<Self, String> {
        match value.action {
            POLICY_ALLOW => Ok(PolicyAction::Allow),
            POLICY_DENY => Ok(PolicyAction::Deny),
            other => Err(format!("invalid policy action {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEntry {
    pub cgroup_id: u64,
    pub family: u32,
    pub ip: String,
    pub port: u16,
    pub action: &'static str,
}

pub fn policy_value(action: PolicyAction) -> PolicyValue {
    PolicyValue {
        action: action.as_u8(),
    }
}

pub fn policy_key(cgroup_id: u64, ip: IpAddr, port: u16) -> Result<PolicyKey, String> {
    if port == 0 {
        return Err("destination port must be non-zero".to_string());
    }

    let mut dst_ip = [0u8; 16];
    let family = match ip {
        IpAddr::V4(v4) => {
            dst_ip[..4].copy_from_slice(&v4.octets());
            AF_INET
        }
        IpAddr::V6(v6) => {
            dst_ip.copy_from_slice(&v6.octets());
            AF_INET6
        }
    };

    let mut key = unsafe { core::mem::zeroed::<PolicyKey>() };
    key.cgroup_id = cgroup_id;
    key.family = family;
    key.dst_ip = dst_ip;
    key.dst_port = port;
    Ok(key)
}

pub fn key_to_ip(key: &PolicyKey) -> String {
    match key.family {
        AF_INET6 => std::net::Ipv6Addr::from(key.dst_ip).to_string(),
        _ => std::net::Ipv4Addr::new(key.dst_ip[0], key.dst_ip[1], key.dst_ip[2], key.dst_ip[3])
            .to_string(),
    }
}

pub fn entry_from_kv(key: PolicyKey, value: PolicyValue) -> Result<PolicyEntry, String> {
    let action = PolicyAction::from_value(value)?;
    Ok(PolicyEntry {
        cgroup_id: key.cgroup_id,
        family: key.family,
        ip: key_to_ip(&key),
        port: key.dst_port,
        action: action.as_str(),
    })
}
