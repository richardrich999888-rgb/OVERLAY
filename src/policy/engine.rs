use crate::{
    kernel::maps::{PolicyKey, PolicyValue},
    policy::maps::{entry_from_kv, policy_key, policy_value, PolicyAction, PolicyEntry},
};
use std::{collections::HashMap as StdHashMap, net::IpAddr};

pub trait PolicyStore {
    fn insert(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), String>;
    fn remove(&mut self, key: &PolicyKey) -> Result<(), String>;
    fn get(&mut self, key: &PolicyKey) -> Result<Option<PolicyValue>, String>;
    fn list(&mut self) -> Result<Vec<(PolicyKey, PolicyValue)>, String>;
}

pub struct PolicyEngine<S> {
    store: S,
}

impl<S: PolicyStore> PolicyEngine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn add(
        &mut self,
        cgroup_id: u64,
        ip: IpAddr,
        port: u16,
        action: PolicyAction,
    ) -> Result<PolicyEntry, String> {
        let key = policy_key(cgroup_id, ip, port)?;
        let value = policy_value(action);
        self.store.insert(key, value)?;
        entry_from_kv(key, value)
    }

    pub fn remove(&mut self, cgroup_id: u64, ip: IpAddr, port: u16) -> Result<PolicyEntry, String> {
        let key = policy_key(cgroup_id, ip, port)?;
        let old = self
            .store
            .get(&key)?
            .ok_or_else(|| "policy not found".to_string())?;
        self.store.remove(&key)?;
        entry_from_kv(key, old)
    }

    pub fn lookup(
        &mut self,
        cgroup_id: u64,
        ip: IpAddr,
        port: u16,
    ) -> Result<Option<PolicyEntry>, String> {
        let key = policy_key(cgroup_id, ip, port)?;
        self.store
            .get(&key)?
            .map(|value| entry_from_kv(key, value))
            .transpose()
    }

    pub fn list(&mut self) -> Result<Vec<PolicyEntry>, String> {
        self.store
            .list()?
            .into_iter()
            .map(|(key, value)| entry_from_kv(key, value))
            .collect()
    }
}

#[derive(Default)]
pub struct MemoryPolicyStore {
    entries: StdHashMap<PolicyKey, PolicyValue>,
}

impl PolicyStore for MemoryPolicyStore {
    fn insert(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), String> {
        self.entries.insert(key, value);
        Ok(())
    }

    fn remove(&mut self, key: &PolicyKey) -> Result<(), String> {
        self.entries.remove(key);
        Ok(())
    }

    fn get(&mut self, key: &PolicyKey) -> Result<Option<PolicyValue>, String> {
        Ok(self.entries.get(key).copied())
    }

    fn list(&mut self) -> Result<Vec<(PolicyKey, PolicyValue)>, String> {
        Ok(self.entries.iter().map(|(k, v)| (*k, *v)).collect())
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{PolicyKey, PolicyStore, PolicyValue};
    use crate::kernel::maps::POLICY_MAP;
    use aya::maps::HashMap;
    use std::{convert::TryFrom, path::Path};

    pub struct BpfPolicyStore {
        map: HashMap<aya::maps::MapData, PolicyKey, PolicyValue>,
    }

    impl BpfPolicyStore {
        pub fn open_pinned(pin_dir: &Path) -> Result<Self, String> {
            let map_path = pin_dir.join(POLICY_MAP);
            let map_data = aya::maps::MapData::from_pin(&map_path).map_err(|e| e.to_string())?;
            // aya 0.12: typed maps are built from the `Map` enum, not a bare
            // `MapData`. Wrap the pinned hash map in its `Map::HashMap` variant;
            // `TryFrom<Map>` validates the kernel map type matches.
            let map =
                HashMap::try_from(aya::maps::Map::HashMap(map_data)).map_err(|e| e.to_string())?;
            Ok(Self { map })
        }
    }

    impl PolicyStore for BpfPolicyStore {
        fn insert(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), String> {
            self.map.insert(key, value, 0).map_err(|e| e.to_string())
        }

        fn remove(&mut self, key: &PolicyKey) -> Result<(), String> {
            self.map.remove(key).map_err(|e| e.to_string())
        }

        fn get(&mut self, key: &PolicyKey) -> Result<Option<PolicyValue>, String> {
            match self.map.get(key, 0) {
                Ok(v) => Ok(Some(v)),
                Err(aya::maps::MapError::KeyNotFound) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }

        fn list(&mut self) -> Result<Vec<(PolicyKey, PolicyValue)>, String> {
            self.map
                .iter()
                .map(|item| item.map_err(|e| e.to_string()))
                .collect()
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn linux_policy_store(_object_path: &std::path::Path) -> Result<MemoryPolicyStore, String> {
    Err("POLICY_MAP management requires Linux and Aya eBPF".to_string())
}
