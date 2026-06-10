use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct KernelVisibilityConfig {
    pub bpf_object: PathBuf,
    pub cgroup_path: PathBuf,
    pub map_pin_path: PathBuf,
}

impl KernelVisibilityConfig {
    pub fn new(
        bpf_object: impl Into<PathBuf>,
        cgroup_path: impl Into<PathBuf>,
    ) -> KernelVisibilityConfig {
        KernelVisibilityConfig {
            bpf_object: bpf_object.into(),
            cgroup_path: cgroup_path.into(),
            map_pin_path: PathBuf::from("/sys/fs/bpf/syntriass"),
        }
    }

    pub fn with_map_pin_path(mut self, map_pin_path: impl Into<PathBuf>) -> Self {
        self.map_pin_path = map_pin_path.into();
        self
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::KernelVisibilityConfig;
    use crate::{
        audit::{events::KernelFlowEvent, sink::AuditSink},
        kernel::maps::{AUDIT_RINGBUF, EVENTS},
        kernel_native::KernelSockEvent,
    };
    use aya::{
        maps::RingBuf,
        programs::{CgroupSockAddr, SockOps},
        Bpf, BpfLoader,
    };
    use std::{convert::TryInto, fs, fs::File};
    use tokio::io::unix::AsyncFd;

    pub struct KernelVisibilityRuntime {
        _bpf: Bpf,
        // AUDIT_RINGBUF: cgroup/connect allow/deny decisions (enforcement audit).
        audit_ring: AsyncFd<RingBuf<aya::maps::MapData>>,
        // EVENTS: sock_ops connection-established detection upcalls.
        events_ring: AsyncFd<RingBuf<aya::maps::MapData>>,
    }

    impl KernelVisibilityRuntime {
        pub fn load(
            config: &KernelVisibilityConfig,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            fs::create_dir_all(&config.map_pin_path)?;
            let mut bpf = BpfLoader::new()
                .map_pin_path(&config.map_pin_path)
                .load_file(&config.bpf_object)?;
            let cgroup = File::open(&config.cgroup_path)?;

            let connect4: &mut CgroupSockAddr = bpf
                .program_mut("syntriass_connect4")
                .ok_or("missing syntriass_connect4")?
                .try_into()?;
            connect4.load()?;
            // aya 0.12: `attach(cgroup)` is single-arg and returns a LinkId that
            // is retained inside the program's link set (kept alive by `_bpf`).
            connect4.attach(&cgroup)?;

            let connect6: &mut CgroupSockAddr = bpf
                .program_mut("syntriass_connect6")
                .ok_or("missing syntriass_connect6")?
                .try_into()?;
            connect6.load()?;
            connect6.attach(&cgroup)?;

            // Attach the sock_ops detection program too. Previously this program
            // existed in the BPF object but nothing loaded it, so its EVENTS
            // upcall (connection-established detection) was dead at runtime.
            let sock_ops: &mut SockOps = bpf
                .program_mut("syntriass_sock_handler")
                .ok_or("missing syntriass_sock_handler")?
                .try_into()?;
            sock_ops.load()?;
            sock_ops.attach(&cgroup)?;

            let audit_ring =
                RingBuf::try_from(bpf.take_map(AUDIT_RINGBUF).ok_or("missing AUDIT_RINGBUF")?)?;
            let events_ring = RingBuf::try_from(bpf.take_map(EVENTS).ok_or("missing EVENTS")?)?;

            Ok(Self {
                _bpf: bpf,
                audit_ring: AsyncFd::new(audit_ring)?,
                events_ring: AsyncFd::new(events_ring)?,
            })
        }

        pub async fn run<S: AuditSink>(
            &mut self,
            sink: &mut S,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            loop {
                tokio::select! {
                    audit = self.audit_ring.readable_mut() => {
                        let mut guard = audit?;
                        let ring = guard.get_inner_mut();
                        while let Some(item) = ring.next() {
                            if let Some(event) = KernelFlowEvent::from_bytes(&item) {
                                sink.emit(&event)?;
                            }
                        }
                        guard.clear_ready();
                    }
                    events = self.events_ring.readable_mut() => {
                        let mut guard = events?;
                        let ring = guard.get_inner_mut();
                        while let Some(item) = ring.next() {
                            if let Some(ev) = KernelSockEvent::from_bytes(&item) {
                                // Connection-established detection upcall. Emitted
                                // as structured JSON for the audit pipeline; the
                                // transparent proxy uses the iptables-REDIRECT
                                // data path, so this stream is visibility, not the
                                // enforcement critical path.
                                eprintln!(
                                    "{{\"kind\":\"sock_established\",\"cookie\":{},\"cgroup_id\":{},\"dst\":\"{}\",\"dst_port\":{}}}",
                                    ev.cookie, ev.cgroup_id, ev.dst_addr_string(), ev.dst_port
                                );
                            }
                        }
                        guard.clear_ready();
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::KernelVisibilityRuntime;

#[cfg(not(target_os = "linux"))]
pub struct KernelVisibilityRuntime;

#[cfg(not(target_os = "linux"))]
impl KernelVisibilityRuntime {
    pub fn load(
        _config: &KernelVisibilityConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Err("SYNTRIASS kernel visibility requires Linux cgroup v2 and Aya eBPF".into())
    }

    pub async fn run<S>(
        &mut self,
        _sink: &mut S,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("SYNTRIASS kernel visibility requires Linux cgroup v2 and Aya eBPF".into())
    }
}
