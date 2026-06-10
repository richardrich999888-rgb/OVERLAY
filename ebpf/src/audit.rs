use aya_ebpf::maps::RingBuf;

use crate::types::KernelFlowEvent;

pub fn submit_audit(ring: &RingBuf, event: KernelFlowEvent) -> Result<(), i64> {
    match ring.reserve::<KernelFlowEvent>(0) {
        Some(mut entry) => {
            entry.write(event);
            entry.submit(0);
            Ok(())
        }
        None => Err(-1),
    }
}
