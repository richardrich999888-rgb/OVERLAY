//! Structural sanitization for the kernel<->user-space event ABI.
//!
//! The eBPF `maps::SockEvent` (kernel) and `kernel_native::KernelSockEvent`
//! (user space) are passed verbatim through the BPF RingBuf, so they MUST stay
//! byte-identical: `#[repr(C)]`, 56 bytes, identical field order.
//!
//! Both definitions already carry `const _: () = assert!(...)` guards (in
//! `src/kernel_native.rs` and `ebpf/src/maps.rs`) so drift on *either* side is a
//! compile error. This test additionally pins the user-space layout with
//! `std::mem::{size_of, align_of}` + `offset_of!`, and documents the canonical
//! layout the kernel struct must match.

use std::mem::{align_of, offset_of, size_of};

use syntriass_overlay::kernel_native::KernelSockEvent;

/// The canonical wire layout (field, offset). The kernel `SockEvent` must match
/// this exactly; if you change one side, change the other or the build breaks.
const CANONICAL_OFFSETS: &[(&str, usize)] = &[
    ("cookie", 0),
    ("cgroup_id", 8),
    ("src_addr", 16),
    ("dst_addr", 32),
    ("src_port", 48),
    ("dst_port", 50),
    ("family", 52),
    ("_pad", 54),
];

#[test]
fn kernel_sock_event_is_exactly_56_bytes() {
    assert_eq!(size_of::<KernelSockEvent>(), 56, "ABI size drift");
    assert_eq!(KernelSockEvent::WIRE_LEN, 56, "WIRE_LEN must equal size_of");
}

#[test]
fn kernel_sock_event_is_8_byte_aligned() {
    // 8-byte alignment (the two leading u64s). A change here would shift every
    // offset and silently corrupt the RingBuf decode.
    assert_eq!(align_of::<KernelSockEvent>(), 8, "ABI alignment drift");
}

#[test]
fn kernel_sock_event_field_offsets_are_canonical() {
    assert_eq!(offset_of!(KernelSockEvent, cookie), 0);
    assert_eq!(offset_of!(KernelSockEvent, cgroup_id), 8);
    assert_eq!(offset_of!(KernelSockEvent, src_addr), 16);
    assert_eq!(offset_of!(KernelSockEvent, dst_addr), 32);
    assert_eq!(offset_of!(KernelSockEvent, src_port), 48);
    assert_eq!(offset_of!(KernelSockEvent, dst_port), 50);
    assert_eq!(offset_of!(KernelSockEvent, family), 52);
    assert_eq!(offset_of!(KernelSockEvent, _pad), 54);

    // The canonical table is the documented contract the kernel side mirrors.
    let last = CANONICAL_OFFSETS.last().unwrap();
    assert!(last.1 < size_of::<KernelSockEvent>());
}

#[test]
fn no_padding_holes_in_the_event() {
    // 8+8+16+16+2+2+2+2 = 56: the explicit `_pad` makes the struct fully packed
    // with no compiler-inserted padding (which would differ from the kernel's
    // verifier-checked layout).
    let summed = 8 + 8 + 16 + 16 + 2 + 2 + 2 + 2;
    assert_eq!(summed, size_of::<KernelSockEvent>());
}
