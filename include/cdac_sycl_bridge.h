/*
 * C-DAC ParaS (SYCL 2020) offload bridge — public ABI.
 *
 * Targets CDAC-SSDG/ParaS-Compiler (`parascc`), a native SYCL 2020 toolchain for
 * architecture-neutral offload across x86 and ARM (NVIDIA Grace, Ampere Altra,
 * Fujitsu A64FX/SVE). This header is the strict cross-language contract: the
 * `CdacSockEvent` struct MUST stay byte-for-byte identical to the Rust
 * `syntriass_overlay::kernel_native::KernelSockEvent` and the eBPF
 * `maps::SockEvent` (#[repr(C)], exactly 56 bytes).
 *
 * Build (C-DAC ParaS layout):
 *   parascc src/accelerator/cdac_sycl_bridge.cpp -Iinclude -DCDAC_ENABLE_SYCL \
 *           -o libcdac_sycl_bridge.so
 * Host fallback (no SYCL toolchain, ABI/layout validation):
 *   g++ -std=c++17 -Iinclude -c src/accelerator/cdac_sycl_bridge.cpp
 */
#ifndef CDAC_SYCL_BRIDGE_H
#define CDAC_SYCL_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wire/offload event — mirrors the Rust 56-byte KernelSockEvent exactly. */
typedef struct CdacSockEvent {
    uint64_t cookie;       /* offset  0 */
    uint64_t cgroup_id;    /* offset  8 */
    uint8_t  src_addr[16]; /* offset 16 */
    uint8_t  dst_addr[16]; /* offset 32 */
    uint16_t src_port;     /* offset 48 */
    uint16_t dst_port;     /* offset 50 */
    uint16_t family;       /* offset 52 */
    uint16_t reserved_pad; /* offset 54 */
} CdacSockEvent;

/* Result codes. Negative = fail-closed (caller must abort the connection). */
#define CDAC_OK           0
#define CDAC_ERR_NULL    (-1)
#define CDAC_ERR_BADLEN  (-2)
#define CDAC_ERR_RUNTIME (-3) /* SYCL/host runtime interrupt caught, failed closed */

/*
 * Offload an out-of-band evaluation of one 56-byte event onto an asynchronous
 * SYCL queue (host ARM vector pipelines when built with -DCDAC_ENABLE_SYCL),
 * returning a stable connection-trace hash in *out_trace_hash.
 *
 * Returns CDAC_OK on success; a negative CDAC_ERR_* on a fail-closed condition.
 */
int cdac_sycl_evaluate(const uint8_t *buf, size_t len, uint64_t *out_trace_hash);

/* Name of the active offload backend (for telemetry / the audit report). */
const char *cdac_sycl_backend_name(void);

#ifdef __cplusplus
}
#endif

#endif /* CDAC_SYCL_BRIDGE_H */
