/*
 * C-DAC ParaS (SYCL 2020) data-parallel offload bridge.
 *
 * Accepts the strict 56-byte SYNTRIASS event contract from the Rust runtime and
 * evaluates it out-of-band on an asynchronous SYCL queue targeting host ARM
 * vector pipelines (NVIDIA Grace / Ampere Altra / Fujitsu A64FX-SVE) under the
 * CDAC-SSDG/ParaS-Compiler `parascc` toolchain. Builds either:
 *   - parascc ... -DCDAC_ENABLE_SYCL   (real SYCL offload), or
 *   - g++ -std=c++17                   (host fallback; identical results).
 */
#include "cdac_sycl_bridge.h"

#include <cstddef>
#include <cstdint>

/* ---- Compile-time ABI lock: any drift from the Rust 56-byte contract fails
 *      the build right here, at the C-DAC compiler's front end. ---- */
static_assert(sizeof(CdacSockEvent) == 56, "CdacSockEvent must be exactly 56 bytes");
static_assert(alignof(CdacSockEvent) == 8, "CdacSockEvent must be 8-byte aligned");
static_assert(offsetof(CdacSockEvent, cookie) == 0, "cookie@0");
static_assert(offsetof(CdacSockEvent, cgroup_id) == 8, "cgroup_id@8");
static_assert(offsetof(CdacSockEvent, src_addr) == 16, "src_addr@16");
static_assert(offsetof(CdacSockEvent, dst_addr) == 32, "dst_addr@32");
static_assert(offsetof(CdacSockEvent, src_port) == 48, "src_port@48");
static_assert(offsetof(CdacSockEvent, dst_port) == 50, "dst_port@50");
static_assert(offsetof(CdacSockEvent, family) == 52, "family@52");
static_assert(offsetof(CdacSockEvent, reserved_pad) == 54, "reserved_pad@54");

#ifdef CDAC_ENABLE_SYCL
#include <sycl/sycl.hpp>
#endif

namespace {

/* FNV-1a over the 56 bytes -> a stable, byte-sensitive connection-trace hash.
 * Used for out-of-band crypto-state evaluation + trace logging; the kernel
 * does NOT depend on it for confidentiality, so a host fallback is sound. */
inline uint64_t fnv1a_trace(const uint8_t *b, size_t n) {
    uint64_t h = 1469598103934665603ULL; /* FNV offset basis */
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint64_t>(b[i]);
        h *= 1099511628211ULL; /* FNV prime */
    }
    return h;
}

} /* namespace */

extern "C" int cdac_sycl_evaluate(const uint8_t *buf, size_t len, uint64_t *out_trace_hash) {
    if (buf == nullptr || out_trace_hash == nullptr) {
        return CDAC_ERR_NULL;
    }
    if (len != sizeof(CdacSockEvent)) {
        return CDAC_ERR_BADLEN; /* strict 56-byte contract */
    }

#ifdef CDAC_ENABLE_SYCL
    try {
        /* Asynchronous, in-order SYCL queue over the default device (host ARM
         * vector pipeline under parascc). The single_task reduces the 56-byte
         * event to its trace hash on the accelerator. */
        sycl::queue q{sycl::default_selector_v, sycl::property::queue::in_order()};
        uint64_t result = 0;
        {
            sycl::buffer<uint8_t, 1> in_buf(buf, sycl::range<1>(len));
            sycl::buffer<uint64_t, 1> out_buf(&result, sycl::range<1>(1));
            q.submit([&](sycl::handler &cgh) {
                auto in = in_buf.get_access<sycl::access_mode::read>(cgh);
                auto out = out_buf.get_access<sycl::access_mode::write>(cgh);
                cgh.single_task([=]() {
                    uint64_t h = 1469598103934665603ULL;
                    for (size_t i = 0; i < len; ++i) {
                        h ^= static_cast<uint64_t>(in[i]);
                        h *= 1099511628211ULL;
                    }
                    out[0] = h;
                });
            });
            q.wait_and_throw();
        }
        *out_trace_hash = result;
        return CDAC_OK;
    } catch (const sycl::exception &) {
        /* Fail closed on any SYCL runtime interrupt inside the Singularity
         * sandbox: still produce the trace via the host path, but signal the
         * runtime fault so the caller can react. */
        *out_trace_hash = fnv1a_trace(buf, len);
        return CDAC_ERR_RUNTIME;
    } catch (...) {
        return CDAC_ERR_RUNTIME;
    }
#else
    /* Host fallback (no SYCL toolchain present): identical trace hash. */
    *out_trace_hash = fnv1a_trace(buf, len);
    return CDAC_OK;
#endif
}

extern "C" const char *cdac_sycl_backend_name(void) {
#ifdef CDAC_ENABLE_SYCL
    return "parascc-sycl2020";
#else
    return "host-fallback";
#endif
}
