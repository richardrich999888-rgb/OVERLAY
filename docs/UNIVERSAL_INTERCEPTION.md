# Universal Interception

**Finding:** C1 — *LD_PRELOAD is the enforcement mechanism*. The overlay
interposed libc symbols (`connect`/`send`/…), which is **fundamentally
incomplete**: it cannot see a static binary, Go's libc-free runtime, or any
process issuing raw syscalls — and it can be unset (`LD_PRELOAD=`) or bypassed.
For a defence platform whose value is *assured* interception, that is a critical
gap.

Labels: **[measured]** a real run on this host produced this · **[implemented]**
code exists · **[design]** specified, requires external infra (§5).

This track did **not** stay a plan: a BPF-capable kernel (6.18, root, `CAP_BPF`+
`CAP_SYS_ADMIN`, cgroup v2, `clang`, `libbpf 1.3`) was available, so the eBPF path
was **built, loaded, attached, and measured** here. The captured run is
`ebpf/COVERAGE_REPORT.txt`; reproduce with `sudo scripts/ebpf_coverage_validate.sh`.

---

## 1. The mechanism — `cgroup/connect4`

A single eBPF program (`ebpf/c/connect4.bpf.c`, `BPF_PROG_TYPE_CGROUP_SOCK_ADDR`,
attach type `BPF_CGROUP_INET4_CONNECT`) runs inside the kernel's `connect(2)`
path, **below libc**. For every outbound IPv4 connection made by any process in
the attached cgroup it:

1. **Observes** — records `{pid, uid, dst ip:port, comm}` into a ring buffer (the
   control daemon consumes these to drive the PQC handshake — the same 56-byte
   `SockEvent`/`KernelSockEvent` ABI the userspace side already speaks).
2. **Enforces (fail-closed)** — if policy marks a destination, it returns `0`,
   which makes the `connect()` syscall fail with `EPERM`. This is the primitive
   that forces traffic through the overlay (deny direct egress; allow only the
   proxied path).

Because the hook is at the cgroup/connect layer, **how** the process made the
call is irrelevant — glibc, musl, static, Go, Rust, or a raw syscall are all seen.
This is exactly why Cilium uses it, and why it maps onto containers/Kubernetes
(attach to the pod's cgroup v2).

## 2. Measured coverage — **[measured]** (`ebpf/COVERAGE_REPORT.txt`)

Host: kernel 6.18.5 x86_64, clang 18.1.3, libbpf 1.3.0. One eBPF program attached
to one cgroup; each runtime built independently and run inside that cgroup,
connecting to a distinct port. **Every runtime's connect was observed by eBPF:**

| Runtime | Build | Uses libc `connect`? | LD_PRELOAD sees it? | **eBPF observed?** |
|---|---|---|---|---|
| glibc (dynamic) | `gcc` | yes | yes | **YES** |
| static glibc | `gcc -static` | yes (statically) | **no** (no dynamic symbol) | **YES** |
| Go | `go build` (CGO off) | **no** (raw syscalls) | **no** | **YES** |
| Rust | `rustc` (glibc) | yes | yes | **YES** |
| Rust musl (static) | `rustc --target …-musl` | musl, statically | **no** | **YES** |
| **direct syscall** | `syscall(SYS_connect)` | **no** (bypasses libc) | **no** | **YES** |
| Python | `python3` (glibc) | yes | yes | **YES** |

7/7 observed; **the four cases LD_PRELOAD is blind to (static, Go, musl-static,
direct syscall) were all caught.** That is the decisive, measured result: the
eBPF hook is a *strict superset* of LD_PRELOAD coverage.

### Enforcement — **[measured]**

With policy set to block port 51999 (which had a **live listener**, so a normal
connect would succeed):

```
MX rc=-1 errno=1(Operation not permitted)
 -> connection DENIED by eBPF despite a live server (fail-closed OK)
 -> eBPF event: comm=mx_glibc dst=127.0.0.1:51999 action=DENY
```

The connect was denied at the kernel — not by a userspace shim that could be
bypassed.

## 3. How it replaces LD_PRELOAD

| | LD_PRELOAD (v1) | eBPF `cgroup/connect4` (this) |
|---|---|---|
| Interception point | libc symbols in the process | kernel connect path (below libc) |
| Static / Go / musl / direct-syscall | **missed** | **caught** (measured) |
| Bypass | `LD_PRELOAD=` unsets it | requires `CAP_BPF` to detach; survives `exec` |
| Enforcement | fail-open shim | kernel `EPERM` deny (fail-closed) |
| Container/K8s fit | per-process env var | per-pod cgroup v2 attach |

The userspace control plane is unchanged: the eBPF ring-buffer event carries the
same fields as `kernel_native::KernelSockEvent`, so the daemon's existing
handshake/kTLS path consumes eBPF events exactly as it consumes the Unix-socket
upcalls today.

## 4. Build & reproduce

```
apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev   # + gcc go rustc python3
ebpf/c/build.sh                          # connect4.bpf.o + loader
sudo scripts/ebpf_coverage_validate.sh   # prints the table above; exits non-zero on any gap
```

The harness **skips** (never fakes) a runtime whose toolchain is absent, and
fails if any *available* runtime is not observed or if enforcement does not deny.

## 5. Honest boundary — what is NOT measured here

- **Kubernetes / multi-node.** The mechanism is validated on a single host's
  cgroup v2. Real K8s coverage = attaching the program to each pod's cgroup (via a
  CNI chain or a privileged DaemonSet, the Cilium model). That requires a cluster
  and is **[design]** — but the per-cgroup primitive it relies on is the exact one
  measured here. **[design]**
- **IPv6.** Only `connect4` is implemented/measured; `connect6`
  (`BPF_CGROUP_INET6_CONNECT`) is the byte-for-byte symmetric program over
  `user_ip6`. **[design — trivial extension]**
- **musl via C.** `musl-gcc` was absent, so the musl case used a Rust
  musl-static binary (which links musl). A C-musl binary is the same syscall path.
- **UDP / `sendmsg` connectionless egress.** `connect4` covers TCP/connected-UDP;
  `cgroup/sendmsg4` is the symmetric hook for unconnected datagrams. **[design]**
- **Production loader = Aya.** The measured loader is C/libbpf (builds with only
  clang+libbpf). The committed Rust/Aya scaffold (`ebpf/src/`) is the production
  path; it needs `bpf-linker` (absent in the default sandbox) to build the
  bytecode, but shares the same `SockEvent` ABI. **[design / scaffold]**
- **CI.** This runs on a BPF-capable host with elevated capabilities, not the
  default CI sandbox. A privileged BPF CI lane should run
  `scripts/ebpf_coverage_validate.sh` per-PR. **[design]**

## 6. Residual risks

- **R1 — attach scope is the cgroup.** Coverage is exactly the set of processes in
  the attached cgroup hierarchy. Deployment must attach at the right cgroup root
  (host-wide, or per-pod in K8s). A process moved out of the cgroup is not seen —
  an operational concern addressed by attaching at the appropriate root.
- **R2 — privilege required.** Loading/attaching needs `CAP_BPF`+`CAP_SYS_ADMIN`
  (or `CAP_NET_ADMIN` for cgroup-attach). This is the intended trust boundary (the
  enforcement agent is privileged; workloads are not) but must be deployed as such.
- **R3 — kernel dependency.** Requires cgroup v2 + `CGROUP_SOCK_ADDR` (≥4.17);
  fielded on 6.18 here. Older/locked-down kernels need the fallback (LD_PRELOAD
  remains as a defence-in-depth layer for the libc cases, not the primary).
- **R4 — IPv6/UDP not yet covered (§5).** Until `connect6`/`sendmsg4` land, those
  egress paths are not enforced by eBPF.
