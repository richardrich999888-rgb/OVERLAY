# SYNTRIASS Overlay — Critical & High Findings

> **Internal Security Review / Pre-Audit Assessment.** Not a certification, not a
> compliance attestation, not a completed audit. Findings are reviewer opinion
> from source reading; exploit scenarios are analytical, not demonstrated in
> production. Each item: root cause · exploit scenario · security impact ·
> reproduction · recommended fix · status.

Severity totals: **4 Critical (1 fixed, 3 open) · 9 High (open)**. Medium/Low/
Informational are in `docs/PRE_AUDIT_SECURITY_REVIEW.md` and the remediation plan.

---

# CRITICAL

## CR-1 — Interceptor fail-OPEN on indeterminate socket type  **[FIXED → Low]**
- **Location:** `src/interceptor.rs::is_stream_socket` and all data-path hooks
  (`send`/`write`/`writev`/`sendmsg`/…).
- **Root cause:** `is_stream_socket` returned `false` for both "not a socket" and
  "could not determine type"; every hook does `if !ensure_tracked(fd) { return
  real_libc(...) }`, so an indeterminate result routed the application's
  **plaintext** straight to real libc.
- **Exploit scenario:** induce a transient `getsockopt(SO_TYPE)` failure (EINTR /
  ENOBUFS / fd-table churn during heavy fork/dup) on a tracked stream socket;
  that `send`/`write` bypasses encryption and emits cleartext.
- **Security impact:** plaintext disclosure of application data — defeats the
  overlay on the affected call.
- **Reproduction:** inject `getsockopt` to return `-1/EINTR` once for a known
  stream fd, then `write()`; observe cleartext at the peer.
- **Fix (implemented this pass):** the probe now returns the real type on success;
  on failure it passes through **only** `ENOTSOCK`/`EBADF` (genuine files / fds
  that will themselves error — no data is sent) and treats **any other errno** as
  a socket → tracked → fail closed. Regression tests
  `interceptor::socket_classification_tests` (file / TCP / UDP / EBADF) added; full
  gate green (28 suites, clippy `-D warnings`, fmt).
- **Re-classification:** **Critical → Low.** Residual: the exact EINTR path cannot
  be triggered deterministically in a unit test, so the security behaviour is
  argued from the code path plus the classification tests, not from a forced-EINTR
  integration test. An external assessor should add a fault-injection test.

## CR-2 — Fork-after-connect AES-GCM nonce/key reuse  **[OPEN]**
- **Location:** `src/interceptor.rs::inherited_after_fork` (~l.835) +
  `src/fd_state.rs::current_pid` (getpid).
- **Root cause:** the only fork defense is `st.owner_pid == current_pid()` using
  `libc::getpid()`. There is no `pthread_atfork` child handler and no per-process
  nonce salt. If parent and child both hold an `Active(SessionKeys)` fd and the
  PID check is defeated (`clone(CLONE_VM)`, PID reuse/wrap, a cloning primitive
  that preserves the apparent PID, or a window before the check runs), both
  processes seal records with the **same key and overlapping nonce counter**.
- **Exploit scenario:** an application (or an attacker-influenced code path) that
  forks after a session is Active and writes from both processes. Two records are
  emitted under the same `(key, nonce)`.
- **Security impact:** **catastrophic** — AES-GCM nonce reuse permits authentication-
  key recovery and plaintext recovery (XOR of keystreams). This is the worst-case
  cryptographic break.
- **Reproduction:** establish an Active session, `fork()`, `send()` from both;
  capture records and check for a repeated `(nonce, key)` pair across the two
  processes.
- **Recommended fix:** (1) install a `pthread_atfork` child handler that
  **poisons/fails-closed the entire fd registry** in the child (no inherited
  session may ever seal); (2) defense-in-depth: mix a per-process random salt
  (drawn at session install) into the nonce/key derivation so inheritance cannot
  collide even if the PID check is bypassed; (3) add a fork integration test that
  asserts the child's first `send` fails closed.
- **Effort:** Medium. **Must precede any pilot.**

## CR-3 — Air-gap artifact integrity is unauthenticated (peer-key MITM)  **[OPEN]**
- **Location:** `deploy/airgap.sh` — `export-identity` (l.45-56), `import-peer`
  (l.58-78), `make-policy-bundle`/`apply-policy-bundle` (l.80-96).
- **Root cause:** the integrity mechanism is an **unkeyed SHA-256 stored inside
  the artifact it protects** (`sha256=` line in the export; `SHA256SUMS` inside
  the bundle tar). Import recomputes the same unkeyed hash and compares.
- **Exploit scenario:** an adversary on the sneakernet path (malicious courier,
  evil-maid, compromised USB) edits an identity export to substitute **their own**
  ed25519/ML-DSA public keys, recomputes the SHA-256, rewrites the `sha256=` line.
  `import-peer` accepts it: the victim node now trusts the attacker's identity.
- **Security impact:** **man-in-the-middle of the entire overlay's
  authentication.** Because runtime auth is a symmetric secret provisioned to the
  identity the operator imported, substituting the imported public identity lets
  the attacker complete handshakes as the "trusted" peer. The documented
  "fail-closed on tampered artifact" guarantee is **false against an active
  adversary** (SHA-256 detects accidental corruption only).
- **Reproduction:** `export-identity out`; edit `ed25519_public`/`mldsa65_public`
  in `out`; recompute `printf '%s\n' "$body" | sha256sum` and replace the
  `sha256=` line; `import-peer out` → succeeds.
- **Recommended fix:** **sign** exports and bundles (the project already ships
  Ed25519+ML-DSA) with the operator/issuing key and verify the signature on import
  against a **pre-distributed trust anchor** carried out-of-band; never let a
  checksum embedded in the artifact be the sole gate. Display the full fingerprint
  for out-of-band operator confirmation.
- **Effort:** Medium-High (needs an offline signing-key story). **Must precede any
  air-gapped pilot.**

## CR-4 — Unauthenticated install/package chain → root supply-chain RCE  **[OPEN]**
- **Location:** `deploy/package.sh` (l.55-63), `deploy/install.sh` (l.26-43).
- **Root cause:** `package.sh` emits a `SHA256SUMS` *inside* the package;
  `install.sh` reads binaries from `--from` and installs/executes them **as root
  without verifying any integrity manifest or signature**. The manifest is
  decorative.
- **Exploit scenario:** an attacker who can modify the distributed tarball (mirror,
  removable media, artifact store) replaces the `daemon` binary or `install.sh`
  and regenerates `SHA256SUMS`. Every installing host runs the trojan as root.
- **Security impact:** arbitrary root code execution across the fleet — supply-chain
  worst case for a defence deployment.
- **Reproduction:** modify a binary in a packaged tarball, regenerate `SHA256SUMS`,
  run `install.sh --from <tarball>`; the trojan installs and runs.
- **Recommended fix:** a **detached signature over the package**, verified by the
  offline installer against a hardware/offline-held public key **before** any
  contained script or binary is executed; verify `SHA256SUMS` against that signed
  root.
- **Effort:** Medium-High (shared signing story with CR-3). **Must precede
  distribution.**

---

# HIGH (all OPEN)

## HI-1 — eBPF enforcement only hooks `cgroup/connect4` (IPv6/UDP bypass)
- **Location:** `ebpf/c/connect4.bpf.c`, `policy.bpf.c`, `policy_v2.bpf.c` — every
  program is `SEC("cgroup/connect4")`.
- **Root cause:** only IPv4 TCP `connect` is hooked. No `connect6` (IPv6 TCP), no
  `sendmsg4`/`sendmsg6` (UDP), no coverage of other egress.
- **Exploit:** an application (or compromised process) that egresses over **IPv6**
  or **UDP** is never seen by the policy engine → its connection is permitted and
  unencrypted. Fail-open for those protocols.
- **Impact:** the "kernel fail-closed" guarantee is **protocol-incomplete**; a
  trivial protocol choice defeats it.
- **Reproduction:** with the engine attached and posture FailClosed, `connect()` an
  IPv6 socket or `sendto()` a UDP socket from the cgroup — it succeeds.
- **Fix:** add `cgroup/connect6`, `cgroup/sendmsg4`, `cgroup/sendmsg6` programs
  mirroring the policy logic; consider `cgroup/sock_create` to default-deny
  unknown families. Validate each on a real kernel.

## HI-2 — Kernel enforcement fails OPEN if the control plane detaches/crashes
- **Location:** eBPF attach lifecycle (`policy_v2_loader.c`); no pinned `bpf_link`.
- **Root cause:** the cgroup program enforces only while attached. Loader/daemon
  death detaches it; `connect` then defaults to allow.
- **Exploit:** kill or crash the control plane (or it OOMs) → egress is permitted
  again, unencrypted, with no kernel gate.
- **Impact:** the kernel guarantee is liveness-dependent; a crash is a fail-open.
- **Fix:** pin the `bpf_link` (`LIBBPF_PIN_BY_NAME` / `bpf_link__pin`) so it
  survives loader death; add a watchdog/systemd `Restart=always` with a
  default-deny posture installed at boot before the daemon starts; consider a
  "deny by default until the daemon asserts healthy" cgroup baseline.

## HI-3 — No `accept`/`accept4` hook; SCM_RIGHTS-passed fds role-confused
- **Location:** `src/interceptor.rs` (connect installs initiator state; no accept
  hook); `src/fd_passing.rs::recv_fd`.
- **Root cause:** responders are adopted lazily on first I/O; descriptors obtained
  via `accept`, `dup`, or SCM_RIGHTS passing are never put through an explicit
  role-assignment, so role is inferred from first I/O.
- **Exploit/Impact:** role confusion / handshake desync on passed and duplicated
  descriptors; combined with the (now-fixed) CR-1 class this was where fail-open
  was most likely.
- **Fix:** hook `accept`/`accept4` to register responders explicitly; define an
  explicit adoption contract for SCM_RIGHTS-passed fds rather than inferring role.

## HI-4 — fd-number-reuse TOCTOU: overlay bytes written to the wrong socket
- **Location:** `src/interceptor.rs` close path vs in-flight `overlay_send`.
- **Root cause:** the registry is keyed by raw `i32` fd; `close` removes the entry
  under the lock but the real `close(fd)` runs after the lock drops, and the kernel
  can immediately recycle the fd number on another thread. An in-flight send on the
  old fd number now targets a **different** kernel socket.
- **Exploit:** thread A loops connect+blocking write on a slow peer; thread B races
  `close` + immediate `socket()/connect()` to reclaim the fd number; A's overlay
  frames land on B's unrelated socket.
- **Impact:** ciphertext/handshake bytes written to the wrong (possibly
  cleartext-expecting) connection → corruption and cross-connection confusion.
- **Fix:** validate fd identity (generation counter or socket cookie) under the
  per-fd lock before each real syscall; serialize close against in-flight I/O.

## HI-5 — Unbounded fd-registry growth; `dup2`/`dup3` not interposed
- **Location:** `src/interceptor.rs` (insert on adopt; remove only via interposed
  `close`).
- **Root cause:** entries are removed only by the interposed `close`. `dup2`/`dup3`
  (atomically close+rebind), `close` via raw syscall, `closefrom`, io_uring close,
  and `O_CLOEXEC` on exec all leave stale entries; `dup2` is not hooked at all, so
  it rebinds an fd number to a new socket while the old `FdState` persists.
- **Impact:** memory-exhaustion DoS (each entry can hold large buffers) **and**
  stale-state binding (new connection inherits old `FdState`, feeding HI-4).
- **Fix:** hook `dup2`/`dup3`/`fcntl(F_DUPFD)`; cap registry size; reap entries
  whose fd is no longer valid.

## HI-6 — Air-gap import writes private seeds via predictable world-readable temp
- **Location:** `deploy/airgap.sh::import-peer` (l.69, 76).
- **Root cause:** `mktemp` creates the temp file with the process umask (often
  0644) in `$TMPDIR`; the `awk` pass copies the **entire** `identity.toml`
  (including private `ed25519_seed`/`mldsa65_seed`) into that predictable file
  before any `chmod`. `cat "$tmp" > "$IDENT"` is also non-atomic (a crash mid-write
  destroys the live identity).
- **Exploit:** a local unprivileged user reads `/tmp/tmp.XXXX` during import and
  exfiltrates the node's private seeds → full impersonation; symlink pre-creation
  is also possible.
- **Fix:** `umask 077` before creating the temp; create it on the same filesystem
  as `$IDENT`; `chmod 0600` immediately; `mv` atomically over `$IDENT`.

## HI-7 — `fleet.sh ingest-health` predictable temp → arbitrary root file overwrite
- **Location:** `deploy/fleet.sh::ingest-health` (l.83-91), the derived `"$tmp.2"`.
- **Root cause:** intermediate file `"$tmp.2"` is a predictable, non-`mktemp` path;
  `awk ... > "$tmp.2"` follows an attacker-pre-created symlink.
- **Exploit:** a local user symlinks `"$tmp.2"` to `/etc/syntriass/identity.toml`
  or a systemd unit; the redirect overwrites it as the invoking user (often root).
- **Fix:** `mktemp` every intermediate file, `umask 077`, keep temps in a
  non-attacker-writable dir, `mv` atomically.

## HI-8 — Unvalidated import/health fields → inventory injection / posture spoofing
- **Location:** `deploy/fleet.sh` (`add` l.41, `import-node` l.50, `ingest-health`
  `awk -v` l.88-89).
- **Root cause:** fields from untrusted export/health files (fingerprint, posture,
  health, epoch) are written verbatim into the TSV and passed through `awk -v`
  (which interprets escapes); an embedded tab/newline injects/forges columns.
- **Exploit:** a tampered export/health file forges inventory rows — e.g. mark an
  attacker node `FullPqc/ok`, or hide a `FailClosed` node from the `status` ALERT —
  defeating fleet posture monitoring.
- **Fix:** validate every imported field against a strict allowlist/regex (hex
  fingerprint, enum posture/health, integer epoch) and reject tabs/newlines before
  writing.

## HI-9 — `install.sh --provision-self` writes seed file with a world-readable window
- **Location:** `deploy/install.sh` (l.82-89).
- **Root cause:** the identity file (both private seeds) is written with default
  umask via `{ echo ...; } > "$ident"`; `chmod 0600` is applied only afterward.
- **Exploit:** a local user reads the freshly written `identity.toml` in the race
  window and obtains the node's private seeds.
- **Fix:** `umask 077` before the redirect, or `install -m 0600 /dev/null "$ident"`
  then append.

---

## Status legend
- **[FIXED → X]** — patched + regression-tested this pass; risk re-classified to X.
- **[OPEN]** — not patched this pass; deliberate (requires design + real
  kernel/multi-host/hardware validation). See `docs/SECURITY_REMEDIATION_PLAN.md`.
