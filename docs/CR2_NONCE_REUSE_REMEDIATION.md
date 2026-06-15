# CR-2 — Fork-After-Connect AES-GCM Nonce Reuse: Remediation

**Internal Security Hardening and Pre-Audit Remediation.** Not a certification.

## Finding (recap)
A forked child inherits an `Active(SessionKeys)` fd including the AES-GCM nonce
counter. If parent and child both seal, they reuse a `(key, nonce)` pair —
catastrophic GCM break (auth-key + plaintext recovery). The only prior defense
was a `getpid()` equality check, defeatable by PID reuse/wrap or a clone path
that preserves the apparent PID, with no `pthread_atfork` handler.

## Remediation — [implemented] [tested]
1. **Fork-aware process token** (`src/fd_state.rs`): `token = BASE ^ FORK_EPOCH`,
   where `BASE` is a per-image random value and `FORK_EPOCH` is incremented by a
   `pthread_atfork` **child** handler — a lone atomic `fetch_add`, the only thing
   safe to run post-fork. The handler is registered idempotently on first use.
2. **Per-session capture**: `FdState.owner_token` is captured at creation.
   `FdState::is_inherited()` compares the token first (robust against PID reuse)
   with `getpid()` as a backstop. `inherited_after_fork()` fails the session
   **closed** on any mismatch — a forked child can never seal/open an inherited
   session; the application must re-handshake (fresh keys).
3. **Defense-in-depth** (`src/interceptor.rs`): a second `pthread_atfork` child
   handler proactively fail-closes every registry session immediately after fork
   (`try_lock`, deadlock-safe). The authoritative guard remains the token check.

## Why nonce uniqueness now holds
- A child's token differs from any session it inherited ⇒ `is_inherited()` is
  true ⇒ the overlay refuses to seal ⇒ the child never produces a second record
  under the parent's `(key, nonce)`.
- A session created **after** fork (in either process) has the live token ⇒ usable
  (no false fail-closed) — fork-before-connect is unaffected.

## Validation — `tests/cr2_nonce_reuse_tests.rs` (real `fork()`)
| Test | Proves |
|---|---|
| `fork_after_connect_child_detects_inherited_and_would_reuse_nonce` | the child detects inherited AND an *unguarded* child seal reproduces the parent's nonce-0 ciphertext **byte-for-byte** (the averted reuse is real) |
| `fdstate_is_inherited_across_real_fork` | the same `FdState` reads inherited in the child, not in the parent |
| `fork_before_connect_child_session_is_usable` | a post-fork child session is usable (no false fail-closed) |
| `multiple_children_all_detect_inherited` | every child detects the inherited session |
| `concurrent_session_creation_not_flagged_inherited` | concurrent same-process sessions are never mis-flagged |

5/5 pass. Full gate green (clippy `-D warnings`, fmt, 29→31 suites).

## Residual assumptions / limitations
- `pthread_atfork` child handlers run for `fork()`/`vfork()` via glibc. A **raw
  `clone()`** that bypasses the libc wrapper does not run atfork handlers — there
  the **token is not bumped by the handler**, so that path relies on the `getpid`
  backstop. `note_fork_in_child()` is exposed for a clone-aware wrapper to call.
  Documented as residual; an external assessor should test the raw-clone path.
- The guard prevents the child from *using* the inherited session; the
  application must reconnect. This is the correct fail-closed behaviour (no silent
  key reuse), but applications that fork-and-continue mid-session will see the
  child's first I/O fail and must re-establish.

## Status
CR-2: **Critical → Closed** `[implemented] [tested]` (with the raw-clone residual
above marked for external review).
