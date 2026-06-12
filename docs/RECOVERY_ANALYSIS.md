# Recovery Analysis

Tags per `BATTLEFIELD_RESILIENCE.md`. How the overlay recovers from disruption,
with measured/tested evidence. The unifying property: **every disruption recovery
path is fail-closed** — disruption never yields plaintext or a hung socket.

## 1. Reconnect / session recovery — **[measured]**

(`tests/battlefield_resilience.rs::reconnect_and_recovery_time`, release host)

| metric | value | note |
|---|---:|---|
| initial handshake | 3 224 µs | establish a hardened session |
| reconnect handshake | 3 456 µs | a fresh handshake after the drop |
| reconnect (measured incl. setup) | 5 185 µs | wall time to a working channel |
| total recovery wall | 14 873 µs | drop-detect → fresh session → first record |

**Fail-closed on drop [tested]:** after the link "drops" (peer rebooted / keys
gone), a *fresh, unrelated* session **cannot** open the old session's ciphertext
(different ephemeral keys + transcript binding). The old channel is dead, not
silently reusable — so a replayed or stale record after a drop is rejected, never
decrypted. Recovery is a new handshake (forward secrecy preserved).

## 2. Intermittent connectivity — **[measured]**

Modelled as repeated drop→reconnect cycles (§1 generalised). Each cycle:
- the prior session fails closed (above);
- a new handshake re-establishes trust (lifecycle-verified identity if used);
- the hardened record layer's anti-replay window tolerates the loss/reorder a
  flapping link produces (`BATTLEFIELD_RESILIENCE.md §1`).

No state leaks across a gap: sessions are independent, ephemeral, and forward-
secret. **[tested]** that a post-gap fresh session rejects pre-gap ciphertext.

## 3. Daemon crash recovery — **[tested]**
(`tests/chaos_orchestration.rs::daemon_context_kill_fails_closed`, real spawned daemon)

1. The real `daemon` binary is spawned (`SYNTRIASS_OVERSOCKET_LISTEN`), with a
   valid identity; concurrent client handshakes complete while it is alive.
2. The daemon is **killed mid-lifecycle** (`child.kill()`).
3. New client connections **fail closed**: the handshake returns `Err` /
   connection reset — **no hang, no plaintext, no degraded plaintext channel**.

Recovery model: the daemon is a restartable, stateless-per-connection supervisor
(its only durable state is the sealed keystore / config). On restart it re-binds
and resumes serving; in-flight connections at crash time are dropped fail-closed,
and clients reconnect (§1). There is **no plaintext fallback** under crash.

## 4. Memory exhaustion — **[tested]**
(`tests/chaos_orchestration.rs::memory_starvation_keeps_traffic_encrypted`)

A bounded 128 MiB buffer is allocated and touched (faulted in) **during** a crypto
operation to create real memory pressure. The result: records still seal/open
correctly and the sealed output **never contains the plaintext marker** — traffic
stays encrypted under pressure. The overlay does not degrade to plaintext when
memory is tight; an allocation failure on a security path returns `Err`
(`#![deny(unused_must_use)]` + the fail-closed error enums), never a bypass.

## 5. CPU starvation — **[measured]**
(`tests/battlefield_resilience.rs::handshake_under_cpu_starvation`)

Under 2× CPU oversubscription (8 hogs / 4 CPUs): **30/30 handshakes complete**,
latency p50 11.9 ms / p99 22.6 ms (≈ 4–8× the ~3 ms baseline). The platform
**slows but does not fail open** — no handshake aborts to an unprotected path, and
the fail-closed invariants hold throughout. Recovery is automatic as load clears
(latency returns to baseline).

## 6. Congestion — **[measured]**
(`tests/battlefield_resilience.rs::congestion_many_concurrent_handshakes`)

100 back-to-back sessions: **100/100** succeed at **249 handshakes/s**, **0
plaintext leaks**. Combined with the anti-DoS admission gate (C6), the responder's
PQC work under a connection storm is also rate/concurrency-bounded
(`HANDSHAKE_DOS_HARDENING.md`), so congestion degrades gracefully rather than
collapsing.

## 7. Recovery-property summary

| Disruption | Detect | Recover | Fail-closed? | Evidence |
|---|---|---|---|---|
| Link drop / reconnect | read error / timeout | fresh handshake (~3.5 ms) | **YES** | §1 [measured] |
| Intermittent connectivity | per-cycle | independent sessions + anti-replay | **YES** | §2 [measured/tested] |
| Daemon crash | connection reset | restart + client reconnect | **YES** | §3 [tested] |
| Memory exhaustion | alloc `Err` | stays encrypted; no bypass | **YES** | §4 [tested] |
| CPU starvation | elevated latency | completes; clears with load | **YES** | §5 [measured] |
| Congestion | none needed | rate/concurrency-bounded | **YES** | §6 [measured] |

## 8. Residual / honest boundary

- **R1 [design]** Daemon auto-restart/supervision (systemd unit, watchdog) is an
  operational control, not in-repo; the *fail-closed-on-crash* behaviour is tested.
- **R2 [design]** Recovery times are this host (release); fielded hardware +
  real-link RTT (netem host, `NETEM_RESULTS.md`) will refine the wall-clock values.
- **R3 [design]** Cross-restart session *resumption* (0-RTT-style) is not
  implemented; recovery is a full fresh handshake (forward-secret, by design).
