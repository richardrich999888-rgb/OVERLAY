# Battlefield Resilience

Tags: **[measured]** a real run produced this number · **[tested]** an automated
assertion passes · **[implemented]** code exists · **[design]** specified, needs
external infra. Companion: `NETEM_RESULTS.md`, `RECOVERY_ANALYSIS.md`.

**Mission:** measurable evidence of SYNTRIASS behaviour under degraded network
conditions. **No unverified claims** — every metric below is tagged and
reproducible.

## 0. netem honesty (read first)

Real `tc netem` was **preferred but is unavailable** in this environment: the
kernel exposes **no traffic-control qdiscs at all** (`netem`/`tbf`/`prio`/`htb`
all return "qdisc kind unknown"; no `net/sched` module directory). The full
diagnosis + the host-side netem plan are in `NETEM_RESULTS.md`
(`scripts/netem_validate.sh` captures it).

Consequently the impairment here is applied in **userspace, to the real bytes of
the real handshake + record layer** — tagged **[measured: userspace model]**,
explicitly distinct from **[design: kernel netem]**. The userspace loss/reorder
model is faithful to a datagram overlay (the record layer's job is precisely to
tolerate loss/reorder and reject replays); kernel netem would add TCP-retransmit
timing, which the host-side plan covers.

Reproduce all of §1–§5: `cargo test --release --test battlefield_resilience -- --nocapture --test-threads=1`

## 1. Loss ladder — record channel **[measured: userspace model]**

Real hybrid-PQC handshake → hardened record sessions; `RECORDS=400` sealed and
delivered through a lossy + bounded-reorder + jitter channel with 15 % replay
injection. Release build, this host:

| loss | delivered | opened (exactly once) | replays rejected | goodput (rec/s) | open p50 | open p99 | **plaintext leaks** |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 % | 350 | 350 | 50 | 3 049 | 1.2 µs | 4.1 µs | **0** |
| 20 % | 324 | 324 | 55 | 2 901 | 1.1 µs | 2.7 µs | **0** |
| 30 % | 256 | 256 | 37 | 2 933 | 1.2 µs | 2.9 µs | **0** |
| 45 % | 228 | 228 | 35 | 2 937 | 1.2 µs | 2.9 µs | **0** |

Invariants asserted at every loss rate **[tested]**: 100 % of delivered records
open exactly once; 100 % of replays rejected; **zero plaintext on the impaired
wire**; no panic, no hang. The encrypted goodput is essentially flat across the
loss ladder — loss reduces *delivered* records, but every delivered record is
processed at full speed (the channel does not collapse under loss).

## 2. Handshake success rate vs loss **[measured: userspace model]**

Single-shot, harsh datagram model (a 2-message handshake fails if *either*
message is lost; no application retransmit). 200 attempts per rate:

| loss | success rate |
|---:|---:|
| 10 % | 0.840 |
| 20 % | 0.650 |
| 30 % | 0.500 |
| 45 % | 0.320 |

These match `(1 − loss)²` (both messages must arrive) — the worst case with no
retransmit. In deployment the overlay rides TCP/kTLS (kernel retransmit) **or**
retries; §1 (record layer) and §3 (reconnect) show recovery. Honest framing: this
is the *floor*, not the fielded number, which kernel-netem validation will refine.

## 3. Reconnect & recovery **[measured]**

| metric | value |
|---|---:|
| initial handshake | 3 224 µs |
| reconnect handshake | 3 456 µs |
| reconnect (measured incl. setup) | 5 185 µs |
| total recovery wall | 14 873 µs |
| dropped-session fail-closed | **YES** (old ciphertext unreadable by a fresh session) |

Full analysis (incl. daemon-crash and memory-exhaustion recovery) in
`RECOVERY_ANALYSIS.md`.

## 4. CPU starvation **[measured]**

8 busy hog threads on 4 CPUs (2× oversubscription), 30 handshakes:

| metric | value |
|---|---:|
| handshakes completed | **30 / 30** |
| handshake latency p50 | 11.9 ms |
| handshake latency p99 | 22.6 ms |
| failed *open* | **0** |

Under heavy CPU starvation latency degrades ~4–8× (vs ~3 ms baseline) but **every
handshake still completes and nothing fails open** **[tested]**.

## 5. Congestion **[measured]**

100 back-to-back sessions: **100 / 100 succeeded**, **249 handshakes/s**, **0
plaintext leaks**. The channel sustains rapid session churn without degradation
or leakage **[tested]**.

## 6. Daemon crash & memory exhaustion **[tested]** (`tests/chaos_orchestration.rs`)

Measured against the **real spawned daemon binary**:

| scenario | behaviour |
|---|---|
| Daemon crash mid-session (`child.kill()`) | new connections **fail closed** (handshake `Err`/reset, no hang, no plaintext) |
| Memory pressure (bounded 128 MiB touched during a crypto op) | traffic stays **encrypted**; record seals/opens correctly; no plaintext under pressure |
| eBPF-map "corruption" placeholder | no-op (documented; no such map in this build) |

See `RECOVERY_ANALYSIS.md` for the recovery semantics.

## 7. Metric coverage matrix

| Required metric | Where | Tag |
|---|---|---|
| handshake success rate | §2 | [measured: userspace] |
| reconnect time | §3 | [measured] |
| throughput (goodput) | §1, §5 | [measured: userspace] |
| latency | §1, §3, §4 | [measured] |
| recovery time | §3, RECOVERY_ANALYSIS | [measured] |
| plaintext leakage | §1, §5 (canary on the wire) | [tested] = 0 |
| fail-closed behaviour | §3, §6 | [tested] |
| 10/20/30/45 % loss | §1, §2 | [measured: userspace] |
| intermittent connectivity | §3 (drop+reconnect) | [measured] |
| daemon crash | §6 | [tested] |
| memory exhaustion | §6 | [tested] |
| CPU starvation | §4 | [measured] |
| congestion | §5 | [measured] |
| **real `tc netem` ladder** | NETEM_RESULTS | **[design]** (host-side plan) |

## 8. Residual / honest boundary

- **R1 [design]** No kernel `tc netem` here (§0). The host-side plan
  (`NETEM_RESULTS.md`, `scripts/netem_validate.sh`) reproduces §1–§2 as
  `[measured: kernel netem]` on a netem-capable host.
- **R2 [design]** Throughput is *encrypted goodput of the record layer*, not a
  link-saturating bandwidth test (no `iperf`/qdisc shaping here).
- **R3** Latencies are this shared host (release); fielded hardware differs.
  Operation *counts* (delivery, replay-rejection, success-rate, leaks=0) are
  host-independent.
