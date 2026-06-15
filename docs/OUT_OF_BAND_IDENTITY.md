# Out-of-Band Identity (Phase 1)

Tags: **[measured]** a real run produced this · **[tested]** an automated test
passes · **[implemented]** code exists · **[design]** specified, needs external
infra.

**Objective:** remove ML-DSA public keys and signatures from the runtime
handshake, without losing mutual authentication, post-quantum confidentiality,
or fail-closed guarantees.

## 1. What changed

The full handshake (`crypto::generic`) carries, on **every** connection, each
peer's ML-DSA-65 **public key** (1952 B) and a fresh ML-DSA-65 **signature**
(3309 B) — ~10.5 KB of identity material per handshake, plus an ML-DSA sign +
verify on the latency path.

The out-of-band variant (`crypto::oob`) moves that **off the runtime path**:

| Concept | Role | Where |
|---|---|---|
| **`IdentityKeyHash`** | 32-byte SHA-256 of `ed25519_pub‖mldsa65_pub` — compact peer reference on the wire | `IdentityKeyHash::of` |
| **`PeerRegistry` + cache** | out-of-band map `IdentityKeyHash → {full identity, auth_secret, expiry}`; O(1) lookup | `PeerRegistry` |
| **`auth_secret`** (SessionToken capability) | per-peer symmetric secret established during a **one-time PQ-authenticated provisioning handshake** | `derive_provisioning_auth_secret` |
| **Runtime handshake** | X25519+ML-KEM KEM (unchanged) + a 32-byte HMAC capability under `auth_secret`, referencing peers by `IdentityKeyHash` | `oob::{begin_initiator,respond,finish}` |

ML-DSA is used **once, at provisioning** (to bootstrap the `auth_secret`, itself
bound to a full ML-DSA-authenticated handshake's keys); the runtime wire carries
neither the ML-DSA public key nor an ML-DSA signature.

## 2. Security preservation

- **Confidentiality + forward secrecy: unchanged.** The KEM exchange (ephemeral
  X25519 + ML-KEM-768) is byte-for-byte the full handshake's; recorded traffic
  stays post-quantum confidential. [implemented]
- **Mutual authentication: preserved.** Each side proves possession of the shared
  `auth_secret` via an HMAC over the transcript, with domain-separated client/
  server labels (no reflection) and the server tag binding the ClientHello
  (channel binding). The MAC is symmetric → **post-quantum secure**. [tested]
- **Fail-closed: preserved.** Unknown `IdentityKeyHash` ⇒ `Authentication`; bad
  tag ⇒ `Authentication`; expired peer ⇒ `BadIdentityConfig`. **No plaintext
  fallback exists.** [tested]
- **Runtime-auth note (honest):** runtime authentication rests on the symmetric
  `auth_secret` (PQ-secure) established at provisioning; the per-handshake ML-DSA
  *signature* is gone. The identity↔key binding remains ML-DSA-authenticated (at
  provisioning, via the credential lifecycle). This is a deliberate move of the
  expensive PQ-signature work off the hot path, not a downgrade of confidentiality.

## 3. Benchmark — **[measured]** (`cargo bench --bench oob_benchmarks`, n=300, release)

| metric | Previous (full) | Current (OOB) | Improvement |
|---|---:|---:|---:|
| handshake size (ClientHello+ServerHello) | 13 050 B | 2 464 B | **81.1 %** |
| handshake latency | 1 845.9 µs | 327.9 µs | **82.2 %** |
| ML-DSA public key on the wire | 3 904 B | **0** | removed |
| ML-DSA signature on the wire | 6 618 B | **0** | removed |

**10 522 B of ML-DSA material removed per runtime handshake.** Latency drops ~5.6×
because the runtime path no longer performs ML-DSA sign + verify (it does one HMAC
each side). Memory impact: the per-handshake transient ML-DSA buffers (~10 KB of
hello material + signature/verify scratch) are eliminated; the OOB hello is 2.5 KB
and the registry footprint is one `PeerRecord` (~2 KB, dominated by the stored
ML-DSA pubkey) per known peer — paid once at provisioning, not per handshake.

## 4. Validation — **[tested]** (`cargo test --lib crypto::oob`, 7 tests)

| Property | Test |
|---|---|
| OOB handshake round-trips; keys agree (seal/open) | `oob_handshake_round_trips_and_keys_agree` |
| **No ML-DSA pubkey / no 3309-B sig on the wire**; hello < 1500 B | `oob_handshake_carries_no_mldsa` |
| Unknown peer ⇒ fail closed | `unknown_peer_fails_closed` |
| Tampered capability ⇒ fail closed | `tampered_capability_fails_closed` |
| Wrong `auth_secret` ⇒ fail closed | `wrong_auth_secret_fails_closed` |
| Expired peer ⇒ fail closed | `expired_peer_fails_closed` |
| Peer lookup succeeds through the cache (hit/miss counters) | `cache_lookup_succeeds` |

## 4a. Identity revocation — **[tested]** (Migration Platform Phase 1)

The registry now carries an explicit **revocation set**, so a compromised or
retired identity can be cut off without deleting its record (re-instatement
stays an explicit operator action):

| API (`src/crypto/oob.rs`) | Behaviour |
|---|---|
| `PeerRegistry::revoke(&hash)` | mark an identity revoked (idempotent; pre-emptive revocation of an unknown hash allowed) |
| `PeerRegistry::unrevoke(&hash)` | lift a revocation; returns whether it was revoked |
| `is_revoked(&hash)` / `revoked_count()` | query state |
| `lookup(&hash)` | **fail-closed:** a revoked hash resolves to `None` (counted as a miss) — a revoked identity can neither initiate nor be responded to |
| `provision(record)` | clears any prior revocation of that exact identity |

Proven end-to-end by `revoked_identity_fails_closed_on_a_real_handshake`: a
runtime OOB session round-trips, the server revokes the client, and the **very
next real handshake fails closed** with `CryptoError::Authentication`; the
initiator side can likewise revoke a peer so it no longer resolves.

## 4b. SessionToken — **[tested]** typed rotating capability

`SessionToken` is a 32-byte, epoch-bound authorization derived from the shared
`auth_secret` (`HMAC(auth_secret, "…session-token v1" ‖ epoch)`):

| Property | Test |
|---|---|
| both peers derive the **same** token for the same epoch | `session_token_agrees_across_peers_and_rotates_by_epoch` |
| a new epoch rotates the token (no re-provisioning) | same |
| comparison is **constant-time** (`SessionToken::verify`) | `subtle::ConstantTimeEq` |

**Scope honesty:** `SessionToken` is [implemented]+[tested] as a typed rotating
capability over the provisioned secret. It is **not yet carried on the runtime
handshake wire** — the runtime handshake authenticates with the per-transcript
HMAC capability in `generic::oob_*`. Binding `SessionToken` into that transcript
(so token rotation gates live sessions) is **[design]** (R2 below).

## 5. Success criteria — status

| Criterion | Status |
|---|---|
| Runtime handshake no longer carries ML-DSA public keys | ✅ [tested] (`oob_handshake_carries_no_mldsa`) |
| Runtime handshake no longer carries ML-DSA signatures | ✅ [tested] (size 2 464 B; no 3309-B field) |
| Peer identity lookup succeeds through cache | ✅ [tested] (`cache_lookup_succeeds`) |
| Identity revocation supported, fail-closed | ✅ [tested] (`revoked_identity_fails_closed_on_a_real_handshake`) |
| SessionToken implemented | ✅ [implemented]+[tested]; runtime-wire binding [design] |
| Mutual authentication preserved | ✅ [tested] (both sides prove the shared `auth_secret`) |
| No plaintext fallback introduced | ✅ [tested] (all error paths `Err`; no `Plaintext`) |

### Re-measured (Migration Platform Phase 1, this host)

| Metric | Value |
|---|---:|
| Runtime handshake size | 13 050 → **2 464 B (−81.1 %)** [measured] |
| Runtime handshake latency | **−81.6 %** vs full (this run 2 736 → 503 µs) [measured] |
| ML-DSA bytes on the runtime wire | **0** (10 522 B/handshake removed) [measured] |
| Revocation memory overhead | `HashSet<[u8;32]>`: **0 B empty**, 32 B/revoked-hash [implemented] |

## 6. Residual / boundary

- **R1 [design]** Wiring `over_socket`/`daemon` to use the OOB handshake (vs the
  full one) on the runtime path, with the registry loaded from the credential
  lifecycle / sealed keystore, is a plumbing change — the primitives are
  implemented + tested; the daemon still calls the full handshake.
- **R2 [design]** Binding `SessionToken` rotation into the runtime transcript, and
  feeding the identity-lifecycle CRL into `PeerRegistry::revoke()` (CRL serial ⇒
  registry revocation) — the revocation mechanism is implemented + tested; the
  CRL→registry feed is the remaining wiring.
- **R3** The OOB engine is suite-768; suite-1024 is the byte-symmetric extension.
