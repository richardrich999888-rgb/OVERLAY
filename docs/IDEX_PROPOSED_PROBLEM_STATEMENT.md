# iDEX Open Challenge — Proposed Problem Statement

*Evidence tags: **[measured] [tested] [implemented] [design]**. Forward-looking
defence-impact statements are analytical context, not product claims, and are
marked as such.*

## Problem Title

**Quantum-safe, fail-closed communications for contested and air-gapped defence
networks — migrating the existing application estate without rip-and-replace.**

## Current Defence Challenge

Defence communications — C4I backbones, tactical radio/SATCOM data links, and
air-gapped command enclaves — depend on classical public-key cryptography
(RSA, ECDH, classical TLS/IPsec). Two forces are converging against this estate:

1. A **cryptographically-relevant quantum computer (CRQC)** will break RSA and
   elliptic-curve key exchange (Shor's algorithm). Public roadmaps and national
   PQC-migration mandates (NIST FIPS 203/204 finalised 2024; allied "migrate by
   ~2030–2035" directives) treat this as a *when*, not *if*.
2. **Contested operations** mean links are jammed, degraded, and partitioned,
   and endpoints are captured or compromised. Security stacks designed for the
   benign enterprise either leak or die under these conditions.

The challenge is not "add PQC" — it is to add PQC **and** preserve availability
under jamming **and** guarantee no plaintext leaks even when a host is
compromised **and** do all of this without rewriting the deployed application
estate.

## Operational Impact

- **Confidentiality with a shelf-life problem.** Strategic and intelligence
  traffic must stay secret for decades. Traffic encrypted classically today and
  recorded by an adversary is decryptable the day a CRQC arrives — the secret is
  *already lost*, silently.
- **Availability under contest.** A secure link that fails open leaks; one that
  fails dead strands the commander. Neither is acceptable on a tactical net.
- **Trust boundary at the endpoint.** Userspace VPN/TLS agents can be bypassed by
  a compromised or malicious process on the same host; the kernel is the only
  place an egress guarantee can be enforced.
- **Migration cost.** Re-engineering every fielded C4I/data-link application for
  PQC is infeasible on the required timeline and budget.

## Current Solutions and Limitations

| Approach | Limitation |
|---|---|
| Classical TLS/IPsec VPN | Quantum-vulnerable key exchange; HNDL-exposed today |
| "PQC TLS" library swaps | Requires per-application integration + recompilation across the estate; userspace-only (bypassable); large PQC signatures inflate every handshake |
| Hardware crypto appliances | Procurement/footprint cost; not deployable into existing software hosts or air-gapped enclaves at scale; often foreign-controlled cryptography |
| LD_PRELOAD/userspace shims | Bypassed by static binaries, Go runtimes, musl, and direct syscalls; fail-open on the paths they miss |

## Why Existing Approaches Fail

1. **Userspace enforcement is bypassable.** A shim or VPN agent only protects the
   processes that route through it. SYNTRIASS validated that LD_PRELOAD misses 4
   of 7 common runtimes; a kernel `cgroup/connect4` data plane intercepts all 7
   and denies non-compliant egress with EPERM **[measured]**.
2. **PQC signatures bloat every connection.** ML-DSA public key + signature add
   ~10.5 KB to each handshake — punishing on a low-bandwidth tactical link.
3. **They fail open, not closed.** When negotiation fails, conventional stacks
   fall back to weaker crypto or plaintext. Defence needs the opposite default.
4. **They are rip-and-replace.** None offer a drop-in migration path for the
   existing application estate.

## Why This Problem Is Becoming Urgent

- NIST PQC standards are **final** (FIPS 203 ML-KEM, FIPS 204 ML-DSA, 2024);
  the migration window has opened and allied mandates set hard dates.
- **HNDL is a present-tense attack:** the recording is happening now; only the
  decryption is deferred. Waiting for a CRQC to appear before migrating means the
  decades-of-secrecy traffic is already forfeit.
- Sovereign control of defence cryptography is a strategic requirement; a foreign
  PQC black box is not an acceptable substitute.

## Harvest-Now-Decrypt-Later Risk

HNDL is the defining urgency. An adversary needs **no quantum computer today** —
only the ability to record ciphertext and the patience to decrypt it later. The
risk is proportional to (secrecy lifetime × interception feasibility). For
defence:

- **Strategic / nuclear C2, diplomatic, and intelligence** traffic has a secrecy
  lifetime of **decades** → maximum HNDL exposure.
- The mitigation must be deployed **before** the CRQC, across the **existing**
  estate, which is exactly what a migration overlay enables. SYNTRIASS removes
  the classical-only key exchange from the wire (hybrid X25519+ML-KEM) so a
  recorded session is not later-decryptable by a quantum adversary
  [implemented]+[tested].

## Impact on Specific Defence Domains

- **C4I:** command-and-control message confidentiality and integrity across
  garrison and deployed networks; a single compromised host must not be able to
  exfiltrate in clear. Kernel fail-closed addresses this directly.
- **Tactical Networks:** low-bandwidth, lossy, jammed RF/SATCOM links. The
  −81 % handshake-size reduction **[measured]** and the autonomous
  FullPqc→EncryptedFallback→FailClosed recovery **[measured]** keep an
  *encrypted* link up under degradation, never plaintext.
- **Air-Gapped Systems:** strategic enclaves with no internet. Offline identity
  provisioning and checksum-verified offline policy distribution let these
  systems be migrated and managed without a network [tested].
- **Defence Data Links:** sensor-to-shooter and ISR feeds with long-lived value;
  HNDL protection plus deterministic fail-closed behaviour protect the link's
  confidentiality and prevent silent downgrade.

## Problem Severity

**Severity: Critical / strategic.** It combines (a) an irreversible
confidentiality loss already accruing via HNDL, (b) an availability requirement
under active contest, and (c) a sovereignty requirement — across an estate too
large to rewrite. The cost of inaction is the silent, decades-long compromise of
the most sensitive defence traffic.

## Expected Defence Benefit if Solved

- **Quantum-safe confidentiality** for the existing application estate with **no
  application rewrite** — migration at software speed and cost.
- **Guaranteed no-plaintext-leak** even under host compromise (kernel-enforced),
  raising the assurance floor of every protected link.
- **Mission availability under jamming** via autonomous, always-encrypted
  degradation.
- **Sovereign cryptographic control** (NIST-standard PQC, Indian-controlled
  implementation, no foreign black box) deployable from strategic command to the
  tactical edge to the air-gapped enclave.
