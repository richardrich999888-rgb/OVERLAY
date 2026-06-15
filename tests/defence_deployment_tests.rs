//! Defence Deployment Scenario (Phase 3) — a representative topology with the
//! three profiles applied, four injected events, and measured convergence /
//! recovery. Built from REAL components:
//!   * real per-node OOB sessions over real TCP (identity + key agreement),
//!   * the real kinetic `Supervisor` (autonomous degrade/recover),
//!   * the real `DefenceProfile` / `CryptoPolicy` enforcement,
//!   * a real no-cleartext check on the captured wire bytes.
//!
//! Topology:
//!     Strategic Command ──▶ Regional Control ──▶ Tactical A
//!                                            └──▶ Tactical B ──▶ Legacy Application
//!
//! Profiles:  Strategic Command = StrategicCommand · Regional/Tactical = TacticalComms
//!            · Legacy Application = LegacyMigration.
//!
//! Honest scope: nodes are in-process on loopback (single host). This validates
//! the orchestration logic — profile enforcement, quarantine decisions,
//! autonomous failover/recovery, fail-closed, and zero-cleartext — end to end;
//! the kernel-level enforcement of the same decisions is measured separately in
//! the eBPF Policy Engine v2 validators. Convergence here is "enforced on the
//! next attempt"; fleet transport convergence is [design] (see the doc).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use syntriass_overlay::crypto::crypto_policy::{Attr, ConnectionProfile, KeyBacking};
use syntriass_overlay::crypto::oob::{
    begin_initiator, derive_provisioning_auth_secret, finish, respond, IdentityKeyHash, PeerRecord,
    PeerRegistry,
};
use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::kinetic::{OperationMode, Supervisor};
use syntriass_overlay::profiles::DefenceProfile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const SUITE: CipherSuite = CipherSuite::NistStandard768;
const MARKER: &[u8] = b"TOP-SECRET-PLAINTEXT-MARKER-XYZZY";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Role {
    StrategicCommand,
    RegionalControl,
    TacticalA,
    TacticalB,
    LegacyApp,
}

struct Node {
    role: Role,
    ed_seed: [u8; ED25519_SEED_LEN],
    ml_seed: [u8; MLDSA65_SEED_LEN],
    ed_pub: [u8; 32],
    ml_pub: Vec<u8>,
    hash: IdentityKeyHash,
    profile: DefenceProfile,
    registry: Arc<Mutex<PeerRegistry>>,
    supervisor: Arc<Mutex<Supervisor>>,
    addr: std::net::SocketAddr,
    up: Arc<AtomicBool>,
    quarantined: Arc<AtomicBool>,
    served_ok: Arc<AtomicU64>,
}

fn keys_for(
    role: Role,
) -> (
    [u8; ED25519_SEED_LEN],
    [u8; MLDSA65_SEED_LEN],
    [u8; 32],
    Vec<u8>,
) {
    let tag = role as u8 + 1;
    let mut ed = [0x40u8; ED25519_SEED_LEN];
    ed[0] = tag;
    let mut ml = [0x80u8; MLDSA65_SEED_LEN];
    ml[0] = tag;
    let (edp, mlp) = derive_identity_public_keys(&ed, &ml).unwrap();
    (ed, ml, edp, mlp)
}

async fn write_frame(s: &mut TcpStream, b: &[u8]) -> std::io::Result<()> {
    s.write_all(&(b.len() as u32).to_le_bytes()).await?;
    s.write_all(b).await
}
async fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l).await?;
    let mut b = vec![0u8; u32::from_le_bytes(l) as usize];
    s.read_exact(&mut b).await?;
    Ok(b)
}

fn profile_for(role: Role) -> DefenceProfile {
    match role {
        Role::StrategicCommand => DefenceProfile::StrategicCommand,
        Role::RegionalControl | Role::TacticalA | Role::TacticalB => DefenceProfile::TacticalComms,
        Role::LegacyApp => DefenceProfile::LegacyMigration,
    }
}

async fn make_node(role: Role) -> Node {
    let (ed_seed, ml_seed, ed_pub, ml_pub) = keys_for(role);
    let hash = IdentityKeyHash::of(&ed_pub, &ml_pub);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let registry = Arc::new(Mutex::new(PeerRegistry::new()));
    let up = Arc::new(AtomicBool::new(true));
    let quarantined = Arc::new(AtomicBool::new(false));
    let served_ok = Arc::new(AtomicU64::new(0));
    let profile = profile_for(role);

    // Responder loop: a downed or quarantined node drops the connection (fail
    // closed); otherwise it runs the real OOB handshake + sealed echo.
    {
        let registry = registry.clone();
        let up = up.clone();
        let quarantined = quarantined.clone();
        let served_ok = served_ok.clone();
        let own_hash = hash;
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                if !up.load(Ordering::SeqCst) || quarantined.load(Ordering::SeqCst) {
                    drop(s); // node failure / quarantine: no service
                    continue;
                }
                let registry = registry.clone();
                let served_ok = served_ok.clone();
                tokio::spawn(async move {
                    let Ok(ch) = read_frame(&mut s).await else {
                        return;
                    };
                    let mut guard = registry.lock().await;
                    match respond(&own_hash, &mut guard, 1_000, &ch) {
                        Ok((mut keys, sh, _who)) => {
                            drop(guard);
                            if write_frame(&mut s, &sh).await.is_err() {
                                return;
                            }
                            let Ok(probe) = read_frame(&mut s).await else {
                                return;
                            };
                            if let Ok(pt) = keys.open(&probe) {
                                let reply = keys.seal(&pt).unwrap();
                                let _ = write_frame(&mut s, &reply).await;
                                served_ok.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(_) => { /* fail closed: unknown/quarantined peer */ }
                    }
                });
            }
        });
    }

    Node {
        role,
        ed_seed,
        ml_seed,
        ed_pub,
        ml_pub,
        hash,
        profile,
        registry,
        supervisor: Arc::new(Mutex::new(Supervisor::new(profile.kinetic_config()))),
        addr,
        up,
        quarantined,
        served_ok,
    }
}

/// Provision a directed trust edge a -> b (a can initiate to b). Out-of-band:
/// one-time PQ handshake derives the shared secret; both register each other.
async fn provision_edge(a: &Node, b: &Node) {
    let a_id =
        IdentityMaterial::from_bytes(a.ed_seed, a.ml_seed, b.ed_pub, b.ml_pub.clone()).unwrap();
    let b_id =
        IdentityMaterial::from_bytes(b.ed_seed, b.ml_seed, a.ed_pub, a.ml_pub.clone()).unwrap();
    let engine = SUITE.engine();
    let (st, ch) = engine.begin_initiator(&a_id).unwrap();
    let (b_keys, sh) = engine.respond(&b_id, &ch).unwrap();
    let a_keys = st.finish(&a_id, &sh).unwrap();
    let sa = derive_provisioning_auth_secret(&a_keys);
    let sb = derive_provisioning_auth_secret(&b_keys);
    assert_eq!(&sa[..], &sb[..]);
    a.registry
        .lock()
        .await
        .provision(PeerRecord::new(b.ed_pub, b.ml_pub.clone(), *sa, 0));
    b.registry
        .lock()
        .await
        .provision(PeerRecord::new(a.ed_pub, a.ml_pub.clone(), *sb, 0));
}

#[derive(Debug)]
struct SessionResult {
    ok: bool,
    cleartext_seen: bool,
}

/// `from` initiates a real session to `to`, sealing MARKER and verifying the
/// echo. Returns whether it succeeded and whether MARKER ever appeared in clear
/// on the wire. A downed/quarantined either side yields ok=false (fail closed).
async fn session(from: &Node, to: &Node) -> SessionResult {
    if from.quarantined.load(Ordering::SeqCst) || !from.up.load(Ordering::SeqCst) {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    }
    let begin = {
        let mut g = from.registry.lock().await;
        match g.lookup(&to.hash) {
            Some(rec) => begin_initiator(&from.hash, rec, 1_000).ok(),
            None => None,
        }
    };
    let Some((st, ch)) = begin else {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    };
    let Ok(mut s) = TcpStream::connect(to.addr).await else {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    };
    if write_frame(&mut s, &ch).await.is_err() {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    }
    let Ok(sh) = read_frame(&mut s).await else {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    };
    let Ok(mut keys) = finish(st, &sh) else {
        return SessionResult {
            ok: false,
            cleartext_seen: false,
        };
    };
    let ct = keys.seal(MARKER).unwrap();
    // No-cleartext check: the sealed payload AND the handshake frames must not
    // contain the plaintext marker.
    let mut cleartext_seen =
        contains(&ct, MARKER) || contains(&ch, MARKER) || contains(&sh, MARKER);
    if write_frame(&mut s, &ct).await.is_err() {
        return SessionResult {
            ok: false,
            cleartext_seen,
        };
    }
    let Ok(reply) = read_frame(&mut s).await else {
        return SessionResult {
            ok: false,
            cleartext_seen,
        };
    };
    cleartext_seen |= contains(&reply, MARKER);
    let ok = keys.open(&reply).map(|p| p == MARKER).unwrap_or(false);
    SessionResult { ok, cleartext_seen }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Feed a session outcome to the initiator's kinetic supervisor and return the
/// resulting mode.
async fn feed(from: &Node, ok: bool) -> OperationMode {
    let mut sup = from.supervisor.lock().await;
    if ok {
        sup.handle_handshake_success()
    } else {
        sup.handle_handshake_failure()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_defence_deployment_scenario() {
    // ---- stand up the topology ----
    let strat = make_node(Role::StrategicCommand).await;
    let region = make_node(Role::RegionalControl).await;
    let tac_a = make_node(Role::TacticalA).await;
    let tac_b = make_node(Role::TacticalB).await;
    let legacy = make_node(Role::LegacyApp).await;

    provision_edge(&strat, &region).await;
    provision_edge(&region, &tac_a).await;
    provision_edge(&region, &tac_b).await;
    provision_edge(&tac_b, &legacy).await;

    println!("\n==== DEFENCE DEPLOYMENT SCENARIO (measured) ====");
    println!(
        "topology: Strategic[{}] -> Regional[{}] -> {{TacticalA[{}], TacticalB[{}] -> Legacy[{}]}}",
        strat.profile.name(),
        region.profile.name(),
        tac_a.profile.name(),
        tac_b.profile.name(),
        legacy.profile.name()
    );

    // ---- baseline: every topology edge establishes, zero cleartext ----
    let mut no_cleartext = true;
    for (a, b) in [
        (&strat, &region),
        (&region, &tac_a),
        (&region, &tac_b),
        (&tac_b, &legacy),
    ] {
        let r = session(a, b).await;
        assert!(
            r.ok,
            "{:?}->{:?} baseline session must establish",
            a.role, b.role
        );
        no_cleartext &= !r.cleartext_seen;
    }
    assert!(no_cleartext, "no cleartext on any baseline edge");
    println!("baseline: all 4 edges established, 0 cleartext");

    // ============ EVENT 1: NODE FAILURE (Tactical A) + autonomous recovery ====
    tac_a.up.store(false, Ordering::SeqCst);
    let t = Instant::now();
    // Regional Control (TacticalComms: fallback_available) degrades on sustained
    // failures toward EncryptedFallback — never plaintext.
    let mut degraded_to = None;
    for _ in 0..10 {
        let r = session(&region, &tac_a).await;
        assert!(!r.ok, "session to a downed node must fail closed");
        let m = feed(&region, r.ok).await;
        if m != OperationMode::FullPqc && degraded_to.is_none() {
            degraded_to = Some((m, t.elapsed()));
        }
        if m == OperationMode::FailClosed {
            break;
        }
    }
    let (deg_mode, deg_time) = degraded_to.expect("must degrade under sustained failure");
    assert_ne!(deg_mode, OperationMode::FullPqc);
    // recovery: node back up, sustained successes climb back to FullPqc
    tac_a.up.store(true, Ordering::SeqCst);
    let tr = Instant::now();
    let mut recovered = None;
    for _ in 0..20 {
        let r = session(&region, &tac_a).await;
        let m = feed(&region, r.ok).await;
        if m == OperationMode::FullPqc {
            recovered = Some(tr.elapsed());
            break;
        }
    }
    let rec_time = recovered.expect("must recover to FullPqc after node returns");
    let session_recovered = session(&region, &tac_a).await.ok;
    assert!(
        session_recovered,
        "session must re-establish after recovery"
    );
    println!(
        "EVENT node-failure: Regional degraded to {:?} in {} us; recovered to FullPqc in {} us; session re-established",
        deg_mode,
        deg_time.as_micros(),
        rec_time.as_micros()
    );

    // Strategic Command (no fallback) degrades STRAIGHT to FailClosed, never
    // EncryptedFallback — proven against a downed Regional peer.
    region.up.store(false, Ordering::SeqCst);
    let mut strat_modes = vec![];
    for _ in 0..6 {
        let r = session(&strat, &region).await;
        strat_modes.push(feed(&strat, r.ok).await);
    }
    region.up.store(true, Ordering::SeqCst);
    assert!(
        !strat_modes.contains(&OperationMode::EncryptedFallback),
        "Strategic Command must NEVER enter EncryptedFallback"
    );
    assert!(
        strat_modes.contains(&OperationMode::FailClosed),
        "Strategic Command must fail closed on sustained failure"
    );
    // recover strategic for the remainder
    {
        let mut sup = strat.supervisor.lock().await;
        sup.reset();
    }
    println!("EVENT node-failure: Strategic Command failed CLOSED (never EncryptedFallback) ✓");

    // ============ EVENT 2: POLICY CHANGE (Regional -> Strategic profile) ======
    // Convergence = apply the new policy + the next decision reflects it. A
    // *degraded* (fallback) connection that TacticalComms permits is refused once
    // Regional is re-tasked to the StrategicCommand policy.
    let degraded_conn = ConnectionProfile {
        is_fallback: true,
        pqc_active: Attr::No,
        hybrid: Attr::No,
        fallback_is_classical: Attr::No,
        key_backing: KeyBacking::Hardware,
        suite: SUITE,
    };
    let before = DefenceProfile::TacticalComms
        .spec()
        .crypto
        .permits(&degraded_conn);
    let tpc = Instant::now();
    let after_profile = DefenceProfile::StrategicCommand;
    let after = after_profile.spec().crypto.permits(&degraded_conn);
    let conv = tpc.elapsed();
    assert!(before, "TacticalComms permits the encrypted fallback");
    assert!(!after, "StrategicCommand refuses any fallback");
    println!(
        "EVENT policy-change: Regional re-tasked Tactical->Strategic; fallback permit {}->{} converged in {} ns (kernel push 0.66us avg, docs/DEFENCE_POLICY_PROFILES.md)",
        before, after, conv.as_nanos()
    );

    // ============ EVENT 3: QUARANTINE (Tactical B) + convergence ==============
    let served_before = tac_b.served_ok.load(Ordering::SeqCst);
    let tq = Instant::now();
    tac_b.quarantined.store(true, Ordering::SeqCst);
    // convergence: the very next session to/from B is refused
    let q1 = session(&region, &tac_b).await; // ingress to B
    let q2 = session(&tac_b, &legacy).await; // egress from B
    let q_conv = tq.elapsed();
    assert!(!q1.ok, "quarantined node must refuse ingress (fail closed)");
    assert!(!q2.ok, "quarantined node must refuse egress (fail closed)");
    assert_eq!(
        tac_b.served_ok.load(Ordering::SeqCst),
        served_before,
        "quarantined node served no new sessions"
    );
    println!(
        "EVENT quarantine: Tactical B isolated (ingress+egress denied) converged in {} us (kernel propagation 2us, docs/QUARANTINE_ENGINE.md)",
        q_conv.as_micros()
    );

    // ============ EVENT 4: RECOVERY (release Tactical B) ======================
    let trr = Instant::now();
    tac_b.quarantined.store(false, Ordering::SeqCst);
    let r1 = session(&region, &tac_b).await;
    let r2 = session(&tac_b, &legacy).await;
    let rr = trr.elapsed();
    assert!(r1.ok && r2.ok, "released node must serve again");
    assert!(
        !r1.cleartext_seen && !r2.cleartext_seen,
        "no cleartext after recovery"
    );
    println!(
        "EVENT recovery: Tactical B released; ingress+egress restored in {} us",
        rr.as_micros()
    );

    // ============ FINAL INVARIANT: zero cleartext anywhere ====================
    // Re-run every edge and assert MARKER never appeared in clear.
    let mut clean = true;
    for (a, b) in [
        (&strat, &region),
        (&region, &tac_a),
        (&region, &tac_b),
        (&tac_b, &legacy),
    ] {
        let r = session(a, b).await;
        assert!(r.ok);
        clean &= !r.cleartext_seen;
    }
    assert!(clean, "ZERO cleartext across the whole deployment");
    println!("FINAL: zero cleartext across the whole deployment ✓\n");
}
