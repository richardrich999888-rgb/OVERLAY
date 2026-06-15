//! Multi-Node Validation (Phase 2) — N-node deployments on one host.
//!
//! Each "node" is an independent identity + `PeerRegistry` + real TCP listener
//! on loopback; pairs are provisioned exactly as a deployment would be (a
//! one-time full PQ-authenticated handshake derives the pairwise auth_secret —
//! the out-of-band step), then every session in the mesh is a REAL runtime OOB
//! handshake over TCP, finished with an encrypted round trip in both directions
//! to prove key agreement.
//!
//! Honest scope: all nodes run in one process on one host (loopback). What this
//! measures is the identity-distribution correctness, the fail-closed behaviour
//! of unknown identities, and the session-establishment rate of the *protocol
//! stack*; cross-host network effects are out of scope here (see
//! docs/MULTINODE_VALIDATION.md for the limits statement).

use std::sync::Arc;
use std::time::Instant;

use syntriass_overlay::crypto::oob::{
    begin_initiator, derive_provisioning_auth_secret, finish, respond, IdentityKeyHash, PeerRecord,
    PeerRegistry,
};
use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const SUITE: CipherSuite = CipherSuite::NistStandard768;

struct NodeKeys {
    ed_seed: [u8; ED25519_SEED_LEN],
    ml_seed: [u8; MLDSA65_SEED_LEN],
    ed_pub: [u8; 32],
    ml_pub: Vec<u8>,
    hash: IdentityKeyHash,
}

fn mk_node(i: u16) -> NodeKeys {
    // Unique, deterministic per-node seeds.
    let mut ed_seed = [0x5Au8; ED25519_SEED_LEN];
    ed_seed[0] = (i & 0xff) as u8;
    ed_seed[1] = (i >> 8) as u8;
    let mut ml_seed = [0xC3u8; MLDSA65_SEED_LEN];
    ml_seed[0] = (i & 0xff) as u8;
    ml_seed[1] = (i >> 8) as u8;
    let (ed_pub, ml_pub) = derive_identity_public_keys(&ed_seed, &ml_seed).unwrap();
    let hash = IdentityKeyHash::of(&ed_pub, &ml_pub);
    NodeKeys {
        ed_seed,
        ml_seed,
        ed_pub,
        ml_pub,
        hash,
    }
}

/// One-time out-of-band provisioning of the pair (a, b): full PQ-authenticated
/// handshake -> shared auth_secret. Returns the secret both register.
fn provision_pair(a: &NodeKeys, b: &NodeKeys) -> [u8; 32] {
    let a_id = IdentityMaterial::from_bytes(a.ed_seed, a.ml_seed, b.ed_pub, b.ml_pub.clone())
        .expect("a identity");
    let b_id = IdentityMaterial::from_bytes(b.ed_seed, b.ml_seed, a.ed_pub, a.ml_pub.clone())
        .expect("b identity");
    let engine = SUITE.engine();
    let (st, ch) = engine.begin_initiator(&a_id).unwrap();
    let (b_keys, sh) = engine.respond(&b_id, &ch).unwrap();
    let a_keys = st.finish(&a_id, &sh).unwrap();
    let sa = derive_provisioning_auth_secret(&a_keys);
    let sb = derive_provisioning_auth_secret(&b_keys);
    assert_eq!(&sa[..], &sb[..], "pairwise auth_secret must agree");
    *sa
}

async fn write_frame(s: &mut TcpStream, b: &[u8]) {
    s.write_all(&(b.len() as u32).to_le_bytes()).await.unwrap();
    s.write_all(b).await.unwrap();
}
async fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l).await.unwrap();
    let mut b = vec![0u8; u32::from_le_bytes(l) as usize];
    s.read_exact(&mut b).await.unwrap();
    b
}

fn vm_hwm_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
        })
        .unwrap_or(0)
}

struct MeshStats {
    nodes: usize,
    pairs: usize,
    provision_s: f64,
    establish_s: f64,
    rate_per_s: f64,
}

/// Provision + run a full runtime mesh over real TCP. Every node runs a real
/// listener; every pair establishes a runtime OOB session and proves agreement
/// with an encrypted echo in both directions.
async fn run_mesh(n: u16) -> MeshStats {
    // ---- identities ----
    let nodes: Vec<NodeKeys> = (0..n).map(mk_node).collect();

    // ---- out-of-band provisioning (all pairs), parallel across threads ----
    let t0 = Instant::now();
    let pairs: Vec<(usize, usize)> = (0..n as usize)
        .flat_map(|i| ((i + 1)..n as usize).map(move |j| (i, j)))
        .collect();
    let secrets: Vec<[u8; 32]> = {
        let nodes = &nodes;
        let chunk = pairs.len().div_ceil(4).max(1);
        std::thread::scope(|s| {
            let handles: Vec<_> = pairs
                .chunks(chunk)
                .map(|c| {
                    s.spawn(move || {
                        c.iter()
                            .map(|&(i, j)| provision_pair(&nodes[i], &nodes[j]))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap())
                .collect()
        })
    };
    let provision_s = t0.elapsed().as_secs_f64();

    // ---- registries: each node registers every provisioned peer ----
    let mut regs: Vec<PeerRegistry> = (0..n as usize).map(|_| PeerRegistry::new()).collect();
    for (k, &(i, j)) in pairs.iter().enumerate() {
        regs[i].provision(PeerRecord::new(
            nodes[j].ed_pub,
            nodes[j].ml_pub.clone(),
            secrets[k],
            0,
        ));
        regs[j].provision(PeerRecord::new(
            nodes[i].ed_pub,
            nodes[i].ml_pub.clone(),
            secrets[k],
            0,
        ));
    }

    // ---- per-node real TCP listeners (responder side) ----
    let regs: Vec<Arc<Mutex<PeerRegistry>>> =
        regs.into_iter().map(|r| Arc::new(Mutex::new(r))).collect();
    let mut addrs = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        addrs.push(listener.local_addr().unwrap());
        let reg = regs[i].clone();
        let own_hash = nodes[i].hash;
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let reg = reg.clone();
                tokio::spawn(async move {
                    let ch = read_frame(&mut s).await;
                    let now = 1_000u64;
                    let mut guard = reg.lock().await;
                    match respond(&own_hash, &mut guard, now, &ch) {
                        Ok((mut keys, sh, _who)) => {
                            drop(guard);
                            write_frame(&mut s, &sh).await;
                            // encrypted echo: open the client probe, seal a reply
                            let probe = read_frame(&mut s).await;
                            let pt = keys.open(&probe).expect("probe must decrypt");
                            let reply = keys.seal(&pt).unwrap();
                            write_frame(&mut s, &reply).await;
                        }
                        Err(_) => {
                            // fail-closed: no ServerHello for an unknown peer
                            drop(guard);
                        }
                    }
                });
            }
        });
    }

    // ---- runtime mesh: a real OOB session per pair, encrypted echo both ways ----
    let t1 = Instant::now();
    let mut done = 0usize;
    for &(i, j) in &pairs {
        // The initiator resolves the peer from its own registry (O(1) cache) and
        // begins a real runtime OOB handshake.
        let (st, ch) = {
            let mut g = regs[i].lock().await;
            let rec = g.lookup(&nodes[j].hash).expect("peer provisioned");
            begin_initiator(&nodes[i].hash, rec, 1_000).unwrap()
        };
        let mut s = TcpStream::connect(addrs[j]).await.unwrap();
        write_frame(&mut s, &ch).await;
        let sh = read_frame(&mut s).await;
        let mut keys = finish(st, &sh).expect("initiator must authenticate the responder");
        // encrypted round trip proves both directions agree
        let msg = format!("mesh-{i}-{j}");
        let ct = keys.seal(msg.as_bytes()).unwrap();
        write_frame(&mut s, &ct).await;
        let reply = read_frame(&mut s).await;
        assert_eq!(
            keys.open(&reply).unwrap(),
            msg.as_bytes(),
            "echo must round-trip encrypted"
        );
        done += 1;
    }
    let establish_s = t1.elapsed().as_secs_f64();
    assert_eq!(done, pairs.len());

    MeshStats {
        nodes: n as usize,
        pairs: pairs.len(),
        provision_s,
        establish_s,
        rate_per_s: pairs.len() as f64 / establish_s,
    }
}

fn print_stats(s: &MeshStats) {
    println!(
        "[multinode] nodes={:2}  sessions={:4}  provision(oob,one-time)={:.2}s  establish={:.3}s  rate={:.0} sessions/s  VmHWM={} KiB",
        s.nodes, s.pairs, s.provision_s, s.establish_s, s.rate_per_s, vm_hwm_kib()
    );
}

#[tokio::test]
async fn level1_three_nodes_full_mesh() {
    let s = run_mesh(3).await;
    print_stats(&s);
    assert_eq!(s.pairs, 3);
}

#[tokio::test]
async fn level2_ten_nodes_full_mesh() {
    let s = run_mesh(10).await;
    print_stats(&s);
    assert_eq!(s.pairs, 45);
}

#[tokio::test]
async fn level3_fifty_nodes_full_mesh() {
    let s = run_mesh(50).await;
    print_stats(&s);
    assert_eq!(s.pairs, 1225);
}

/// Fail-closed: a node that was never provisioned (identity unknown to the
/// fleet) cannot establish a session with any node — the responder rejects the
/// unknown IdentityKeyHash and sends nothing back.
#[tokio::test]
async fn unprovisioned_node_is_rejected_fleet_wide() {
    let a = mk_node(1);
    let b = mk_node(2);
    let intruder = mk_node(999);

    // a <-> b provisioned; the intruder is not.
    let sec = provision_pair(&a, &b);
    let mut reg_b = PeerRegistry::new();
    reg_b.provision(PeerRecord::new(a.ed_pub, a.ml_pub.clone(), sec, 0));

    // The intruder forges a hello toward b using its own (unregistered) identity
    // and a guessed secret.
    let mut reg_intruder = PeerRegistry::new();
    reg_intruder.provision(PeerRecord::new(
        b.ed_pub,
        b.ml_pub.clone(),
        [0xEE; 32], // wrong secret — it was never provisioned
        0,
    ));
    let rec = reg_intruder.lookup(&b.hash).unwrap();
    let (_st, ch) = begin_initiator(&intruder.hash, rec, 1_000).unwrap();

    let r = respond(&b.hash, &mut reg_b, 1_000, &ch);
    assert!(
        r.is_err(),
        "unknown identity must be rejected (fail closed)"
    );

    // And a legitimate peer with a wrong secret is also rejected.
    let mut reg_b2 = PeerRegistry::new();
    reg_b2.provision(PeerRecord::new(a.ed_pub, a.ml_pub.clone(), [0xEE; 32], 0));
    let mut reg_a = PeerRegistry::new();
    reg_a.provision(PeerRecord::new(b.ed_pub, b.ml_pub.clone(), sec, 0));
    let rec = reg_a.lookup(&b.hash).unwrap();
    let (_st, ch) = begin_initiator(&a.hash, rec, 1_000).unwrap();
    let r2 = respond(&b.hash, &mut reg_b2, 1_000, &ch);
    assert!(
        r2.is_err(),
        "capability mismatch must be rejected (fail closed)"
    );
    println!("[multinode] unprovisioned + wrong-capability identities rejected fleet-wide");
}
