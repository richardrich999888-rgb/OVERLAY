//! On-the-wire validation that the anti-DoS admission gate (finding C6) is on the
//! **real daemon execution path**, not just a library object.
//!
//! Each test stands up a responder that runs `over_socket::establish_and_bridge_gated`
//! — the exact function `src/bin/daemon.rs` calls for every accepted connection —
//! over real loopback TCP, and drives real / adversarial clients at it. The
//! responder's classified outcome tells us whether a connection reached the
//! expensive PQC stage or was rejected at the gate first.
//!
//! Outcome classification (no kTLS in this sandbox, so a fully-admitted handshake
//! ends at the kTLS bridge):
//!   * `reached_pqc`  — `Ok` / `Ktls(..)` / `Crypto(..)`: the ML-KEM/ML-DSA
//!     responder actually ran (the gate admitted the peer).
//!   * `Admission(..)` — rejected at the gate; **no PQC ran**.
//!
//! No fabricated numbers: every count is the real outcome of the real gated path.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use syntriass_overlay::crypto::{derive_identity_public_keys, CipherSuite, IdentityMaterial};
use syntriass_overlay::handshake_guard::{
    monotonic_secs, AdmissionError, GuardConfig, HandshakeGuard,
};
use syntriass_overlay::over_socket::{
    establish_and_bridge_gated, gated_initiator_handshake, OverSocketError,
};

const SUITE: CipherSuite = CipherSuite::NistStandard768;

fn trusting_identities() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
    let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

#[derive(Default)]
struct Outcomes {
    reached_pqc: AtomicU64,
    badmac: AtomicU64,
    replay: AtomicU64,
    throttled: AtomicU64,
    global: AtomicU64,
    protocol: AtomicU64,
    other: AtomicU64,
}

impl Outcomes {
    fn total(&self) -> u64 {
        self.reached_pqc.load(Ordering::Relaxed)
            + self.badmac.load(Ordering::Relaxed)
            + self.replay.load(Ordering::Relaxed)
            + self.throttled.load(Ordering::Relaxed)
            + self.global.load(Ordering::Relaxed)
            + self.protocol.load(Ordering::Relaxed)
            + self.other.load(Ordering::Relaxed)
    }

    fn classify(&self, res: Result<(), OverSocketError>) {
        let slot = match res {
            // A fully-admitted handshake runs PQC then dies at the kTLS bridge.
            Ok(()) | Err(OverSocketError::Ktls(_)) | Err(OverSocketError::Crypto(_)) => {
                &self.reached_pqc
            }
            Err(OverSocketError::Admission(AdmissionError::BadMac)) => &self.badmac,
            Err(OverSocketError::Admission(AdmissionError::Replay)) => &self.replay,
            Err(OverSocketError::Admission(AdmissionError::Throttled)) => &self.throttled,
            Err(OverSocketError::Admission(
                AdmissionError::GlobalRateLimited | AdmissionError::AtCapacity,
            )) => &self.global,
            Err(OverSocketError::Admission(_)) => &self.other,
            Err(OverSocketError::Protocol(_)) => &self.protocol,
            Err(OverSocketError::Io(_)) => &self.other,
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }
}

/// Start a gated responder on a loopback port. Returns its address, the shared
/// outcome counters, and the shared guard (for inspection).
async fn start_responder(
    cfg: GuardConfig,
) -> (SocketAddr, Arc<Outcomes>, Arc<Mutex<HandshakeGuard>>) {
    let (_client_id, server_id) = trusting_identities();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let outcomes = Arc::new(Outcomes::default());
    let guard = Arc::new(Mutex::new(HandshakeGuard::new(cfg, monotonic_secs())));
    let server_id = Arc::new(server_id);

    let out = Arc::clone(&outcomes);
    let g = Arc::clone(&guard);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let out = Arc::clone(&out);
            let g = Arc::clone(&g);
            let id = Arc::clone(&server_id);
            tokio::spawn(async move {
                let res = establish_and_bridge_gated(stream, &id, SUITE, &g).await;
                out.classify(res);
            });
        }
    });
    (addr, outcomes, guard)
}

async fn wait_for_total(outcomes: &Outcomes, want: u64) {
    for _ in 0..200 {
        if outcomes.total() >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "responder recorded {} outcomes, expected {want}",
        outcomes.total()
    );
}

async fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(s: &mut TcpStream, payload: &[u8]) {
    s.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    s.write_all(payload).await.unwrap();
    s.flush().await.unwrap();
}

#[tokio::test]
async fn gated_path_admits_genuine_peer_and_runs_pqc() {
    let (addr, outcomes, _g) = start_responder(GuardConfig::default()).await;
    let (client_id, _server_id) = trusting_identities();

    for _ in 0..3 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        // A genuine peer completes the cookie round-trip and the PQC handshake.
        let _ = gated_initiator_handshake(&mut s, &client_id, SUITE).await;
    }
    wait_for_total(&outcomes, 3).await;
    assert_eq!(outcomes.reached_pqc.load(Ordering::Relaxed), 3);
    assert_eq!(outcomes.badmac.load(Ordering::Relaxed), 0);
    eprintln!("[wire: honest ] reached_pqc=3 admission_rejections=0");
}

#[tokio::test]
async fn gated_path_rejects_forged_cookie_before_pqc() {
    let (addr, outcomes, _g) = start_responder(GuardConfig::default()).await;
    let flood = 10u64;
    for _ in 0..flood {
        let mut s = TcpStream::connect(addr).await.unwrap();
        // Receive the real cookie, then corrupt its MAC and echo it back.
        let mut cookie = read_frame(&mut s).await.unwrap();
        let last = cookie.len() - 1;
        cookie[last] ^= 0xFF;
        let mut msg = cookie;
        msg.extend_from_slice(&[0u8; 64]); // junk where the ClientHello would be
        write_frame(&mut s, &msg).await;
        let _ = read_frame(&mut s).await; // server closes after BadMac
    }
    wait_for_total(&outcomes, flood).await;
    assert_eq!(
        outcomes.reached_pqc.load(Ordering::Relaxed),
        0,
        "a forged cookie must not reach PQC on the wire"
    );
    assert_eq!(outcomes.badmac.load(Ordering::Relaxed), flood);
    eprintln!("[wire: forged ] forged={flood} reached_pqc=0 badmac={flood}");
}

#[tokio::test]
async fn gated_path_rejects_replayed_cookie() {
    let (addr, outcomes, _g) = start_responder(GuardConfig::default()).await;
    let (client_id, _server_id) = trusting_identities();
    let engine = SUITE.engine();

    // 1) A legitimate handshake that consumes its cookie. We drive it manually so
    //    we can capture the exact cookie bytes for the replay.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let cookie_frame = read_frame(&mut s).await.unwrap();
    let (_state, client_hello) = engine.begin_initiator(&client_id).unwrap();
    let mut first = cookie_frame.clone();
    first.extend_from_slice(&client_hello);
    write_frame(&mut s, &first).await;
    let _ = read_frame(&mut s).await; // ServerHello -> this connection reached PQC

    // 2) Replay the *same* cookie from a fresh connection (same loopback IP). The
    //    cookie is valid but already consumed -> rejected as Replay, no PQC.
    let replays = 5u64;
    for _ in 0..replays {
        let mut s2 = TcpStream::connect(addr).await.unwrap();
        let _new_cookie = read_frame(&mut s2).await.unwrap(); // ignored by the attacker
        let (_st, ch) = engine.begin_initiator(&client_id).unwrap();
        let mut replayed = cookie_frame.clone(); // the OLD, already-consumed cookie
        replayed.extend_from_slice(&ch);
        write_frame(&mut s2, &replayed).await;
        let _ = read_frame(&mut s2).await;
    }

    wait_for_total(&outcomes, 1 + replays).await;
    assert_eq!(
        outcomes.reached_pqc.load(Ordering::Relaxed),
        1,
        "only the first (genuine) handshake reaches PQC"
    );
    assert_eq!(outcomes.replay.load(Ordering::Relaxed), replays);
    eprintln!("[wire: replay ] genuine_pqc=1 replays_rejected={replays}");
}

#[tokio::test]
async fn global_gate_caps_admitted_pqc_under_concurrent_load() {
    // High per-source budget so the per-source limiter never fires; a small,
    // non-refilling global burst so the aggregate cap is the only thing that bites.
    let cfg = GuardConfig {
        rate_capacity: 10_000,
        rate_refill_per_sec: 10_000,
        global_pqc_burst: 5,
        global_pqc_per_sec: 0, // no refill -> exactly `burst` admits, ever
        max_in_flight_pqc: 0,
        ..GuardConfig::default()
    };
    let (addr, outcomes, _g) = start_responder(cfg).await;
    let (client_id, _server_id) = trusting_identities();
    let client_id = Arc::new(client_id);

    let load = 40u64;
    let mut handles = Vec::new();
    for _ in 0..load {
        let id = Arc::clone(&client_id);
        handles.push(tokio::spawn(async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            let _ = gated_initiator_handshake(&mut s, &id, SUITE).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    wait_for_total(&outcomes, load).await;

    // Exactly the global burst reached PQC; everything else was shed at the gate
    // with zero PQC — the distributed-load aggregate cap, on the real wire.
    assert_eq!(
        outcomes.reached_pqc.load(Ordering::Relaxed),
        5,
        "global burst must cap admitted PQC under load"
    );
    assert_eq!(outcomes.global.load(Ordering::Relaxed), load - 5);
    eprintln!(
        "[wire: load   ] concurrent={load} admitted_pqc=5 global_shed={}",
        outcomes.global.load(Ordering::Relaxed)
    );
}
