//! Automated chaos fault-injection + secure-fallback extraction.
//!
//! Mimics a local Chaos Mesh scenario against the REAL code paths: it kills the
//! compiled control daemon mid-lifecycle, applies bounded memory pressure, and
//! pokes a stand-in eBPF-map path, asserting the system always **fails closed**
//! and never emits cleartext. It also measures the real control-plane
//! Garrison -> EncryptedFallback switchover latency.
//!
//! Honest scope: there is no eBPF `OPERATION_MODE_FLAG` map in this build (we
//! ship the *encrypted* fallback, not a plaintext Kinetic flag), so that chaos
//! action is a clearly-labeled placeholder. The "~47 us" figure is the
//! control-plane decision+derive, not a kernel data-plane switch.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use syntriass_overlay::crypto::fallback::{self, FallbackInitiator};
use syntriass_overlay::crypto::{
    derive_fallback_session, derive_identity_public_keys, CipherSuite, IdentityMaterial,
    FALLBACK_NONCE_LEN, FALLBACK_PSK_LEN,
};
use syntriass_overlay::kernel_native::{select_posture, AvailabilityPosture};
use syntriass_overlay::over_socket::initiator_handshake;

const SUITE: CipherSuite = CipherSuite::NistStandard768;
/// A plaintext marker that must NEVER appear on the wire.
const MARKER: &[u8] = b"CLASSIFIED-MISSION-CLEARTEXT-MARKER";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Kills the child daemon on drop so a failed assertion never leaks a process.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn client_identity() -> IdentityMaterial {
    let (ce, cm) = ([0x11u8; 32], [0x22u8; 32]);
    let (se, sm) = ([0x33u8; 32], [0x44u8; 32]);
    let (s_ed_pub, s_ml_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    IdentityMaterial::from_bytes(ce, cm, s_ed_pub, s_ml_pub).unwrap()
}

async fn client_handshake(port: u16, id: &IdentityMaterial) -> Result<(), String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| format!("connect: {e}"))?;
    initiator_handshake(&mut s, id, SUITE)
        .await
        .map(|_| ())
        .map_err(|e| format!("handshake: {e}"))
}

#[tokio::test]
async fn daemon_context_kill_fails_closed() {
    let port = free_port();
    // The daemon plays the responder (server identity); it trusts the client.
    let (s_ed, s_ml) = ([0x33u8; 32], [0x44u8; 32]);
    let (c_ed, c_ml) = ([0x11u8; 32], [0x22u8; 32]);
    let (c_ed_pub, c_ml_pub) = derive_identity_public_keys(&c_ed, &c_ml).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_daemon"))
        .env("SYNTRIASS_OVERSOCKET_LISTEN", format!("127.0.0.1:{port}"))
        .env("SYNTRIASS_ED25519_SEED_HEX", hex(&s_ed))
        .env("SYNTRIASS_MLDSA65_SEED_HEX", hex(&s_ml))
        .env("SYNTRIASS_PEER_ED25519_PUB_HEX", hex(&c_ed_pub))
        .env("SYNTRIASS_PEER_MLDSA65_PUB_HEX", hex(&c_ml_pub))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon binary");
    let mut guard = ChildGuard(child);

    // Wait for the daemon to bind.
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "daemon never started listening");

    // Phase 1 (daemon up): concurrent handshakes complete across the live daemon.
    let id = client_identity();
    let mut ok = 0;
    for _ in 0..3 {
        if client_handshake(port, &id).await.is_ok() {
            ok += 1;
        }
    }
    assert!(ok >= 1, "no handshake completed while the daemon was alive");

    // Inject the fault: abruptly kill the control daemon mid-lifecycle.
    guard.0.kill().expect("kill daemon");
    let _ = guard.0.wait();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Phase 2 (daemon down): new connections fail closed -- no hang, no plaintext,
    // no degraded plaintext channel.
    let res = client_handshake(port, &id).await;
    assert!(
        res.is_err(),
        "with the daemon killed, the connection MUST fail closed, got {res:?}"
    );
}

#[test]
fn memory_starvation_keeps_traffic_encrypted() {
    // Bounded synthetic memory pressure (freed after) during a crypto operation.
    let mut hog = vec![0u8; 128 * 1024 * 1024];
    for i in (0..hog.len()).step_by(4096) {
        hog[i] = 1; // fault each page in
    }

    let psk = [0x9bu8; FALLBACK_PSK_LEN];
    let (cn, sn) = ([0x1u8; FALLBACK_NONCE_LEN], [0x2u8; FALLBACK_NONCE_LEN]);
    let mut c = derive_fallback_session(&psk, &cn, &sn, true).unwrap();
    let mut s = derive_fallback_session(&psk, &cn, &sn, false).unwrap();

    let ct = c.seal(MARKER).unwrap();
    assert!(
        !contains(&ct, MARKER),
        "no cleartext even under memory pressure"
    );
    assert_eq!(s.open(&ct).unwrap(), MARKER);

    drop(hog);
}

#[test]
fn ebpf_map_corruption_placeholder_is_noop() {
    // PLACEHOLDER: the eBPF OPERATION_MODE_FLAG map does not exist in this build
    // (we ship the encrypted fallback, not a plaintext Kinetic flag). "Corrupt" a
    // stand-in pinned path and confirm the posture logic -- driven by LOCAL
    // signals, never by this file -- is unaffected.
    let path = std::env::temp_dir().join("syntriass_OPERATION_MODE_FLAG");
    std::fs::write(&path, b"\xff\xff\xff\xff corrupted").unwrap();

    assert_eq!(select_posture(true, true), AvailabilityPosture::FullPqc);
    assert_eq!(
        select_posture(false, true),
        AvailabilityPosture::EncryptedFallback
    );
    assert_eq!(
        select_posture(false, false),
        AvailabilityPosture::FailClosed
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn control_plane_fallback_switchover_latency() {
    // Real control-plane Garrison(0x00) -> EncryptedFallback(0x01) extraction:
    // the posture decision plus the PSK key derivation a switch performs.
    let psk = [0x5au8; FALLBACK_PSK_LEN];
    let (cn, sn) = ([0x3u8; FALLBACK_NONCE_LEN], [0x4u8; FALLBACK_NONCE_LEN]);
    let iters: u128 = 2000;
    let (mut total, mut max) = (0u128, 0u128);
    for _ in 0..iters {
        let t = Instant::now();
        if select_posture(false, true) == AvailabilityPosture::EncryptedFallback {
            let _ = derive_fallback_session(&psk, &cn, &sn, true).unwrap();
        }
        let e = t.elapsed().as_nanos();
        total += e;
        if e > max {
            max = e;
        }
    }
    println!(
        "control-plane Garrison->EncryptedFallback decision+derive: mean {} ns, max {} ns ({iters} iters)",
        total / iters,
        max
    );
    println!("NOTE: control-plane number; the eBPF kernel data-plane switch is not implemented.");
    assert!(
        max < 5_000_000,
        "switchover decision+derive must stay well under 5 ms"
    );
}

#[tokio::test]
async fn fallback_emits_no_cleartext_across_the_wire() {
    // Establish the authenticated PSK fallback in-process...
    let psk = [0x77u8; FALLBACK_PSK_LEN];
    let (init, hello) = FallbackInitiator::begin(psk);
    let (mut server_keys, finished) = fallback::respond(&psk, &hello).unwrap();
    let mut client_keys = init.finish(&finished).unwrap();
    let record = client_keys.seal(MARKER).unwrap();

    // ...then ship the sealed record across a real loopback boundary through a
    // recording relay (the "wire tap" / virtual ethernet boundary).
    let srv = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv_addr = srv.local_addr().unwrap();
    let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut s, _) = srv.accept().await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        buf
    });

    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let cap = captured.clone();
    let relay_task = tokio::spawn(async move {
        let (a, _) = relay.accept().await.unwrap();
        let b = TcpStream::connect(srv_addr).await.unwrap();
        let (mut ar, _aw) = a.into_split();
        let (_br, mut bw) = b.into_split();
        let mut buf = [0u8; 4096];
        loop {
            let n = match ar.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            cap.lock().unwrap().extend_from_slice(&buf[..n]); // tap the wire
            if bw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = bw.shutdown().await;
    });

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    client.write_all(&record).await.unwrap();
    client.shutdown().await.unwrap();

    let on_wire = server.await.unwrap();
    relay_task.await.unwrap();
    let tapped = captured.lock().unwrap().clone();

    // The server decrypts to the marker; the wire never carries it in cleartext.
    assert_eq!(
        server_keys.open(&on_wire).unwrap(),
        MARKER,
        "server must decrypt the record"
    );
    assert!(
        !contains(&tapped, MARKER),
        "plaintext marker LEAKED across the boundary"
    );
    assert!(
        !tapped.is_empty(),
        "the relay must have observed (encrypted) bytes"
    );
}

#[test]
fn availability_posture_has_no_plaintext_variant() {
    // Exhaustive match with no wildcard: if a `Plaintext` variant were ever added,
    // this fails to compile (non-exhaustive) -- cleartext egress stays structurally
    // unrepresentable even under total infrastructure failure.
    for posture in [
        AvailabilityPosture::FullPqc,
        AvailabilityPosture::EncryptedFallback,
        AvailabilityPosture::FailClosed,
    ] {
        match posture {
            AvailabilityPosture::FullPqc
            | AvailabilityPosture::EncryptedFallback
            | AvailabilityPosture::FailClosed => {}
        }
    }
}
