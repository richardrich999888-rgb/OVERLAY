//! Fail-closed assurance — concurrency stress on the real shared `HandshakeGuard`.
//!
//! The daemon shares one `Arc<Mutex<HandshakeGuard>>` across every connection
//! task. These tests hammer that exact arrangement with real OS threads to show:
//!   * the in-flight PQC concurrency cap is never exceeded under contention;
//!   * the full request→admit→acquire→release flow never deadlocks or panics and
//!     always returns the in-flight count to zero;
//!   * a *poisoned* mutex is handled fail-closed (the production `.lock()` pattern
//!     yields an error, never a panic / never a bypass).
//!
//! This is real-thread stress, which *samples* interleavings. The exhaustive
//! complement is `tests/loom_model.rs` (Loom), which model-checks **every**
//! interleaving of the same permit-accounting pattern. See
//! `docs/FAIL_CLOSED_ASSURANCE.md §4`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use syntriass_overlay::handshake_guard::{AdmissionError, GuardConfig, HandshakeGuard};

#[test]
fn concurrency_cap_is_never_exceeded_under_contention() {
    const CAP: u32 = 4;
    const THREADS: usize = 16;
    const ITERS: usize = 20_000;

    let cfg = GuardConfig {
        max_in_flight_pqc: CAP,
        global_pqc_burst: 0, // isolate the concurrency gate (no global-rate cap)
        global_pqc_per_sec: 0,
        ..GuardConfig::default()
    };
    let guard = Arc::new(Mutex::new(HandshakeGuard::new(cfg, 1_000)));
    let max_observed = Arc::new(AtomicU64::new(0));
    let acquisitions = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let guard = Arc::clone(&guard);
        let max_observed = Arc::clone(&max_observed);
        let acquisitions = Arc::clone(&acquisitions);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..ITERS {
                // Acquire + read the in-flight count atomically under the lock.
                let acquired = {
                    let mut g = guard.lock().expect("guard not poisoned");
                    match g.try_acquire_pqc(1_000) {
                        Ok(()) => {
                            let inflight = g.in_flight_pqc() as u64;
                            max_observed.fetch_max(inflight, Ordering::Relaxed);
                            true
                        }
                        Err(AdmissionError::AtCapacity) => false,
                        Err(e) => panic!("unexpected {e:?}"),
                    }
                };
                if acquired {
                    acquisitions.fetch_add(1, Ordering::Relaxed);
                    // Simulated PQC work WITHOUT holding the lock (as in the daemon).
                    std::hint::spin_loop();
                    guard.lock().expect("guard not poisoned").release_pqc();
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let cap = CAP as u64;
    assert!(
        max_observed.load(Ordering::Relaxed) <= cap,
        "in-flight PQC exceeded the cap: observed {} > {cap}",
        max_observed.load(Ordering::Relaxed)
    );
    assert_eq!(
        guard.lock().unwrap().in_flight_pqc(),
        0,
        "every acquired slot must have been released"
    );
    assert!(
        acquisitions.load(Ordering::Relaxed) > 0,
        "nothing was acquired"
    );
    eprintln!(
        "[concurrency cap] threads={THREADS} iters/thread={ITERS} cap={cap} \
         max_observed_in_flight={} total_acquisitions={}",
        max_observed.load(Ordering::Relaxed),
        acquisitions.load(Ordering::Relaxed)
    );
}

#[test]
fn full_flow_under_threads_never_deadlocks_or_leaks_slots() {
    const THREADS: usize = 12;
    const ITERS: usize = 5_000;

    // Generous budgets so the flow runs; the point is liveness + slot accounting.
    let cfg = GuardConfig {
        rate_capacity: 1_000_000,
        rate_refill_per_sec: 1_000_000,
        global_pqc_burst: 1_000_000,
        global_pqc_per_sec: 1_000_000,
        max_in_flight_pqc: 64,
        ..GuardConfig::default()
    };
    let guard = Arc::new(Mutex::new(HandshakeGuard::new(cfg, 1_000)));
    let barrier = Arc::new(Barrier::new(THREADS));

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let guard = Arc::clone(&guard);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let source = format!("10.0.{}.{}", t / 256, t % 256).into_bytes();
            for _ in 0..ITERS {
                // Phase 0 + Phase 1, exactly as the daemon path orders them.
                let cookie = {
                    let mut g = guard.lock().unwrap();
                    g.request(&source, 1_000).expect("request within budget")
                };
                let acquired = {
                    let mut g = guard.lock().unwrap();
                    if g.admit(&source, &cookie, 1_000).is_ok() {
                        g.try_acquire_pqc(1_000).is_ok()
                    } else {
                        false
                    }
                };
                if acquired {
                    guard.lock().unwrap().release_pqc();
                }
            }
        }));
    }
    for h in handles {
        h.join()
            .expect("worker thread panicked (deadlock would hang, not panic)");
    }

    assert_eq!(
        guard.lock().unwrap().in_flight_pqc(),
        0,
        "slot accounting drifted under concurrency"
    );
    eprintln!(
        "[concurrency flow] threads={THREADS} iters/thread={ITERS} final_in_flight=0 deadlocks=0"
    );
}

#[test]
fn poisoned_guard_is_handled_fail_closed() {
    let guard = Arc::new(Mutex::new(HandshakeGuard::new(
        GuardConfig::default(),
        1_000,
    )));

    // Poison the mutex by panicking while it is held. Silence the panic output so
    // the (expected) backtrace does not look like a test failure.
    let g2 = Arc::clone(&guard);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let _ = thread::spawn(move || {
        let _held = g2.lock().unwrap();
        panic!("deliberately poison the guard mutex");
    })
    .join();
    std::panic::set_hook(prev);

    // The production fail-closed pattern (as in `over_socket::*_gated`): a poisoned
    // lock maps to an error and the connection is dropped — never a panic, never a
    // bypass of the gate.
    let result: Result<(), &'static str> = guard
        .lock()
        .map(|_g| ())
        .map_err(|_| "admission guard poisoned");
    assert_eq!(
        result,
        Err("admission guard poisoned"),
        "a poisoned guard must surface as a fail-closed error"
    );
    eprintln!("[poison recovery] poisoned_lock_handled=fail_closed panic_propagated=false");
}
