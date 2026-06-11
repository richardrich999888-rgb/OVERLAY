//! Exhaustive concurrency model-checking (Loom) of the PQC-permit accounting.
//!
//! `tests/concurrency_stress.rs` stresses the real `HandshakeGuard` with OS
//! threads, which *samples* interleavings. Loom explores **every** reachable
//! interleaving of a model. The model here is the exact synchronization pattern
//! the production code uses (`handshake_guard::try_acquire_pqc` /
//! `release_pqc` under the daemon's single shared mutex): one lock guards an
//! in-flight counter; acquire = check `< CAP` then increment under one critical
//! section; release = saturating decrement.
//!
//! Two results:
//!   * the production pattern (check+increment inside ONE critical section)
//!     upholds `in_flight <= CAP` and drains to 0 in ALL interleavings;
//!   * a negative control shows the model has teeth: the broken TOCTOU variant
//!     (check in one critical section, increment in another) is CAUGHT by Loom
//!     — it finds an interleaving that exceeds the cap.
//!
//! Scope note (honest): this checks the permit-accounting *pattern* with Loom's
//! sync primitives, not the full `HandshakeGuard` struct (whose HMAC/RNG calls
//! are irrelevant to interleaving). The pattern is line-for-line the one in
//! `try_acquire_pqc`/`release_pqc` + the daemon's `Mutex` usage.

use loom::sync::{Arc, Mutex};
use loom::thread;

// Two contending threads against a cap of one fully exercises the mutual-
// exclusion property while keeping Loom's interleaving space small enough to
// explore exhaustively in seconds.
const CAP: u32 = 1;
const WORKERS: usize = 2;

/// The production pattern: check-and-increment in a single critical section.
fn try_acquire(counter: &Mutex<u32>) -> bool {
    let mut c = counter.lock().unwrap();
    if *c >= CAP {
        return false;
    }
    *c += 1;
    true
}

/// The production release: saturating decrement in its own critical section.
fn release(counter: &Mutex<u32>) {
    let mut c = counter.lock().unwrap();
    *c = c.saturating_sub(1);
}

#[test]
fn loom_cap_holds_in_all_interleavings() {
    loom::model(|| {
        let counter = Arc::new(Mutex::new(0u32));
        let max_seen = Arc::new(Mutex::new(0u32));

        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let counter = Arc::clone(&counter);
            let max_seen = Arc::clone(&max_seen);
            handles.push(thread::spawn(move || {
                if try_acquire(&counter) {
                    // Record the high-water mark while the permit is held.
                    {
                        let c = counter.lock().unwrap();
                        let mut m = max_seen.lock().unwrap();
                        if *c > *m {
                            *m = *c;
                        }
                        assert!(*c <= CAP, "cap exceeded: {} > {CAP}", *c);
                    }
                    release(&counter);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // After every thread finishes, all permits are returned...
        assert_eq!(*counter.lock().unwrap(), 0, "permits leaked");
        // ...and the cap was respected at every instant of every interleaving.
        assert!(*max_seen.lock().unwrap() <= CAP);
    });
}

#[test]
fn loom_release_is_saturating_in_all_interleavings() {
    loom::model(|| {
        let counter = Arc::new(Mutex::new(0u32));
        let mut handles = Vec::new();
        // Threads racing acquire/release with one spurious extra release: the
        // counter must never underflow (saturating), so accounting cannot wedge
        // the gate permanently open or panic.
        for i in 0..2 {
            let counter = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                if i == 0 {
                    release(&counter); // spurious release against an empty gate
                } else if try_acquire(&counter) {
                    release(&counter);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(*counter.lock().unwrap(), 0);
    });
}

/// Negative control: prove Loom actually detects the defect class. The broken
/// pattern checks the cap in one critical section and increments in another
/// (check-then-act across a lock release). Loom must FIND an interleaving where
/// the cap is exceeded — i.e. the assertion inside the model fails.
#[test]
fn loom_catches_the_broken_toctou_variant() {
    let found_violation = std::panic::catch_unwind(|| {
        loom::model(|| {
            let counter = Arc::new(Mutex::new(0u32));
            let mut handles = Vec::new();
            for _ in 0..WORKERS + 1 {
                let counter = Arc::clone(&counter);
                handles.push(thread::spawn(move || {
                    // BROKEN: the check and the increment are separate critical
                    // sections — another thread can interleave between them.
                    let under_cap = { *counter.lock().unwrap() < CAP };
                    if under_cap {
                        let mut c = counter.lock().unwrap();
                        *c += 1;
                        assert!(*c <= CAP, "TOCTOU: cap exceeded");
                    }
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
        });
    })
    .is_err();
    assert!(
        found_violation,
        "Loom failed to catch the broken TOCTOU variant — the model has no teeth"
    );
}
