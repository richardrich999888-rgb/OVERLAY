//! CR-2 — Fork-After-Connect AES-GCM Nonce Reuse: regression tests.
//!
//! Internal Security Hardening and Pre-Audit Remediation.
//!
//! These tests use a REAL `fork()` to prove that a forked child cannot reuse a
//! parent session's AES-GCM key/nonce state. The defence is the fork-aware
//! process token (`fd_state::current_process_token`, bumped by a `pthread_atfork`
//! child handler) plus `FdState::is_inherited`. We demonstrate both the *danger*
//! (an unguarded child seal reproduces the parent's nonce-0 ciphertext byte for
//! byte) and the *guard* (the child detects the session as inherited and a
//! correct overlay refuses to seal).
//!
//! The child path is deliberately minimal and ends in `libc::_exit` to avoid
//! running destructors/atexit in a post-fork, possibly-multi-threaded image.

use std::io::Read;

use syntriass_overlay::crypto::{
    derive_identity_public_keys, CipherSuite, IdentityMaterial, ED25519_SEED_LEN, MLDSA65_SEED_LEN,
};
use syntriass_overlay::fd_state::{current_process_token, FdState};

fn trusting_pair() -> (IdentityMaterial, IdentityMaterial) {
    let (ce, cm) = ([0x11u8; ED25519_SEED_LEN], [0x22u8; MLDSA65_SEED_LEN]);
    let (se, sm) = ([0x33u8; ED25519_SEED_LEN], [0x44u8; MLDSA65_SEED_LEN]);
    let (ce_pub, cm_pub) = derive_identity_public_keys(&ce, &cm).unwrap();
    let (se_pub, sm_pub) = derive_identity_public_keys(&se, &sm).unwrap();
    let client = IdentityMaterial::from_bytes(ce, cm, se_pub, sm_pub).unwrap();
    let server = IdentityMaterial::from_bytes(se, sm, ce_pub, cm_pub).unwrap();
    (client, server)
}

/// A real handshake; returns the client's established `SessionKeys`.
fn fresh_session() -> syntriass_overlay::crypto::SessionKeys {
    let (client, server) = trusting_pair();
    let engine = CipherSuite::NistStandard768.engine();
    let (state, ch) = engine.begin_initiator(&client).unwrap();
    let (_skeys, sh) = engine.respond(&server, &ch).unwrap();
    state.finish(&client, &sh).unwrap()
}

/// CORE PROOF: with a session established BEFORE fork, the parent and an
/// (unguarded) child would each seal the same plaintext at counter 0 and produce
/// IDENTICAL ciphertext — i.e. AES-GCM nonce reuse. We confirm that identity
/// (the danger is real) AND that the child independently detects the session as
/// inherited (the guard a correct overlay enforces), so it must refuse to seal.
#[test]
fn fork_after_connect_child_detects_inherited_and_would_reuse_nonce() {
    let mut keys = fresh_session();
    let parent_token = current_process_token(); // also registers the atfork handler

    // pipe: child -> parent (guard byte, ct len, ct bytes)
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (rd, wr) = (fds[0], fds[1]);

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        // ---- CHILD ----
        unsafe { libc::close(rd) };
        // The guard a correct overlay checks. After fork the token MUST differ.
        let inherited = (parent_token != current_process_token()) as u8;
        // Demonstration only: an *unguarded* seal here reuses counter 0 (the keys
        // were inherited pre-seal). A compliant overlay never reaches this.
        let ct = keys.seal(b"nonce-zero-plaintext").unwrap_or_default();
        let len = (ct.len() as u32).to_le_bytes();
        unsafe {
            libc::write(wr, [inherited].as_ptr() as *const libc::c_void, 1);
            libc::write(wr, len.as_ptr() as *const libc::c_void, 4);
            libc::write(wr, ct.as_ptr() as *const libc::c_void, ct.len());
            libc::close(wr);
            libc::_exit(0);
        }
    }

    // ---- PARENT ----
    unsafe { libc::close(wr) };
    let parent_ct = keys.seal(b"nonce-zero-plaintext").unwrap(); // counter 0

    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
    let mut hdr = [0u8; 5];
    f.read_exact(&mut hdr).unwrap();
    let inherited = hdr[0];
    let clen = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
    let mut child_ct = vec![0u8; clen];
    f.read_exact(&mut child_ct).unwrap();
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    // 1) The guard: the child detected the session as inherited (token bumped by
    //    the pthread_atfork handler). A compliant overlay therefore fails closed.
    assert_eq!(
        inherited, 1,
        "child MUST detect the inherited session (fork-aware token mismatch)"
    );
    // 2) The danger is real: had the child sealed (unguarded), it produced the
    //    SAME ciphertext as the parent's counter-0 seal — proof of (key,nonce)
    //    reuse that the guard exists to prevent.
    assert_eq!(
        child_ct, parent_ct,
        "unguarded child seal reproduced the parent's nonce-0 ciphertext (this is the averted GCM nonce reuse)"
    );
}

/// The guard via the real `FdState`: a responder state built in the parent reads
/// as inherited in the child and not in the parent.
#[test]
fn fdstate_is_inherited_across_real_fork() {
    let st = FdState::responder(CipherSuite::NistStandard768);
    let _ = current_process_token(); // ensure atfork handler is registered

    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(rd) };
        let b = [st.is_inherited() as u8];
        unsafe {
            libc::write(wr, b.as_ptr() as *const libc::c_void, 1);
            libc::close(wr);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(wr) };
    // Parent: the session it created is NOT inherited in the parent.
    assert!(
        !st.is_inherited(),
        "parent's own session must not read inherited"
    );
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
    let mut b = [0u8; 1];
    f.read_exact(&mut b).unwrap();
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        b[0], 1,
        "the SAME session must read as inherited in the child"
    );
}

/// Fork BEFORE connect: a child that creates its own session after fork has a
/// session that is valid in the child (its token matches) — fork-before-connect
/// is safe and does not falsely fail closed.
#[test]
fn fork_before_connect_child_session_is_usable() {
    let _ = current_process_token();
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe { libc::close(rd) };
        // Created AFTER fork in the child: token matches this process image.
        let st = FdState::responder(CipherSuite::NistStandard768);
        let ok = (!st.is_inherited()) as u8; // must be usable (not inherited)
        unsafe {
            libc::write(wr, [ok].as_ptr() as *const libc::c_void, 1);
            libc::close(wr);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(wr) };
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
    let mut b = [0u8; 1];
    f.read_exact(&mut b).unwrap();
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(
        b[0], 1,
        "a session created in the child AFTER fork must be usable (not inherited)"
    );
}

/// Multiple child processes: every child detects the parent's pre-fork session
/// as inherited; each child's token differs from the parent's.
#[test]
fn multiple_children_all_detect_inherited() {
    let st = FdState::responder(CipherSuite::NistStandard768);
    let _ = current_process_token();
    for _ in 0..4 {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::close(rd) };
            let b = [st.is_inherited() as u8];
            unsafe {
                libc::write(wr, b.as_ptr() as *const libc::c_void, 1);
                libc::close(wr);
                libc::_exit(0);
            }
        }
        unsafe { libc::close(wr) };
        let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
        let mut b = [0u8; 1];
        f.read_exact(&mut b).unwrap();
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            b[0], 1,
            "each forked child must detect the inherited session"
        );
    }
}

/// Concurrent session creation in the SAME process must never be misread as
/// inherited (the token is stable within a process image).
#[test]
fn concurrent_session_creation_not_flagged_inherited() {
    let _ = current_process_token();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                let st = FdState::responder(CipherSuite::NistStandard768);
                assert!(
                    !st.is_inherited(),
                    "a session created in a thread of THIS process must not read inherited"
                );
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
