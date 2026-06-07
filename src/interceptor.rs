//! Syntriass overlay: an `LD_PRELOAD` shared object that transparently wraps a
//! POSIX stream socket in a hybrid X25519 + ML-KEM AEAD tunnel without the
//! application's knowledge. Linux only (glibc symbol interposition).
//!
//! ## Why both peers must run this
//! Encrypted, framed bytes go on the wire. The peer recovers plaintext only if
//! it ALSO loads this library. Symmetric overlay, not MITM of a remote server.
//!
//! ## Frame format (single, unambiguous, suite-aware)
//! ```text
//!   u32 big-endian  LENGTH of (suite_id + type + payload)
//!   u8              SUITE_ID  (0x01 = NIST-768, 0x02 = NIST-1024)
//!   u8              TYPE      (1=ClientHello, 2=ServerHello, 3=Data)
//!   [u8]            PAYLOAD
//! ```
//! One layout. The suite id is also folded into the HKDF key schedule, so a
//! tampered suite byte yields non-matching keys and the AEAD fails closed.
//!
//! ## Negotiation (fail closed, no downgrade)
//! Initiator proposes its policy-pinned suite. Responder accepts only if the
//! proposed suite equals its own policy suite; otherwise the session is dropped.
//! There is no legacy/no-PQC suite and no silent downgrade.
//!
//! ## Honest blocking I/O
//! Blocking fds (per `fcntl(F_GETFL)`) loop on the real `recv`/`send` until a
//! whole frame is available or the peer closes; no injected `EAGAIN`. On a
//! non-blocking fd, `EAGAIN`/`EWOULDBLOCK` are propagated truthfully.

use crate::crypto::{self, CipherSuite};
use crate::fd_state::{FdState, Phase, REGISTRY};
use libc::{c_int, c_void, size_t, ssize_t};
use once_cell::sync::OnceCell;
use std::ptr;

// ---- Frame constants ----
const HDR_LEN: usize = 4; // u32 length prefix
const TYPE_CLIENT_HELLO: u8 = 1;
const TYPE_SERVER_HELLO: u8 = 2;
const TYPE_DATA: u8 = 3;
/// Defensive cap on a single frame body (suite + type + payload). Fail closed.
const MAX_FRAME_BODY: usize = 1 << 20; // 1 MiB

// ---- Process-wide policy, resolved once at first use. ----
static POLICY: OnceCell<CipherSuite> = OnceCell::new();

/// Resolve the policy suite once. A malformed policy value falls back to the
/// safe default (NIST-768) rather than running unprotected; `resolve_policy`
/// only errors on an explicitly bad token, which we treat as "use default".
fn policy() -> Option<CipherSuite> {
    let suite = *POLICY
        .get_or_init(|| crypto::resolve_policy().unwrap_or(CipherSuite::NistStandard768));
    Some(suite)
}

// ---- Real libc symbols, resolved once via dlsym(RTLD_NEXT, ...). ----
type ConnectFn = unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t;
type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, size_t, c_int) -> ssize_t;

struct RealSyms {
    connect: ConnectFn,
    send: SendFn,
    recv: RecvFn,
}

static REAL: OnceCell<RealSyms> = OnceCell::new();

/// Resolve a symbol or abort: continuing without the real symbol would be unsafe.
unsafe fn resolve<T>(name: &[u8]) -> T {
    let p = libc::dlsym(libc::RTLD_NEXT, name.as_ptr() as *const libc::c_char);
    if p.is_null() {
        libc::abort();
    }
    std::mem::transmute_copy::<*mut c_void, T>(&p)
}

fn real() -> &'static RealSyms {
    REAL.get_or_init(|| unsafe {
        RealSyms {
            connect: resolve::<ConnectFn>(b"connect\0"),
            send: resolve::<SendFn>(b"send\0"),
            recv: resolve::<RecvFn>(b"recv\0"),
        }
    })
}

unsafe fn set_errno(err: c_int) {
    let p = libc::__errno_location();
    if !p.is_null() {
        *p = err;
    }
}

unsafe fn errno() -> c_int {
    let p = libc::__errno_location();
    if p.is_null() { 0 } else { *p }
}

/// True if the fd is in blocking mode (O_NONBLOCK clear).
unsafe fn is_blocking(fd: c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    flags >= 0 && (flags & libc::O_NONBLOCK) == 0
}

/// Encode a frame: u32_be(len(suite+type+payload)) || suite_id || type || payload.
fn frame(suite_id: u8, tag: u8, payload: &[u8]) -> Vec<u8> {
    let body_len = 2 + payload.len(); // suite_id + type + payload
    let mut out = Vec::with_capacity(HDR_LEN + body_len);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.push(suite_id);
    out.push(tag);
    out.extend_from_slice(payload);
    out
}

/// One parsed frame.
struct ParsedFrame {
    suite_id: u8,
    tag: u8,
    payload: Vec<u8>,
}

/// Try to pop one complete frame. Ok(None) = need more bytes. Err = malformed.
fn try_pop_frame(rx_wire: &mut Vec<u8>) -> Result<Option<ParsedFrame>, ()> {
    if rx_wire.len() < HDR_LEN {
        return Ok(None);
    }
    let mut len_bytes = [0u8; HDR_LEN];
    len_bytes.copy_from_slice(&rx_wire[0..HDR_LEN]);
    let body_len = u32::from_be_bytes(len_bytes) as usize;
    // Body must contain at least suite_id + type.
    if body_len < 2 || body_len > MAX_FRAME_BODY {
        return Err(());
    }
    if rx_wire.len() < HDR_LEN + body_len {
        return Ok(None);
    }
    let suite_id = rx_wire[HDR_LEN];
    let tag = rx_wire[HDR_LEN + 1];
    let payload = rx_wire[HDR_LEN + 2..HDR_LEN + body_len].to_vec();
    rx_wire.drain(0..HDR_LEN + body_len);
    Ok(Some(ParsedFrame { suite_id, tag, payload }))
}

/// Flush tx_backlog. Ok(true)=drained, Ok(false)=bytes remain, Err=hard error.
unsafe fn flush_backlog(fd: c_int, st: &mut FdState, flags: c_int) -> Result<bool, ()> {
    while !st.tx_backlog.is_empty() {
        let n = (real().send)(
            fd,
            st.tx_backlog.as_ptr() as *const c_void,
            st.tx_backlog.len(),
            flags,
        );
        if n > 0 {
            st.tx_backlog.drain(0..n as usize);
        } else if n == 0 {
            return Ok(false);
        } else {
            let e = errno();
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                return Ok(false);
            }
            return Err(());
        }
    }
    Ok(true)
}

/// Pull one chunk off the wire into rx_wire. Returns the real recv() return.
unsafe fn pull_wire(fd: c_int, st: &mut FdState, flags: c_int) -> ssize_t {
    let mut buf = [0u8; 8192];
    let n = (real().recv)(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), flags);
    if n > 0 {
        st.rx_wire.extend_from_slice(&buf[0..n as usize]);
    }
    n
}

/// Advance the handshake using whatever is in rx_wire. May enqueue a ServerHello.
/// Enforces suite negotiation: responder drops if the proposed suite != policy.
fn drive_handshake(st: &mut FdState) {
    loop {
        let f = match try_pop_frame(&mut st.rx_wire) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(()) => {
                st.phase = Phase::Failed;
                return;
            }
        };

        let current = std::mem::replace(&mut st.phase, Phase::Failed);
        match (current, f.tag) {
            (Phase::ResponderAwaitingClientHello, TYPE_CLIENT_HELLO) => {
                // Fail closed unless the proposed suite exactly matches policy.
                match CipherSuite::from_id(f.suite_id) {
                    Some(proposed) if proposed == st.policy_suite => {
                        let engine = proposed.engine();
                        match engine.respond(&f.payload) {
                            Ok((keys, server_hello_body)) => {
                                st.tx_backlog.extend_from_slice(&frame(
                                    proposed.id(),
                                    TYPE_SERVER_HELLO,
                                    &server_hello_body,
                                ));
                                st.phase = Phase::Active(keys);
                            }
                            Err(_) => st.phase = Phase::Failed,
                        }
                    }
                    // Unknown suite, or a suite our policy does not permit:
                    // drop the session. No downgrade, no negotiation second-guess.
                    _ => st.phase = Phase::Failed,
                }
            }
            (Phase::InitiatorAwaitingServerHello(state), TYPE_SERVER_HELLO) => {
                // The responder must have answered with the same suite we proposed.
                if f.suite_id != st.policy_suite.id() {
                    st.phase = Phase::Failed;
                } else {
                    match state.finish(&f.payload) {
                        Ok(keys) => st.phase = Phase::Active(keys),
                        Err(_) => st.phase = Phase::Failed,
                    }
                }
            }
            _ => st.phase = Phase::Failed,
        }

        if matches!(st.phase, Phase::Failed | Phase::Active(_)) {
            return;
        }
    }
}

// =================== Interposed symbols ===================

/// Hooked `connect`. On success we become the initiator and queue a ClientHello
/// for our policy-pinned suite.
#[no_mangle]
pub unsafe extern "C" fn connect(
    fd: c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> c_int {
    let res = (real().connect)(fd, addr, addrlen);
    if res == 0 {
        if let Some(suite) = policy() {
            let engine = suite.engine();
            let (state, hello_body) = engine.begin_initiator();
            let f = frame(suite.id(), TYPE_CLIENT_HELLO, &hello_body);
            let mut reg = REGISTRY.lock().unwrap();
            reg.insert(fd, FdState::initiator(suite, state, f));
        }
    }
    res
}

/// Hooked `send`. Drives the handshake to completion if needed, then frames and
/// encrypts the application payload. Returns the plaintext length on success.
#[no_mangle]
pub unsafe extern "C" fn send(
    fd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
) -> ssize_t {
    let mut reg = REGISTRY.lock().unwrap();
    if !reg.contains_key(&fd) {
        drop(reg);
        return (real().send)(fd, buf, len, flags);
    }
    let blocking = is_blocking(fd);
    let st = reg.get_mut(&fd).unwrap();

    if flush_backlog(fd, st, flags).is_err() {
        st.phase = Phase::Failed;
        set_errno(libc::EIO);
        return -1;
    }

    loop {
        match &st.phase {
            Phase::Active(_) => break,
            Phase::Failed => {
                set_errno(libc::EPIPE);
                return -1;
            }
            _ => {}
        }
        if !st.tx_backlog.is_empty() {
            match flush_backlog(fd, st, flags) {
                Ok(true) => {}
                Ok(false) if !blocking => {
                    set_errno(libc::EAGAIN);
                    return -1;
                }
                Ok(false) => continue,
                Err(()) => {
                    st.phase = Phase::Failed;
                    set_errno(libc::EIO);
                    return -1;
                }
            }
        }
        let n = pull_wire(fd, st, flags);
        if n == 0 {
            st.phase = Phase::Failed;
            set_errno(libc::EPIPE);
            return -1;
        }
        if n < 0 {
            let e = errno();
            if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && !blocking {
                return -1;
            }
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                continue;
            }
            st.phase = Phase::Failed;
            set_errno(e);
            return -1;
        }
        drive_handshake(st);
    }

    let plaintext = std::slice::from_raw_parts(buf as *const u8, len);
    let suite_id = st.policy_suite.id();
    if let Phase::Active(keys) = &mut st.phase {
        match keys.seal(plaintext) {
            Ok(ct) => st.tx_backlog.extend_from_slice(&frame(suite_id, TYPE_DATA, &ct)),
            Err(_) => {
                st.phase = Phase::Failed;
                set_errno(libc::EIO);
                return -1;
            }
        }
    }

    match flush_backlog(fd, st, flags) {
        Ok(true) => len as ssize_t,
        Ok(false) if blocking => loop {
            match flush_backlog(fd, st, flags) {
                Ok(true) => break len as ssize_t,
                Ok(false) => continue,
                Err(()) => {
                    st.phase = Phase::Failed;
                    set_errno(libc::EIO);
                    break -1;
                }
            }
        },
        Ok(false) => len as ssize_t, // record is buffered; app's bytes are owned
        Err(()) => {
            st.phase = Phase::Failed;
            set_errno(libc::EIO);
            -1
        }
    }
}

/// Hooked `recv`. Responder initializes here on first contact. Reassembles
/// frames, drives the handshake, decrypts Data frames, returns plaintext.
#[no_mangle]
pub unsafe extern "C" fn recv(
    fd: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
) -> ssize_t {
    let mut reg = REGISTRY.lock().unwrap();

    if !reg.contains_key(&fd) {
        // Only adopt connected stream sockets, and only if policy resolved.
        let mut stype: c_int = 0;
        let mut slen = std::mem::size_of::<c_int>() as libc::socklen_t;
        let ok = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut stype as *mut _ as *mut c_void,
            &mut slen,
        );
        match (ok, policy()) {
            (0, Some(suite)) if stype == libc::SOCK_STREAM => {
                reg.insert(fd, FdState::responder(suite));
            }
            _ => {
                drop(reg);
                return (real().recv)(fd, buf, len, flags);
            }
        }
    }

    let blocking = is_blocking(fd);
    let st = reg.get_mut(&fd).unwrap();

    loop {
        if !st.rx_plain.is_empty() {
            let amt = std::cmp::min(len, st.rx_plain.len());
            let chunk: Vec<u8> = st.rx_plain.drain(0..amt).collect();
            ptr::copy_nonoverlapping(chunk.as_ptr(), buf as *mut u8, amt);
            return amt as ssize_t;
        }

        if !matches!(st.phase, Phase::Active(_) | Phase::Failed) {
            let _ = flush_backlog(fd, st, flags);
            drive_handshake(st);
            let _ = flush_backlog(fd, st, flags);
        }

        if matches!(st.phase, Phase::Failed) {
            set_errno(libc::EPIPE);
            return -1;
        }

        if matches!(st.phase, Phase::Active(_)) {
            loop {
                match try_pop_frame(&mut st.rx_wire) {
                    Ok(Some(f)) if f.tag == TYPE_DATA => {
                        // A data frame must carry our negotiated suite id.
                        if f.suite_id != st.policy_suite.id() {
                            st.phase = Phase::Failed;
                            set_errno(libc::EPIPE);
                            return -1;
                        }
                        if let Phase::Active(keys) = &mut st.phase {
                            match keys.open(&f.payload) {
                                Ok(pt) => st.rx_plain.extend_from_slice(&pt),
                                Err(_) => {
                                    st.phase = Phase::Failed;
                                    set_errno(libc::EPIPE);
                                    return -1;
                                }
                            }
                        }
                    }
                    Ok(Some(_)) => {
                        st.phase = Phase::Failed;
                        set_errno(libc::EPIPE);
                        return -1;
                    }
                    Ok(None) => break,
                    Err(()) => {
                        st.phase = Phase::Failed;
                        set_errno(libc::EPIPE);
                        return -1;
                    }
                }
            }
            if !st.rx_plain.is_empty() {
                continue;
            }
        }

        let n = pull_wire(fd, st, flags);
        if n == 0 {
            if st.rx_plain.is_empty() {
                return 0;
            }
            continue;
        }
        if n < 0 {
            let e = errno();
            if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && !blocking {
                return -1;
            }
            if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && blocking {
                continue;
            }
            return -1;
        }
    }
}
