//! Linux/glibc symbol interposition for the Syntriass overlay.
//!
//! Every intercepted stream-socket write path routes plaintext through the same
//! authenticated, encrypted record pipeline. Unknown stream sockets are adopted
//! as responders and must complete the overlay handshake before application data
//! can move. If policy or identity material is missing, the fd is tracked as
//! failed so later I/O returns an error instead of leaking plaintext.

use crate::crypto::{self, CipherSuite};
use crate::fd_state::{
    current_pid, record_blocked_bypass_attempt, FdPhase, FdState, MAX_WIRE_RX_BUFFER, REGISTRY,
};
#[cfg(target_os = "linux")]
use libc::c_uint;
use libc::{c_int, c_void, iovec, msghdr, size_t, ssize_t};
use once_cell::sync::{Lazy, OnceCell};
use std::collections::HashMap;
use std::panic::{self, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};
use std::{cmp, ptr, slice};
use zeroize::Zeroize;

const HDR_LEN: usize = 4;
const TYPE_CLIENT_HELLO: u8 = 1;
const TYPE_SERVER_HELLO: u8 = 2;
const TYPE_DATA: u8 = 3;
const MAX_FRAME_BODY: usize = MAX_WIRE_RX_BUFFER - HDR_LEN;
const MAX_RECORD_PLAINTEXT: usize = 64 * 1024;
const MAX_IOV_COPY: usize = 16 * 1024 * 1024;

fn policy() -> Result<CipherSuite, ()> {
    crypto::resolve_policy().map_err(|_| ())
}

fn failed_policy_suite() -> CipherSuite {
    policy().unwrap_or(CipherSuite::NistStandard768)
}

fn ffi_guard_c_int(f: impl FnOnce() -> c_int) -> c_int {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => unsafe {
            set_errno(libc::EIO);
            -1
        },
    }
}

fn ffi_guard_ssize(f: impl FnOnce() -> ssize_t) -> ssize_t {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => unsafe {
            set_errno(libc::EIO);
            -1
        },
    }
}

#[cfg(target_os = "linux")]
fn msg_iovlen_to_usize(len: size_t) -> usize {
    len
}

#[cfg(not(target_os = "linux"))]
fn msg_iovlen_to_usize(len: c_int) -> usize {
    len as usize
}

type ConnectFn = unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t;
type SendtoFn = unsafe extern "C" fn(
    c_int,
    *const c_void,
    size_t,
    c_int,
    *const libc::sockaddr,
    libc::socklen_t,
) -> ssize_t;
type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, size_t, c_int) -> ssize_t;
type WriteFn = unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t;
type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t;
type WritevFn = unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t;
type ReadvFn = unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t;
type SendmsgFn = unsafe extern "C" fn(c_int, *const msghdr, c_int) -> ssize_t;
type RecvmsgFn = unsafe extern "C" fn(c_int, *mut msghdr, c_int) -> ssize_t;
#[cfg(target_os = "linux")]
type SendmmsgFn = unsafe extern "C" fn(c_int, *mut libc::mmsghdr, c_uint, c_int) -> c_int;
#[cfg(target_os = "linux")]
type SendfileFn = unsafe extern "C" fn(c_int, c_int, *mut libc::off_t, size_t) -> ssize_t;
#[cfg(target_os = "linux")]
type Sendfile64Fn = unsafe extern "C" fn(c_int, c_int, *mut libc::off64_t, size_t) -> ssize_t;
#[cfg(target_os = "linux")]
type SpliceFn = unsafe extern "C" fn(
    c_int,
    *mut libc::loff_t,
    c_int,
    *mut libc::loff_t,
    size_t,
    c_uint,
) -> ssize_t;
type CloseFn = unsafe extern "C" fn(c_int) -> c_int;

struct RealSyms {
    connect: ConnectFn,
    send: SendFn,
    sendto: SendtoFn,
    recv: RecvFn,
    write: WriteFn,
    read: ReadFn,
    writev: WritevFn,
    readv: ReadvFn,
    sendmsg: SendmsgFn,
    recvmsg: RecvmsgFn,
    #[cfg(target_os = "linux")]
    sendmmsg: SendmmsgFn,
    #[cfg(target_os = "linux")]
    sendfile: SendfileFn,
    #[cfg(target_os = "linux")]
    sendfile64: Sendfile64Fn,
    #[cfg(target_os = "linux")]
    splice: SpliceFn,
    close: CloseFn,
}

static REAL: OnceCell<RealSyms> = OnceCell::new();
static INTERPOSITION_ENABLED: Lazy<bool> = Lazy::new(|| {
    let Ok(preload) = std::env::var("LD_PRELOAD") else {
        return false;
    };
    preload
        .split([':', ' '])
        .any(|entry| entry.contains("syntriass_overlay") || entry.contains("syntriass-overlay"))
});

fn interposition_enabled() -> bool {
    *INTERPOSITION_ENABLED
}

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
            sendto: resolve::<SendtoFn>(b"sendto\0"),
            recv: resolve::<RecvFn>(b"recv\0"),
            write: resolve::<WriteFn>(b"write\0"),
            read: resolve::<ReadFn>(b"read\0"),
            writev: resolve::<WritevFn>(b"writev\0"),
            readv: resolve::<ReadvFn>(b"readv\0"),
            sendmsg: resolve::<SendmsgFn>(b"sendmsg\0"),
            recvmsg: resolve::<RecvmsgFn>(b"recvmsg\0"),
            #[cfg(target_os = "linux")]
            sendmmsg: resolve::<SendmmsgFn>(b"sendmmsg\0"),
            #[cfg(target_os = "linux")]
            sendfile: resolve::<SendfileFn>(b"sendfile\0"),
            #[cfg(target_os = "linux")]
            sendfile64: resolve::<Sendfile64Fn>(b"sendfile64\0"),
            #[cfg(target_os = "linux")]
            splice: resolve::<SpliceFn>(b"splice\0"),
            close: resolve::<CloseFn>(b"close\0"),
        }
    })
}

unsafe fn errno_location() -> *mut c_int {
    #[cfg(target_os = "linux")]
    {
        libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    {
        libc::__error()
    }
}

unsafe fn set_errno(err: c_int) {
    let p = errno_location();
    if !p.is_null() {
        *p = err;
    }
}

unsafe fn errno() -> c_int {
    let p = errno_location();
    if p.is_null() {
        0
    } else {
        *p
    }
}

unsafe fn is_blocking(fd: c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    flags >= 0 && (flags & libc::O_NONBLOCK) == 0
}

unsafe fn is_stream_socket(fd: c_int) -> bool {
    let mut stype: c_int = 0;
    let mut slen = std::mem::size_of::<c_int>() as libc::socklen_t;
    let ok = libc::getsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        &mut stype as *mut _ as *mut c_void,
        &mut slen,
    );
    ok == 0 && stype == libc::SOCK_STREAM
}

unsafe fn block_stream_egress(fd: c_int) -> bool {
    if is_stream_socket(fd) {
        record_blocked_bypass_attempt();
        set_errno(libc::EOPNOTSUPP);
        return true;
    }
    false
}

fn frame(suite_id: u8, tag: u8, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let body_len = 2usize.checked_add(payload.len()).ok_or(())?;
    if body_len > MAX_FRAME_BODY {
        return Err(());
    }
    let mut out = Vec::with_capacity(HDR_LEN + body_len);
    out.extend_from_slice(&(body_len as u32).to_be_bytes());
    out.push(suite_id);
    out.push(tag);
    out.extend_from_slice(payload);
    Ok(out)
}

struct ParsedFrame {
    suite_id: u8,
    tag: u8,
    payload: Vec<u8>,
}

fn try_pop_frame(rx_wire: &mut Vec<u8>) -> Result<Option<ParsedFrame>, ()> {
    if rx_wire.len() < HDR_LEN {
        return Ok(None);
    }
    let mut len_bytes = [0u8; HDR_LEN];
    len_bytes.copy_from_slice(&rx_wire[..HDR_LEN]);
    let body_len = u32::from_be_bytes(len_bytes) as usize;
    if !(2..=MAX_FRAME_BODY).contains(&body_len) {
        return Err(());
    }
    if rx_wire.len() < HDR_LEN + body_len {
        return Ok(None);
    }
    let suite_id = rx_wire[HDR_LEN];
    let tag = rx_wire[HDR_LEN + 1];
    let payload = rx_wire[HDR_LEN + 2..HDR_LEN + body_len].to_vec();
    rx_wire[..HDR_LEN + body_len].zeroize();
    rx_wire.drain(0..HDR_LEN + body_len);
    Ok(Some(ParsedFrame {
        suite_id,
        tag,
        payload,
    }))
}

unsafe fn flush_backlog(fd: c_int, st: &mut FdState, flags: c_int) -> Result<bool, ()> {
    while !st.tx_backlog.is_empty() {
        let n = (real().send)(
            fd,
            st.tx_backlog.as_ptr() as *const c_void,
            st.tx_backlog.len(),
            flags,
        );
        match n.cmp(&0) {
            cmp::Ordering::Greater => {
                let sent = n as usize;
                st.tx_backlog[..sent].zeroize();
                st.tx_backlog.drain(0..sent);
            }
            cmp::Ordering::Equal => return Ok(false),
            cmp::Ordering::Less => {
                let e = errno();
                if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                    return Ok(false);
                }
                return Err(());
            }
        }
    }
    Ok(true)
}

unsafe fn pull_wire(fd: c_int, st: &mut FdState, flags: c_int) -> Result<ssize_t, ()> {
    let mut buf = [0u8; 8192];
    let n = (real().recv)(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), flags);
    if n > 0 {
        st.append_rx_wire(&buf[..n as usize]).map_err(|_| ())?;
    }
    buf.zeroize();
    Ok(n)
}

fn queue_frame(st: &mut FdState, suite_id: u8, tag: u8, payload: &[u8]) -> Result<(), ()> {
    let mut f = frame(suite_id, tag, payload)?;
    let res = st.append_tx(&f).map_err(|_| ());
    f.zeroize();
    res
}

fn drive_handshake(st: &mut FdState) {
    loop {
        let f = match try_pop_frame(&mut st.rx_wire) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(()) => {
                st.fail_closed();
                return;
            }
        };

        let current = std::mem::replace(&mut st.phase, FdPhase::Failed);
        match (current, f.tag) {
            (FdPhase::ResponderAwaitingClientHello, TYPE_CLIENT_HELLO) => {
                let proposed = CipherSuite::from_id(f.suite_id);
                match (proposed, crypto::resolve_identity()) {
                    (Some(proposed), Ok(identity)) if proposed == st.policy_suite => {
                        let engine = proposed.engine();
                        match engine.respond(&identity, &f.payload) {
                            Ok((keys, server_hello_body)) => {
                                if queue_frame(
                                    st,
                                    proposed.id(),
                                    TYPE_SERVER_HELLO,
                                    &server_hello_body,
                                )
                                .is_ok()
                                {
                                    st.activate(keys);
                                } else {
                                    st.fail_closed();
                                }
                            }
                            Err(_) => st.fail_closed(),
                        }
                    }
                    _ => st.fail_closed(),
                }
            }
            (FdPhase::InitiatorAwaitingServerHello(state), TYPE_SERVER_HELLO) => {
                match crypto::resolve_identity() {
                    Ok(identity) if f.suite_id == st.policy_suite.id() => {
                        match state.finish(&identity, &f.payload) {
                            Ok(keys) => st.activate(keys),
                            Err(_) => st.fail_closed(),
                        }
                    }
                    _ => st.fail_closed(),
                }
            }
            _ => st.fail_closed(),
        }

        if matches!(st.phase, FdPhase::Failed | FdPhase::Active(_)) {
            return;
        }
    }
}

/// Clone the per-fd `Arc` out of the registry under the *global* lock, then drop
/// the registry guard. The returned `Arc` outlives the global lock; the caller
/// takes the per-fd lock only after this function has returned, so no registry
/// guard is ever alive at the point of a per-fd `.lock()`.
/// Lock the global registry, recovering from poisoning instead of panicking.
/// If a previous thread panicked while holding this lock (now caught by an FFI
/// shield), the map itself is structurally intact, so taking the inner guard
/// keeps every *other* connection working rather than wedging the whole overlay.
fn lock_registry() -> MutexGuard<'static, HashMap<i32, Arc<Mutex<FdState>>>> {
    match REGISTRY.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn lookup(fd: c_int) -> Option<Arc<Mutex<FdState>>> {
    let reg = lock_registry();
    reg.get(&fd).cloned()
}

unsafe fn ensure_tracked(fd: c_int) -> bool {
    {
        let reg = lock_registry();
        if reg.contains_key(&fd) {
            return true;
        }
    }
    if !is_stream_socket(fd) {
        return false;
    }
    let suite = failed_policy_suite();
    let mut reg = lock_registry();
    reg.entry(fd).or_insert_with(|| {
        Arc::new(Mutex::new(match policy() {
            Ok(suite) => FdState::responder(suite),
            Err(()) => FdState::failed(suite),
        }))
    });
    true
}

unsafe fn install_initiator_state(fd: c_int) {
    let suite_for_failure = failed_policy_suite();
    // All crypto runs before the global lock is taken; no I/O under the lock.
    let state = match (policy(), crypto::resolve_identity()) {
        (Ok(suite), Ok(identity)) => {
            let engine = suite.engine();
            match engine.begin_initiator(&identity) {
                Ok((state, hello_body)) => {
                    match frame(suite.id(), TYPE_CLIENT_HELLO, &hello_body) {
                        Ok(f) => FdState::initiator(suite, state, f),
                        Err(()) => FdState::failed(suite),
                    }
                }
                Err(_) => FdState::failed(suite),
            }
        }
        _ => FdState::failed(suite_for_failure),
    };
    let mut reg = lock_registry();
    reg.insert(fd, Arc::new(Mutex::new(state)));
}

unsafe fn drive_until_active_for_write(
    fd: c_int,
    st: &mut FdState,
    flags: c_int,
    blocking: bool,
) -> Result<(), c_int> {
    if flush_backlog(fd, st, flags).is_err() {
        st.fail_closed();
        return Err(libc::EIO);
    }
    loop {
        match &st.phase {
            FdPhase::Active(_) => return Ok(()),
            FdPhase::Failed => return Err(libc::EPIPE),
            _ => {}
        }
        if !st.tx_backlog.is_empty() {
            match flush_backlog(fd, st, flags) {
                Ok(true) => {}
                Ok(false) if !blocking => return Err(libc::EAGAIN),
                Ok(false) => continue,
                Err(()) => {
                    st.fail_closed();
                    return Err(libc::EIO);
                }
            }
        }
        match pull_wire(fd, st, flags) {
            Ok(0) => {
                st.fail_closed();
                return Err(libc::EPIPE);
            }
            Ok(n) if n > 0 => drive_handshake(st),
            Ok(_) => {
                let e = errno();
                if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && !blocking {
                    return Err(e);
                }
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK {
                    st.fail_closed();
                    return Err(e);
                }
            }
            Err(()) => {
                st.fail_closed();
                return Err(libc::EPIPE);
            }
        }
    }
}

unsafe fn append_or_flush(
    fd: c_int,
    st: &mut FdState,
    bytes: &[u8],
    flags: c_int,
    blocking: bool,
) -> Result<(), c_int> {
    if st.append_tx(bytes).is_ok() {
        return Ok(());
    }
    match flush_backlog(fd, st, flags) {
        Ok(true) => {}
        Ok(false) if !blocking => return Err(libc::EAGAIN),
        Ok(false) => {}
        Err(()) => {
            st.fail_closed();
            return Err(libc::EIO);
        }
    }
    st.append_tx(bytes).map_err(|_| libc::EMSGSIZE)
}

unsafe fn overlay_send(fd: c_int, plaintext: &[u8], flags: c_int) -> ssize_t {
    let Some(state) = lookup(fd) else {
        set_errno(libc::EBADF);
        return -1;
    };
    // Per-fd lock taken exactly once here; the global registry lock is already
    // released (dropped inside `lookup`). All blocking I/O below runs under this
    // single guard and never re-locks this mutex on this thread.
    // std `Mutex` is non-reentrant; we never re-lock it on this thread. On
    // poisoning (a panic caught by the FFI shield mid-I/O) we fail this one
    // connection closed with EIO; with `panic = "unwind"` the host stays up.
    let mut st_guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            // Per-fd state may be mid-mutation; fail this connection closed
            // rather than act on possibly-inconsistent state. Host stays up.
            set_errno(libc::EIO);
            return -1;
        }
    };
    let st = &mut *st_guard;
    if inherited_after_fork(st) {
        set_errno(libc::EPIPE);
        return -1;
    }
    if st.fail_if_stale_idle_config() {
        set_errno(libc::EPIPE);
        return -1;
    }
    let blocking = is_blocking(fd);
    if let Err(e) = drive_until_active_for_write(fd, st, flags, blocking) {
        set_errno(e);
        return -1;
    }
    if plaintext.is_empty() {
        return 0;
    }

    let suite_id = st.policy_suite.id();
    let mut offset = 0usize;
    while offset < plaintext.len() {
        let end = cmp::min(offset + MAX_RECORD_PLAINTEXT, plaintext.len());
        let ct = match &mut st.phase {
            FdPhase::Active(keys) => match keys.seal(&plaintext[offset..end]) {
                Ok(ct) => ct,
                Err(_) => {
                    st.fail_closed();
                    set_errno(libc::EIO);
                    return -1;
                }
            },
            _ => {
                st.fail_closed();
                set_errno(libc::EPIPE);
                return -1;
            }
        };
        let mut f = match frame(suite_id, TYPE_DATA, &ct) {
            Ok(f) => f,
            Err(()) => {
                st.fail_closed();
                set_errno(libc::EMSGSIZE);
                return -1;
            }
        };
        if let Err(e) = append_or_flush(fd, st, &f, flags, blocking) {
            f.zeroize();
            st.fail_closed();
            set_errno(e);
            return -1;
        }
        f.zeroize();
        offset = end;
    }

    match flush_backlog(fd, st, flags) {
        Ok(true) => plaintext.len() as ssize_t,
        Ok(false) if !blocking => plaintext.len() as ssize_t,
        Ok(false) => loop {
            match flush_backlog(fd, st, flags) {
                Ok(true) => break plaintext.len() as ssize_t,
                Ok(false) => continue,
                Err(()) => {
                    st.fail_closed();
                    set_errno(libc::EIO);
                    break -1;
                }
            }
        },
        Err(()) => {
            st.fail_closed();
            set_errno(libc::EIO);
            -1
        }
    }
}

unsafe fn copy_plaintext_to_app(st: &mut FdState, buf: *mut c_void, len: size_t) -> ssize_t {
    let amt = cmp::min(len, st.rx_plain.len());
    ptr::copy_nonoverlapping(st.rx_plain.as_ptr(), buf as *mut u8, amt);
    st.rx_plain[..amt].zeroize();
    st.rx_plain.drain(0..amt);
    amt as ssize_t
}

unsafe fn overlay_recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    if len == 0 {
        return 0;
    }
    if buf.is_null() {
        set_errno(libc::EFAULT);
        return -1;
    }
    let Some(state) = lookup(fd) else {
        set_errno(libc::EBADF);
        return -1;
    };
    // Per-fd lock taken exactly once here; the global registry lock is already
    // released (dropped inside `lookup`). All blocking I/O below runs under this
    // single guard and never re-locks this mutex on this thread.
    // std `Mutex` is non-reentrant; we never re-lock it on this thread. On
    // poisoning (a panic caught by the FFI shield mid-I/O) we fail this one
    // connection closed with EIO; with `panic = "unwind"` the host stays up.
    let mut st_guard = match state.lock() {
        Ok(g) => g,
        Err(_) => {
            // Per-fd state may be mid-mutation; fail this connection closed
            // rather than act on possibly-inconsistent state. Host stays up.
            set_errno(libc::EIO);
            return -1;
        }
    };
    let st = &mut *st_guard;
    if inherited_after_fork(st) {
        set_errno(libc::EPIPE);
        return -1;
    }
    if st.fail_if_stale_idle_config() {
        set_errno(libc::EPIPE);
        return -1;
    }
    let blocking = is_blocking(fd);

    loop {
        if !st.rx_plain.is_empty() {
            return copy_plaintext_to_app(st, buf, len);
        }

        if !matches!(st.phase, FdPhase::Active(_) | FdPhase::Failed) {
            let _ = flush_backlog(fd, st, flags);
            drive_handshake(st);
            let _ = flush_backlog(fd, st, flags);
        }

        if matches!(st.phase, FdPhase::Failed) {
            set_errno(libc::EPIPE);
            return -1;
        }

        if matches!(st.phase, FdPhase::Active(_)) {
            loop {
                match try_pop_frame(&mut st.rx_wire) {
                    Ok(Some(f)) if f.tag == TYPE_DATA => {
                        if f.suite_id != st.policy_suite.id() {
                            st.fail_closed();
                            set_errno(libc::EPIPE);
                            return -1;
                        }
                        if let FdPhase::Active(keys) = &mut st.phase {
                            match keys.open(&f.payload) {
                                Ok(mut pt) => {
                                    if st.append_rx_plain(&pt).is_err() {
                                        pt.zeroize();
                                        st.fail_closed();
                                        set_errno(libc::EPIPE);
                                        return -1;
                                    }
                                    pt.zeroize();
                                }
                                Err(_) => {
                                    st.fail_closed();
                                    set_errno(libc::EPIPE);
                                    return -1;
                                }
                            }
                        }
                    }
                    Ok(Some(_)) => {
                        st.fail_closed();
                        set_errno(libc::EPIPE);
                        return -1;
                    }
                    Ok(None) => break,
                    Err(()) => {
                        st.fail_closed();
                        set_errno(libc::EPIPE);
                        return -1;
                    }
                }
            }
            if !st.rx_plain.is_empty() {
                continue;
            }
        }

        match pull_wire(fd, st, flags) {
            Ok(0) => return 0,
            Ok(n) if n > 0 => continue,
            Ok(_) => {
                let e = errno();
                if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && !blocking {
                    return -1;
                }
                if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && blocking {
                    continue;
                }
                return -1;
            }
            Err(()) => {
                st.fail_closed();
                set_errno(libc::EPIPE);
                return -1;
            }
        }
    }
}

fn inherited_after_fork(st: &mut FdState) -> bool {
    if st.owner_pid == current_pid() {
        return false;
    }
    st.fail_closed();
    true
}

unsafe fn input_slice<'a>(buf: *const c_void, len: size_t) -> Result<&'a [u8], c_int> {
    if len == 0 {
        return Ok(&[]);
    }
    if buf.is_null() {
        return Err(libc::EFAULT);
    }
    Ok(slice::from_raw_parts(buf as *const u8, len))
}

unsafe fn iov_total(iov: *const iovec, iovcnt: usize) -> Result<usize, c_int> {
    if iovcnt == 0 {
        return Ok(0);
    }
    if iov.is_null() {
        return Err(libc::EFAULT);
    }
    let iovs = slice::from_raw_parts(iov, iovcnt);
    let mut total = 0usize;
    for item in iovs {
        total = total.checked_add(item.iov_len).ok_or(libc::EMSGSIZE)?;
        if total > MAX_IOV_COPY {
            return Err(libc::EMSGSIZE);
        }
    }
    Ok(total)
}

unsafe fn gather_iov(iov: *const iovec, iovcnt: usize) -> Result<Vec<u8>, c_int> {
    let total = iov_total(iov, iovcnt)?;
    let mut out = Vec::with_capacity(total);
    let iovs = if iovcnt == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(iov, iovcnt)
    };
    for item in iovs {
        if item.iov_len > 0 && item.iov_base.is_null() {
            out.zeroize();
            return Err(libc::EFAULT);
        }
        let bytes = slice::from_raw_parts(item.iov_base as *const u8, item.iov_len);
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

unsafe fn scatter_iov(iov: *const iovec, iovcnt: usize, data: &[u8]) -> Result<(), c_int> {
    if data.is_empty() {
        return Ok(());
    }
    if iov.is_null() {
        return Err(libc::EFAULT);
    }
    let iovs = slice::from_raw_parts(iov, iovcnt);
    let mut copied = 0usize;
    for item in iovs {
        if copied == data.len() {
            break;
        }
        if item.iov_len > 0 && item.iov_base.is_null() {
            return Err(libc::EFAULT);
        }
        let amt = cmp::min(item.iov_len, data.len() - copied);
        ptr::copy_nonoverlapping(data[copied..].as_ptr(), item.iov_base as *mut u8, amt);
        copied += amt;
    }
    Ok(())
}

unsafe fn overlay_write_iov(fd: c_int, iov: *const iovec, iovcnt: usize, flags: c_int) -> ssize_t {
    let mut data = match gather_iov(iov, iovcnt) {
        Ok(data) => data,
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    let n = overlay_send(fd, &data, flags);
    data.zeroize();
    n
}

unsafe fn overlay_read_iov(fd: c_int, iov: *const iovec, iovcnt: usize, flags: c_int) -> ssize_t {
    let total = match iov_total(iov, iovcnt) {
        Ok(total) => cmp::min(total, MAX_IOV_COPY),
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    if total == 0 {
        return 0;
    }
    let mut tmp = vec![0u8; total];
    let n = overlay_recv(fd, tmp.as_mut_ptr() as *mut c_void, tmp.len(), flags);
    if n > 0 {
        if let Err(e) = scatter_iov(iov, iovcnt, &tmp[..n as usize]) {
            tmp.zeroize();
            set_errno(e);
            return -1;
        }
    }
    tmp.zeroize();
    n
}

#[no_mangle]
/// Interposes libc `connect(2)`.
///
/// # Safety
/// Called by the dynamic loader with the same raw pointers and fd contract as
/// libc `connect`; `addr` must be valid for `addrlen` when libc would require it.
pub unsafe extern "C" fn connect(
    fd: c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> c_int {
    ffi_guard_c_int(|| {
        if !interposition_enabled() {
            return (real().connect)(fd, addr, addrlen);
        }
        let res = (real().connect)(fd, addr, addrlen);
        let saved_errno = if res < 0 { errno() } else { 0 };
        if res == 0 || (res < 0 && saved_errno == libc::EINPROGRESS) {
            install_initiator_state(fd);
        }
        if res < 0 {
            set_errno(saved_errno);
        }
        res
    })
}

#[no_mangle]
/// Interposes libc `send(2)`.
///
/// # Safety
/// `buf` must be valid for `len` bytes under the normal libc `send` contract.
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().send)(fd, buf, len, flags);
        }
        if !ensure_tracked(fd) {
            return (real().send)(fd, buf, len, flags);
        }
        let plaintext = match input_slice(buf, len) {
            Ok(s) => s,
            Err(e) => {
                set_errno(e);
                return -1;
            }
        };
        overlay_send(fd, plaintext, flags)
    })
}

#[no_mangle]
/// Interposes libc `sendto(2)`.
///
/// # Safety
/// Raw pointers must satisfy libc `sendto`'s contract. Stream sockets are
/// fail-closed because `sendto` cannot preserve overlay framing/encryption
/// semantics.
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().sendto)(fd, buf, len, flags, addr, addrlen);
        }
        if block_stream_egress(fd) {
            return -1;
        }
        (real().sendto)(fd, buf, len, flags, addr, addrlen)
    })
}

#[no_mangle]
/// Interposes libc `recv(2)`.
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes under the normal libc `recv`
/// contract.
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().recv)(fd, buf, len, flags);
        }
        if !ensure_tracked(fd) {
            return (real().recv)(fd, buf, len, flags);
        }
        overlay_recv(fd, buf, len, flags)
    })
}

#[no_mangle]
/// Interposes libc `write(2)`.
///
/// # Safety
/// `buf` must be valid for `len` bytes under the normal libc `write` contract.
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, len: size_t) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().write)(fd, buf, len);
        }
        if !ensure_tracked(fd) {
            return (real().write)(fd, buf, len);
        }
        let plaintext = match input_slice(buf, len) {
            Ok(s) => s,
            Err(e) => {
                set_errno(e);
                return -1;
            }
        };
        overlay_send(fd, plaintext, 0)
    })
}

#[no_mangle]
/// Interposes libc `read(2)`.
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes under the normal libc `read`
/// contract.
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, len: size_t) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().read)(fd, buf, len);
        }
        if !ensure_tracked(fd) {
            return (real().read)(fd, buf, len);
        }
        overlay_recv(fd, buf, len, 0)
    })
}

#[no_mangle]
/// Interposes libc `writev(2)`.
///
/// # Safety
/// `iov` must reference `iovcnt` valid iovec entries under the normal libc
/// `writev` contract.
pub unsafe extern "C" fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().writev)(fd, iov, iovcnt);
        }
        if iovcnt < 0 {
            set_errno(libc::EINVAL);
            return -1;
        }
        if !ensure_tracked(fd) {
            return (real().writev)(fd, iov, iovcnt);
        }
        overlay_write_iov(fd, iov, iovcnt as usize, 0)
    })
}

#[no_mangle]
/// Interposes libc `readv(2)`.
///
/// # Safety
/// `iov` must reference `iovcnt` valid writable iovec entries under the normal
/// libc `readv` contract.
pub unsafe extern "C" fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().readv)(fd, iov, iovcnt);
        }
        if iovcnt < 0 {
            set_errno(libc::EINVAL);
            return -1;
        }
        if !ensure_tracked(fd) {
            return (real().readv)(fd, iov, iovcnt);
        }
        overlay_read_iov(fd, iov, iovcnt as usize, 0)
    })
}

#[no_mangle]
/// Interposes libc `sendmsg(2)`.
///
/// # Safety
/// `msg` must be a valid pointer to an `msghdr` whose iovec entries satisfy the
/// normal libc `sendmsg` contract.
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().sendmsg)(fd, msg, flags);
        }
        if msg.is_null() {
            set_errno(libc::EFAULT);
            return -1;
        }
        if !ensure_tracked(fd) {
            return (real().sendmsg)(fd, msg, flags);
        }
        let msg_ref = &*msg;
        overlay_write_iov(
            fd,
            msg_ref.msg_iov,
            msg_iovlen_to_usize(msg_ref.msg_iovlen),
            flags,
        )
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// Interposes libc `sendmmsg(2)`.
///
/// # Safety
/// `msgvec` must satisfy libc `sendmmsg`'s contract. Stream sockets are
/// fail-closed because batched datagram send cannot safely carry overlay
/// records.
pub unsafe extern "C" fn sendmmsg(
    fd: c_int,
    msgvec: *mut libc::mmsghdr,
    vlen: c_uint,
    flags: c_int,
) -> c_int {
    ffi_guard_c_int(|| {
        if !interposition_enabled() {
            return (real().sendmmsg)(fd, msgvec, vlen, flags);
        }
        if block_stream_egress(fd) {
            return -1;
        }
        (real().sendmmsg)(fd, msgvec, vlen, flags)
    })
}

#[no_mangle]
/// Interposes libc `recvmsg(2)`.
///
/// # Safety
/// `msg` must be a valid writable pointer to an `msghdr` whose iovec entries
/// satisfy the normal libc `recvmsg` contract.
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().recvmsg)(fd, msg, flags);
        }
        if msg.is_null() {
            set_errno(libc::EFAULT);
            return -1;
        }
        if !ensure_tracked(fd) {
            return (real().recvmsg)(fd, msg, flags);
        }
        let msg_ref = &mut *msg;
        msg_ref.msg_flags = 0;
        msg_ref.msg_controllen = 0;
        overlay_read_iov(
            fd,
            msg_ref.msg_iov,
            msg_iovlen_to_usize(msg_ref.msg_iovlen),
            flags,
        )
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// Interposes libc `sendfile(2)`.
///
/// # Safety
/// Follows libc `sendfile`'s fd and pointer contract. A stream `out_fd` is
/// fail-closed because zero-copy plaintext cannot be transformed into overlay
/// records without changing the syscall semantics.
pub unsafe extern "C" fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut libc::off_t,
    count: size_t,
) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().sendfile)(out_fd, in_fd, offset, count);
        }
        if block_stream_egress(out_fd) {
            return -1;
        }
        (real().sendfile)(out_fd, in_fd, offset, count)
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// Interposes libc `sendfile64(2)`.
///
/// # Safety
/// Follows libc `sendfile64`'s fd and pointer contract. A stream `out_fd` is
/// fail-closed for the same reason as `sendfile`.
pub unsafe extern "C" fn sendfile64(
    out_fd: c_int,
    in_fd: c_int,
    offset: *mut libc::off64_t,
    count: size_t,
) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().sendfile64)(out_fd, in_fd, offset, count);
        }
        if block_stream_egress(out_fd) {
            return -1;
        }
        (real().sendfile64)(out_fd, in_fd, offset, count)
    })
}

#[cfg(target_os = "linux")]
#[no_mangle]
/// Interposes libc `splice(2)`.
///
/// # Safety
/// Follows libc `splice`'s fd and pointer contract. Any stream socket endpoint
/// is fail-closed so plaintext cannot bypass overlay framing.
pub unsafe extern "C" fn splice(
    fd_in: c_int,
    off_in: *mut libc::loff_t,
    fd_out: c_int,
    off_out: *mut libc::loff_t,
    len: size_t,
    flags: c_uint,
) -> ssize_t {
    ffi_guard_ssize(|| {
        if !interposition_enabled() {
            return (real().splice)(fd_in, off_in, fd_out, off_out, len, flags);
        }
        if block_stream_egress(fd_in) || block_stream_egress(fd_out) {
            return -1;
        }
        (real().splice)(fd_in, off_in, fd_out, off_out, len, flags)
    })
}

#[no_mangle]
/// Interposes libc `close(2)`.
///
/// # Safety
/// `fd` must follow the normal libc `close` contract.
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    ffi_guard_c_int(|| {
        if !interposition_enabled() {
            return (real().close)(fd);
        }
        // Global lock only: remove the map entry and drop the registry's `Arc`.
        // If another thread holds a cloned `Arc` and is mid-I/O on this fd, its clone
        // keeps the `FdState` (and its zeroizing `Drop`) alive until it finishes --
        // no use-after-free. We do not hold the per-fd lock here, so `close` cannot
        // block behind a thread parked in a blocking read.
        let removed = {
            let mut reg = lock_registry();
            reg.remove(&fd)
        };
        drop(removed);
        (real().close)(fd)
    })
}

#[cfg(test)]
mod crash_isolation_tests {
    //! Fault-injection: prove an internal panic / lock-poison on the interposed
    //! path is converted to a clean `-1`/`EIO` and the host process stays up,
    //! instead of SIGABRT-ing it. Under `panic = "abort"` (the old release
    //! profile) `catch_unwind` could not catch and the process aborted; the tests
    //! run under the unwind profile that the cdylib now also uses.
    use super::*;
    use crate::crypto::CipherSuite;

    fn silence_panics() {
        std::panic::set_hook(Box::new(|_| {}));
    }

    #[test]
    fn ffi_guard_converts_panic_to_eio_without_crashing() {
        silence_panics();
        let rc = ffi_guard_ssize(|| panic!("simulated bug on interposed write path"));
        assert_eq!(rc, -1, "guarded ssize panic must return -1");
        unsafe { assert_eq!(errno(), libc::EIO, "errno must be EIO") };
        let rc2 = ffi_guard_c_int(|| panic!("simulated bug on interposed connect path"));
        assert_eq!(rc2, -1, "guarded c_int panic must return -1");
        // Reaching this line at all proves the host (this process) survived.
    }

    #[test]
    fn registry_lock_recovers_from_poison() {
        // `lock_registry` works in the normal case...
        {
            let _g = lock_registry();
        }
        // ...and the recovery pattern it uses (`into_inner`) yields a usable
        // guard even after poisoning. Demonstrated on a local mutex so we do not
        // permanently poison the shared REGISTRY for sibling tests.
        silence_panics();
        let m = Mutex::new(0xABCDu32);
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _g = m.lock().unwrap();
            panic!("poison");
        }));
        let g = match m.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        assert_eq!(*g, 0xABCD, "poison recovery must preserve the data");
    }

    #[test]
    fn poisoned_fd_state_is_fail_closed_detectable() {
        // A panic while holding a per-fd lock poisons it; the overlay_send/recv
        // graceful path treats `state.lock()` == Err as fail-closed (returns EIO).
        silence_panics();
        let st = Arc::new(Mutex::new(FdState::failed(CipherSuite::NistStandard768)));
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _g = st.lock().unwrap();
            panic!("poison per-fd state mid-mutation");
        }));
        assert!(
            st.lock().is_err(),
            "poisoned per-fd lock must be observable so I/O fails closed"
        );
    }
}
