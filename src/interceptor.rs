//! Linux/glibc symbol interposition for the Syntriass overlay.
//!
//! Every intercepted stream-socket write path routes plaintext through the same
//! authenticated, encrypted record pipeline. Unknown stream sockets are adopted
//! as responders and must complete the overlay handshake before application data
//! can move. If policy or identity material is missing, the fd is tracked as
//! failed so later I/O returns an error instead of leaking plaintext.

use crate::crypto::{self, CipherSuite};
use crate::fd_state::{FdPhase, FdState, MAX_WIRE_RX_BUFFER, REGISTRY};
use libc::{c_int, c_void, iovec, msghdr, size_t, ssize_t};
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};
use std::{cmp, ptr, slice};
use zeroize::Zeroize;

const HDR_LEN: usize = 4;
const TYPE_CLIENT_HELLO: u8 = 1;
const TYPE_SERVER_HELLO: u8 = 2;
const TYPE_DATA: u8 = 3;
const MAX_FRAME_BODY: usize = MAX_WIRE_RX_BUFFER - HDR_LEN;
const MAX_RECORD_PLAINTEXT: usize = 64 * 1024;
const MAX_IOV_COPY: usize = 16 * 1024 * 1024;

static POLICY: OnceCell<Result<CipherSuite, &'static str>> = OnceCell::new();

fn policy() -> Result<CipherSuite, ()> {
    POLICY
        .get_or_init(crypto::resolve_policy)
        .as_ref()
        .copied()
        .map_err(|_| ())
}

fn failed_policy_suite() -> CipherSuite {
    policy().unwrap_or(CipherSuite::NistStandard768)
}

type ConnectFn = unsafe extern "C" fn(c_int, *const libc::sockaddr, libc::socklen_t) -> c_int;
type SendFn = unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t;
type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, size_t, c_int) -> ssize_t;
type WriteFn = unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t;
type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t;
type WritevFn = unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t;
type ReadvFn = unsafe extern "C" fn(c_int, *const iovec, c_int) -> ssize_t;
type SendmsgFn = unsafe extern "C" fn(c_int, *const msghdr, c_int) -> ssize_t;
type RecvmsgFn = unsafe extern "C" fn(c_int, *mut msghdr, c_int) -> ssize_t;
type CloseFn = unsafe extern "C" fn(c_int) -> c_int;

struct RealSyms {
    connect: ConnectFn,
    send: SendFn,
    recv: RecvFn,
    write: WriteFn,
    read: ReadFn,
    writev: WritevFn,
    readv: ReadvFn,
    sendmsg: SendmsgFn,
    recvmsg: RecvmsgFn,
    close: CloseFn,
}

static REAL: OnceCell<RealSyms> = OnceCell::new();

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
            write: resolve::<WriteFn>(b"write\0"),
            read: resolve::<ReadFn>(b"read\0"),
            writev: resolve::<WritevFn>(b"writev\0"),
            readv: resolve::<ReadvFn>(b"readv\0"),
            sendmsg: resolve::<SendmsgFn>(b"sendmsg\0"),
            recvmsg: resolve::<RecvmsgFn>(b"recvmsg\0"),
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
        if n > 0 {
            let sent = n as usize;
            st.tx_backlog[..sent].zeroize();
            st.tx_backlog.drain(0..sent);
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
                st.phase = FdPhase::Failed;
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
                                    st.phase = FdPhase::Active(keys);
                                } else {
                                    st.phase = FdPhase::Failed;
                                }
                            }
                            Err(_) => st.phase = FdPhase::Failed,
                        }
                    }
                    _ => st.phase = FdPhase::Failed,
                }
            }
            (FdPhase::InitiatorAwaitingServerHello(state), TYPE_SERVER_HELLO) => {
                match crypto::resolve_identity() {
                    Ok(identity) if f.suite_id == st.policy_suite.id() => {
                        match state.finish(&identity, &f.payload) {
                            Ok(keys) => st.phase = FdPhase::Active(keys),
                            Err(_) => st.phase = FdPhase::Failed,
                        }
                    }
                    _ => st.phase = FdPhase::Failed,
                }
            }
            _ => st.phase = FdPhase::Failed,
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
fn lookup(fd: c_int) -> Option<Arc<Mutex<FdState>>> {
    let reg = REGISTRY.lock().unwrap();
    reg.get(&fd).cloned()
}

unsafe fn ensure_tracked(fd: c_int) -> bool {
    {
        let reg = REGISTRY.lock().unwrap();
        if reg.contains_key(&fd) {
            return true;
        }
    }
    if !is_stream_socket(fd) {
        return false;
    }
    let suite = failed_policy_suite();
    let mut reg = REGISTRY.lock().unwrap();
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
    let mut reg = REGISTRY.lock().unwrap();
    reg.insert(fd, Arc::new(Mutex::new(state)));
}

unsafe fn drive_until_active_for_write(
    fd: c_int,
    st: &mut FdState,
    flags: c_int,
    blocking: bool,
) -> Result<(), c_int> {
    if flush_backlog(fd, st, flags).is_err() {
        st.phase = FdPhase::Failed;
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
                    st.phase = FdPhase::Failed;
                    return Err(libc::EIO);
                }
            }
        }
        match pull_wire(fd, st, flags) {
            Ok(0) => {
                st.phase = FdPhase::Failed;
                return Err(libc::EPIPE);
            }
            Ok(n) if n > 0 => drive_handshake(st),
            Ok(_) => {
                let e = errno();
                if (e == libc::EAGAIN || e == libc::EWOULDBLOCK) && !blocking {
                    return Err(e);
                }
                if e != libc::EAGAIN && e != libc::EWOULDBLOCK {
                    st.phase = FdPhase::Failed;
                    return Err(e);
                }
            }
            Err(()) => {
                st.phase = FdPhase::Failed;
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
            st.phase = FdPhase::Failed;
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
    // Sharp edge: std `Mutex` is non-reentrant and `.unwrap()` aborts on poison;
    // with `panic = "abort"` a mid-I/O panic is fatal for this connection. Known,
    // to revisit later -- error handling unchanged this round.
    let mut st_guard = state.lock().unwrap();
    let st = &mut *st_guard;
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
                    st.phase = FdPhase::Failed;
                    set_errno(libc::EIO);
                    return -1;
                }
            },
            _ => {
                st.phase = FdPhase::Failed;
                set_errno(libc::EPIPE);
                return -1;
            }
        };
        let mut f = match frame(suite_id, TYPE_DATA, &ct) {
            Ok(f) => f,
            Err(()) => {
                st.phase = FdPhase::Failed;
                set_errno(libc::EMSGSIZE);
                return -1;
            }
        };
        if let Err(e) = append_or_flush(fd, st, &f, flags, blocking) {
            f.zeroize();
            st.phase = FdPhase::Failed;
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
                    st.phase = FdPhase::Failed;
                    set_errno(libc::EIO);
                    break -1;
                }
            }
        },
        Err(()) => {
            st.phase = FdPhase::Failed;
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
    // Sharp edge: std `Mutex` is non-reentrant and `.unwrap()` aborts on poison;
    // with `panic = "abort"` a mid-I/O panic is fatal for this connection. Known,
    // to revisit later -- error handling unchanged this round.
    let mut st_guard = state.lock().unwrap();
    let st = &mut *st_guard;
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
                            st.phase = FdPhase::Failed;
                            set_errno(libc::EPIPE);
                            return -1;
                        }
                        if let FdPhase::Active(keys) = &mut st.phase {
                            match keys.open(&f.payload) {
                                Ok(mut pt) => {
                                    if st.append_rx_plain(&pt).is_err() {
                                        pt.zeroize();
                                        st.phase = FdPhase::Failed;
                                        set_errno(libc::EPIPE);
                                        return -1;
                                    }
                                    pt.zeroize();
                                }
                                Err(_) => {
                                    st.phase = FdPhase::Failed;
                                    set_errno(libc::EPIPE);
                                    return -1;
                                }
                            }
                        }
                    }
                    Ok(Some(_)) => {
                        st.phase = FdPhase::Failed;
                        set_errno(libc::EPIPE);
                        return -1;
                    }
                    Ok(None) => break,
                    Err(()) => {
                        st.phase = FdPhase::Failed;
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
                st.phase = FdPhase::Failed;
                set_errno(libc::EPIPE);
                return -1;
            }
        }
    }
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
    let res = (real().connect)(fd, addr, addrlen);
    if res == 0 || (res < 0 && errno() == libc::EINPROGRESS) {
        install_initiator_state(fd);
    }
    res
}

#[no_mangle]
/// Interposes libc `send(2)`.
///
/// # Safety
/// `buf` must be valid for `len` bytes under the normal libc `send` contract.
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
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
}

#[no_mangle]
/// Interposes libc `recv(2)`.
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes under the normal libc `recv`
/// contract.
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    if !ensure_tracked(fd) {
        return (real().recv)(fd, buf, len, flags);
    }
    overlay_recv(fd, buf, len, flags)
}

#[no_mangle]
/// Interposes libc `write(2)`.
///
/// # Safety
/// `buf` must be valid for `len` bytes under the normal libc `write` contract.
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, len: size_t) -> ssize_t {
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
}

#[no_mangle]
/// Interposes libc `read(2)`.
///
/// # Safety
/// `buf` must be valid for writes of `len` bytes under the normal libc `read`
/// contract.
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, len: size_t) -> ssize_t {
    if !ensure_tracked(fd) {
        return (real().read)(fd, buf, len);
    }
    overlay_recv(fd, buf, len, 0)
}

#[no_mangle]
/// Interposes libc `writev(2)`.
///
/// # Safety
/// `iov` must reference `iovcnt` valid iovec entries under the normal libc
/// `writev` contract.
pub unsafe extern "C" fn writev(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    if iovcnt < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    if !ensure_tracked(fd) {
        return (real().writev)(fd, iov, iovcnt);
    }
    overlay_write_iov(fd, iov, iovcnt as usize, 0)
}

#[no_mangle]
/// Interposes libc `readv(2)`.
///
/// # Safety
/// `iov` must reference `iovcnt` valid writable iovec entries under the normal
/// libc `readv` contract.
pub unsafe extern "C" fn readv(fd: c_int, iov: *const iovec, iovcnt: c_int) -> ssize_t {
    if iovcnt < 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    if !ensure_tracked(fd) {
        return (real().readv)(fd, iov, iovcnt);
    }
    overlay_read_iov(fd, iov, iovcnt as usize, 0)
}

#[no_mangle]
/// Interposes libc `sendmsg(2)`.
///
/// # Safety
/// `msg` must be a valid pointer to an `msghdr` whose iovec entries satisfy the
/// normal libc `sendmsg` contract.
pub unsafe extern "C" fn sendmsg(fd: c_int, msg: *const msghdr, flags: c_int) -> ssize_t {
    if msg.is_null() {
        set_errno(libc::EFAULT);
        return -1;
    }
    if !ensure_tracked(fd) {
        return (real().sendmsg)(fd, msg, flags);
    }
    let msg_ref = &*msg;
    overlay_write_iov(fd, msg_ref.msg_iov, msg_ref.msg_iovlen as usize, flags)
}

#[no_mangle]
/// Interposes libc `recvmsg(2)`.
///
/// # Safety
/// `msg` must be a valid writable pointer to an `msghdr` whose iovec entries
/// satisfy the normal libc `recvmsg` contract.
pub unsafe extern "C" fn recvmsg(fd: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t {
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
    overlay_read_iov(fd, msg_ref.msg_iov, msg_ref.msg_iovlen as usize, flags)
}

#[no_mangle]
/// Interposes libc `close(2)`.
///
/// # Safety
/// `fd` must follow the normal libc `close` contract.
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    // Global lock only: remove the map entry and drop the registry's `Arc`.
    // If another thread holds a cloned `Arc` and is mid-I/O on this fd, its clone
    // keeps the `FdState` (and its zeroizing `Drop`) alive until it finishes --
    // no use-after-free. We do not hold the per-fd lock here, so `close` cannot
    // block behind a thread parked in a blocking read.
    let removed = {
        let mut reg = REGISTRY.lock().unwrap();
        reg.remove(&fd)
    };
    drop(removed);
    (real().close)(fd)
}
