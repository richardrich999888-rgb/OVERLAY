//! `SCM_RIGHTS` file-descriptor passing over a Unix domain socket.
//!
//! The v2 control daemon does not `accept()` the connection it protects — the
//! eBPF/injection layer owns the paused socket and hands the descriptor across a
//! process boundary as ancillary `SCM_RIGHTS` control data. These helpers send and
//! receive exactly one fd, and **fail closed**: any malformed / truncated / wrong
//! ancillary data yields no fd (and any unexpected extra fds are closed, not
//! leaked), so the caller aborts the channel instead of touching cleartext.

#[cfg(target_os = "linux")]
use libc::{c_int, c_void};
use std::io;
use std::os::unix::io::RawFd;

/// Send `payload` (≥1 byte is sent regardless) plus a single fd over `uds` using
/// an `SCM_RIGHTS` ancillary message.
#[cfg(target_os = "linux")]
pub fn send_fd(uds: RawFd, payload: &[u8], fd: RawFd) -> io::Result<()> {
    use std::mem;
    use std::ptr;

    // sendmsg needs at least one data byte to carry the ancillary fd.
    let data: &[u8] = if payload.is_empty() { &[0u8] } else { payload };
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    // 8-byte-aligned control buffer (generous; a one-fd cmsg needs 24 bytes).
    let mut cbuf = [0u64; 8];
    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) } as usize;

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::other("no control buffer space for SCM_RIGHTS"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as usize;
        ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut c_int, fd);
    }

    let sent = unsafe { libc::sendmsg(uds, &msg, 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a message from `uds`, returning the inline data and, if present, a
/// single passed fd. Fail-closed: truncated control data, the wrong cmsg, or an
/// unexpected number of fds all yield `None` (extra fds are closed).
#[cfg(target_os = "linux")]
pub fn recv_fd(uds: RawFd) -> io::Result<(Vec<u8>, Option<RawFd>)> {
    use std::mem;
    use std::ptr;

    let mut databuf = [0u8; 256];
    let mut iov = libc::iovec {
        iov_base: databuf.as_mut_ptr() as *mut c_void,
        iov_len: databuf.len(),
    };
    let mut cbuf = [0u64; 8];
    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) } as usize;

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space;

    let n = unsafe { libc::recvmsg(uds, &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let data = databuf[..n as usize].to_vec();

    // Control data truncated -> we cannot trust any fd: fail closed.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Ok((data, None));
    }

    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut received: Option<RawFd> = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let payload_len = ((*cmsg).cmsg_len as usize).saturating_sub(header_len);
                let nfds = payload_len / mem::size_of::<c_int>();
                let fds = libc::CMSG_DATA(cmsg) as *const c_int;
                if nfds == 1 {
                    received = Some(ptr::read_unaligned(fds));
                } else {
                    // Unexpected fd count: close them all and fail closed.
                    for i in 0..nfds {
                        libc::close(ptr::read_unaligned(fds.add(i)));
                    }
                }
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((data, received))
}

#[cfg(not(target_os = "linux"))]
pub fn send_fd(_uds: RawFd, _payload: &[u8], _fd: RawFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS fd passing is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn recv_fd(_uds: RawFd) -> io::Result<(Vec<u8>, Option<RawFd>)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS fd passing is Linux-only",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    /// Create a connected AF_UNIX socketpair as two `OwnedFd`s.
    fn uds_pair() -> (std::os::unix::io::OwnedFd, std::os::unix::io::OwnedFd) {
        use std::os::unix::io::OwnedFd;
        let mut fds = [0 as c_int; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "socketpair failed");
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn round_trips_one_fd() {
        let (a, b) = uds_pair();
        // Pass one end of a throwaway pipe through the UDS.
        let mut pipe = [0 as c_int; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let (read_end, write_end) = (pipe[0], pipe[1]);

        send_fd(a.as_raw_fd(), b"go", read_end).unwrap();
        let (data, got) = recv_fd(b.as_raw_fd()).unwrap();
        assert_eq!(data, b"go");
        let got = got.expect("an fd must have been received");
        assert!(got >= 0);

        // The received fd is a *dup* of read_end (different number, same pipe).
        assert_ne!(got, read_end);
        unsafe {
            libc::close(got);
            libc::close(read_end);
            libc::close(write_end);
        }
    }

    #[test]
    fn no_ancillary_data_yields_none() {
        let (a, b) = uds_pair();
        // Plain write with no SCM_RIGHTS control message.
        let msg = b"plain";
        let n = unsafe { libc::send(a.as_raw_fd(), msg.as_ptr() as *const c_void, msg.len(), 0) };
        assert_eq!(n, msg.len() as isize);
        let (data, got) = recv_fd(b.as_raw_fd()).unwrap();
        assert_eq!(data, b"plain");
        assert!(
            got.is_none(),
            "no fd should be reported -> caller fails closed"
        );
    }
}
