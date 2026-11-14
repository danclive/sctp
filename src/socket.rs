use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use libc::{c_int, c_void, socklen_t};

use crate::AssociationId;
use crate::addr;
use crate::event::Event;
use crate::message::{NextInfo, Received, ReceivedData, RecvInfo, SendInfo};
use crate::notification::Notification;
use crate::sys;

/// Alignment of ancillary data headers on the platform.
const CMSG_ALIGN: usize = mem::size_of::<usize>();

const fn cmsg_align(len: usize) -> usize {
    (len + CMSG_ALIGN - 1) & !(CMSG_ALIGN - 1)
}

const fn cmsg_len(data_len: usize) -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>()) + data_len
}

const fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(cmsg_len(data_len))
}

/// Enough room for `SCTP_RCVINFO`, `SCTP_SNDRCV` and `SCTP_NXTINFO`.
const CONTROL_BUFFER_SIZE: usize = cmsg_space(mem::size_of::<sys::sctp_rcvinfo>())
    + cmsg_space(mem::size_of::<sys::sctp_sndrcvinfo>())
    + cmsg_space(mem::size_of::<sys::sctp_nxtinfo>());

/// Enough room for the `SCTP_SNDINFO` and `SCTP_PRINFO` headers.
const SEND_CONTROL_SIZE: usize = cmsg_space(mem::size_of::<sys::sctp_sndinfo>())
    + cmsg_space(mem::size_of::<sys::sctp_prinfo>());

/// Ancillary data must be aligned like `cmsghdr`.
#[repr(align(8))]
struct ControlBuffer<const N: usize>([u8; N]);

impl<const N: usize> ControlBuffer<N> {
    fn new() -> ControlBuffer<N> {
        ControlBuffer([0; N])
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    fn len(&self) -> usize {
        N
    }
}

/// Upper bound for buffers that grow when the kernel reports `ENOMEM`.
const MAX_OPTION_BUFFER: usize = 1 << 16;

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Checks a `-1`-on-error return value.
pub(crate) fn cvt(ret: c_int) -> io::Result<c_int> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Checks a `-1`-on-error return value, retrying on `EINTR`.
pub(crate) fn cvt_r(mut f: impl FnMut() -> c_int) -> io::Result<c_int> {
    loop {
        match cvt(f()) {
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// Checks a `-1`-on-error `ssize_t` return value.
fn cvt_ssize(ret: libc::ssize_t) -> io::Result<libc::ssize_t> {
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Checks a `-1`-on-error `ssize_t` return value, retrying on `EINTR`.
fn cvt_r_ssize(mut f: impl FnMut() -> libc::ssize_t) -> io::Result<libc::ssize_t> {
    loop {
        match cvt_ssize(f()) {
            Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// Appends one ancillary data header and its payload to `control`.
///
/// `control` must be aligned like `cmsghdr`.
fn push_cmsg<T>(control: &mut [u8], offset: &mut usize, cmsg_type: c_int, value: &T) {
    let header_len = cmsg_align(mem::size_of::<libc::cmsghdr>());
    let total = cmsg_len(mem::size_of::<T>());
    debug_assert!(*offset + cmsg_space(mem::size_of::<T>()) <= control.len());

    unsafe {
        let header = control.as_mut_ptr().add(*offset).cast::<libc::cmsghdr>();
        header.write(libc::cmsghdr {
            cmsg_len: total as _,
            cmsg_level: sys::IPPROTO_SCTP,
            cmsg_type,
        });
        ptr::copy_nonoverlapping(
            ptr::from_ref(value).cast::<u8>(),
            control.as_mut_ptr().add(*offset + header_len),
            mem::size_of::<T>(),
        );
    }

    *offset += cmsg_space(mem::size_of::<T>());
}

fn to_socklen(len: usize) -> io::Result<socklen_t> {
    socklen_t::try_from(len).map_err(|_| invalid_input("buffer is too large"))
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFD) })?;
    cvt(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) })?;
    Ok(())
}

/// A raw SCTP socket.
pub(crate) struct Socket {
    fd: OwnedFd,
}

impl Socket {
    /// Creates an SCTP socket of the given type and enables receive information.
    pub(crate) fn open(family: c_int, ty: c_int) -> io::Result<Socket> {
        let fd = match cvt(unsafe {
            libc::socket(family, ty | libc::SOCK_CLOEXEC, sys::IPPROTO_SCTP)
        }) {
            Ok(fd) => fd,
            // Kernels without SOCK_CLOEXEC reject it with EINVAL.
            Err(ref error) if error.raw_os_error() == Some(libc::EINVAL) => {
                let fd = cvt(unsafe { libc::socket(family, ty, sys::IPPROTO_SCTP) })?;
                set_cloexec(fd)?;
                fd
            }
            Err(error) => return Err(error),
        };

        let socket = Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        // Without SCTP_RCVINFO received messages only carry the payload, so
        // enable it unconditionally to be able to report `RecvInfo`.
        socket.set_receive_rcv_info(true)?;
        Ok(socket)
    }

    fn from_fd(fd: RawFd) -> Socket {
        Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Socket> {
        Ok(Socket {
            fd: self.fd.try_clone()?,
        })
    }

    pub(crate) fn bind(&self, address: &SocketAddr) -> io::Result<()> {
        let (storage, len) = addr::to_storage(address);
        cvt(unsafe { libc::bind(self.fd.as_raw_fd(), ptr::from_ref(&storage).cast(), len) })?;
        Ok(())
    }

    pub(crate) fn bindx(&self, addrs: &[SocketAddr], add: bool) -> io::Result<()> {
        if addrs.is_empty() {
            return Err(invalid_input("no addresses given"));
        }
        let buf = addr::encode_all(&unique(addrs));
        let optname = if add {
            sys::SCTP_SOCKOPT_BINDX_ADD
        } else {
            sys::SCTP_SOCKOPT_BINDX_REM
        };
        self.set_opt_buf(sys::IPPROTO_SCTP, optname, &buf)
    }

    pub(crate) fn listen(&self, backlog: c_int) -> io::Result<()> {
        cvt(unsafe { libc::listen(self.fd.as_raw_fd(), backlog) })?;
        Ok(())
    }

    pub(crate) fn connect(&self, address: &SocketAddr) -> io::Result<()> {
        let (storage, len) = addr::to_storage(address);
        cvt_r(|| unsafe {
            libc::connect(self.fd.as_raw_fd(), ptr::from_ref(&storage).cast(), len)
        })?;
        Ok(())
    }

    /// Connects to all addresses at once (SCTP multi-homing).
    ///
    /// The kernel returns the new association identifier as the return value
    /// of the `SCTP_SOCKOPT_CONNECTX` socket option.
    pub(crate) fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<AssociationId> {
        if addrs.is_empty() {
            return Err(invalid_input("no addresses given"));
        }
        let buf = addr::encode_all(&unique(addrs));
        let ret = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                sys::IPPROTO_SCTP,
                sys::SCTP_SOCKOPT_CONNECTX,
                buf.as_ptr().cast(),
                to_socklen(buf.len())?,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    pub(crate) fn connect_timeout(
        &self,
        address: &SocketAddr,
        timeout: Duration,
    ) -> io::Result<()> {
        self.set_nonblocking(true)?;
        let result = self.connect_nonblocking(address, timeout);
        let restored = self.set_nonblocking(false);
        result.and(restored)
    }

    fn connect_nonblocking(&self, address: &SocketAddr, timeout: Duration) -> io::Result<()> {
        match self.connect(address) {
            Ok(()) => return Ok(()),
            Err(ref error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(error) => return Err(error),
        }

        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| invalid_input("timeout is too large"))?;
        let mut pollfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().min(i32::MAX as u128) as c_int;
            match cvt(unsafe { libc::poll(&mut pollfd, 1, millis) }) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection timed out",
                    ));
                }
                Ok(_) => {}
                Err(ref error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }

            let error: c_int = self.get_opt(libc::SOL_SOCKET, libc::SO_ERROR)?;
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            return Ok(());
        }
    }

    pub(crate) fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as socklen_t;
        let fd = cvt_r(|| unsafe {
            libc::accept4(
                self.fd.as_raw_fd(),
                ptr::from_mut(&mut storage).cast(),
                &raw mut len,
                libc::SOCK_CLOEXEC,
            )
        })?;
        let address = addr::from_storage(&storage)?;
        Ok((Socket::from_fd(fd), address))
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as socklen_t;
        cvt(unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                ptr::from_mut(&mut storage).cast(),
                &raw mut len,
            )
        })?;
        addr::from_storage(&storage)
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as socklen_t;
        cvt(unsafe {
            libc::getpeername(
                self.fd.as_raw_fd(),
                ptr::from_mut(&mut storage).cast(),
                &raw mut len,
            )
        })?;
        addr::from_storage(&storage)
    }

    fn get_addrs(
        &self,
        optname: c_int,
        association_id: AssociationId,
    ) -> io::Result<Vec<SocketAddr>> {
        let mut capacity = 8 + 8 * mem::size_of::<libc::sockaddr_storage>();
        loop {
            let mut buf = vec![0u8; capacity];
            buf[..4].copy_from_slice(&association_id.to_ne_bytes());
            match self.get_opt_buf(sys::IPPROTO_SCTP, optname, &mut buf) {
                Ok(_) => return parse_addrs(&buf),
                Err(error) => {
                    if error.raw_os_error() != Some(libc::ENOMEM) {
                        return Err(error);
                    }
                    capacity *= 2;
                    if capacity > MAX_OPTION_BUFFER {
                        return Err(error);
                    }
                }
            }
        }
    }

    pub(crate) fn local_addrs(&self, association_id: AssociationId) -> io::Result<Vec<SocketAddr>> {
        self.get_addrs(sys::SCTP_GET_LOCAL_ADDRS, association_id)
    }

    pub(crate) fn peer_addrs(&self, association_id: AssociationId) -> io::Result<Vec<SocketAddr>> {
        self.get_addrs(sys::SCTP_GET_PEER_ADDRS, association_id)
    }

    pub(crate) fn association_ids(&self) -> io::Result<Vec<AssociationId>> {
        let mut capacity = 4 + 16 * mem::size_of::<AssociationId>();
        loop {
            let mut buf = vec![0u8; capacity];
            match self.get_opt_buf(sys::IPPROTO_SCTP, sys::SCTP_GET_ASSOC_ID_LIST, &mut buf) {
                Ok(_) => {
                    if buf.len() < 4 {
                        return Err(invalid_data("truncated association id list"));
                    }
                    let count = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
                    let Some(list_len) = count.checked_mul(mem::size_of::<AssociationId>()) else {
                        return Err(invalid_data("truncated association id list"));
                    };
                    let Some(end) = list_len.checked_add(4) else {
                        return Err(invalid_data("truncated association id list"));
                    };
                    if end > buf.len() {
                        return Err(invalid_data("truncated association id list"));
                    }
                    return Ok(buf[4..end]
                        .chunks_exact(4)
                        .map(|chunk| i32::from_ne_bytes(chunk.try_into().unwrap()))
                        .collect());
                }
                Err(error) => {
                    if !matches!(
                        error.raw_os_error(),
                        Some(libc::EINVAL) | Some(libc::ENOMEM)
                    ) {
                        return Err(error);
                    }
                    capacity *= 2;
                    if capacity > MAX_OPTION_BUFFER {
                        return Err(error);
                    }
                }
            }
        }
    }

    pub(crate) fn peeloff(&self, association_id: AssociationId) -> io::Result<Socket> {
        let mut arg = sys::sctp_peeloff_arg {
            assoc_id: association_id,
            sd: -1,
        };
        let mut len = mem::size_of_val(&arg) as socklen_t;
        let ret = cvt(unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                sys::IPPROTO_SCTP,
                sys::SCTP_SOCKOPT_PEELOFF,
                ptr::from_mut(&mut arg).cast(),
                &raw mut len,
            )
        })?;

        let fd = if arg.sd >= 0 { arg.sd } else { ret };
        Ok(Socket::from_fd(fd))
    }

    pub(crate) fn send(
        &self,
        buf: &[u8],
        address: Option<&SocketAddr>,
        info: Option<&SendInfo>,
    ) -> io::Result<usize> {
        // SCTP has no zero-length messages; mirror `std` and accept empty writes.
        if buf.is_empty() && info.is_none_or(|info| info.flags.is_empty()) {
            return Ok(0);
        }

        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut address_len = 0;
        if let Some(address) = address {
            let (value, len) = addr::to_storage(address);
            storage = value;
            address_len = len;
        }

        let mut control = ControlBuffer::<SEND_CONTROL_SIZE>::new();
        let mut control_len = 0;
        if let Some(info) = info {
            push_cmsg(
                control.as_mut_slice(),
                &mut control_len,
                sys::SCTP_SNDINFO,
                &info.to_raw(),
            );
            if let Some(prinfo) = info.pr_info() {
                push_cmsg(
                    control.as_mut_slice(),
                    &mut control_len,
                    sys::SCTP_PRINFO,
                    &prinfo,
                );
            }
        }

        let mut iov = libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        if address_len != 0 {
            msg.msg_name = ptr::from_mut(&mut storage).cast();
            msg.msg_namelen = address_len;
        }
        msg.msg_iov = ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        if control_len != 0 {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = control_len;
        }

        let len = cvt_r_ssize(|| unsafe {
            libc::sendmsg(self.fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL)
        })?;
        Ok(len as usize)
    }

    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut control = ControlBuffer::<CONTROL_BUFFER_SIZE>::new();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = ptr::from_mut(&mut storage).cast();
        msg.msg_namelen = mem::size_of_val(&storage) as socklen_t;
        msg.msg_iov = ptr::from_mut(&mut iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();

        let len =
            cvt_r_ssize(|| unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, 0) })? as usize;

        if msg.msg_flags & sys::MSG_NOTIFICATION != 0 {
            return Ok(Received::Notification(Notification::parse(&buf[..len])?));
        }

        let address = if msg.msg_namelen as usize >= mem::size_of::<libc::sockaddr_in>() {
            addr::from_storage(&storage).ok()
        } else {
            None
        };

        let mut info = RecvInfo::default();
        let mut have_info = false;
        let mut next = None;

        let mut offset = 0;
        let control_len = msg.msg_controllen as usize;
        let header_len = mem::size_of::<libc::cmsghdr>();
        while offset + header_len <= control_len {
            let header: libc::cmsghdr =
                unsafe { ptr::read_unaligned(control.as_ptr().add(offset).cast()) };
            let length = header.cmsg_len;
            if length < header_len || offset + length > control_len {
                break;
            }
            let data_len = length - header_len;
            let data = unsafe { control.as_ptr().add(offset + header_len) };

            if header.cmsg_level == sys::IPPROTO_SCTP {
                match header.cmsg_type {
                    sys::SCTP_RCVINFO if data_len >= mem::size_of::<sys::sctp_rcvinfo>() => {
                        let raw: sys::sctp_rcvinfo = unsafe { ptr::read_unaligned(data.cast()) };
                        info = RecvInfo::from_rcvinfo(&raw);
                        have_info = true;
                    }
                    sys::SCTP_SNDRCV
                        if !have_info && data_len >= mem::size_of::<sys::sctp_sndrcvinfo>() =>
                    {
                        let raw: sys::sctp_sndrcvinfo = unsafe { ptr::read_unaligned(data.cast()) };
                        info = RecvInfo::from_sndrcvinfo(&raw);
                        have_info = true;
                    }
                    sys::SCTP_NXTINFO if data_len >= mem::size_of::<sys::sctp_nxtinfo>() => {
                        let raw: sys::sctp_nxtinfo = unsafe { ptr::read_unaligned(data.cast()) };
                        next = Some(NextInfo::from_raw(&raw));
                    }
                    _ => {}
                }
            }

            offset += cmsg_align(length);
        }

        Ok(Received::Data(ReceivedData {
            len,
            address,
            info,
            next,
            complete: msg.msg_flags & libc::MSG_EOR != 0,
        }))
    }

    pub(crate) fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let len = cvt_ssize(unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_PEEK,
            )
        })?;
        Ok(len as usize)
    }

    pub(crate) fn shutdown(&self, how: c_int) -> io::Result<()> {
        cvt(unsafe { libc::shutdown(self.fd.as_raw_fd(), how) })?;
        Ok(())
    }

    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = cvt(unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) })?;
        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        cvt(unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, new_flags) })?;
        Ok(())
    }

    pub(crate) fn set_timeout(&self, timeout: Option<Duration>, kind: c_int) -> io::Result<()> {
        let value = match timeout {
            Some(duration) => {
                if duration.as_nanos() == 0 {
                    return Err(invalid_input("cannot set a zero duration timeout"));
                }
                let secs = duration.as_secs().min(libc::time_t::MAX as u64);
                let mut value = libc::timeval {
                    tv_sec: secs as libc::time_t,
                    tv_usec: duration.subsec_micros() as libc::suseconds_t,
                };
                if value.tv_sec == 0 && value.tv_usec == 0 {
                    value.tv_usec = 1;
                }
                value
            }
            None => libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        };
        self.set_opt(libc::SOL_SOCKET, kind, &value)
    }

    pub(crate) fn timeout(&self, kind: c_int) -> io::Result<Option<Duration>> {
        let value: libc::timeval = self.get_opt(libc::SOL_SOCKET, kind)?;
        if value.tv_sec == 0 && value.tv_usec == 0 {
            return Ok(None);
        }
        let secs = Duration::from_secs(value.tv_sec.max(0) as u64);
        let micros = Duration::from_micros(value.tv_usec.max(0) as u64);
        Ok(Some(secs.saturating_add(micros)))
    }

    pub(crate) fn events(&self) -> io::Result<Event> {
        let raw: sys::sctp_event_subscribe = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_EVENTS)?;
        Ok(Event::from_subscribe(&raw))
    }

    pub(crate) fn set_events(&self, events: Event) -> io::Result<()> {
        let raw = events.to_subscribe();
        match self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_EVENTS, &raw) {
            // Kernels predating stream reset only know the first ten events.
            Err(ref error) if error.raw_os_error() == Some(libc::EINVAL) => {
                self.set_opt_buf(sys::IPPROTO_SCTP, sys::SCTP_EVENTS, &raw[..10])
            }
            other => other,
        }
    }

    pub(crate) fn event(&self, association_id: AssociationId, event: Event) -> io::Result<bool> {
        let type_ = event
            .notification_type()
            .ok_or_else(|| invalid_input("exactly one event must be given"))?;
        let raw: sys::sctp_event = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_EVENT,
            sys::sctp_event {
                assoc_id: association_id,
                type_,
                on: 0,
            },
        )?;
        Ok(raw.on != 0)
    }

    pub(crate) fn set_event(
        &self,
        association_id: AssociationId,
        event: Event,
        enable: bool,
    ) -> io::Result<()> {
        let type_ = event
            .notification_type()
            .ok_or_else(|| invalid_input("exactly one event must be given"))?;
        let raw = sys::sctp_event {
            assoc_id: association_id,
            type_,
            on: u8::from(enable),
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_EVENT, &raw)
    }

    // -----------------------------------------------------------------
    // Generic option plumbing
    // -----------------------------------------------------------------

    /// Reads an option whose value is a plain-old-data `T`.
    ///
    /// `T` must accept an all-zero bit pattern; all call sites use structures
    /// made of integers and socket addresses.
    pub(crate) fn get_opt<T: Copy>(&self, level: c_int, optname: c_int) -> io::Result<T> {
        let mut slot = MaybeUninit::<T>::zeroed();
        let mut len = mem::size_of::<T>() as socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                level,
                optname,
                slot.as_mut_ptr().cast(),
                &raw mut len,
            )
        })?;
        Ok(unsafe { slot.assume_init() })
    }

    /// Like [`get_opt`](Socket::get_opt), but starts from `initial`.
    ///
    /// Some options take an input value (usually an association id) and write
    /// their result back into the same buffer.
    pub(crate) fn get_opt_with<T: Copy>(
        &self,
        level: c_int,
        optname: c_int,
        initial: T,
    ) -> io::Result<T> {
        let mut slot = MaybeUninit::new(initial);
        let mut len = mem::size_of::<T>() as socklen_t;
        cvt(unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                level,
                optname,
                slot.as_mut_ptr().cast(),
                &raw mut len,
            )
        })?;
        Ok(unsafe { slot.assume_init() })
    }

    pub(crate) fn set_opt<T>(&self, level: c_int, optname: c_int, value: &T) -> io::Result<()> {
        cvt(unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                optname,
                ptr::from_ref(value).cast(),
                mem::size_of::<T>() as socklen_t,
            )
        })?;
        Ok(())
    }

    pub(crate) fn set_opt_buf(&self, level: c_int, optname: c_int, value: &[u8]) -> io::Result<()> {
        let len = to_socklen(value.len())?;
        cvt(unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                level,
                optname,
                value.as_ptr().cast(),
                len,
            )
        })?;
        Ok(())
    }

    /// Reads a variable-length option into `buf`, returning its new length.
    pub(crate) fn get_opt_buf(
        &self,
        level: c_int,
        optname: c_int,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        let mut len = to_socklen(buf.len())?;
        cvt(unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                level,
                optname,
                buf.as_mut_ptr().cast::<c_void>(),
                &raw mut len,
            )
        })?;
        Ok(len as usize)
    }
}

/// Removes duplicate addresses while preserving their order.
fn unique(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut unique = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if !unique.contains(addr) {
            unique.push(*addr);
        }
    }
    unique
}

fn parse_addrs(buf: &[u8]) -> io::Result<Vec<SocketAddr>> {
    if buf.len() < 8 {
        return Err(invalid_data("truncated address list"));
    }
    let count = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize;
    let mut offset = 8;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        if offset > buf.len() {
            return Err(invalid_data("truncated address list"));
        }
        let (address, len) = addr::decode(&buf[offset..])?;
        addrs.push(address);
        offset += len;
    }
    Ok(addrs)
}

impl From<OwnedFd> for Socket {
    fn from(fd: OwnedFd) -> Socket {
        Socket { fd }
    }
}

impl From<Socket> for OwnedFd {
    fn from(socket: Socket) -> OwnedFd {
        socket.fd
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(fd: RawFd) -> Socket {
        Socket {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        }
    }
}
