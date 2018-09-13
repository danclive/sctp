use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::ptr;
use std::time::{Duration};
use std::mem;
use std::cmp;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};

use libc;

use net::cvt;
use net::cvt_r;
use net::{AsInner, FromInner, IntoInner};
use net::fd::FileDesc;
use net::addr::sockaddr_to_addr;
use net::fd;
use net::event::Event;
use net::notification::{notification_parse, Notification};

use sys;

#[allow(dead_code)]
pub enum BindOp {
    /// Add bind addresses
    AddAddr,
    /// Remove bind addresses
    RemAddr
}

impl BindOp {
    fn flag(&self) -> libc::c_int {
        return match *self {
            BindOp::AddAddr => sys::SCTP_BINDX_ADD_ADDR,
            BindOp::RemAddr => sys::SCTP_BINDX_REM_ADDR
        };
    }
}

enum SctpAddrType {
    Local,
    Peer
}

impl SctpAddrType {
    unsafe fn get(&self, sock: libc::c_int, id: sys::sctp_assoc_t, ptr: *mut *mut libc::sockaddr) -> libc::c_int {
        return match *self {
            SctpAddrType::Local => sys::sctp_getladdrs(sock, id, ptr),
            SctpAddrType::Peer => sys::sctp_getpaddrs(sock, id, ptr)
        };
    }

    unsafe fn free(&self, ptr: *mut libc::sockaddr) -> libc::c_int {
        return match *self {
            SctpAddrType::Local => sys::sctp_freeladdrs(ptr),
            SctpAddrType::Peer => sys::sctp_freepaddrs(ptr)
        };
    }
}

pub struct Socket(FileDesc);

impl Socket {
    pub fn new(addr: &SocketAddr, ty: libc::c_int) -> io::Result<Socket> {
        let fam = match *addr {
            SocketAddr::V4(..) => libc::AF_INET,
            SocketAddr::V6(..) => libc::AF_INET6,
        };
        Socket::new_raw(fam, ty)
    }

    pub fn new_raw(fam: libc::c_int, ty: libc::c_int) -> io::Result<Socket> {
        unsafe{
            match cvt(libc::socket(fam, ty | libc::SOCK_CLOEXEC, sys::IPPROTO_SCTP)) {
                Ok(fd) => {
                    let fd = FileDesc::new(fd);
                    let socket = Socket(fd);

                    socket.default_event_subscribe()?;

                    return Ok(socket)
                }
                Err(ref e) if e.raw_os_error() == Some(libc::EINVAL) => {}
                Err(e) => return Err(e),
            }

            let fd = cvt(libc::socket(fam, ty, sys::IPPROTO_SCTP))?;
            let fd = FileDesc::new(fd);
            fd.set_cloexec()?;
            let socket = Socket(fd);

            socket.default_event_subscribe()?;

            Ok(socket)
        }
    }

    pub fn accept(&self, storage: *mut libc::sockaddr, len: *mut libc::socklen_t) -> io::Result<Socket> {;
        let fd = cvt_r(|| unsafe {
            libc::accept4(self.0.raw(), storage, len, libc::SOCK_CLOEXEC)
        })?;
        let fd = FileDesc::new(fd);

        Ok(Socket(fd))
    }

    pub fn listen(&self, backlog: libc::c_int) -> io::Result<()> {
        cvt(unsafe { libc::listen(self.0.raw(), backlog) })?;

        Ok(())
    }

    pub fn bind(&self, addr: &SocketAddr) -> io::Result<()> {
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { libc::bind(self.0.raw(), addrp, len as _)})?;

        Ok(())
    }

    pub fn bindx(&self, addrs: &[SocketAddr], op: BindOp) -> io::Result<()> {
        let buf: *mut u8 = unsafe {
            libc::malloc((addrs.len() * mem::size_of::<libc::sockaddr_in6>()) as libc::size_t) as *mut u8
        };

        let mut offset = 0isize;
        for addr in addrs {
            let (addrp, len) = addr.into_inner();

            unsafe {
                ptr::copy_nonoverlapping(addrp as *mut u8, buf.offset(offset), len as usize);
            }

            offset += len as isize;
        }

        cvt( unsafe { sys::sctp_bindx(self.0.raw(), buf as *const libc::sockaddr, addrs.len() as i32, op.flag()) })?;

        unsafe { libc::free(buf as *mut libc::c_void); }

        Ok(())
    }

    pub fn connect(&self, addr: &SocketAddr) -> io::Result<()> {
        let (addrp, len) = addr.into_inner();
            
        cvt_r(|| unsafe { libc::connect(self.0.raw(), addrp, len) })?;

        Ok(())
    }

    pub fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<sys::sctp_assoc_t> {
        let buf: *mut u8 = unsafe {
            libc::malloc((addrs.len() * mem::size_of::<libc::sockaddr_in6>()) as libc::size_t) as *mut u8
        };

        let mut offset = 0isize;
        for addr in addrs {
            let (addrp, len) = addr.into_inner();

            unsafe {
                ptr::copy_nonoverlapping(addrp as *mut u8, buf.offset(offset), len as usize);
            }

            offset += len as isize;
        }

        let mut assoc: sys::sctp_assoc_t = 0;

        cvt_r(|| unsafe { sys::sctp_connectx(self.0.raw(), buf as *const libc::sockaddr, addrs.len() as i32, &mut assoc) })?;

        unsafe { libc::free(buf as *mut libc::c_void); }

        Ok(assoc)
    }

    fn addrs(&self, id: sys::sctp_assoc_t, what: SctpAddrType) -> io::Result<Vec<SocketAddr>> {
        let mut addrs: *mut u8 = ptr::null_mut();

        let len = unsafe { what.get(self.0.raw(), id, mem::transmute(&mut addrs)) };

        if len < 0 {
            return Err(Error::new(ErrorKind::Other, "Cannot retrieve addresses"))
        }

        if len == 0 {
            return Err(Error::new(ErrorKind::AddrNotAvailable, "Socket is unbound"))
        }

        let mut addrs2 = Vec::with_capacity(len as usize);
        let mut offset = 0;

        for _ in 0..len {
            let scokaddr = unsafe { addrs.offset(offset) } as *const libc::sockaddr;

            let len = match unsafe { (*scokaddr).sa_family } as i32 {
                libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
                libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
                family => {
                    unsafe { what.free(addrs as *mut libc::sockaddr) };
                    return Err(Error::new(ErrorKind::Other, format!("Unsupported address family : {}", family)))
                }
            } as libc::socklen_t;

            addrs2.push(sockaddr_to_addr(unsafe { &*(scokaddr as *const libc::sockaddr_storage) }, len as usize)?);
            offset += len as isize;
        }

        unsafe { what.free(addrs as *mut libc::sockaddr) };

        Ok(addrs2)
    }

    pub fn local_addrs(&self, id: sys::sctp_assoc_t) -> io::Result<Vec<SocketAddr>> {
        self.addrs(id, SctpAddrType::Local)
    }

    pub fn peer_addrs(&self, id: sys::sctp_assoc_t) -> io::Result<Vec<SocketAddr>> {
        self.addrs(id, SctpAddrType::Peer)
    }

    pub fn duplicate(&self) -> io::Result<Socket> {
        self.0.duplicate().map(Socket)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = cvt(unsafe {
            libc::recv(
                self.0.raw(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_PEEK
            )
        })?;

        Ok(ret as usize)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    pub fn recvmsg(&self, msg: &mut [u8]) -> io::Result<(usize, u16, Option<SocketAddr>, Option<Notification>)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;

        let mut info: sys::sctp_sndrcvinfo = unsafe { mem::zeroed() };
        let mut flags: libc::c_int = 0;

        let ret = cvt(unsafe {
            sys::sctp_recvmsg(
                self.0.raw(),
                msg.as_mut_ptr() as *mut libc::c_void,
                cmp::min(msg.len(), fd::max_len()),
                &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr,
                &mut len,
                &mut info as *mut sys::sctp_sndrcvinfo,
                &mut flags
            )
        })?;

        let notification = if flags & sys::MSG_NOTIFICATION == sys::MSG_NOTIFICATION {
            let buf: &[u8] = &msg[0..(ret as usize)];
            notification_parse(buf)?
        } else {
            None
        };

        let addr = match sockaddr_to_addr(&storage, len as usize) {
            Ok(addr) => Some(addr),
            Err(_) => None
        };

        Ok((ret as usize, info.sinfo_stream, addr, notification))
    }

    pub fn sendmsg(&self, msg: &[u8], addr: Option<SocketAddr>, stream: u16, ttl: u32) -> io::Result<usize> {

        let (addrp, len) = match addr {
            Some(addr) => addr.into_inner(),
            None => (ptr::null(), 0)
        };

        let ret = cvt(unsafe {
            sys::sctp_sendmsg(
                self.0.raw(),
                msg.as_ptr() as *const libc::c_void,
                cmp::min(msg.len(), fd::max_len()),
                addrp,
                len,
                0,
                0,
                stream,
                ttl,
                0
            )
        })?;

        Ok(ret as usize)

    }

    pub fn set_timeout(&self, dur: Option<Duration>, kind: libc::c_int) -> io::Result<()> {
        let timeout = match dur {
            Some(dur) => {
                if dur.as_secs() == 0 && dur.subsec_nanos() == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "cannot set a 0 duration timeout"));
                }

                let secs = if dur.as_secs() > libc::time_t::max_value() as u64 {
                    libc::time_t::max_value()
                } else {
                    dur.as_secs() as libc::time_t
                };
                let mut timeout = libc::timeval {
                    tv_sec: secs,
                    tv_usec: (dur.subsec_nanos() / 1000) as libc::suseconds_t,
                };
                if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    timeout.tv_usec = 1;
                }
                timeout
            }
            None => {
                libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }
            }
        };
        self.setsockopt(libc::SOL_SOCKET, kind, timeout)
    }

    pub fn timeout(&self, kind: libc::c_int) -> io::Result<Option<Duration>> {
        let raw: libc::timeval = self.getsockopt(libc::SOL_SOCKET, kind)?;
        if raw.tv_sec == 0 && raw.tv_usec == 0 {
            Ok(None)
        } else {
            let sec = raw.tv_sec as u64;
            let nsec = (raw.tv_usec as u32) * 1000;
            Ok(Some(Duration::new(sec, nsec)))
        }
    }

    pub fn shutdown(&self) -> io::Result<()> {
        cvt(unsafe { libc::shutdown(self.0.raw(), libc::SHUT_RDWR) })?;
        Ok(())
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.setsockopt(sys::SOL_SCTP, sys::SCTP_NODELAY, nodelay as libc::c_int)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        let raw: libc::c_int = self.sctp_opt_info(sys::SCTP_NODELAY, 0)?;
        Ok(raw != 0)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = nonblocking as libc::c_int;
        cvt(unsafe { libc::ioctl(*self.as_inner(), libc::FIONBIO, &mut nonblocking) }).map(|_| ())
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: libc::c_int = self.getsockopt(libc::SOL_SOCKET, libc::SO_ERROR)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(io::Error::from_raw_os_error(raw as i32)))
        }
    }

    pub fn setsockopt<T>(&self, opt: libc::c_int, val: libc::c_int, payload: T) -> io::Result<()> {
        unsafe {
            let payload = &payload as *const T as *const libc::c_void;

            cvt(libc::setsockopt(
                *self.as_inner(),
                opt,
                val,
                payload,
                mem::size_of::<T>() as libc::socklen_t
            ))?;

            Ok(())
        }
    }

    pub fn getsockopt<T: Copy>(&self, opt: libc::c_int, val: libc::c_int) -> io::Result<T> {
        unsafe {
            let mut slot: T = mem::zeroed();
            let mut len = mem::size_of::<T>() as libc::socklen_t;

            cvt(libc::getsockopt(
                *self.as_inner(),
                opt,
                val,
                &mut slot as *mut T as *mut libc::c_void,
                &mut len
            ))?;

            assert_eq!(len as usize, mem::size_of::<T>());
            Ok(slot)
        }
    }

    pub fn sctp_opt_info<T>(&self, optname: libc::c_int, assoc: sys::sctp_assoc_t) -> io::Result<T> {
        unsafe {
            let mut val: T = mem::zeroed();
            let mut len = mem::size_of::<T>() as libc::socklen_t;

            cvt(sys::sctp_opt_info(*self.as_inner(), assoc, optname, mem::transmute(&mut val), &mut len))?;

            Ok(val)
        }
    }

    pub fn default_event_subscribe(&self) -> io::Result<()> {
        let mut subscribe: sys::sctp_event_subscribe = unsafe { mem::zeroed() };

        subscribe.sctp_data_io_event = 1;

        self.setsockopt(sys::IPPROTO_SCTP, sys::SCTP_EVENTS, subscribe)?;

        Ok(())
    }

    pub fn event_subsctibe(&self, event: Event) -> io::Result<()> {
        let mut subscribe: sys::sctp_event_subscribe = unsafe { mem::zeroed() };

        if event.contains(Event::data_io()) {
            subscribe.sctp_data_io_event = 1;
        }

        if event.contains(Event::association()) {
            subscribe.sctp_association_event = 1;
        }

        if event.contains(Event::address()) {
            subscribe.sctp_address_event = 1;
        }

        if event.contains(Event::send_failure()) {
            subscribe.sctp_send_failure_event = 1;
        }

        if event.contains(Event::peer_error()) {
            subscribe.sctp_peer_error_event = 1;
        }

        if event.contains(Event::shutdown()) {
            subscribe.sctp_shutdown_event = 1;
        }

        if event.contains(Event::partial_delivery()) {
            subscribe.sctp_partial_delivery_event = 1;
        }

        if event.contains(Event::adaptation_layer()) {
            subscribe.sctp_adaptation_layer_event = 1;
        }

        if event.contains(Event::authentication()) {
            subscribe.sctp_authentication_event = 1;
        }

        if event.contains(Event::sender_dry()) {
            subscribe.sctp_sender_dry_event = 1;
        }

        self.setsockopt(sys::IPPROTO_SCTP, sys::SCTP_EVENTS, subscribe)?;

        Ok(())
    }
}

impl AsInner<libc::c_int> for Socket {
    fn as_inner(&self) -> &libc::c_int { self.0.as_inner() }
}

impl FromInner<libc::c_int> for Socket {
    fn from_inner(fd: libc::c_int) -> Socket { Socket(FileDesc::new(fd)) }
}

impl IntoInner<libc::c_int> for Socket {
    fn into_inner(self) -> libc::c_int { self.0.into_raw() }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.0.raw()
    }
}

impl FromRawFd for Socket {
    unsafe fn from_raw_fd(fd: RawFd) -> Socket {
        Socket(FileDesc::new(fd))
    }
}
