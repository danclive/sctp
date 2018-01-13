use std::net::{ToSocketAddrs, SocketAddr, Shutdown};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::mem;
use std::time::Duration;
use std::fmt;
use std::os::unix::io::{AsRawFd, RawFd, FromRawFd};

use libc;

use net::socket::Socket;
use net::socket::BindOp;
use net::addr::sockaddr_to_addr;
use net::addr::parse_addr;
use net::AsInner;
use net::event::Event;
use net::notification::Notification;

fn each_addr<A: ToSocketAddrs, F, T>(addr: A, mut f: F) -> io::Result<T>
    where F: FnMut(&SocketAddr) -> io::Result<T>
{
    let mut last_err = None;
    for addr in addr.to_socket_addrs()? {
        match f(&addr) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::new(ErrorKind::InvalidInput, "could not resolve to any addresses")
    }))
}

pub struct SctpStream(Socket);

impl SctpStream {
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<SctpStream> {
        let f = |addr: &SocketAddr| {
            let sock = Socket::new(addr, libc::SOCK_STREAM)?;

            sock.connect(addr)?;
            
            Ok(sock)
        };

        each_addr(addr, f).map(SctpStream)
    }

    pub fn connectx<A: ToSocketAddrs>(addrs: &[A]) -> io::Result<SctpStream>{
        if addrs.len() == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "No addresses given"));
        }

        let mut addrs2 = Vec::with_capacity(addrs.len());
        let mut family = libc::AF_INET;

        for addr in addrs {
            let addr = parse_addr(addr)?;

            if let SocketAddr::V6(..) = addr {
                family = libc::AF_INET6;
            }

            addrs2.push(addr);
        }

        let sock = Socket::new_raw(family, libc::SOCK_STREAM)?;

        sock.connectx(&addrs2)?;

        Ok(SctpStream(sock))
    }

    pub fn sendmsg(&self, msg: &[u8], stream: u16) -> io::Result<usize> {
        self.0.sendmsg(msg, None, stream, 0)
    }

    pub fn recvmsg(&self, msg: &mut [u8]) -> io::Result<(usize, u16, Option<Notification>)> {
        let (size, stream, _, notification) = self.0.recvmsg(msg)?;
        return Ok((size, stream, notification))
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs(0)
    }

    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.peer_addrs(0)
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_timeout(dur, libc::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.timeout(libc::SO_SNDTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_timeout(dur, libc::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.timeout(libc::SO_RCVTIMEO)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.0.nodelay()
    }

    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.0.setsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF, &(size as libc::c_int))
    }

    pub fn get_send_buffer_size(&self) -> io::Result<usize> {
        let raw: u32 = self.0.getsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF)?;
        Ok(raw as usize)
    }

    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.0.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF, &(size as libc::c_int))
    }

    pub fn get_recv_buffer_size(&self) -> io::Result<usize> {
        let raw: u32 = self.0.getsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
        Ok(raw as usize)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.0.setsockopt(libc::IPPROTO_IP, libc::IP_TTL, ttl as libc::c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: libc::c_int = self.0.getsockopt(libc::IPPROTO_IP, libc::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.peek(buf)
    }

    pub fn shutdown(&self, _: Shutdown) -> io::Result<()> {
        self.0.shutdown()
    }

    pub fn event_subsctibe(&self, event: Event) -> io::Result<()> {
        self.0.event_subsctibe(event)
    }

    pub fn try_clone(&self) -> io::Result<SctpStream> {
        Ok(SctpStream(self.0.duplicate()?))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }
}

impl Read for SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for SctpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> Read for &'a SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a> Write for &'a SctpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = f.debug_struct("SctpStream");

        if let Ok(addrs) = self.local_addrs() {
            res.field("local_addrs", &addrs);
        }

        if let Ok(addrs) = self.peer_addrs() {
            res.field("peer_addrs", &addrs);
        }

        res.field("fd", self.0.as_inner()).finish()
    }
}

impl AsRawFd for SctpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for SctpStream {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpStream {
        let sock = Socket::from_raw_fd(fd);
        SctpStream(sock)
    }
}

pub struct SctpListener(Socket);

impl SctpListener {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpListener> {
        let f = |addr: &SocketAddr| {
            let sock = Socket::new(addr, libc::SOCK_STREAM)?;

            sock.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;

            sock.bind(addr)?;

            sock.listen(128)?;

            Ok(sock)
        };

        each_addr(addr, f).map(SctpListener)
    }

    pub fn bindx<A: ToSocketAddrs>(addrs: &[A]) -> io::Result<SctpListener> {
        if addrs.len() == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "No addresses given"));
        }

        let mut addrs2 = Vec::with_capacity(addrs.len());
        let mut family = libc::AF_INET;

        for addr in addrs {
            let addr = parse_addr(addr)?;

            if let SocketAddr::V6(..) = addr {
                family = libc::AF_INET6;
            }

            addrs2.push(addr);
        }

        let sock = Socket::new_raw(family, libc::SOCK_STREAM)?;

        sock.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;

        sock.bindx(&addrs2, BindOp::AddAddr)?;

        sock.listen(128)?;

        Ok(SctpListener(sock))
    }

    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;

        let sock = self.0.accept(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr, &mut len)?;
        let addr = sockaddr_to_addr(&storage, len as usize)?;

        Ok((SctpStream(sock), addr))
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs(0)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.0.setsockopt(libc::IPPROTO_IP, libc::IP_TTL, ttl as libc::c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: libc::c_int = self.0.getsockopt(libc::IPPROTO_IP, libc::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    pub fn event_subsctibe(&self, event: Event) -> io::Result<()> {
        self.0.event_subsctibe(event)
    }

    pub fn try_clone(&self) -> io::Result<SctpListener> {
        Ok(SctpListener(self.0.duplicate()?))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }
}

impl AsRawFd for SctpListener {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for SctpListener {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpListener {
        let sock = Socket::from_raw_fd(fd);
        SctpListener(sock)
    }
}

pub struct SctpEndpoint(Socket);

impl SctpEndpoint {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpEndpoint> {
        let f = |addr: &SocketAddr| {
            let sock = Socket::new(addr, libc::SOCK_SEQPACKET)?;

            sock.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;

            sock.bind(addr)?;

            sock.listen(128)?;

            Ok(sock)
        };

        each_addr(addr, f).map(SctpEndpoint)
    }

    pub fn bindx<A: ToSocketAddrs>(addrs: &[A]) -> io::Result<SctpEndpoint> {
        if addrs.len() == 0 {
            return Err(Error::new(ErrorKind::InvalidInput, "No addresses given"));
        }

        let mut addrs2 = Vec::with_capacity(addrs.len());
        let mut family = libc::AF_INET;

        for addr in addrs {
            let addr = parse_addr(addr)?;

            if let SocketAddr::V6(..) = addr {
                family = libc::AF_INET6;
            }

            addrs2.push(addr);
        }

        let sock = Socket::new_raw(family, libc::SOCK_SEQPACKET)?;

        sock.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;

        sock.bindx(&addrs2, BindOp::AddAddr)?;

        sock.listen(128)?;

        Ok(SctpEndpoint(sock))
    }

    // pub fn new() -> io::Result<SctpEndpoint> {
    //     let sock = Socket::new_raw(family, libc::SOCK_SEQPACKET)?;

    //     sock.setsockopt(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;

    //     Ok(SctpEndpoint(sock))
    // }

    pub fn revc_from(&self, msg: &mut [u8]) -> io::Result<(usize, u16, Option<SocketAddr>, Option<Notification>)> {
        self.0.recvmsg(msg)
    }

    pub fn send_to<A: ToSocketAddrs>(&self, msg: &[u8], addr: A, stream: u16) -> io:: Result<usize> {
        let addr = parse_addr(addr)?;

        self.0.sendmsg(msg, Some(addr), stream, 0)
    }

    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.0.local_addrs(0)
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.0.set_nodelay(nodelay)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.0.nodelay()
    }

    pub fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.0.setsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF, &(size as libc::c_int))
    }

    pub fn get_send_buffer_size(&self) -> io::Result<usize> {
        let raw: u32 = self.0.getsockopt(libc::SOL_SOCKET, libc::SO_SNDBUF)?;
        Ok(raw as usize)
    }

    pub fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.0.setsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF, &(size as libc::c_int))
    }

    pub fn get_recv_buffer_size(&self) -> io::Result<usize> {
        let raw: u32 = self.0.getsockopt(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
        Ok(raw as usize)
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_timeout(dur, libc::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.timeout(libc::SO_SNDTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_timeout(dur, libc::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.0.timeout(libc::SO_RCVTIMEO)
    }

    pub fn event_subsctibe(&self, event: Event) -> io::Result<()> {
        self.0.event_subsctibe(event)
    }

    pub fn try_clone(&self) -> io::Result<SctpStream> {
        Ok(SctpStream(self.0.duplicate()?))
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.0.take_error()
    }
}

impl AsRawFd for SctpEndpoint {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl FromRawFd for SctpEndpoint {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpEndpoint {
        let sock = Socket::from_raw_fd(fd);
        SctpEndpoint(sock)
    }
}
