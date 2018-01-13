use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::mem;
use std::io::{self, Error, ErrorKind};

use libc;

use net::{FromInner, IntoInner};

struct SocketAddrV42 {
    pub inner: libc::sockaddr_in
}

struct SocketAddrV62 {
    pub inner: libc::sockaddr_in6
}

impl FromInner<libc::sockaddr_in> for SocketAddrV4 {
    fn from_inner(addr: libc::sockaddr_in) -> SocketAddrV4 {
        unsafe {
            mem::transmute(SocketAddrV42 { inner: addr })
        }
    }
}

impl FromInner<libc::sockaddr_in6> for SocketAddrV6 {
    fn from_inner(addr: libc::sockaddr_in6) -> SocketAddrV6 {
        unsafe {
            mem::transmute(SocketAddrV62 { inner: addr })
        }
    }
}

impl<'a> IntoInner<(*const libc::sockaddr, libc::socklen_t)> for &'a SocketAddr {
    fn into_inner(self) -> (*const libc::sockaddr, libc::socklen_t) {
        match *self {
            SocketAddr::V4(ref a) => {
                (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t)
            }
            SocketAddr::V6(ref a) => {
                (a as *const _ as *const _, mem::size_of_val(a) as libc::socklen_t)
            }
        }
    }
}

pub fn sockaddr_to_addr(storage: &libc::sockaddr_storage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in>());
            Ok(SocketAddr::V4(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const libc::sockaddr_in)
            })))
        }
        libc::AF_INET6 => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in6>());
            Ok(SocketAddr::V6(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const libc::sockaddr_in6)
            })))
        }
        _ => {
            Err(Error::new(ErrorKind::Other, "Cannot retrieve addresses"))
        }
    }
}

pub fn parse_addr<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    addr.to_socket_addrs()?.next().ok_or(Error::new(ErrorKind::InvalidInput, "Address is not valid"))
}
