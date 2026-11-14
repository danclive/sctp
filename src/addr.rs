use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::ptr;

use libc::{self, sockaddr_storage, socklen_t};

/// Converts a [`SocketAddr`] into the raw representation used by the kernel.
pub(crate) fn to_storage(addr: &SocketAddr) -> (sockaddr_storage, socklen_t) {
    let mut storage: sockaddr_storage = unsafe { mem::zeroed() };

    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe { ptr::write(ptr::addr_of_mut!(storage).cast(), sin) };
            (storage, mem::size_of::<libc::sockaddr_in>() as socklen_t)
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe { ptr::write(ptr::addr_of_mut!(storage).cast(), sin6) };
            (storage, mem::size_of::<libc::sockaddr_in6>() as socklen_t)
        }
    }
}

/// Reads the first sockaddr out of `storage`.
pub(crate) fn from_storage(storage: &sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin: libc::sockaddr_in = unsafe { ptr::read(ptr::from_ref(storage).cast()) };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            let sin6: libc::sockaddr_in6 = unsafe { ptr::read(ptr::from_ref(storage).cast()) };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported address family {family}"),
        )),
    }
}

/// The address family to pass to `socket(2)` for `addr`.
pub(crate) fn family(addr: &SocketAddr) -> libc::c_int {
    match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    }
}

/// The number of bytes an address occupies in a packed address list.
fn encoded_len(addr: &SocketAddr) -> usize {
    match addr {
        SocketAddr::V4(_) => mem::size_of::<libc::sockaddr_in>(),
        SocketAddr::V6(_) => mem::size_of::<libc::sockaddr_in6>(),
    }
}

/// Appends the wire representation of `addr` to `buf`.
///
/// Multi-homed operations (`bindx`, `connectx`) expect a buffer of
/// back-to-back `sockaddr`s.
pub(crate) fn encode(addr: &SocketAddr, buf: &mut Vec<u8>) {
    let (storage, len) = to_storage(addr);
    let bytes =
        unsafe { std::slice::from_raw_parts(ptr::from_ref(&storage).cast::<u8>(), len as usize) };
    buf.extend_from_slice(bytes);
}

/// Builds the packed address list expected by `bindx`/`connectx`.
pub(crate) fn encode_all(addrs: &[SocketAddr]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(addrs.iter().map(encoded_len).sum());
    for addr in addrs {
        encode(addr, &mut buf);
    }
    buf
}

/// Decodes one address from the head of `buf`, returning it and its length.
pub(crate) fn decode(buf: &[u8]) -> io::Result<(SocketAddr, usize)> {
    if buf.len() < mem::size_of::<libc::sa_family_t>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated socket address",
        ));
    }

    let family = u16::from_ne_bytes([buf[0], buf[1]]) as libc::c_int;
    let len = match family {
        libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
        family => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address family {family}"),
            ));
        }
    };

    if buf.len() < len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated socket address",
        ));
    }

    let mut storage: sockaddr_storage = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(buf.as_ptr(), ptr::addr_of_mut!(storage).cast::<u8>(), len);
    }

    Ok((from_storage(&storage)?, len))
}

/// Resolves `addrs` and removes duplicate addresses while keeping their order.
pub(crate) fn resolve_all<A: ToSocketAddrs>(addrs: A) -> io::Result<Vec<SocketAddr>> {
    let mut resolved = Vec::new();
    for addr in addrs.to_socket_addrs()? {
        if !resolved.contains(&addr) {
            resolved.push(addr);
        }
    }
    Ok(resolved)
}
