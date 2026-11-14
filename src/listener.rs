use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

use crate::DEFAULT_BACKLOG;
use crate::addr;
use crate::socket::Socket;
use crate::stream::SctpStream;

/// An SCTP socket listening for associations (one-to-one style).
///
/// This is the SCTP counterpart of [`std::net::TcpListener`]: every accepted
/// association becomes its own [`SctpStream`].
///
/// # Examples
///
/// ```no_run
/// use sctp::SctpListener;
///
/// # fn main() -> std::io::Result<()> {
/// let listener = SctpListener::bind("0.0.0.0:0")?;
/// for accepted in listener.incoming() {
///     let (stream, peer) = accepted?;
///     println!("accepted association from {peer} on {:?}", stream.local_addr()?);
/// }
/// # Ok(())
/// # }
/// ```
pub struct SctpListener {
    inner: Socket,
}

impl SctpListener {
    pub(crate) fn socket(&self) -> &Socket {
        &self.inner
    }

    /// Binds to the first address `addr` resolves to that can be bound.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpListener> {
        let addrs = addr::resolve_all(addr)?;
        let mut last_error = None;

        for address in &addrs {
            let result = (|| {
                let socket = Socket::open(addr::family(address), libc::SOCK_STREAM)?;
                socket.bind(address)?;
                socket.listen(DEFAULT_BACKLOG)?;
                Ok(SctpListener { inner: socket })
            })();

            match result {
                Ok(listener) => return Ok(listener),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any addresses",
            )
        }))
    }

    /// Binds to every address in `addrs` (multi-homing).
    ///
    /// All addresses must belong to the same address family.
    pub fn bindx(addrs: &[SocketAddr]) -> io::Result<SctpListener> {
        let family = crate::single_family(addrs)?;
        let socket = Socket::open(family, libc::SOCK_STREAM)?;
        socket.bindx(addrs, true)?;
        socket.listen(DEFAULT_BACKLOG)?;
        Ok(SctpListener { inner: socket })
    }

    /// Accepts a new association.
    pub fn accept(&self) -> io::Result<(SctpStream, SocketAddr)> {
        let (socket, address) = self.inner.accept()?;
        Ok((SctpStream::from_socket(socket), address))
    }

    /// Returns an iterator over incoming associations.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns every bound address.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.inner.local_addrs(0)
    }

    /// Creates a new handle to the same socket.
    pub fn try_clone(&self) -> io::Result<SctpListener> {
        Ok(SctpListener {
            inner: self.inner.try_clone()?,
        })
    }
}

/// An iterator over incoming associations.
///
/// Created by [`SctpListener::incoming`].
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a SctpListener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<(SctpStream, SocketAddr)>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept())
    }
}

impl fmt::Debug for SctpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpListener")
            .field("local", &self.local_addr().ok())
            .field("fd", &self.inner.as_raw_fd())
            .finish()
    }
}

impl AsFd for SctpListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for SctpListener {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl FromRawFd for SctpListener {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpListener {
        SctpListener {
            inner: unsafe { Socket::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for SctpListener {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl From<OwnedFd> for SctpListener {
    fn from(fd: OwnedFd) -> SctpListener {
        SctpListener {
            inner: Socket::from(fd),
        }
    }
}

impl From<SctpListener> for OwnedFd {
    fn from(listener: SctpListener) -> OwnedFd {
        listener.inner.into()
    }
}

impl_common_socket_options!(SctpListener);
