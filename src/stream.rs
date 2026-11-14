use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, ToSocketAddrs};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::Duration;

use crate::addr;
use crate::event::Event;
use crate::message::{Received, SendInfo};
use crate::notification::StreamResetFlags;
use crate::option::{
    AssocInfo, AssociationStats, DelayedSack, PeerAddressInfo, PeerAddressParams,
    PeerAddressThresholds, RtoInfo, StreamResetOptions, StreamScheduler,
};
use crate::socket::Socket;

/// A connected SCTP socket (one-to-one style, `SOCK_STREAM`).
///
/// A stream is a full SCTP association with a single peer. It behaves like
/// [`std::net::TcpStream`], but every write is a message that preserves its
/// boundaries, and each message carries a stream identifier and a payload
/// protocol identifier.
///
/// # Examples
///
/// ```no_run
/// use std::io::{Read, Write};
/// use sctp::{SctpListener, SctpStream};
///
/// # fn main() -> std::io::Result<()> {
/// let listener = SctpListener::bind("127.0.0.1:0")?;
/// let client = SctpStream::connect(listener.local_addr()?)?;
/// let (mut server, _) = listener.accept()?;
///
/// client.send(b"hello")?;
/// let mut buf = [0; 16];
/// let n = server.read(&mut buf)?;
/// assert_eq!(&buf[..n], b"hello");
/// # Ok(())
/// # }
/// ```
pub struct SctpStream {
    inner: Socket,
}

impl SctpStream {
    pub(crate) fn socket(&self) -> &Socket {
        &self.inner
    }

    pub(crate) fn from_socket(inner: Socket) -> SctpStream {
        SctpStream { inner }
    }

    /// Opens an SCTP association with the first address `addr` resolves to
    /// that accepts a connection.
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<SctpStream> {
        let addrs = addr::resolve_all(addr)?;
        let mut last_error = None;

        for address in &addrs {
            let result = (|| {
                let socket = Socket::open(addr::family(address), libc::SOCK_STREAM)?;
                socket.connect(address)?;
                Ok(SctpStream { inner: socket })
            })();

            match result {
                Ok(stream) => return Ok(stream),
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

    /// Opens an SCTP association with `addr`, failing if `timeout` elapses
    /// first.
    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<SctpStream> {
        let socket = Socket::open(addr::family(addr), libc::SOCK_STREAM)?;
        socket.connect_timeout(addr, timeout)?;
        Ok(SctpStream { inner: socket })
    }

    /// Opens an SCTP association using every address in `addrs` as a local
    /// destination of the same association (multi-homing).
    ///
    /// All addresses must belong to the same address family.
    pub fn connectx(addrs: &[SocketAddr]) -> io::Result<SctpStream> {
        let family = crate::single_family(addrs)?;
        let socket = Socket::open(family, libc::SOCK_STREAM)?;
        socket.connectx(addrs)?;
        Ok(SctpStream { inner: socket })
    }

    /// Returns the address of the peer.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }

    /// Returns the local address of the association.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns every local address of the association.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.inner.local_addrs(0)
    }

    /// Returns every peer address of the association.
    pub fn peer_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.inner.peer_addrs(0)
    }

    /// Adds local addresses to the association.
    pub fn add_local_addresses(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx(addrs, true)
    }

    /// Removes local addresses from the association.
    pub fn remove_local_addresses(&self, addrs: &[SocketAddr]) -> io::Result<()> {
        self.inner.bindx(addrs, false)
    }

    /// Sends a message on stream 0.
    ///
    /// The number of bytes accepted by the kernel is returned; SCTP either
    /// accepts a whole message or nothing at all.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf, None, None)
    }

    /// Sends a message with explicit per-message parameters.
    pub fn send_with(&self, buf: &[u8], info: &SendInfo) -> io::Result<usize> {
        self.inner.send(buf, None, Some(info))
    }

    /// Receives one message or notification.
    ///
    /// If `buf` is smaller than the message, the message is delivered in
    /// fragments and [`ReceivedData::complete`] is `false`; call `recv` again
    /// to obtain the rest.
    ///
    /// Notifications are also read through `buf`; [`Event::SEND_FAILURE`] can
    /// return the whole failed message, so use a buffer large enough when that
    /// event is enabled.
    ///
    /// [`ReceivedData::complete`]: crate::ReceivedData::complete
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        self.inner.recv(buf)
    }

    /// Returns the number of bytes that the next message occupies, without
    /// consuming it.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    /// Shuts the association down.
    ///
    /// SCTP only implements `SHUT_WR` and `SHUT_RDWR`; both initiate the
    /// graceful shutdown procedure.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };
        self.inner.shutdown(how)
    }

    /// Sets the read timeout.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(timeout, libc::SO_RCVTIMEO)
    }

    /// Returns the read timeout.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_RCVTIMEO)
    }

    /// Sets the write timeout.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(timeout, libc::SO_SNDTIMEO)
    }

    /// Returns the write timeout.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_SNDTIMEO)
    }

    /// Creates a new handle to the same socket.
    pub fn try_clone(&self) -> io::Result<SctpStream> {
        Ok(SctpStream {
            inner: self.inner.try_clone()?,
        })
    }

    // --- Association specific options ---------------------------------

    /// Returns the `SCTP_RTOINFO` parameters of the association.
    pub fn rto_info(&self) -> io::Result<RtoInfo> {
        self.inner.rto_info(0)
    }

    /// Sets the `SCTP_RTOINFO` parameters of the association.
    pub fn set_rto_info(&self, info: &RtoInfo) -> io::Result<()> {
        self.inner.set_rto_info(0, info)
    }

    /// Returns the `SCTP_ASSOCINFO` parameters of the association.
    pub fn assoc_info(&self) -> io::Result<AssocInfo> {
        self.inner.assoc_info(0)
    }

    /// Sets the writable `SCTP_ASSOCINFO` parameters of the association.
    pub fn set_assoc_info(&self, info: &AssocInfo) -> io::Result<()> {
        self.inner.set_assoc_info(0, info)
    }

    /// Returns the maximum fragment size.
    pub fn max_segment(&self) -> io::Result<u32> {
        self.inner.max_segment(0)
    }

    /// Sets the maximum fragment size; 0 restores the default.
    pub fn set_max_segment(&self, max_segment: u32) -> io::Result<()> {
        self.inner.set_max_segment(0, max_segment)
    }

    /// Returns the default context used when no [`SendInfo`] is supplied.
    pub fn context(&self) -> io::Result<u32> {
        self.inner.context(0)
    }

    /// Sets the default context.
    pub fn set_context(&self, context: u32) -> io::Result<()> {
        self.inner.set_context(0, context)
    }

    /// Returns the maximum burst size.
    pub fn max_burst(&self) -> io::Result<u32> {
        self.inner.max_burst(0)
    }

    /// Sets the maximum burst size.
    pub fn set_max_burst(&self, max_burst: u32) -> io::Result<()> {
        self.inner.set_max_burst(0, max_burst)
    }

    /// Returns the delayed `SACK` parameters.
    pub fn delayed_sack(&self) -> io::Result<DelayedSack> {
        self.inner.delayed_sack(0)
    }

    /// Sets the delayed `SACK` parameters.
    pub fn set_delayed_sack(&self, params: &DelayedSack) -> io::Result<()> {
        self.inner.set_delayed_sack(0, params)
    }

    /// Returns the parameters of a peer address, or of the primary address.
    pub fn peer_addr_params(&self, addr: Option<&SocketAddr>) -> io::Result<PeerAddressParams> {
        self.inner.peer_addr_params(0, addr)
    }

    /// Sets the parameters of a peer address, or of every peer address.
    pub fn set_peer_addr_params(
        &self,
        addr: Option<&SocketAddr>,
        params: &PeerAddressParams,
    ) -> io::Result<()> {
        self.inner.set_peer_addr_params(0, addr, params)
    }

    /// Returns the retransmission thresholds of a peer address.
    pub fn peer_addr_thresholds(
        &self,
        addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddressThresholds> {
        self.inner.peer_addr_thresholds(0, addr)
    }

    /// Sets the retransmission thresholds of a peer address.
    pub fn set_peer_addr_thresholds(
        &self,
        addr: Option<&SocketAddr>,
        thresholds: &PeerAddressThresholds,
    ) -> io::Result<()> {
        self.inner.set_peer_addr_thresholds(0, addr, thresholds)
    }

    /// Returns the primary peer address.
    pub fn primary_addr(&self) -> io::Result<SocketAddr> {
        self.inner.primary_addr(0)
    }

    /// Sets the primary peer address.
    pub fn set_primary_addr(&self, addr: &SocketAddr) -> io::Result<()> {
        self.inner.set_primary_addr(0, addr)
    }

    /// Asks the peer to use `addr` as its primary address.
    pub fn set_peer_primary_addr(&self, addr: &SocketAddr) -> io::Result<()> {
        self.inner.set_peer_primary_addr(0, addr)
    }

    /// Returns the status of the association.
    pub fn status(&self) -> io::Result<crate::AssociationStatus> {
        self.inner.status(0)
    }

    /// Returns information about a peer address.
    pub fn peer_addr_info(&self, addr: &SocketAddr) -> io::Result<PeerAddressInfo> {
        self.inner.peer_addr_info(0, addr)
    }

    /// Returns the statistics of the association.
    pub fn assoc_stats(&self) -> io::Result<AssociationStats> {
        self.inner.assoc_stats(0)
    }

    /// Returns the default parameters used when no [`SendInfo`] is supplied.
    pub fn default_send_info(&self) -> io::Result<SendInfo> {
        self.inner.default_send_info(0)
    }

    /// Sets the default parameters used when no [`SendInfo`] is supplied.
    pub fn set_default_send_info(&self, info: &SendInfo) -> io::Result<()> {
        self.inner.set_default_send_info(0, info)
    }

    /// Returns the stream scheduler of the association.
    pub fn stream_scheduler(&self) -> io::Result<StreamScheduler> {
        self.inner.stream_scheduler(0)
    }

    /// Sets the stream scheduler of the association.
    pub fn set_stream_scheduler(&self, scheduler: StreamScheduler) -> io::Result<()> {
        self.inner.set_stream_scheduler(0, scheduler)
    }

    /// Sets the scheduler value of a stream.
    pub fn set_stream_scheduler_value(&self, stream_id: u16, value: u16) -> io::Result<()> {
        self.inner.set_stream_scheduler_value(0, stream_id, value)
    }

    /// Enables inbound stream reconfiguration requests.
    pub fn enable_stream_reset(&self, options: StreamResetOptions) -> io::Result<()> {
        self.inner.enable_stream_reset(0, options)
    }

    /// Resets the given streams.
    pub fn reset_streams(&self, flags: StreamResetFlags, streams: &[u16]) -> io::Result<()> {
        self.inner.reset_streams(0, flags, streams)
    }

    /// Resets the association.
    pub fn reset_association(&self) -> io::Result<()> {
        self.inner.reset_association(0)
    }

    /// Adds inbound and outbound streams to the association.
    pub fn add_streams(&self, inbound: u16, outbound: u16) -> io::Result<()> {
        self.inner.add_streams(0, inbound, outbound)
    }

    /// Returns whether `event` is enabled for the association.
    pub fn event(&self, event: Event) -> io::Result<bool> {
        self.inner.event(0, event)
    }

    /// Enables or disables a single event for the association.
    pub fn set_event(&self, event: Event, enable: bool) -> io::Result<()> {
        self.inner.set_event(0, event, enable)
    }
}

impl Read for SctpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Read for &SctpStream {
    /// Receives a message, discarding notifications.
    ///
    /// Use [`SctpStream::recv`] if notifications need to be observed.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.inner.recv(buf)? {
                Received::Data(data) => return Ok(data.len),
                Received::Notification(_) => continue,
            }
        }
    }
}

impl Write for SctpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &SctpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.send(buf, None, None)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for SctpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpStream")
            .field("local", &self.local_addr().ok())
            .field("peer", &self.peer_addr().ok())
            .field("fd", &self.inner.as_raw_fd())
            .finish()
    }
}

impl AsFd for SctpStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for SctpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl FromRawFd for SctpStream {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpStream {
        SctpStream {
            inner: unsafe { Socket::from_raw_fd(fd) },
        }
    }
}

impl IntoRawFd for SctpStream {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl From<OwnedFd> for SctpStream {
    fn from(fd: OwnedFd) -> SctpStream {
        SctpStream {
            inner: Socket::from(fd),
        }
    }
}

impl From<SctpStream> for OwnedFd {
    fn from(stream: SctpStream) -> OwnedFd {
        stream.inner.into()
    }
}

impl_common_socket_options!(SctpStream);
