use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};

use crate::addr;
use crate::event::Event;
use crate::message::{MessageFlags, Received, RecvInfo, SendInfo};
use crate::notification::StreamResetFlags;
use crate::option::{
    AssocInfo, AssociationStats, DelayedSack, PeerAddressInfo, PeerAddressParams,
    PeerAddressThresholds, RtoInfo, StreamResetOptions, StreamScheduler,
};
use crate::socket::Socket;
use crate::stream::SctpStream;
use crate::{AssociationId, DEFAULT_BACKLOG};

/// An SCTP endpoint in one-to-many style (`SOCK_SEQPACKET`).
///
/// A single endpoint multiplexes any number of associations. Incoming
/// associations are reported through [`Event::ASSOCIATION`] notifications, and
/// outgoing ones are created with [`connect`](SctpEndpoint::connect) or
/// implicitly by [`send_to`](SctpEndpoint::send_to). Every association is
/// identified by an [`AssociationId`].
///
/// # Examples
///
/// ```no_run
/// use sctp::{Event, Received, SendInfo, SctpEndpoint};
///
/// # fn main() -> std::io::Result<()> {
/// let server = SctpEndpoint::bind("127.0.0.1:0")?;
/// server.set_events(Event::ASSOCIATION)?;
///
/// let client = SctpEndpoint::bind("127.0.0.1:0")?;
/// let assoc = client.connect(server.local_addr()?)?;
/// client.send_with(b"hello", &SendInfo::new(1))?;
///
/// let mut buf = [0; 64];
/// loop {
///     match server.recv(&mut buf)? {
///         Received::Data(data) => {
///             println!("got {:?} on stream {}", &buf[..data.len], data.info.stream_id);
///             break;
///         }
///         Received::Notification(notification) => println!("{notification:?}"),
///     }
/// }
/// # let _ = assoc;
/// # Ok(())
/// # }
/// ```
pub struct SctpEndpoint {
    inner: Socket,
    default_association: AtomicI32,
}

impl SctpEndpoint {
    pub(crate) fn socket(&self) -> &Socket {
        &self.inner
    }

    /// Binds to the first address `addr` resolves to that can be bound.
    ///
    /// The socket is put into listening mode so that it accepts associations.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<SctpEndpoint> {
        let addrs = addr::resolve_all(addr)?;
        let mut last_error = None;

        for address in &addrs {
            let result = (|| {
                let socket = Socket::open(addr::family(address), libc::SOCK_SEQPACKET)?;
                socket.bind(address)?;
                socket.listen(DEFAULT_BACKLOG)?;
                Ok(SctpEndpoint::from_socket(socket))
            })();

            match result {
                Ok(endpoint) => return Ok(endpoint),
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
    pub fn bindx(addrs: &[SocketAddr]) -> io::Result<SctpEndpoint> {
        let family = crate::single_family(addrs)?;
        let socket = Socket::open(family, libc::SOCK_SEQPACKET)?;
        socket.bindx(addrs, true)?;
        socket.listen(DEFAULT_BACKLOG)?;
        Ok(SctpEndpoint::from_socket(socket))
    }

    fn from_socket(socket: Socket) -> SctpEndpoint {
        SctpEndpoint {
            inner: socket,
            default_association: AtomicI32::new(0),
        }
    }

    /// Creates a new handle to the same socket.
    ///
    /// The current default association is copied to the new handle; changing
    /// it on one handle does not affect the other.
    pub fn try_clone(&self) -> io::Result<SctpEndpoint> {
        Ok(SctpEndpoint {
            inner: self.inner.try_clone()?,
            default_association: AtomicI32::new(self.default_association()),
        })
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Returns the bound addresses, or the local addresses of `association_id`
    /// when it is not 0.
    pub fn local_addrs(&self, association_id: AssociationId) -> io::Result<Vec<SocketAddr>> {
        self.inner.local_addrs(association_id)
    }

    /// Returns the peer addresses of an association.
    pub fn peer_addrs(&self, association_id: AssociationId) -> io::Result<Vec<SocketAddr>> {
        self.inner.peer_addrs(association_id)
    }

    /// Returns the identifiers of all associations of this endpoint.
    pub fn association_ids(&self) -> io::Result<Vec<AssociationId>> {
        self.inner.association_ids()
    }

    /// Returns the number of associations of this endpoint.
    pub fn association_count(&self) -> io::Result<u32> {
        self.inner.assoc_number()
    }

    /// The association used by [`send`](SctpEndpoint::send) when no
    /// association is supplied.
    pub fn default_association(&self) -> AssociationId {
        self.default_association.load(Ordering::Relaxed)
    }

    /// Establishes an association with the first address `addr` resolves to
    /// that accepts it.
    ///
    /// The association becomes the default one used by
    /// [`send`](SctpEndpoint::send).
    pub fn connect<A: ToSocketAddrs>(&self, addr: A) -> io::Result<AssociationId> {
        let addrs = addr::resolve_all(addr)?;
        let mut last_error = None;

        for address in &addrs {
            match self.inner.connectx(&[*address]) {
                Ok(association_id) => {
                    self.default_association
                        .store(association_id, Ordering::Relaxed);
                    return Ok(association_id);
                }
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

    /// Establishes an association using every address in `addrs`
    /// (multi-homing).
    ///
    /// All addresses must belong to the same address family. The association
    /// becomes the default one used by [`send`](SctpEndpoint::send).
    pub fn connectx(&self, addrs: &[SocketAddr]) -> io::Result<AssociationId> {
        let association_id = self.inner.connectx(addrs)?;
        self.default_association
            .store(association_id, Ordering::Relaxed);
        Ok(association_id)
    }

    /// Sends a message on the default association.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.send_with(buf, &SendInfo::default())
    }

    /// Sends a message with explicit per-message parameters.
    ///
    /// The association is taken from
    /// [`SendInfo::association_id`], falling back to the default association.
    pub fn send_with(&self, buf: &[u8], info: &SendInfo) -> io::Result<usize> {
        if info.association_id != 0 {
            return self.inner.send(buf, None, Some(info));
        }

        let association_id = self.default_association();
        if association_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no default association",
            ));
        }
        self.inner.send(
            buf,
            None,
            Some(&SendInfo {
                association_id,
                ..*info
            }),
        )
    }

    /// Sends a message to `addr`, creating an association when necessary.
    pub fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], addr: A) -> io::Result<usize> {
        self.send_to_with(buf, addr, &SendInfo::default())
    }

    /// Sends a message to `addr` with explicit per-message parameters.
    pub fn send_to_with<A: ToSocketAddrs>(
        &self,
        buf: &[u8],
        addr: A,
        info: &SendInfo,
    ) -> io::Result<usize> {
        let addr = crate::first_addr(addr)?;
        self.inner.send(buf, Some(&addr), Some(info))
    }

    /// Returns the number of bytes that the next message occupies, without
    /// consuming it.
    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    /// Sets the read timeout.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_timeout(timeout, libc::SO_RCVTIMEO)
    }

    /// Returns the read timeout.
    pub fn read_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.timeout(libc::SO_RCVTIMEO)
    }

    /// Sets the write timeout.
    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.inner.set_timeout(timeout, libc::SO_SNDTIMEO)
    }

    /// Returns the write timeout.
    pub fn write_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.inner.timeout(libc::SO_SNDTIMEO)
    }

    /// Receives one message or notification.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        self.inner.recv(buf)
    }

    /// Receives a data message, returning its length, source address and
    /// per-message information.
    ///
    /// Notifications are discarded; use [`recv`](SctpEndpoint::recv) to
    /// observe them.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, RecvInfo)> {
        loop {
            match self.inner.recv(buf)? {
                Received::Data(data) => {
                    let address = data.address.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "received message without a source address",
                        )
                    })?;
                    return Ok((data.len, address, data.info));
                }
                Received::Notification(_) => continue,
            }
        }
    }

    /// Turns an association into its own one-to-one socket.
    ///
    /// After a successful peel-off the association is no longer served by the
    /// endpoint.
    pub fn peeloff(&self, association_id: AssociationId) -> io::Result<SctpStream> {
        let stream = SctpStream::from_socket(self.inner.peeloff(association_id)?);
        if self.default_association() == association_id {
            self.default_association.store(0, Ordering::Relaxed);
        }
        Ok(stream)
    }

    /// Gracefully shuts an association down.
    pub fn shutdown(&self, association_id: AssociationId) -> io::Result<()> {
        let info = SendInfo {
            flags: MessageFlags::EOF,
            association_id,
            ..SendInfo::default()
        };
        self.inner.send(&[], None, Some(&info))?;
        Ok(())
    }

    /// Aborts an association.
    pub fn abort(&self, association_id: AssociationId) -> io::Result<()> {
        let info = SendInfo {
            flags: MessageFlags::ABORT,
            association_id,
            ..SendInfo::default()
        };
        self.inner.send(&[], None, Some(&info))?;
        Ok(())
    }

    /// Returns the identifier of the association that `addr` belongs to.
    pub fn association_id(&self, addr: &SocketAddr) -> io::Result<AssociationId> {
        for id in self.association_ids()? {
            if self.peer_addrs(id)?.contains(addr) {
                return Ok(id);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no association for the given address",
        ))
    }

    // --- Association specific options ---------------------------------

    /// Returns the `SCTP_RTOINFO` parameters of an association.
    pub fn rto_info(&self, association_id: AssociationId) -> io::Result<RtoInfo> {
        self.inner.rto_info(association_id)
    }

    /// Sets the `SCTP_RTOINFO` parameters of an association.
    pub fn set_rto_info(&self, association_id: AssociationId, info: &RtoInfo) -> io::Result<()> {
        self.inner.set_rto_info(association_id, info)
    }

    /// Returns the `SCTP_ASSOCINFO` parameters of an association.
    pub fn assoc_info(&self, association_id: AssociationId) -> io::Result<AssocInfo> {
        self.inner.assoc_info(association_id)
    }

    /// Sets the writable `SCTP_ASSOCINFO` parameters of an association.
    pub fn set_assoc_info(
        &self,
        association_id: AssociationId,
        info: &AssocInfo,
    ) -> io::Result<()> {
        self.inner.set_assoc_info(association_id, info)
    }

    /// Returns the maximum fragment size of an association.
    pub fn max_segment(&self, association_id: AssociationId) -> io::Result<u32> {
        self.inner.max_segment(association_id)
    }

    /// Sets the maximum fragment size of an association.
    pub fn set_max_segment(
        &self,
        association_id: AssociationId,
        max_segment: u32,
    ) -> io::Result<()> {
        self.inner.set_max_segment(association_id, max_segment)
    }

    /// Returns the default context of an association.
    pub fn context(&self, association_id: AssociationId) -> io::Result<u32> {
        self.inner.context(association_id)
    }

    /// Sets the default context of an association.
    pub fn set_context(&self, association_id: AssociationId, context: u32) -> io::Result<()> {
        self.inner.set_context(association_id, context)
    }

    /// Returns the maximum burst size of an association.
    pub fn max_burst(&self, association_id: AssociationId) -> io::Result<u32> {
        self.inner.max_burst(association_id)
    }

    /// Sets the maximum burst size of an association.
    pub fn set_max_burst(&self, association_id: AssociationId, max_burst: u32) -> io::Result<()> {
        self.inner.set_max_burst(association_id, max_burst)
    }

    /// Returns the delayed `SACK` parameters of an association.
    pub fn delayed_sack(&self, association_id: AssociationId) -> io::Result<DelayedSack> {
        self.inner.delayed_sack(association_id)
    }

    /// Sets the delayed `SACK` parameters of an association.
    pub fn set_delayed_sack(
        &self,
        association_id: AssociationId,
        params: &DelayedSack,
    ) -> io::Result<()> {
        self.inner.set_delayed_sack(association_id, params)
    }

    /// Returns the parameters of one peer address of an association.
    pub fn peer_addr_params(
        &self,
        association_id: AssociationId,
        addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddressParams> {
        self.inner.peer_addr_params(association_id, addr)
    }

    /// Sets the parameters of one peer address of an association.
    pub fn set_peer_addr_params(
        &self,
        association_id: AssociationId,
        addr: Option<&SocketAddr>,
        params: &PeerAddressParams,
    ) -> io::Result<()> {
        self.inner
            .set_peer_addr_params(association_id, addr, params)
    }

    /// Returns the retransmission thresholds of a peer address.
    pub fn peer_addr_thresholds(
        &self,
        association_id: AssociationId,
        addr: Option<&SocketAddr>,
    ) -> io::Result<PeerAddressThresholds> {
        self.inner.peer_addr_thresholds(association_id, addr)
    }

    /// Sets the retransmission thresholds of a peer address.
    pub fn set_peer_addr_thresholds(
        &self,
        association_id: AssociationId,
        addr: Option<&SocketAddr>,
        thresholds: &PeerAddressThresholds,
    ) -> io::Result<()> {
        self.inner
            .set_peer_addr_thresholds(association_id, addr, thresholds)
    }

    /// Returns the primary peer address of an association.
    pub fn primary_addr(&self, association_id: AssociationId) -> io::Result<SocketAddr> {
        self.inner.primary_addr(association_id)
    }

    /// Sets the primary peer address of an association.
    pub fn set_primary_addr(
        &self,
        association_id: AssociationId,
        addr: &SocketAddr,
    ) -> io::Result<()> {
        self.inner.set_primary_addr(association_id, addr)
    }

    /// Asks the peer to use `addr` as its primary address.
    pub fn set_peer_primary_addr(
        &self,
        association_id: AssociationId,
        addr: &SocketAddr,
    ) -> io::Result<()> {
        self.inner.set_peer_primary_addr(association_id, addr)
    }

    /// Returns the status of an association.
    pub fn status(&self, association_id: AssociationId) -> io::Result<crate::AssociationStatus> {
        self.inner.status(association_id)
    }

    /// Returns information about one peer address of an association.
    pub fn peer_addr_info(
        &self,
        association_id: AssociationId,
        addr: &SocketAddr,
    ) -> io::Result<PeerAddressInfo> {
        self.inner.peer_addr_info(association_id, addr)
    }

    /// Returns the statistics of an association.
    pub fn assoc_stats(&self, association_id: AssociationId) -> io::Result<AssociationStats> {
        self.inner.assoc_stats(association_id)
    }

    /// Returns the default per-message parameters of an association.
    pub fn default_send_info(&self, association_id: AssociationId) -> io::Result<SendInfo> {
        self.inner.default_send_info(association_id)
    }

    /// Sets the default per-message parameters of an association.
    pub fn set_default_send_info(
        &self,
        association_id: AssociationId,
        info: &SendInfo,
    ) -> io::Result<()> {
        self.inner.set_default_send_info(association_id, info)
    }

    /// Returns the stream scheduler of an association.
    pub fn stream_scheduler(&self, association_id: AssociationId) -> io::Result<StreamScheduler> {
        self.inner.stream_scheduler(association_id)
    }

    /// Sets the stream scheduler of an association.
    pub fn set_stream_scheduler(
        &self,
        association_id: AssociationId,
        scheduler: StreamScheduler,
    ) -> io::Result<()> {
        self.inner.set_stream_scheduler(association_id, scheduler)
    }

    /// Sets the scheduler value of a stream.
    pub fn set_stream_scheduler_value(
        &self,
        association_id: AssociationId,
        stream_id: u16,
        value: u16,
    ) -> io::Result<()> {
        self.inner
            .set_stream_scheduler_value(association_id, stream_id, value)
    }

    /// Enables inbound stream reconfiguration requests.
    pub fn enable_stream_reset(
        &self,
        association_id: AssociationId,
        options: StreamResetOptions,
    ) -> io::Result<()> {
        self.inner.enable_stream_reset(association_id, options)
    }

    /// Resets streams of an association.
    pub fn reset_streams(
        &self,
        association_id: AssociationId,
        flags: StreamResetFlags,
        streams: &[u16],
    ) -> io::Result<()> {
        self.inner.reset_streams(association_id, flags, streams)
    }

    /// Resets an association.
    pub fn reset_association(&self, association_id: AssociationId) -> io::Result<()> {
        self.inner.reset_association(association_id)
    }

    /// Adds inbound and outbound streams to an association.
    pub fn add_streams(
        &self,
        association_id: AssociationId,
        inbound: u16,
        outbound: u16,
    ) -> io::Result<()> {
        self.inner.add_streams(association_id, inbound, outbound)
    }

    /// Returns whether `event` is enabled for an association.
    pub fn event(&self, association_id: AssociationId, event: Event) -> io::Result<bool> {
        self.inner.event(association_id, event)
    }

    /// Enables or disables a single event for an association.
    pub fn set_event(
        &self,
        association_id: AssociationId,
        event: Event,
        enable: bool,
    ) -> io::Result<()> {
        self.inner.set_event(association_id, event, enable)
    }

    /// Returns the idle timeout after which associations are closed
    /// automatically.
    pub fn autoclose(&self) -> io::Result<u32> {
        self.inner.autoclose()
    }

    /// Sets the idle timeout after which associations are closed
    /// automatically; 0 disables automatic closing.
    pub fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        self.inner.set_autoclose(seconds)
    }
}

impl fmt::Debug for SctpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SctpEndpoint")
            .field("local", &self.local_addr().ok())
            .field("associations", &self.association_ids().ok())
            .field("default_association", &self.default_association())
            .field("fd", &self.inner.as_raw_fd())
            .finish()
    }
}

impl AsFd for SctpEndpoint {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl AsRawFd for SctpEndpoint {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl FromRawFd for SctpEndpoint {
    unsafe fn from_raw_fd(fd: RawFd) -> SctpEndpoint {
        SctpEndpoint::from_socket(unsafe { Socket::from_raw_fd(fd) })
    }
}

impl IntoRawFd for SctpEndpoint {
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl From<OwnedFd> for SctpEndpoint {
    fn from(fd: OwnedFd) -> SctpEndpoint {
        SctpEndpoint::from_socket(Socket::from(fd))
    }
}

impl From<SctpEndpoint> for OwnedFd {
    fn from(endpoint: SctpEndpoint) -> OwnedFd {
        endpoint.inner.into()
    }
}

impl_common_socket_options!(SctpEndpoint);
