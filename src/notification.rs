use std::io;
use std::mem::size_of;
use std::net::SocketAddr;
use std::ptr;
use std::time::Duration;

use crate::AssociationId;
use crate::MessageFlags;
use crate::SendInfo;
use crate::addr;
use crate::sys;

/// A notification delivered by the SCTP stack.
///
/// Notifications share the receive path with data messages; they are only
/// generated for events the socket subscribed to with
/// [`set_events`](crate::SctpStream::set_events).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Notification {
    /// An association was established, restarted or lost.
    AssociationChange(AssociationChange),
    /// One of the peer's addresses changed state.
    PeerAddressChange(PeerAddressChange),
    /// A message could not be delivered (`SCTP_SEND_FAILED`).
    SendFailed(SendFailed),
    /// The peer reported an error.
    RemoteError(RemoteError),
    /// The peer initiated a graceful shutdown.
    Shutdown(ShutdownEvent),
    /// A partial delivery was aborted.
    PartialDelivery(PartialDeliveryEvent),
    /// The peer's adaptation layer indication.
    Adaptation(AdaptationEvent),
    /// An authentication key change.
    Authentication(AuthenticationEvent),
    /// The send queue has emptied.
    SenderDry(SenderDryEvent),
    /// Stream reset requests completed.
    StreamReset(StreamResetEvent),
    /// An association reset request completed.
    AssociationReset(AssociationResetEvent),
    /// Streams were added to the association.
    StreamChange(StreamChangeEvent),
    /// A message could not be delivered (`SCTP_SEND_FAILED_EVENT`).
    SendFailedEvent(SendFailedEvent),
}

impl Notification {
    /// The association this notification belongs to.
    pub fn association_id(&self) -> AssociationId {
        match self {
            Notification::AssociationChange(n) => n.association_id,
            Notification::PeerAddressChange(n) => n.association_id,
            Notification::SendFailed(n) => n.association_id,
            Notification::RemoteError(n) => n.association_id,
            Notification::Shutdown(n) => n.association_id,
            Notification::PartialDelivery(n) => n.association_id,
            Notification::Adaptation(n) => n.association_id,
            Notification::Authentication(n) => n.association_id,
            Notification::SenderDry(n) => n.association_id,
            Notification::StreamReset(n) => n.association_id,
            Notification::AssociationReset(n) => n.association_id,
            Notification::StreamChange(n) => n.association_id,
            Notification::SendFailedEvent(n) => n.association_id,
        }
    }
}

/// State reported by [`AssociationChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssociationState {
    /// The association is now up and can carry data.
    CommUp,
    /// The association was lost.
    CommLost,
    /// The peer restarted the association.
    Restart,
    /// A graceful shutdown completed.
    ShutdownComplete,
    /// The association could not be established.
    CantStartAssociation,
    /// A state this crate does not know about.
    Unknown(u16),
}

impl AssociationState {
    fn from_raw(state: u16) -> AssociationState {
        match state {
            0 => AssociationState::CommUp,
            1 => AssociationState::CommLost,
            2 => AssociationState::Restart,
            3 => AssociationState::ShutdownComplete,
            4 => AssociationState::CantStartAssociation,
            other => AssociationState::Unknown(other),
        }
    }
}

/// An SCTP protocol error cause.
///
/// See RFC 4960 section 3.3.10 for the meaning of each cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCause {
    /// Invalid stream identifier.
    InvalidStreamIdentifier,
    /// A mandatory parameter is missing.
    MissingMandatoryParameter,
    /// The state cookie has expired.
    StaleCookie,
    /// The endpoint is out of resources.
    OutOfResources,
    /// An address could not be resolved.
    UnresolvableAddress,
    /// An unrecognized chunk type was received.
    UnrecognizedChunkType,
    /// A mandatory parameter has an invalid value.
    InvalidMandatoryParameter,
    /// Unrecognized parameters were received.
    UnrecognizedParameters,
    /// A `DATA` chunk without user data was received.
    NoUserData,
    /// A `COOKIE ECHO` arrived while shutting down.
    CookieReceivedWhileShuttingDown,
    /// The association restarts with new addresses.
    RestartWithNewAddresses,
    /// The user aborted the association.
    UserInitiatedAbort,
    /// The peer violated the protocol.
    ProtocolViolation,
    /// A cause this crate does not know about.
    Unknown(u16),
}

impl ErrorCause {
    /// Decodes a cause code, where 0 means "no error".
    pub fn from_raw(cause: u16) -> Option<ErrorCause> {
        match cause {
            0 => None,
            1 => Some(ErrorCause::InvalidStreamIdentifier),
            2 => Some(ErrorCause::MissingMandatoryParameter),
            3 => Some(ErrorCause::StaleCookie),
            4 => Some(ErrorCause::OutOfResources),
            5 => Some(ErrorCause::UnresolvableAddress),
            6 => Some(ErrorCause::UnrecognizedChunkType),
            7 => Some(ErrorCause::InvalidMandatoryParameter),
            8 => Some(ErrorCause::UnrecognizedParameters),
            9 => Some(ErrorCause::NoUserData),
            10 => Some(ErrorCause::CookieReceivedWhileShuttingDown),
            11 => Some(ErrorCause::RestartWithNewAddresses),
            12 => Some(ErrorCause::UserInitiatedAbort),
            13 => Some(ErrorCause::ProtocolViolation),
            other => Some(ErrorCause::Unknown(other)),
        }
    }
}

/// An association state change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationChange {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// The new state.
    pub state: AssociationState,
    /// The protocol error cause, if the state change was caused by one.
    pub error: Option<ErrorCause>,
    /// Number of outbound streams negotiated.
    pub outbound_streams: u16,
    /// Number of inbound streams negotiated.
    pub inbound_streams: u16,
    /// Additional data supplied by the peer, for example the abort reason.
    pub data: Vec<u8>,
}

/// State reported by [`PeerAddressChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerAddressState {
    /// The address is reachable again.
    Available,
    /// The address is considered unreachable.
    Unreachable,
    /// The peer removed the address from the association.
    Removed,
    /// The peer added the address to the association.
    Added,
    /// The address became the primary destination.
    MadePrimary,
    /// The address was confirmed by a heartbeat.
    Confirmed,
    /// The address is potentially failed.
    PotentiallyFailed,
    /// A state this crate does not know about.
    Unknown(i32),
}

impl PeerAddressState {
    fn from_raw(state: i32) -> PeerAddressState {
        match state {
            0 => PeerAddressState::Available,
            1 => PeerAddressState::Unreachable,
            2 => PeerAddressState::Removed,
            3 => PeerAddressState::Added,
            4 => PeerAddressState::MadePrimary,
            5 => PeerAddressState::Confirmed,
            6 => PeerAddressState::PotentiallyFailed,
            other => PeerAddressState::Unknown(other),
        }
    }
}

/// Error reported by [`PeerAddressChange`].
///
/// These are the `SCTP_SN_ERROR` values; see RFC 6458 section 6.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerAddressError {
    /// The retransmission threshold was reached.
    RetransmissionThresholdReached,
    /// A `SACK` was received.
    ReceivedSack,
    /// A heartbeat was acknowledged.
    HeartbeatSucceeded,
    /// A user request caused the state change.
    ResponseToUserRequest,
    /// An internal error occurred.
    InternalError,
    /// The shutdown guard timer expired.
    ShutdownGuardExpired,
    /// The peer is faulty.
    PeerFaulty,
    /// An error this crate does not know about.
    Unknown(i32),
}

impl PeerAddressError {
    fn from_raw(error: i32) -> PeerAddressError {
        match error {
            0 => PeerAddressError::RetransmissionThresholdReached,
            1 => PeerAddressError::ReceivedSack,
            2 => PeerAddressError::HeartbeatSucceeded,
            3 => PeerAddressError::ResponseToUserRequest,
            4 => PeerAddressError::InternalError,
            5 => PeerAddressError::ShutdownGuardExpired,
            6 => PeerAddressError::PeerFaulty,
            other => PeerAddressError::Unknown(other),
        }
    }
}

/// One of the peer's addresses changed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddressChange {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// The address whose state changed.
    pub address: SocketAddr,
    /// The new state.
    pub state: PeerAddressState,
    /// The `SCTP_SN_ERROR` reason for the change.
    ///
    /// The kernel reports [`PeerAddressError::RetransmissionThresholdReached`]
    /// (the zero value) when it has no more specific reason, for example when
    /// an address becomes available again.
    pub error: PeerAddressError,
}

/// Whether a failed message ever left the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendFailedState {
    /// The message was never sent.
    DataUnsent,
    /// The message was sent but not acknowledged.
    DataSent,
    /// A state this crate does not know about.
    Unknown(u16),
}

impl SendFailedState {
    fn from_raw(state: u16) -> SendFailedState {
        match state {
            0 => SendFailedState::DataUnsent,
            1 => SendFailedState::DataSent,
            other => SendFailedState::Unknown(other),
        }
    }
}

/// Header information of a message that failed to be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailedMessageInfo {
    /// The stream the message was sent on.
    pub stream_id: u16,
    /// The stream sequence number assigned to the message.
    pub stream_seq: u16,
    /// Message flags.
    pub flags: MessageFlags,
    /// The payload protocol identifier.
    pub ppid: u32,
    /// The application context.
    pub context: u32,
    /// The lifetime the message was given (PR-SCTP).
    pub time_to_live: Duration,
    /// The transmission sequence number of the message.
    pub tsn: u32,
    /// The highest contiguously received transmission sequence number.
    pub cumulative_tsn: u32,
    /// The association the message belonged to.
    pub association_id: AssociationId,
}

impl FailedMessageInfo {
    fn from_raw(raw: &sys::sctp_sndrcvinfo) -> FailedMessageInfo {
        FailedMessageInfo {
            stream_id: raw.stream,
            stream_seq: raw.ssn,
            flags: MessageFlags::from_bits(raw.flags),
            ppid: raw.ppid,
            context: raw.context,
            time_to_live: Duration::from_millis(u64::from(raw.timetolive)),
            tsn: raw.tsn,
            cumulative_tsn: raw.cumtsn,
            association_id: raw.assoc_id,
        }
    }
}

/// A message could not be delivered (`SCTP_SEND_FAILED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFailed {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Whether the message was put on the wire.
    pub state: SendFailedState,
    /// The error code describing the failure.
    pub error: u32,
    /// Header information of the failed message.
    pub info: FailedMessageInfo,
    /// The payload of the failed message.
    pub data: Vec<u8>,
}

/// A message could not be delivered (`SCTP_SEND_FAILED_EVENT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFailedEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Whether the message was put on the wire.
    pub state: SendFailedState,
    /// The error code describing the failure.
    pub error: u32,
    /// Header information of the failed message.
    pub info: SendInfo,
    /// The payload of the failed message.
    pub data: Vec<u8>,
}

/// The peer reported an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// The error cause carried in the `ERROR` chunk.
    pub cause: ErrorCause,
    /// The complete error cause information element, as sent by the peer.
    pub data: Vec<u8>,
}

/// The peer initiated a graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShutdownEvent {
    /// The association being shut down.
    pub association_id: AssociationId,
}

/// Why a partial delivery ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartialDeliveryIndication {
    /// The partially delivered message was aborted.
    Aborted,
    /// An indication this crate does not know about.
    Unknown(u32),
}

impl PartialDeliveryIndication {
    fn from_raw(indication: u32) -> PartialDeliveryIndication {
        match indication {
            0 => PartialDeliveryIndication::Aborted,
            other => PartialDeliveryIndication::Unknown(other),
        }
    }
}

/// A partial delivery was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PartialDeliveryEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Why the partial delivery ended.
    pub indication: PartialDeliveryIndication,
    /// The stream of the aborted message.
    pub stream_id: u32,
    /// The sequence number of the aborted message.
    pub sequence: u32,
}

/// The peer's adaptation layer indication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdaptationEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// The adaptation layer indication sent by the peer.
    pub adaptation_indication: u32,
}

/// What happened to an authentication key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthenticationIndication {
    /// A new key became active.
    NewKey,
    /// A key can be freed.
    FreeKey,
    /// Authentication is not enabled.
    NoAuthentication,
    /// An indication this crate does not know about.
    Unknown(u32),
}

impl AuthenticationIndication {
    fn from_raw(indication: u32) -> AuthenticationIndication {
        match indication {
            0 => AuthenticationIndication::NewKey,
            1 => AuthenticationIndication::FreeKey,
            2 => AuthenticationIndication::NoAuthentication,
            other => AuthenticationIndication::Unknown(other),
        }
    }
}

/// An authentication key change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthenticationEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// The key identifier.
    pub key_id: u16,
    /// The alternate key identifier.
    pub alternate_key_id: u16,
    /// What happened to the key.
    pub indication: AuthenticationIndication,
}

/// The send queue became empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderDryEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
}

/// Flags carried by stream reset and association reset notifications.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StreamResetFlags(u16);

impl StreamResetFlags {
    /// Inbound streams were reset.
    pub const INCOMING: StreamResetFlags = StreamResetFlags(0x0001);
    /// Outbound streams were reset.
    pub const OUTGOING: StreamResetFlags = StreamResetFlags(0x0002);
    /// The request was denied by the peer.
    pub const DENIED: StreamResetFlags = StreamResetFlags(0x0004);
    /// The request failed.
    pub const FAILED: StreamResetFlags = StreamResetFlags(0x0008);

    /// The empty set.
    pub const fn empty() -> StreamResetFlags {
        StreamResetFlags(0)
    }

    /// The raw bit representation.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Builds flags from raw bits.
    pub const fn from_bits(bits: u16) -> StreamResetFlags {
        StreamResetFlags(bits)
    }

    /// Returns `true` if every flag in `other` is set.
    pub const fn contains(self, other: StreamResetFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for StreamResetFlags {
    type Output = StreamResetFlags;

    fn bitor(self, rhs: StreamResetFlags) -> StreamResetFlags {
        StreamResetFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for StreamResetFlags {
    fn bitor_assign(&mut self, rhs: StreamResetFlags) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Debug for StreamResetFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut set = *self;
        if set.0 == 0 {
            return f.write_str("StreamResetFlags(empty)");
        }

        f.write_str("StreamResetFlags(")?;
        let mut first = true;
        for (name, flag) in [
            ("INCOMING", StreamResetFlags::INCOMING),
            ("OUTGOING", StreamResetFlags::OUTGOING),
            ("DENIED", StreamResetFlags::DENIED),
            ("FAILED", StreamResetFlags::FAILED),
        ] {
            if set.contains(flag) {
                if !first {
                    f.write_str(" | ")?;
                }
                first = false;
                f.write_str(name)?;
                set.0 &= !flag.0;
            }
        }
        if set.0 != 0 {
            if !first {
                f.write_str(" | ")?;
            }
            write!(f, "{:#06x}", set.0)?;
        }
        f.write_str(")")
    }
}

/// Stream reset requests completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamResetEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Which resets completed and whether they succeeded.
    pub flags: StreamResetFlags,
    /// The affected streams.
    pub streams: Vec<u16>,
}

/// An association reset request completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssociationResetEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Whether the reset was denied or failed.
    pub flags: StreamResetFlags,
    /// The local transmission sequence number after the reset.
    pub local_tsn: u32,
    /// The peer's transmission sequence number after the reset.
    pub remote_tsn: u32,
}

/// Streams were added to the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamChangeEvent {
    /// The association this notification belongs to.
    pub association_id: AssociationId,
    /// Whether the request was denied or failed.
    pub flags: StreamResetFlags,
    /// The new number of inbound streams.
    pub inbound_streams: u16,
    /// The new number of outbound streams.
    pub outbound_streams: u16,
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_struct<T: Copy>(buf: &[u8]) -> io::Result<T> {
    if buf.len() < size_of::<T>() {
        return Err(invalid_data("truncated SCTP notification"));
    }
    Ok(unsafe { ptr::read_unaligned(buf.as_ptr().cast()) })
}

impl Notification {
    /// Parses a notification from the payload returned by `recvmsg(2)`.
    pub(crate) fn parse(buf: &[u8]) -> io::Result<Notification> {
        let header: sys::sctp_notification_header = read_struct(buf)?;

        let length = header.length as usize;
        if length < size_of::<sys::sctp_notification_header>() || length > buf.len() {
            return Err(invalid_data("invalid SCTP notification length"));
        }
        let buf = &buf[..length];

        let notification = match header.type_ {
            sys::SCTP_ASSOC_CHANGE => {
                let raw: sys::sctp_assoc_change = read_struct(buf)?;
                Notification::AssociationChange(AssociationChange {
                    association_id: raw.assoc_id,
                    state: AssociationState::from_raw(raw.state),
                    error: ErrorCause::from_raw(raw.error),
                    outbound_streams: raw.outbound_streams,
                    inbound_streams: raw.inbound_streams,
                    data: buf[size_of::<sys::sctp_assoc_change>()..].to_vec(),
                })
            }
            sys::SCTP_PEER_ADDR_CHANGE => {
                let raw: sys::sctp_paddr_change = read_struct(buf)?;
                let address = raw.address;
                Notification::PeerAddressChange(PeerAddressChange {
                    association_id: raw.assoc_id,
                    address: addr::from_storage(&address)?,
                    state: PeerAddressState::from_raw(raw.state),
                    error: PeerAddressError::from_raw(raw.error),
                })
            }
            sys::SCTP_SEND_FAILED => {
                let raw: sys::sctp_send_failed = read_struct(buf)?;
                Notification::SendFailed(SendFailed {
                    association_id: raw.assoc_id,
                    state: SendFailedState::from_raw(raw.flags),
                    error: raw.error,
                    info: FailedMessageInfo::from_raw(&raw.info),
                    data: buf[size_of::<sys::sctp_send_failed>()..].to_vec(),
                })
            }
            sys::SCTP_SEND_FAILED_EVENT => {
                let raw: sys::sctp_send_failed_event = read_struct(buf)?;
                Notification::SendFailedEvent(SendFailedEvent {
                    association_id: raw.assoc_id,
                    state: SendFailedState::from_raw(raw.flags),
                    error: raw.error,
                    info: SendInfo::from_raw(&raw.info),
                    data: buf[size_of::<sys::sctp_send_failed_event>()..].to_vec(),
                })
            }
            sys::SCTP_REMOTE_ERROR => {
                let raw: sys::sctp_remote_error = read_struct(buf)?;
                // `sre_error` carries the error cause exactly as it appeared on
                // the wire, i.e. in network byte order.
                let cause_code = u16::from_be(raw.error);
                let cause =
                    ErrorCause::from_raw(cause_code).unwrap_or(ErrorCause::Unknown(cause_code));
                Notification::RemoteError(RemoteError {
                    association_id: raw.assoc_id,
                    cause,
                    data: buf[size_of::<sys::sctp_remote_error>()..].to_vec(),
                })
            }
            sys::SCTP_SHUTDOWN_EVENT => {
                let raw: sys::sctp_shutdown_event = read_struct(buf)?;
                Notification::Shutdown(ShutdownEvent {
                    association_id: raw.assoc_id,
                })
            }
            sys::SCTP_PARTIAL_DELIVERY_EVENT => {
                let raw: sys::sctp_pdapi_event = read_struct(buf)?;
                Notification::PartialDelivery(PartialDeliveryEvent {
                    association_id: raw.assoc_id,
                    indication: PartialDeliveryIndication::from_raw(raw.indication),
                    stream_id: raw.stream,
                    sequence: raw.seq,
                })
            }
            sys::SCTP_ADAPTATION_INDICATION => {
                let raw: sys::sctp_adaptation_event = read_struct(buf)?;
                Notification::Adaptation(AdaptationEvent {
                    association_id: raw.assoc_id,
                    adaptation_indication: raw.adaptation_ind,
                })
            }
            sys::SCTP_AUTHENTICATION_EVENT => {
                let raw: sys::sctp_authkey_event = read_struct(buf)?;
                Notification::Authentication(AuthenticationEvent {
                    association_id: raw.assoc_id,
                    key_id: raw.keynumber,
                    alternate_key_id: raw.altkeynumber,
                    indication: AuthenticationIndication::from_raw(raw.indication),
                })
            }
            sys::SCTP_SENDER_DRY_EVENT => {
                let raw: sys::sctp_sender_dry_event = read_struct(buf)?;
                Notification::SenderDry(SenderDryEvent {
                    association_id: raw.assoc_id,
                })
            }
            sys::SCTP_STREAM_RESET_EVENT => {
                let raw: sys::sctp_stream_reset_event = read_struct(buf)?;
                let tail = &buf[size_of::<sys::sctp_stream_reset_event>()..];
                let streams = tail
                    .chunks_exact(2)
                    .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
                    .collect();
                Notification::StreamReset(StreamResetEvent {
                    association_id: raw.assoc_id,
                    flags: StreamResetFlags::from_bits(raw.flags),
                    streams,
                })
            }
            sys::SCTP_ASSOC_RESET_EVENT => {
                let raw: sys::sctp_assoc_reset_event = read_struct(buf)?;
                Notification::AssociationReset(AssociationResetEvent {
                    association_id: raw.assoc_id,
                    flags: StreamResetFlags::from_bits(raw.flags),
                    local_tsn: raw.local_tsn,
                    remote_tsn: raw.remote_tsn,
                })
            }
            sys::SCTP_STREAM_CHANGE_EVENT => {
                let raw: sys::sctp_stream_change_event = read_struct(buf)?;
                Notification::StreamChange(StreamChangeEvent {
                    association_id: raw.assoc_id,
                    flags: StreamResetFlags::from_bits(raw.flags),
                    inbound_streams: raw.instrms,
                    outbound_streams: raw.outstrms,
                })
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown SCTP notification type {other:#06x}"),
                ));
            }
        };

        Ok(notification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(type_: u16, length: usize) -> Vec<u8> {
        header_with_flags(type_, 0, length)
    }

    fn header_with_flags(type_: u16, flags: u16, length: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(length);
        buf.extend_from_slice(&type_.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&(length as u32).to_ne_bytes());
        buf
    }

    #[test]
    fn parse_assoc_change() {
        let mut buf = header(sys::SCTP_ASSOC_CHANGE, 22);
        buf.extend_from_slice(&0u16.to_ne_bytes()); // state: COMM_UP
        buf.extend_from_slice(&0u16.to_ne_bytes()); // error
        buf.extend_from_slice(&10u16.to_ne_bytes());
        buf.extend_from_slice(&20u16.to_ne_bytes());
        buf.extend_from_slice(&42i32.to_ne_bytes());
        buf.extend_from_slice(b"hi");

        let notification = Notification::parse(&buf).unwrap();
        let Notification::AssociationChange(change) = notification else {
            panic!("wrong variant");
        };
        assert_eq!(change.association_id, 42);
        assert_eq!(change.state, AssociationState::CommUp);
        assert_eq!(change.error, None);
        assert_eq!(change.outbound_streams, 10);
        assert_eq!(change.inbound_streams, 20);
        assert_eq!(change.data, b"hi");
    }

    #[test]
    fn parse_stream_reset() {
        let mut buf = header_with_flags(
            sys::SCTP_STREAM_RESET_EVENT,
            (StreamResetFlags::INCOMING | StreamResetFlags::OUTGOING).bits(),
            18,
        );
        buf.extend_from_slice(&7i32.to_ne_bytes());
        buf.extend_from_slice(&1u16.to_ne_bytes());
        buf.extend_from_slice(&2u16.to_ne_bytes());
        buf.extend_from_slice(&3u16.to_ne_bytes());

        let notification = Notification::parse(&buf).unwrap();
        let Notification::StreamReset(event) = notification else {
            panic!("wrong variant");
        };
        assert_eq!(event.association_id, 7);
        assert!(event.flags.contains(StreamResetFlags::INCOMING));
        assert!(event.flags.contains(StreamResetFlags::OUTGOING));
        assert_eq!(event.streams, [1, 2, 3]);
    }

    #[test]
    fn parse_remote_error_uses_network_order() {
        let mut buf = header(sys::SCTP_REMOTE_ERROR, 18);
        buf.extend_from_slice(&2u16.to_be_bytes()); // cause: missing mandatory parameter
        buf.extend_from_slice(&[0, 0]); // padding to the 4-byte aligned association id
        buf.extend_from_slice(&0i32.to_ne_bytes());
        buf.extend_from_slice(&[0xaa, 0xbb]);

        let notification = Notification::parse(&buf).unwrap();
        let Notification::RemoteError(error) = notification else {
            panic!("wrong variant");
        };
        assert_eq!(error.cause, ErrorCause::MissingMandatoryParameter);
        assert_eq!(error.data, [0xaa, 0xbb]);
    }

    #[test]
    fn rejects_truncated_notifications() {
        let buf = header(sys::SCTP_ASSOC_CHANGE, 20);
        assert!(Notification::parse(&buf).is_err());

        let mut buf = header(sys::SCTP_ASSOC_CHANGE, 20);
        buf.truncate(8);
        assert!(Notification::parse(&buf).is_err());
    }

    #[test]
    fn rejects_unknown_types() {
        let buf = header(0x7fff, 8);
        assert_eq!(
            Notification::parse(&buf).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
