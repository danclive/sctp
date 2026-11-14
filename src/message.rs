use std::fmt;
use std::net::SocketAddr;
use std::ops;

use crate::AssociationId;
use crate::notification::Notification;

/// Flags describing how a message is sent or was received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MessageFlags(u16);

impl MessageFlags {
    /// Deliver the message unordered.
    pub const UNORDERED: MessageFlags = MessageFlags(1 << 0);
    /// Override the association's primary destination address.
    pub const ADDRESS_OVERRIDE: MessageFlags = MessageFlags(1 << 1);
    /// Abort the association after sending.
    pub const ABORT: MessageFlags = MessageFlags(1 << 2);
    /// Request an immediate `SACK` for this message.
    pub const SACK_IMMEDIATELY: MessageFlags = MessageFlags(1 << 3);
    /// Send on every association of the socket.
    pub const SEND_ALL: MessageFlags = MessageFlags(1 << 6);
    /// Abandon every message of the association (PR-SCTP).
    pub const PR_SCTP_ALL: MessageFlags = MessageFlags(1 << 7);
    /// Gracefully shut the association down after sending.
    pub const EOF: MessageFlags = MessageFlags(0x0200);

    /// Mask covering the PR-SCTP policy bits.
    pub const PR_SCTP_POLICY_MASK: MessageFlags = MessageFlags(0x0030);
    /// PR-SCTP: abandon the message after a given lifetime.
    pub const PR_SCTP_TTL: MessageFlags = MessageFlags(0x0010);
    /// PR-SCTP: abandon the message after a given number of retransmissions.
    pub const PR_SCTP_RTX: MessageFlags = MessageFlags(0x0020);
    /// PR-SCTP: abandon lower priority messages first.
    pub const PR_SCTP_PRIO: MessageFlags = MessageFlags(0x0030);

    /// The empty set of flags.
    pub const fn empty() -> MessageFlags {
        MessageFlags(0)
    }

    /// The raw bit representation.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Builds flags from raw bits.
    pub const fn from_bits(bits: u16) -> MessageFlags {
        MessageFlags(bits)
    }

    /// Returns `true` if no flag is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if every flag in `other` is set.
    pub const fn contains(self, other: MessageFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Adds `other` to the set.
    pub fn insert(&mut self, other: MessageFlags) {
        self.0 |= other.0;
    }

    /// Removes `other` from the set.
    pub fn remove(&mut self, other: MessageFlags) {
        self.0 &= !other.0;
    }
}

impl fmt::Debug for MessageFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(&str, MessageFlags); 7] = [
            ("UNORDERED", MessageFlags::UNORDERED),
            ("ADDRESS_OVERRIDE", MessageFlags::ADDRESS_OVERRIDE),
            ("ABORT", MessageFlags::ABORT),
            ("SACK_IMMEDIATELY", MessageFlags::SACK_IMMEDIATELY),
            ("SEND_ALL", MessageFlags::SEND_ALL),
            ("PR_SCTP_ALL", MessageFlags::PR_SCTP_ALL),
            ("EOF", MessageFlags::EOF),
        ];

        let mut set = *self;
        if set.0 == 0 {
            return f.write_str("MessageFlags(empty)");
        }

        f.write_str("MessageFlags(")?;
        let mut first = true;
        for (name, flag) in NAMES {
            if set.contains(flag) {
                if !first {
                    f.write_str(" | ")?;
                }
                first = false;
                f.write_str(name)?;
                set.remove(flag);
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

impl ops::BitOr for MessageFlags {
    type Output = MessageFlags;

    fn bitor(self, rhs: MessageFlags) -> MessageFlags {
        MessageFlags(self.0 | rhs.0)
    }
}

impl ops::BitOrAssign for MessageFlags {
    fn bitor_assign(&mut self, rhs: MessageFlags) {
        self.0 |= rhs.0;
    }
}

impl ops::BitAnd for MessageFlags {
    type Output = MessageFlags;

    fn bitand(self, rhs: MessageFlags) -> MessageFlags {
        MessageFlags(self.0 & rhs.0)
    }
}

impl ops::BitAndAssign for MessageFlags {
    fn bitand_assign(&mut self, rhs: MessageFlags) {
        self.0 &= rhs.0;
    }
}

impl ops::Not for MessageFlags {
    type Output = MessageFlags;

    fn not(self) -> MessageFlags {
        MessageFlags(!self.0)
    }
}

/// Partial reliability policy for a message (PR-SCTP, RFC 3758).
///
/// With a policy other than [`PrPolicy::None`] the message may be abandoned
/// instead of being retransmitted indefinitely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum PrPolicy {
    /// Deliver the message reliably.
    #[default]
    None,
    /// Abandon the message after [`SendInfo::pr_value`] milliseconds.
    Ttl,
    /// Abandon the message after [`SendInfo::pr_value`] retransmissions.
    Retransmissions,
    /// Abandon messages with a lower priority first; `pr_value` is the
    /// priority.
    Priority,
}

impl PrPolicy {
    pub(crate) fn to_raw(self) -> u16 {
        match self {
            PrPolicy::None => crate::sys::SCTP_PR_SCTP_NONE,
            PrPolicy::Ttl => crate::sys::SCTP_PR_SCTP_TTL,
            PrPolicy::Retransmissions => crate::sys::SCTP_PR_SCTP_RTX,
            PrPolicy::Priority => crate::sys::SCTP_PR_SCTP_PRIO,
        }
    }
}

/// Per-message parameters supplied when sending.
///
/// This mirrors `struct sctp_sndinfo` from RFC 6458. The [`Default`]
/// implementation sends on stream 0 with no flags, `PPID` 0, context 0 and
/// reliable delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SendInfo {
    /// The outbound stream to use.
    pub stream_id: u16,
    /// Message flags.
    pub flags: MessageFlags,
    /// The payload protocol identifier; opaque to SCTP.
    pub ppid: u32,
    /// Application context; opaque to SCTP.
    pub context: u32,
    /// The association to send on.
    ///
    /// Ignored by one-to-one sockets; one-to-many sockets use it when no
    /// destination address is given.
    pub association_id: AssociationId,
    /// The partial reliability policy of the message.
    pub pr_policy: PrPolicy,
    /// The lifetime, retransmission count or priority used by
    /// [`pr_policy`](SendInfo::pr_policy).
    pub pr_value: u32,
}

impl SendInfo {
    /// Parameters for sending on `stream_id`, with everything else defaulted.
    pub const fn new(stream_id: u16) -> SendInfo {
        SendInfo {
            stream_id,
            flags: MessageFlags::empty(),
            ppid: 0,
            context: 0,
            association_id: 0,
            pr_policy: PrPolicy::None,
            pr_value: 0,
        }
    }

    /// Sets the payload protocol identifier.
    pub const fn with_ppid(mut self, ppid: u32) -> SendInfo {
        self.ppid = ppid;
        self
    }

    /// Sets the message flags.
    pub const fn with_flags(mut self, flags: MessageFlags) -> SendInfo {
        self.flags = flags;
        self
    }

    /// Sets the application context.
    pub const fn with_context(mut self, context: u32) -> SendInfo {
        self.context = context;
        self
    }

    /// Sets the target association.
    pub const fn with_association_id(mut self, association_id: AssociationId) -> SendInfo {
        self.association_id = association_id;
        self
    }

    /// Sets the partial reliability policy and its value.
    pub const fn with_partial_reliability(mut self, policy: PrPolicy, value: u32) -> SendInfo {
        self.pr_policy = policy;
        self.pr_value = value;
        self
    }

    pub(crate) fn to_raw(self) -> crate::sys::sctp_sndinfo {
        crate::sys::sctp_sndinfo {
            sid: self.stream_id,
            flags: self.flags.bits(),
            ppid: self.ppid,
            context: self.context,
            assoc_id: self.association_id,
        }
    }

    pub(crate) fn from_raw(raw: &crate::sys::sctp_sndinfo) -> SendInfo {
        SendInfo {
            stream_id: raw.sid,
            flags: MessageFlags::from_bits(raw.flags),
            ppid: raw.ppid,
            context: raw.context,
            association_id: raw.assoc_id,
            pr_policy: PrPolicy::None,
            pr_value: 0,
        }
    }

    pub(crate) fn pr_info(self) -> Option<crate::sys::sctp_prinfo> {
        match self.pr_policy {
            PrPolicy::None => None,
            policy => Some(crate::sys::sctp_prinfo {
                policy: policy.to_raw(),
                value: self.pr_value,
            }),
        }
    }
}

/// Per-message information reported when receiving.
///
/// This mirrors `struct sctp_rcvinfo` from RFC 6458.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RecvInfo {
    /// The inbound stream the message was sent on.
    pub stream_id: u16,
    /// The stream sequence number of the message.
    pub stream_seq: u16,
    /// Message flags, such as [`MessageFlags::UNORDERED`].
    pub flags: MessageFlags,
    /// The payload protocol identifier chosen by the sender.
    pub ppid: u32,
    /// The transmission sequence number of the first fragment.
    pub tsn: u32,
    /// The highest transmission sequence number received contiguously.
    pub cumulative_tsn: u32,
    /// The application context.
    ///
    /// On Linux this is the receiver's association context (set with
    /// `SCTP_CONTEXT`), not a value carried by the message.
    pub context: u32,
    /// The association the message belongs to.
    pub association_id: AssociationId,
}

impl RecvInfo {
    pub(crate) fn from_rcvinfo(raw: &crate::sys::sctp_rcvinfo) -> RecvInfo {
        RecvInfo {
            stream_id: raw.sid,
            stream_seq: raw.ssn,
            flags: MessageFlags::from_bits(raw.flags),
            ppid: raw.ppid,
            tsn: raw.tsn,
            cumulative_tsn: raw.cumtsn,
            context: raw.context,
            association_id: raw.assoc_id,
        }
    }

    pub(crate) fn from_sndrcvinfo(raw: &crate::sys::sctp_sndrcvinfo) -> RecvInfo {
        RecvInfo {
            stream_id: raw.stream,
            stream_seq: raw.ssn,
            flags: MessageFlags::from_bits(raw.flags),
            ppid: raw.ppid,
            tsn: raw.tsn,
            cumulative_tsn: raw.cumtsn,
            context: raw.context,
            association_id: raw.assoc_id,
        }
    }
}

/// Information about the message that follows the one just received.
///
/// Only available when the socket has [`SCTP_RECVNXTINFO`] enabled, see
/// [`SctpStream::set_receive_next_info`].
///
/// [`SCTP_RECVNXTINFO`]: https://www.kernel.org/doc/html/latest/networking/sctp.html
/// [`SctpStream::set_receive_next_info`]: crate::SctpStream::set_receive_next_info
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NextInfo {
    /// The inbound stream of the next message.
    pub stream_id: u16,
    /// Flags of the next message.
    pub flags: MessageFlags,
    /// The payload protocol identifier of the next message.
    pub ppid: u32,
    /// The size of the next message in bytes.
    pub length: u32,
    /// The association the next message belongs to.
    pub association_id: AssociationId,
}

impl NextInfo {
    pub(crate) fn from_raw(raw: &crate::sys::sctp_nxtinfo) -> NextInfo {
        NextInfo {
            stream_id: raw.sid,
            flags: MessageFlags::from_bits(raw.flags),
            ppid: raw.ppid,
            length: raw.length,
            association_id: raw.assoc_id,
        }
    }
}

/// A received data message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedData {
    /// Number of bytes stored in the caller's buffer.
    pub len: usize,
    /// The source address, when the protocol reported one.
    pub address: Option<SocketAddr>,
    /// SCTP per-message information.
    pub info: RecvInfo,
    /// Information about the next queued message, if requested.
    pub next: Option<NextInfo>,
    /// Whether this is the last fragment of the message.
    ///
    /// A message that did not fit into the buffer is delivered in fragments;
    /// keep receiving until `complete` is `true`.
    pub complete: bool,
}

/// A message read from a socket: either user data or a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// A data message was read.
    Data(ReceivedData),
    /// A notification was read.
    Notification(Notification),
}

impl Received {
    /// Returns the data message, if this is one.
    pub fn data(&self) -> Option<&ReceivedData> {
        match self {
            Received::Data(data) => Some(data),
            Received::Notification(_) => None,
        }
    }

    /// Returns the notification, if this is one.
    pub fn notification(&self) -> Option<&Notification> {
        match self {
            Received::Data(_) => None,
            Received::Notification(notification) => Some(notification),
        }
    }

    /// Converts into the data message, if this is one.
    pub fn into_data(self) -> Option<ReceivedData> {
        match self {
            Received::Data(data) => Some(data),
            Received::Notification(_) => None,
        }
    }

    /// Converts into the notification, if this is one.
    pub fn into_notification(self) -> Option<Notification> {
        match self {
            Received::Data(_) => None,
            Received::Notification(notification) => Some(notification),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_info_builder() {
        let info = SendInfo::new(3)
            .with_ppid(0xdead_beef)
            .with_context(7)
            .with_flags(MessageFlags::UNORDERED);

        assert_eq!(info.stream_id, 3);
        assert_eq!(info.ppid, 0xdead_beef);
        assert_eq!(info.context, 7);
        assert!(info.flags.contains(MessageFlags::UNORDERED));

        let raw = info.to_raw();
        assert_eq!(SendInfo::from_raw(&raw), info);
    }

    #[test]
    fn message_flags_debug() {
        assert_eq!(
            format!("{:?}", MessageFlags::empty()),
            "MessageFlags(empty)"
        );
        assert_eq!(
            format!("{:?}", MessageFlags::UNORDERED | MessageFlags::EOF),
            "MessageFlags(UNORDERED | EOF)"
        );
        assert_eq!(
            format!("{:?}", MessageFlags::from_bits(0x0400)),
            "MessageFlags(0x0400)"
        );
    }
}
