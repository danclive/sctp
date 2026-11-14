use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::AssociationId;
use crate::addr;
use crate::message::SendInfo;
use crate::socket::Socket;
use crate::sys;

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Converts a duration to the milliseconds expected by SCTP socket options.
fn to_millis(duration: Duration) -> io::Result<u32> {
    u32::try_from(duration.as_millis()).map_err(|_| invalid_input("duration is too large"))
}

fn from_millis(millis: u32) -> Duration {
    Duration::from_millis(u64::from(millis))
}

fn buffer_size(size: usize) -> io::Result<libc::c_int> {
    libc::c_int::try_from(size).map_err(|_| invalid_input("buffer size is too large"))
}

/// Parameters for establishing new associations (`SCTP_INITMSG`).
///
/// Zero values leave the kernel defaults untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InitParams {
    /// Number of outbound streams requested.
    pub outbound_streams: u16,
    /// Number of inbound streams the peer may use.
    pub inbound_streams: u16,
    /// Maximum number of `INIT` retransmissions.
    pub max_attempts: u16,
    /// Maximum `INIT` retransmission timeout.
    pub init_timeout: Duration,
}

/// Retransmission timeout parameters (`SCTP_RTOINFO`).
///
/// See RFC 4960 section 15 for the meaning of each value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RtoInfo {
    /// The initial retransmission timeout.
    pub initial: Duration,
    /// The maximum retransmission timeout.
    pub max: Duration,
    /// The minimum retransmission timeout.
    pub min: Duration,
}

/// Association parameters (`SCTP_ASSOCINFO`).
///
/// Only [`max_retransmits`](AssocInfo::max_retransmits) and
/// [`cookie_life`](AssocInfo::cookie_life) can be set; the other fields are
/// reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AssocInfo {
    /// Maximum number of retransmissions before the association fails.
    pub max_retransmits: u16,
    /// Number of peer addresses (read-only).
    pub peer_destinations: u16,
    /// The peer's advertised receiver window in bytes (read-only).
    pub peer_receiver_window: u32,
    /// The local receiver window in bytes (read-only).
    pub local_receiver_window: u32,
    /// Lifetime of the state cookie.
    pub cookie_life: Duration,
}

/// Delayed `SACK` parameters (`SCTP_DELAYED_SACK`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DelayedSack {
    /// Delay before sending a `SACK`, or [`None`] to disable delayed `SACK`.
    pub delay: Option<Duration>,
    /// Number of messages to receive before sending a `SACK`; 1 disables
    /// delayed `SACK`.
    pub frequency: u32,
}

/// Flags for [`PeerAddressParams`] (`enum sctp_spp_flags`).
///
/// Each pair (`heartbeats`/`no_heartbeats`, ...) selects a change; setting
/// both members of a pair is invalid.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PeerAddressFlags(u32);

impl PeerAddressFlags {
    /// Enable heartbeats.
    pub const HEARTBEATS: PeerAddressFlags = PeerAddressFlags(sys::SPP_HB_ENABLE);
    /// Disable heartbeats.
    pub const NO_HEARTBEATS: PeerAddressFlags = PeerAddressFlags(sys::SPP_HB_DISABLE);
    /// Send a heartbeat immediately.
    pub const HEARTBEAT_NOW: PeerAddressFlags = PeerAddressFlags(sys::SPP_HB_DEMAND);
    /// Enable path MTU discovery.
    pub const PATH_MTU_DISCOVERY: PeerAddressFlags = PeerAddressFlags(sys::SPP_PMTUD_ENABLE);
    /// Disable path MTU discovery.
    pub const NO_PATH_MTU_DISCOVERY: PeerAddressFlags = PeerAddressFlags(sys::SPP_PMTUD_DISABLE);
    /// Enable delayed `SACK`.
    pub const DELAYED_SACK: PeerAddressFlags = PeerAddressFlags(sys::SPP_SACKDELAY_ENABLE);
    /// Disable delayed `SACK`.
    pub const NO_DELAYED_SACK: PeerAddressFlags = PeerAddressFlags(sys::SPP_SACKDELAY_DISABLE);
    /// Heartbeats are disabled if the interval is zero.
    pub const HEARTBEAT_INTERVAL_IS_ZERO: PeerAddressFlags =
        PeerAddressFlags(sys::SPP_HB_TIME_IS_ZERO);
    /// Set the IPv6 flow label.
    pub const IPV6_FLOW_LABEL: PeerAddressFlags = PeerAddressFlags(sys::SPP_IPV6_FLOWLABEL);
    /// Set the IPv4/IPv6 differentiated services code point.
    pub const DSCP: PeerAddressFlags = PeerAddressFlags(sys::SPP_DSCP);

    /// The empty set.
    pub const fn empty() -> PeerAddressFlags {
        PeerAddressFlags(0)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Builds flags from raw bits.
    pub const fn from_bits(bits: u32) -> PeerAddressFlags {
        PeerAddressFlags(bits)
    }

    /// Returns `true` if every flag in `other` is set.
    pub const fn contains(self, other: PeerAddressFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for PeerAddressFlags {
    type Output = PeerAddressFlags;

    fn bitor(self, rhs: PeerAddressFlags) -> PeerAddressFlags {
        PeerAddressFlags(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for PeerAddressFlags {
    fn bitor_assign(&mut self, rhs: PeerAddressFlags) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Debug for PeerAddressFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut set = *self;
        if set.0 == 0 {
            return f.write_str("PeerAddressFlags(empty)");
        }

        f.write_str("PeerAddressFlags(")?;
        let mut first = true;
        for (name, flag) in [
            ("HEARTBEATS", PeerAddressFlags::HEARTBEATS),
            ("NO_HEARTBEATS", PeerAddressFlags::NO_HEARTBEATS),
            ("HEARTBEAT_NOW", PeerAddressFlags::HEARTBEAT_NOW),
            ("PATH_MTU_DISCOVERY", PeerAddressFlags::PATH_MTU_DISCOVERY),
            (
                "NO_PATH_MTU_DISCOVERY",
                PeerAddressFlags::NO_PATH_MTU_DISCOVERY,
            ),
            ("DELAYED_SACK", PeerAddressFlags::DELAYED_SACK),
            ("NO_DELAYED_SACK", PeerAddressFlags::NO_DELAYED_SACK),
            (
                "HEARTBEAT_INTERVAL_IS_ZERO",
                PeerAddressFlags::HEARTBEAT_INTERVAL_IS_ZERO,
            ),
            ("IPV6_FLOW_LABEL", PeerAddressFlags::IPV6_FLOW_LABEL),
            ("DSCP", PeerAddressFlags::DSCP),
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

/// Parameters of a single peer address (`SCTP_PEER_ADDR_PARAMS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PeerAddressParams {
    /// Heartbeat interval; [`None`] maps to zero.
    pub heartbeat_interval: Option<Duration>,
    /// Maximum number of retransmissions before the address is considered
    /// unreachable.
    pub path_max_retransmits: u16,
    /// Path MTU; 0 lets SCTP discover it.
    pub path_mtu: u32,
    /// Delayed `SACK` timer for this address.
    pub sack_delay: Option<Duration>,
    /// Which parameters to change.
    pub flags: PeerAddressFlags,
    /// IPv6 flow label, when [`PeerAddressFlags::IPV6_FLOW_LABEL`] is set.
    pub ipv6_flow_label: u32,
    /// Differentiated services code point, when [`PeerAddressFlags::DSCP`] is set.
    pub dscp: u8,
}

/// Peer address thresholds (`SCTP_PEER_ADDR_THLDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PeerAddressThresholds {
    /// Maximum number of retransmissions before the address is considered
    /// unreachable.
    pub path_max_retransmits: u16,
    /// Number of retransmissions after which the address is reported as
    /// potentially failed.
    pub potentially_failed_threshold: u16,
}

/// The connection state of an association, as reported by `SCTP_STATUS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// The association does not exist.
    Empty,
    /// The association is closed.
    Closed,
    /// Waiting for the `INIT` acknowledgement.
    CookieWait,
    /// The state cookie was sent, waiting for the `COOKIE` acknowledgement.
    CookieEchoed,
    /// The association is established.
    Established,
    /// A shutdown is pending.
    ShutdownPending,
    /// A `SHUTDOWN` was sent.
    ShutdownSent,
    /// A `SHUTDOWN` was received.
    ShutdownReceived,
    /// A `SHUTDOWN` acknowledgement was sent.
    ShutdownAckSent,
    /// A state this crate does not know about.
    Unknown(i32),
}

/// Reachability state of a peer address (`enum sctp_spinfo_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerAddressStatus {
    /// The address is not used for data transfer.
    Inactive,
    /// The address is marked as potentially failed.
    PotentiallyFailed,
    /// The address is reachable and used for data transfer.
    Active,
    /// The address was reported by the peer but not confirmed by a heartbeat.
    Unconfirmed,
    /// A state this crate does not know about.
    Unknown(i32),
}

/// The status of an association (`SCTP_STATUS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssociationStatus {
    /// The association the status belongs to.
    pub association_id: AssociationId,
    /// The current association state.
    pub state: ConnectionState,
    /// The peer's receiver window in bytes.
    pub receiver_window: u32,
    /// Number of data chunks sent but not yet acknowledged.
    pub unacked_chunks: u16,
    /// Number of data chunks waiting to be received.
    pub pending_chunks: u16,
    /// Number of inbound streams.
    pub inbound_streams: u16,
    /// Number of outbound streams.
    pub outbound_streams: u16,
    /// Current fragmentation point in bytes.
    pub fragmentation_point: u32,
    /// Information about the primary peer address.
    pub primary: PeerAddressInfo,
}

/// Information about one of the peer's addresses (`SCTP_GET_PEER_ADDR_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddressInfo {
    /// The association the address belongs to.
    pub association_id: AssociationId,
    /// The peer address.
    pub address: SocketAddr,
    /// Reachability state of the address.
    pub state: PeerAddressStatus,
    /// Congestion window, as reported by the kernel.
    pub congestion_window: u32,
    /// Smoothed round-trip time.
    pub smoothed_rtt: Duration,
    /// Retransmission timeout.
    pub retransmission_timeout: Duration,
    /// Path MTU in bytes.
    pub mtu: u32,
}

/// Per-association statistics (`SCTP_GET_ASSOC_STATS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AssociationStats {
    /// The association the statistics belong to.
    pub association_id: AssociationId,
    /// Address of the transport with the highest observed RTO, if any.
    pub observed_rto_address: Option<SocketAddr>,
    /// Highest observed RTO since the previous call.
    pub max_observed_rto: Duration,
    /// `SACK`s received.
    pub sacks_received: u64,
    /// `SACK`s sent.
    pub sacks_sent: u64,
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Retransmitted chunks.
    pub retransmitted_chunks: u64,
    /// Out of sequence transmission sequence numbers received.
    pub out_of_sequence_tsns: u64,
    /// Duplicate chunks received.
    pub duplicate_chunks: u64,
    /// Gap acknowledgement chunks received.
    pub gap_acknowledgements: u64,
    /// Unordered chunks sent.
    pub unordered_chunks_sent: u64,
    /// Unordered chunks received.
    pub unordered_chunks_received: u64,
    /// Ordered chunks sent.
    pub ordered_chunks_sent: u64,
    /// Ordered chunks received.
    pub ordered_chunks_received: u64,
    /// Control chunks sent.
    pub control_chunks_sent: u64,
    /// Control chunks received.
    pub control_chunks_received: u64,
}

/// The algorithm used to schedule messages across streams (`SCTP_STREAM_SCHEDULER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StreamScheduler {
    /// First come, first served.
    #[default]
    FirstComeFirstServed,
    /// Priority based scheduling.
    Priority,
    /// Round robin.
    RoundRobin,
    /// Fair capacity.
    FairCapacity,
    /// Weighted fair queueing.
    WeightedFairQueueing,
    /// A scheduler this crate does not know about.
    Unknown(i32),
}

impl StreamScheduler {
    fn from_raw(raw: i32) -> StreamScheduler {
        match raw {
            sys::SCTP_SS_FCFS => StreamScheduler::FirstComeFirstServed,
            sys::SCTP_SS_PRIO => StreamScheduler::Priority,
            sys::SCTP_SS_RR => StreamScheduler::RoundRobin,
            sys::SCTP_SS_FC => StreamScheduler::FairCapacity,
            sys::SCTP_SS_WFQ => StreamScheduler::WeightedFairQueueing,
            other => StreamScheduler::Unknown(other),
        }
    }

    fn to_raw(self) -> i32 {
        match self {
            StreamScheduler::FirstComeFirstServed => sys::SCTP_SS_FCFS,
            StreamScheduler::Priority => sys::SCTP_SS_PRIO,
            StreamScheduler::RoundRobin => sys::SCTP_SS_RR,
            StreamScheduler::FairCapacity => sys::SCTP_SS_FC,
            StreamScheduler::WeightedFairQueueing => sys::SCTP_SS_WFQ,
            StreamScheduler::Unknown(raw) => raw,
        }
    }
}

/// Stream reset capabilities enabled with `SCTP_ENABLE_STREAM_RESET`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StreamResetOptions(u32);

impl StreamResetOptions {
    /// Allow inbound stream reset requests.
    pub const INCOMING: StreamResetOptions = StreamResetOptions(sys::SCTP_ENABLE_RESET_STREAM_REQ);
    /// Allow association reset requests.
    pub const ASSOCIATION: StreamResetOptions =
        StreamResetOptions(sys::SCTP_ENABLE_RESET_ASSOC_REQ);
    /// Allow stream addition requests.
    pub const STREAM_CHANGE: StreamResetOptions =
        StreamResetOptions(sys::SCTP_ENABLE_CHANGE_ASSOC_REQ);

    /// No stream reconfiguration requests are accepted.
    pub const fn none() -> StreamResetOptions {
        StreamResetOptions(0)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Builds options from raw bits.
    pub const fn from_bits(bits: u32) -> StreamResetOptions {
        StreamResetOptions(bits)
    }

    /// Returns `true` if every option in `other` is set.
    pub const fn contains(self, other: StreamResetOptions) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for StreamResetOptions {
    type Output = StreamResetOptions;

    fn bitor(self, rhs: StreamResetOptions) -> StreamResetOptions {
        StreamResetOptions(self.0 | rhs.0)
    }
}

impl std::fmt::Debug for StreamResetOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut set = *self;
        if set.0 == 0 {
            return f.write_str("StreamResetOptions(none)");
        }
        f.write_str("StreamResetOptions(")?;
        let mut first = true;
        for (name, flag) in [
            ("INCOMING", StreamResetOptions::INCOMING),
            ("ASSOCIATION", StreamResetOptions::ASSOCIATION),
            ("STREAM_CHANGE", StreamResetOptions::STREAM_CHANGE),
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

fn flags_from_peer_params(flags: u32) -> PeerAddressFlags {
    PeerAddressFlags::from_bits(flags)
}

impl Socket {
    // -----------------------------------------------------------------
    // Generic socket options
    // -----------------------------------------------------------------

    /// Returns the socket error, consuming it like `SO_ERROR` does.
    pub(crate) fn take_error(&self) -> io::Result<Option<io::Error>> {
        let raw: libc::c_int = self.get_opt(libc::SOL_SOCKET, libc::SO_ERROR)?;
        if raw == 0 {
            Ok(None)
        } else {
            Ok(Some(io::Error::from_raw_os_error(raw)))
        }
    }

    pub(crate) fn set_send_buffer_size(&self, size: usize) -> io::Result<()> {
        self.set_opt(libc::SOL_SOCKET, libc::SO_SNDBUF, &buffer_size(size)?)
    }

    pub(crate) fn send_buffer_size(&self) -> io::Result<usize> {
        let raw: libc::c_int = self.get_opt(libc::SOL_SOCKET, libc::SO_SNDBUF)?;
        Ok(raw.max(0) as usize)
    }

    pub(crate) fn set_recv_buffer_size(&self, size: usize) -> io::Result<()> {
        self.set_opt(libc::SOL_SOCKET, libc::SO_RCVBUF, &buffer_size(size)?)
    }

    pub(crate) fn recv_buffer_size(&self) -> io::Result<usize> {
        let raw: libc::c_int = self.get_opt(libc::SOL_SOCKET, libc::SO_RCVBUF)?;
        Ok(raw.max(0) as usize)
    }

    // -----------------------------------------------------------------
    // SCTP options
    // -----------------------------------------------------------------

    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        let raw: libc::c_int = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_NODELAY)?;
        Ok(raw != 0)
    }

    pub(crate) fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.set_opt(
            sys::IPPROTO_SCTP,
            sys::SCTP_NODELAY,
            &libc::c_int::from(nodelay),
        )
    }

    pub(crate) fn init_params(&self) -> io::Result<InitParams> {
        let raw: sys::sctp_initmsg = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_INITMSG)?;
        Ok(InitParams {
            outbound_streams: raw.num_ostreams,
            inbound_streams: raw.max_instreams,
            max_attempts: raw.max_attempts,
            init_timeout: Duration::from_millis(u64::from(raw.max_init_timeo)),
        })
    }

    pub(crate) fn set_init_params(&self, params: &InitParams) -> io::Result<()> {
        let timeout = u16::try_from(params.init_timeout.as_millis())
            .map_err(|_| invalid_input("init timeout is too large"))?;
        let raw = sys::sctp_initmsg {
            num_ostreams: params.outbound_streams,
            max_instreams: params.inbound_streams,
            max_attempts: params.max_attempts,
            max_init_timeo: timeout,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_INITMSG, &raw)
    }

    pub(crate) fn rto_info(&self, association_id: AssociationId) -> io::Result<RtoInfo> {
        let raw: sys::sctp_rtoinfo = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_RTOINFO,
            sys::sctp_rtoinfo {
                assoc_id: association_id,
                initial: 0,
                max: 0,
                min: 0,
            },
        )?;
        Ok(RtoInfo {
            initial: from_millis(raw.initial),
            max: from_millis(raw.max),
            min: from_millis(raw.min),
        })
    }

    pub(crate) fn set_rto_info(
        &self,
        association_id: AssociationId,
        info: &RtoInfo,
    ) -> io::Result<()> {
        let raw = sys::sctp_rtoinfo {
            assoc_id: association_id,
            initial: to_millis(info.initial)?,
            max: to_millis(info.max)?,
            min: to_millis(info.min)?,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_RTOINFO, &raw)
    }

    pub(crate) fn assoc_info(&self, association_id: AssociationId) -> io::Result<AssocInfo> {
        let raw: sys::sctp_assocparams = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_ASSOCINFO,
            sys::sctp_assocparams {
                assoc_id: association_id,
                maxrxt: 0,
                number_peer_destinations: 0,
                peer_rwnd: 0,
                local_rwnd: 0,
                cookie_life: 0,
            },
        )?;
        Ok(AssocInfo {
            max_retransmits: raw.maxrxt,
            peer_destinations: raw.number_peer_destinations,
            peer_receiver_window: raw.peer_rwnd,
            local_receiver_window: raw.local_rwnd,
            cookie_life: from_millis(raw.cookie_life),
        })
    }

    pub(crate) fn set_assoc_info(
        &self,
        association_id: AssociationId,
        info: &AssocInfo,
    ) -> io::Result<()> {
        let raw = sys::sctp_assocparams {
            assoc_id: association_id,
            maxrxt: info.max_retransmits,
            number_peer_destinations: 0,
            peer_rwnd: 0,
            local_rwnd: 0,
            cookie_life: to_millis(info.cookie_life)?,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_ASSOCINFO, &raw)
    }

    pub(crate) fn max_segment(&self, association_id: AssociationId) -> io::Result<u32> {
        let raw: sys::sctp_assoc_value = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_MAXSEG,
            sys::sctp_assoc_value {
                assoc_id: association_id,
                value: 0,
            },
        )?;
        Ok(raw.value)
    }

    pub(crate) fn set_max_segment(
        &self,
        association_id: AssociationId,
        max_segment: u32,
    ) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: association_id,
            value: max_segment,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_MAXSEG, &raw)
    }

    pub(crate) fn disable_fragments(&self) -> io::Result<bool> {
        let raw: libc::c_int = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_DISABLE_FRAGMENTS)?;
        Ok(raw != 0)
    }

    pub(crate) fn set_disable_fragments(&self, disable: bool) -> io::Result<()> {
        self.set_opt(
            sys::IPPROTO_SCTP,
            sys::SCTP_DISABLE_FRAGMENTS,
            &libc::c_int::from(disable),
        )
    }

    pub(crate) fn autoclose(&self) -> io::Result<u32> {
        let raw: libc::c_int = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_AUTOCLOSE)?;
        Ok(raw.max(0) as u32)
    }

    pub(crate) fn set_autoclose(&self, seconds: u32) -> io::Result<()> {
        let raw = libc::c_int::try_from(seconds)
            .map_err(|_| invalid_input("autoclose interval is too large"))?;
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_AUTOCLOSE, &raw)
    }

    pub(crate) fn adaptation_layer(&self) -> io::Result<u32> {
        let raw: sys::sctp_setadaptation =
            self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_ADAPTATION_LAYER)?;
        Ok(raw.adaptation_ind)
    }

    pub(crate) fn set_adaptation_layer(&self, adaptation: u32) -> io::Result<()> {
        let raw = sys::sctp_setadaptation {
            adaptation_ind: adaptation,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_ADAPTATION_LAYER, &raw)
    }

    pub(crate) fn context(&self, association_id: AssociationId) -> io::Result<u32> {
        let raw: sys::sctp_assoc_value = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_CONTEXT,
            sys::sctp_assoc_value {
                assoc_id: association_id,
                value: 0,
            },
        )?;
        Ok(raw.value)
    }

    pub(crate) fn set_context(
        &self,
        association_id: AssociationId,
        context: u32,
    ) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: association_id,
            value: context,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_CONTEXT, &raw)
    }

    pub(crate) fn fragment_interleave(&self) -> io::Result<bool> {
        let raw: libc::c_int = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_FRAGMENT_INTERLEAVE)?;
        Ok(raw != 0)
    }

    pub(crate) fn set_fragment_interleave(&self, interleave: bool) -> io::Result<()> {
        self.set_opt(
            sys::IPPROTO_SCTP,
            sys::SCTP_FRAGMENT_INTERLEAVE,
            &libc::c_int::from(interleave),
        )
    }

    pub(crate) fn partial_delivery_point(&self) -> io::Result<u32> {
        self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_PARTIAL_DELIVERY_POINT)
    }

    pub(crate) fn set_partial_delivery_point(&self, point: u32) -> io::Result<()> {
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_PARTIAL_DELIVERY_POINT, &point)
    }

    pub(crate) fn max_burst(&self, association_id: AssociationId) -> io::Result<u32> {
        let raw: sys::sctp_assoc_value = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_MAX_BURST,
            sys::sctp_assoc_value {
                assoc_id: association_id,
                value: 0,
            },
        )?;
        Ok(raw.value)
    }

    pub(crate) fn set_max_burst(
        &self,
        association_id: AssociationId,
        max_burst: u32,
    ) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: association_id,
            value: max_burst,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_MAX_BURST, &raw)
    }

    pub(crate) fn delayed_sack(&self, association_id: AssociationId) -> io::Result<DelayedSack> {
        let raw: sys::sctp_sack_info = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_DELAYED_SACK,
            sys::sctp_sack_info {
                assoc_id: association_id,
                delay: 0,
                freq: 0,
            },
        )?;
        Ok(DelayedSack {
            delay: (raw.delay != 0).then(|| from_millis(raw.delay)),
            frequency: raw.freq,
        })
    }

    pub(crate) fn set_delayed_sack(
        &self,
        association_id: AssociationId,
        params: &DelayedSack,
    ) -> io::Result<()> {
        let raw = sys::sctp_sack_info {
            assoc_id: association_id,
            delay: params.delay.map(to_millis).transpose()?.unwrap_or(0),
            freq: params.frequency,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_DELAYED_SACK, &raw)
    }

    pub(crate) fn peer_addr_params(
        &self,
        association_id: AssociationId,
        address: Option<&SocketAddr>,
    ) -> io::Result<PeerAddressParams> {
        let (storage, _) = match address {
            Some(address) => addr::to_storage(address),
            None => (unsafe { std::mem::zeroed() }, 0),
        };
        let raw: sys::sctp_paddrparams = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_PEER_ADDR_PARAMS,
            sys::sctp_paddrparams {
                assoc_id: association_id,
                address: storage,
                hbinterval: 0,
                pathmaxrxt: 0,
                pathmtu: 0,
                sackdelay: 0,
                flags: 0,
                ipv6_flowlabel: 0,
                dscp: 0,
                _padding: [0],
            },
        )?;
        let hbinterval: u32 = raw.hbinterval;
        let pathmaxrxt: u16 = raw.pathmaxrxt;
        let pathmtu: u32 = raw.pathmtu;
        let sackdelay: u32 = raw.sackdelay;
        let flags: u32 = raw.flags;
        let ipv6_flowlabel: u32 = raw.ipv6_flowlabel;
        let dscp: u8 = raw.dscp;
        Ok(PeerAddressParams {
            heartbeat_interval: (hbinterval != 0).then(|| from_millis(hbinterval)),
            path_max_retransmits: pathmaxrxt,
            path_mtu: pathmtu,
            sack_delay: (sackdelay != 0).then(|| from_millis(sackdelay)),
            flags: flags_from_peer_params(flags),
            ipv6_flow_label: ipv6_flowlabel,
            dscp,
        })
    }

    pub(crate) fn set_peer_addr_params(
        &self,
        association_id: AssociationId,
        address: Option<&SocketAddr>,
        params: &PeerAddressParams,
    ) -> io::Result<()> {
        let (storage, _) = match address {
            Some(address) => addr::to_storage(address),
            None => (unsafe { std::mem::zeroed() }, 0),
        };
        let raw = sys::sctp_paddrparams {
            assoc_id: association_id,
            address: storage,
            hbinterval: params
                .heartbeat_interval
                .map(to_millis)
                .transpose()?
                .unwrap_or(0),
            pathmaxrxt: params.path_max_retransmits,
            pathmtu: params.path_mtu,
            sackdelay: params.sack_delay.map(to_millis).transpose()?.unwrap_or(0),
            flags: params.flags.bits(),
            ipv6_flowlabel: params.ipv6_flow_label,
            dscp: params.dscp,
            _padding: [0],
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_PEER_ADDR_PARAMS, &raw)
    }

    pub(crate) fn peer_addr_thresholds(
        &self,
        association_id: AssociationId,
        address: Option<&SocketAddr>,
    ) -> io::Result<PeerAddressThresholds> {
        let (storage, _) = match address {
            Some(address) => addr::to_storage(address),
            None => (unsafe { std::mem::zeroed() }, 0),
        };
        let raw: sys::sctp_paddrthlds = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_PEER_ADDR_THLDS,
            sys::sctp_paddrthlds {
                assoc_id: association_id,
                address: storage,
                pathmaxrxt: 0,
                pathpfthld: 0,
            },
        )?;
        Ok(PeerAddressThresholds {
            path_max_retransmits: raw.pathmaxrxt,
            potentially_failed_threshold: raw.pathpfthld,
        })
    }

    pub(crate) fn set_peer_addr_thresholds(
        &self,
        association_id: AssociationId,
        address: Option<&SocketAddr>,
        thresholds: &PeerAddressThresholds,
    ) -> io::Result<()> {
        let (storage, _) = match address {
            Some(address) => addr::to_storage(address),
            None => (unsafe { std::mem::zeroed() }, 0),
        };
        let raw = sys::sctp_paddrthlds {
            assoc_id: association_id,
            address: storage,
            pathmaxrxt: thresholds.path_max_retransmits,
            pathpfthld: thresholds.potentially_failed_threshold,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_PEER_ADDR_THLDS, &raw)
    }

    pub(crate) fn primary_addr(&self, association_id: AssociationId) -> io::Result<SocketAddr> {
        let raw: sys::sctp_prim = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_PRIMARY_ADDR,
            sys::sctp_prim {
                assoc_id: association_id,
                address: unsafe { std::mem::zeroed() },
            },
        )?;
        let address = raw.address;
        addr::from_storage(&address)
    }

    pub(crate) fn set_primary_addr(
        &self,
        association_id: AssociationId,
        address: &SocketAddr,
    ) -> io::Result<()> {
        let (storage, _) = addr::to_storage(address);
        let raw = sys::sctp_prim {
            assoc_id: association_id,
            address: storage,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_PRIMARY_ADDR, &raw)
    }

    pub(crate) fn set_peer_primary_addr(
        &self,
        association_id: AssociationId,
        address: &SocketAddr,
    ) -> io::Result<()> {
        let (storage, _) = addr::to_storage(address);
        let raw = sys::sctp_setpeerprim {
            assoc_id: association_id,
            address: storage,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_SET_PEER_PRIMARY_ADDR, &raw)
    }

    pub(crate) fn status(&self, association_id: AssociationId) -> io::Result<AssociationStatus> {
        let raw: sys::sctp_status = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_STATUS,
            sys::sctp_status {
                assoc_id: association_id,
                state: 0,
                rwnd: 0,
                unackdata: 0,
                penddata: 0,
                instrms: 0,
                outstrms: 0,
                fragmentation_point: 0,
                primary: unsafe { std::mem::zeroed() },
            },
        )?;
        Ok(AssociationStatus {
            association_id: raw.assoc_id,
            state: connection_state(raw.state),
            receiver_window: raw.rwnd,
            unacked_chunks: raw.unackdata,
            pending_chunks: raw.penddata,
            inbound_streams: raw.instrms,
            outbound_streams: raw.outstrms,
            fragmentation_point: raw.fragmentation_point,
            primary: peer_address_info(&raw.primary)?,
        })
    }

    pub(crate) fn peer_addr_info(
        &self,
        association_id: AssociationId,
        address: &SocketAddr,
    ) -> io::Result<PeerAddressInfo> {
        let (storage, _) = addr::to_storage(address);
        let raw: sys::sctp_paddrinfo = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_GET_PEER_ADDR_INFO,
            sys::sctp_paddrinfo {
                assoc_id: association_id,
                address: storage,
                state: 0,
                cwnd: 0,
                srtt: 0,
                rto: 0,
                mtu: 0,
            },
        )?;
        peer_address_info(&raw)
    }

    pub(crate) fn assoc_stats(
        &self,
        association_id: AssociationId,
    ) -> io::Result<AssociationStats> {
        let raw: sys::sctp_assoc_stats = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_GET_ASSOC_STATS,
            sys::sctp_assoc_stats {
                assoc_id: association_id,
                obs_rto_ipaddr: unsafe { std::mem::zeroed() },
                maxrto: 0,
                isacks: 0,
                osacks: 0,
                opackets: 0,
                ipackets: 0,
                rtxchunks: 0,
                outofseqtsns: 0,
                idupchunks: 0,
                gapcnt: 0,
                ouodchunks: 0,
                iuodchunks: 0,
                oodchunks: 0,
                iodchunks: 0,
                octrlchunks: 0,
                ictrlchunks: 0,
            },
        )?;
        let observed_rto_address = if raw.maxrto == 0 {
            None
        } else {
            addr::from_storage(&raw.obs_rto_ipaddr).ok()
        };
        Ok(AssociationStats {
            association_id: raw.assoc_id,
            observed_rto_address,
            max_observed_rto: Duration::from_millis(raw.maxrto),
            sacks_received: raw.isacks,
            sacks_sent: raw.osacks,
            packets_sent: raw.opackets,
            packets_received: raw.ipackets,
            retransmitted_chunks: raw.rtxchunks,
            out_of_sequence_tsns: raw.outofseqtsns,
            duplicate_chunks: raw.idupchunks,
            gap_acknowledgements: raw.gapcnt,
            unordered_chunks_sent: raw.ouodchunks,
            unordered_chunks_received: raw.iuodchunks,
            ordered_chunks_sent: raw.oodchunks,
            ordered_chunks_received: raw.iodchunks,
            control_chunks_sent: raw.octrlchunks,
            control_chunks_received: raw.ictrlchunks,
        })
    }

    pub(crate) fn default_send_info(&self, association_id: AssociationId) -> io::Result<SendInfo> {
        let raw: sys::sctp_sndinfo = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_DEFAULT_SNDINFO,
            sys::sctp_sndinfo {
                sid: 0,
                flags: 0,
                ppid: 0,
                context: 0,
                assoc_id: association_id,
            },
        )?;
        let mut info = SendInfo::from_raw(&raw);
        info.association_id = association_id;
        Ok(info)
    }

    pub(crate) fn set_default_send_info(
        &self,
        association_id: AssociationId,
        info: &SendInfo,
    ) -> io::Result<()> {
        let mut raw = info.to_raw();
        raw.assoc_id = association_id;
        raw.flags &= sys::SCTP_UNORDERED | sys::SCTP_ADDR_OVER | sys::SCTP_ABORT | sys::SCTP_EOF;
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_DEFAULT_SNDINFO, &raw)
    }

    /// Enables or disables `SCTP_RCVINFO` ancillary data on received messages.
    pub(crate) fn set_receive_rcv_info(&self, enable: bool) -> io::Result<()> {
        self.set_opt(
            sys::IPPROTO_SCTP,
            sys::SCTP_RECVRCVINFO,
            &libc::c_int::from(enable),
        )
    }

    pub(crate) fn receive_next_info(&self) -> io::Result<bool> {
        let raw: libc::c_int = self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_RECVNXTINFO)?;
        Ok(raw != 0)
    }

    pub(crate) fn set_receive_next_info(&self, enable: bool) -> io::Result<()> {
        self.set_opt(
            sys::IPPROTO_SCTP,
            sys::SCTP_RECVNXTINFO,
            &libc::c_int::from(enable),
        )
    }

    pub(crate) fn stream_scheduler(
        &self,
        association_id: AssociationId,
    ) -> io::Result<StreamScheduler> {
        let raw: sys::sctp_assoc_value = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_STREAM_SCHEDULER,
            sys::sctp_assoc_value {
                assoc_id: association_id,
                value: 0,
            },
        )?;
        Ok(StreamScheduler::from_raw(raw.value as i32))
    }

    pub(crate) fn set_stream_scheduler(
        &self,
        association_id: AssociationId,
        scheduler: StreamScheduler,
    ) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: association_id,
            value: scheduler.to_raw() as u32,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_STREAM_SCHEDULER, &raw)
    }

    pub(crate) fn set_stream_scheduler_value(
        &self,
        association_id: AssociationId,
        stream_id: u16,
        value: u16,
    ) -> io::Result<()> {
        let raw = sys::sctp_stream_value {
            assoc_id: association_id,
            stream_id,
            stream_value: value,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_STREAM_SCHEDULER_VALUE, &raw)
    }

    pub(crate) fn enable_stream_reset(
        &self,
        association_id: AssociationId,
        options: StreamResetOptions,
    ) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: association_id,
            value: options.bits(),
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_ENABLE_STREAM_RESET, &raw)
    }

    pub(crate) fn reset_streams(
        &self,
        association_id: AssociationId,
        flags: crate::notification::StreamResetFlags,
        streams: &[u16],
    ) -> io::Result<()> {
        let count =
            u16::try_from(streams.len()).map_err(|_| invalid_input("too many streams to reset"))?;
        let mut buf = Vec::with_capacity(8 + streams.len() * 2);
        buf.extend_from_slice(&association_id.to_ne_bytes());
        buf.extend_from_slice(&flags.bits().to_ne_bytes());
        buf.extend_from_slice(&count.to_ne_bytes());
        for stream in streams {
            buf.extend_from_slice(&stream.to_ne_bytes());
        }
        self.set_opt_buf(sys::IPPROTO_SCTP, sys::SCTP_RESET_STREAMS, &buf)
    }

    pub(crate) fn reset_association(&self, association_id: AssociationId) -> io::Result<()> {
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_RESET_ASSOC, &association_id)
    }

    pub(crate) fn add_streams(
        &self,
        association_id: AssociationId,
        inbound: u16,
        outbound: u16,
    ) -> io::Result<()> {
        let raw = sys::sctp_add_streams {
            assoc_id: association_id,
            instrms: inbound,
            outstrms: outbound,
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_ADD_STREAMS, &raw)
    }

    pub(crate) fn assoc_number(&self) -> io::Result<u32> {
        self.get_opt(sys::IPPROTO_SCTP, sys::SCTP_GET_ASSOC_NUMBER)
    }

    pub(crate) fn set_reconfig_supported(&self, enable: bool) -> io::Result<()> {
        let raw = sys::sctp_assoc_value {
            assoc_id: crate::FUTURE_ASSOCIATION,
            value: u32::from(enable),
        };
        self.set_opt(sys::IPPROTO_SCTP, sys::SCTP_RECONFIG_SUPPORTED, &raw)
    }

    pub(crate) fn reconfig_supported(&self) -> io::Result<bool> {
        let raw: sys::sctp_assoc_value = self.get_opt_with(
            sys::IPPROTO_SCTP,
            sys::SCTP_RECONFIG_SUPPORTED,
            sys::sctp_assoc_value {
                assoc_id: crate::FUTURE_ASSOCIATION,
                value: 0,
            },
        )?;
        Ok(raw.value != 0)
    }
}

fn connection_state(state: i32) -> ConnectionState {
    match state {
        sys::SCTP_EMPTY => ConnectionState::Empty,
        sys::SCTP_CLOSED => ConnectionState::Closed,
        sys::SCTP_COOKIE_WAIT => ConnectionState::CookieWait,
        sys::SCTP_COOKIE_ECHOED => ConnectionState::CookieEchoed,
        sys::SCTP_ESTABLISHED => ConnectionState::Established,
        sys::SCTP_SHUTDOWN_PENDING => ConnectionState::ShutdownPending,
        sys::SCTP_SHUTDOWN_SENT => ConnectionState::ShutdownSent,
        sys::SCTP_SHUTDOWN_RECEIVED => ConnectionState::ShutdownReceived,
        sys::SCTP_SHUTDOWN_ACK_SENT => ConnectionState::ShutdownAckSent,
        other => ConnectionState::Unknown(other),
    }
}

fn peer_address_status(state: i32) -> PeerAddressStatus {
    match state {
        sys::SCTP_INACTIVE => PeerAddressStatus::Inactive,
        sys::SCTP_PF => PeerAddressStatus::PotentiallyFailed,
        sys::SCTP_ACTIVE => PeerAddressStatus::Active,
        sys::SCTP_UNCONFIRMED => PeerAddressStatus::Unconfirmed,
        other => PeerAddressStatus::Unknown(other),
    }
}

fn peer_address_info(raw: &sys::sctp_paddrinfo) -> io::Result<PeerAddressInfo> {
    let address = raw.address;
    Ok(PeerAddressInfo {
        association_id: raw.assoc_id,
        address: addr::from_storage(&address)?,
        state: peer_address_status(raw.state),
        congestion_window: raw.cwnd,
        smoothed_rtt: from_millis(raw.srtt),
        retransmission_timeout: from_millis(raw.rto),
        mtu: raw.mtu,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_conversions() {
        assert_eq!(to_millis(Duration::from_millis(1500)).unwrap(), 1500);
        assert!(to_millis(Duration::from_secs(u64::from(u32::MAX) + 1)).is_err());
        assert_eq!(from_millis(1500), Duration::from_millis(1500));
    }

    #[test]
    fn scheduler_roundtrip() {
        for scheduler in [
            StreamScheduler::FirstComeFirstServed,
            StreamScheduler::Priority,
            StreamScheduler::RoundRobin,
            StreamScheduler::FairCapacity,
            StreamScheduler::WeightedFairQueueing,
            StreamScheduler::Unknown(42),
        ] {
            assert_eq!(StreamScheduler::from_raw(scheduler.to_raw()), scheduler);
        }
    }

    #[test]
    fn flags_debug() {
        assert_eq!(
            format!(
                "{:?}",
                PeerAddressFlags::HEARTBEATS | PeerAddressFlags::PATH_MTU_DISCOVERY
            ),
            "PeerAddressFlags(HEARTBEATS | PATH_MTU_DISCOVERY)"
        );
    }
}
