//! Raw Linux SCTP socket API definitions.
//!
//! These items mirror the ABI described by `<linux/sctp.h>` and RFC 6458.
//! Linux exposes the whole SCTP socket API through `getsockopt(2)` and
//! `setsockopt(2)` (level `IPPROTO_SCTP`) plus ancillary data on
//! `sendmsg(2)`/`recvmsg(2)`, so no `libsctp` (lksctp-tools) is required.

#![allow(non_camel_case_types)]
#![allow(dead_code)] // the full ABI is documented even where unused

use libc::{c_int, sockaddr, sockaddr_storage};

pub(crate) type assoc_t = i32;

pub(crate) const IPPROTO_SCTP: c_int = 132;

// ---------------------------------------------------------------------------
// Socket options
// ---------------------------------------------------------------------------

pub(crate) const SCTP_RTOINFO: c_int = 0;
pub(crate) const SCTP_ASSOCINFO: c_int = 1;
pub(crate) const SCTP_INITMSG: c_int = 2;
pub(crate) const SCTP_NODELAY: c_int = 3;
pub(crate) const SCTP_AUTOCLOSE: c_int = 4;
pub(crate) const SCTP_SET_PEER_PRIMARY_ADDR: c_int = 5;
pub(crate) const SCTP_PRIMARY_ADDR: c_int = 6;
pub(crate) const SCTP_ADAPTATION_LAYER: c_int = 7;
pub(crate) const SCTP_DISABLE_FRAGMENTS: c_int = 8;
pub(crate) const SCTP_PEER_ADDR_PARAMS: c_int = 9;
pub(crate) const SCTP_DEFAULT_SEND_PARAM: c_int = 10;
pub(crate) const SCTP_EVENTS: c_int = 11;
pub(crate) const SCTP_MAXSEG: c_int = 13;
pub(crate) const SCTP_STATUS: c_int = 14;
pub(crate) const SCTP_GET_PEER_ADDR_INFO: c_int = 15;
pub(crate) const SCTP_DELAYED_SACK: c_int = 16;
pub(crate) const SCTP_CONTEXT: c_int = 17;
pub(crate) const SCTP_FRAGMENT_INTERLEAVE: c_int = 18;
pub(crate) const SCTP_PARTIAL_DELIVERY_POINT: c_int = 19;
pub(crate) const SCTP_MAX_BURST: c_int = 20;
pub(crate) const SCTP_GET_ASSOC_NUMBER: c_int = 28;
pub(crate) const SCTP_GET_ASSOC_ID_LIST: c_int = 29;
pub(crate) const SCTP_PEER_ADDR_THLDS: c_int = 31;
pub(crate) const SCTP_RECVRCVINFO: c_int = 32;
pub(crate) const SCTP_RECVNXTINFO: c_int = 33;
pub(crate) const SCTP_DEFAULT_SNDINFO: c_int = 34;
pub(crate) const SCTP_REUSE_PORT: c_int = 36;

pub(crate) const SCTP_SOCKOPT_BINDX_ADD: c_int = 100;
pub(crate) const SCTP_SOCKOPT_BINDX_REM: c_int = 101;
pub(crate) const SCTP_SOCKOPT_PEELOFF: c_int = 102;
pub(crate) const SCTP_GET_PEER_ADDRS: c_int = 108;
pub(crate) const SCTP_GET_LOCAL_ADDRS: c_int = 109;
pub(crate) const SCTP_SOCKOPT_CONNECTX: c_int = 110;
pub(crate) const SCTP_SOCKOPT_CONNECTX3: c_int = 111;
pub(crate) const SCTP_GET_ASSOC_STATS: c_int = 112;
pub(crate) const SCTP_RECONFIG_SUPPORTED: c_int = 117;
pub(crate) const SCTP_ENABLE_STREAM_RESET: c_int = 118;
pub(crate) const SCTP_RESET_STREAMS: c_int = 119;
pub(crate) const SCTP_RESET_ASSOC: c_int = 120;
pub(crate) const SCTP_ADD_STREAMS: c_int = 121;
pub(crate) const SCTP_STREAM_SCHEDULER: c_int = 123;
pub(crate) const SCTP_STREAM_SCHEDULER_VALUE: c_int = 124;
pub(crate) const SCTP_EVENT: c_int = 127;

// ---------------------------------------------------------------------------
// Values used with SCTP_SOCKOPT_BINDX_*
// ---------------------------------------------------------------------------

pub(crate) const SCTP_BINDX_ADD_ADDR: c_int = 0x01;
pub(crate) const SCTP_BINDX_REM_ADDR: c_int = 0x02;

// ---------------------------------------------------------------------------
// Ancillary data types (`enum sctp_cmsg_type`)
// ---------------------------------------------------------------------------

pub(crate) const SCTP_SNDRCV: c_int = 1;
pub(crate) const SCTP_SNDINFO: c_int = 2;
pub(crate) const SCTP_RCVINFO: c_int = 3;
pub(crate) const SCTP_NXTINFO: c_int = 4;
pub(crate) const SCTP_PRINFO: c_int = 5;

// ---------------------------------------------------------------------------
// Notification types (`enum sctp_sn_type`)
// ---------------------------------------------------------------------------

pub(crate) const SCTP_DATA_IO_EVENT: u16 = 0x8000;
pub(crate) const SCTP_ASSOC_CHANGE: u16 = 0x8001;
pub(crate) const SCTP_PEER_ADDR_CHANGE: u16 = 0x8002;
pub(crate) const SCTP_SEND_FAILED: u16 = 0x8003;
pub(crate) const SCTP_REMOTE_ERROR: u16 = 0x8004;
pub(crate) const SCTP_SHUTDOWN_EVENT: u16 = 0x8005;
pub(crate) const SCTP_PARTIAL_DELIVERY_EVENT: u16 = 0x8006;
pub(crate) const SCTP_ADAPTATION_INDICATION: u16 = 0x8007;
pub(crate) const SCTP_AUTHENTICATION_EVENT: u16 = 0x8008;
pub(crate) const SCTP_SENDER_DRY_EVENT: u16 = 0x8009;
pub(crate) const SCTP_STREAM_RESET_EVENT: u16 = 0x800a;
pub(crate) const SCTP_ASSOC_RESET_EVENT: u16 = 0x800b;
pub(crate) const SCTP_STREAM_CHANGE_EVENT: u16 = 0x800c;
pub(crate) const SCTP_SEND_FAILED_EVENT: u16 = 0x800d;

/// Number of notification types that can be subscribed to via `SCTP_EVENTS`.
pub(crate) const EVENT_COUNT: usize = 14;

// ---------------------------------------------------------------------------
// Message flags (`enum sctp_sinfo_flags`)
// ---------------------------------------------------------------------------

pub(crate) const SCTP_UNORDERED: u16 = 1 << 0;
pub(crate) const SCTP_ADDR_OVER: u16 = 1 << 1;
pub(crate) const SCTP_ABORT: u16 = 1 << 2;
pub(crate) const SCTP_SACK_IMMEDIATELY: u16 = 1 << 3;
pub(crate) const SCTP_SENDALL: u16 = 1 << 6;
pub(crate) const SCTP_PR_SCTP_ALL: u16 = 1 << 7;

pub(crate) const SCTP_PR_SCTP_NONE: u16 = 0x0000;
pub(crate) const SCTP_PR_SCTP_TTL: u16 = 0x0010;
pub(crate) const SCTP_PR_SCTP_RTX: u16 = 0x0020;
pub(crate) const SCTP_PR_SCTP_PRIO: u16 = 0x0030;
pub(crate) const SCTP_EOF: u16 = 0x0200; // MSG_FIN

/// The `msg_flags` bit set on a received notification.
pub(crate) const MSG_NOTIFICATION: c_int = 0x8000;

// ---------------------------------------------------------------------------
// Notification states, errors and flags
// ---------------------------------------------------------------------------

pub(crate) const SCTP_PARTIAL_DELIVERY_ABORTED: u32 = 0;

pub(crate) const SCTP_AUTH_NEW_KEY: u32 = 0;
pub(crate) const SCTP_AUTH_FREE_KEY: u32 = 1;
pub(crate) const SCTP_AUTH_NO_AUTH: u32 = 2;

pub(crate) const SCTP_STREAM_RESET_INCOMING_SSN: u16 = 0x0001;
pub(crate) const SCTP_STREAM_RESET_OUTGOING_SSN: u16 = 0x0002;
pub(crate) const SCTP_STREAM_RESET_DENIED: u16 = 0x0004;
pub(crate) const SCTP_STREAM_RESET_FAILED: u16 = 0x0008;

// ---------------------------------------------------------------------------
// Stream reset / scheduler options
// ---------------------------------------------------------------------------

pub(crate) const SCTP_ENABLE_RESET_STREAM_REQ: u32 = 0x01;
pub(crate) const SCTP_ENABLE_RESET_ASSOC_REQ: u32 = 0x02;
pub(crate) const SCTP_ENABLE_CHANGE_ASSOC_REQ: u32 = 0x04;

pub(crate) const SCTP_SS_FCFS: i32 = 0;
pub(crate) const SCTP_SS_PRIO: i32 = 1;
pub(crate) const SCTP_SS_RR: i32 = 2;
pub(crate) const SCTP_SS_FC: i32 = 3;
pub(crate) const SCTP_SS_WFQ: i32 = 4;

// ---------------------------------------------------------------------------
// Association states (`enum sctp_sstat_state`)
// ---------------------------------------------------------------------------

pub(crate) const SCTP_EMPTY: i32 = 0;
pub(crate) const SCTP_CLOSED: i32 = 1;
pub(crate) const SCTP_COOKIE_WAIT: i32 = 2;
pub(crate) const SCTP_COOKIE_ECHOED: i32 = 3;
pub(crate) const SCTP_ESTABLISHED: i32 = 4;
pub(crate) const SCTP_SHUTDOWN_PENDING: i32 = 5;
pub(crate) const SCTP_SHUTDOWN_SENT: i32 = 6;
pub(crate) const SCTP_SHUTDOWN_RECEIVED: i32 = 7;
pub(crate) const SCTP_SHUTDOWN_ACK_SENT: i32 = 8;

// ---------------------------------------------------------------------------
// Peer address states (`enum sctp_spinfo_state`)
// ---------------------------------------------------------------------------

pub(crate) const SCTP_INACTIVE: i32 = 0;
pub(crate) const SCTP_PF: i32 = 1;
pub(crate) const SCTP_ACTIVE: i32 = 2;
pub(crate) const SCTP_UNCONFIRMED: i32 = 3;
pub(crate) const SCTP_UNKNOWN: i32 = 0xffff;

// ---------------------------------------------------------------------------
// `struct sctp_paddrparams` flags (`enum sctp_spp_flags`)
// ---------------------------------------------------------------------------

pub(crate) const SPP_HB_ENABLE: u32 = 1 << 0;
pub(crate) const SPP_HB_DISABLE: u32 = 1 << 1;
pub(crate) const SPP_HB_DEMAND: u32 = 1 << 2;
pub(crate) const SPP_PMTUD_ENABLE: u32 = 1 << 3;
pub(crate) const SPP_PMTUD_DISABLE: u32 = 1 << 4;
pub(crate) const SPP_SACKDELAY_ENABLE: u32 = 1 << 5;
pub(crate) const SPP_SACKDELAY_DISABLE: u32 = 1 << 6;
pub(crate) const SPP_HB_TIME_IS_ZERO: u32 = 1 << 7;
pub(crate) const SPP_IPV6_FLOWLABEL: u32 = 1 << 8;
pub(crate) const SPP_DSCP: u32 = 1 << 9;

// ---------------------------------------------------------------------------
// Structures
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_initmsg {
    pub num_ostreams: u16,
    pub max_instreams: u16,
    pub max_attempts: u16,
    pub max_init_timeo: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_rtoinfo {
    pub assoc_id: assoc_t,
    pub initial: u32,
    pub max: u32,
    pub min: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_assocparams {
    pub assoc_id: assoc_t,
    pub maxrxt: u16,
    pub number_peer_destinations: u16,
    pub peer_rwnd: u32,
    pub local_rwnd: u32,
    pub cookie_life: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_sack_info {
    pub assoc_id: assoc_t,
    pub delay: u32,
    pub freq: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_assoc_value {
    pub assoc_id: assoc_t,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_setadaptation {
    pub adaptation_ind: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_prim {
    pub assoc_id: assoc_t,
    pub address: sockaddr_storage,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_setpeerprim {
    pub assoc_id: assoc_t,
    pub address: sockaddr_storage,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_paddrparams {
    pub assoc_id: assoc_t,
    pub address: sockaddr_storage,
    pub hbinterval: u32,
    pub pathmaxrxt: u16,
    pub pathmtu: u32,
    pub sackdelay: u32,
    pub flags: u32,
    pub ipv6_flowlabel: u32,
    pub dscp: u8,
    /// Trailing padding: C rounds the size up to the 4-byte `aligned(4)`.
    pub _padding: [u8; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_paddrthlds {
    pub assoc_id: assoc_t,
    pub address: sockaddr_storage,
    pub pathmaxrxt: u16,
    pub pathpfthld: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_sndinfo {
    pub sid: u16,
    pub flags: u16,
    pub ppid: u32,
    pub context: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_prinfo {
    pub policy: u16,
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_rcvinfo {
    pub sid: u16,
    pub ssn: u16,
    pub flags: u16,
    pub ppid: u32,
    pub tsn: u32,
    pub cumtsn: u32,
    pub context: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_nxtinfo {
    pub sid: u16,
    pub flags: u16,
    pub ppid: u32,
    pub length: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_sndrcvinfo {
    pub stream: u16,
    pub ssn: u16,
    pub flags: u16,
    pub ppid: u32,
    pub context: u32,
    pub timetolive: u32,
    pub tsn: u32,
    pub cumtsn: u32,
    pub assoc_id: assoc_t,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_paddrinfo {
    pub assoc_id: assoc_t,
    pub address: sockaddr_storage,
    pub state: i32,
    pub cwnd: u32,
    pub srtt: u32,
    pub rto: u32,
    pub mtu: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_status {
    pub assoc_id: assoc_t,
    pub state: i32,
    pub rwnd: u32,
    pub unackdata: u16,
    pub penddata: u16,
    pub instrms: u16,
    pub outstrms: u16,
    pub fragmentation_point: u32,
    pub primary: sctp_paddrinfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_assoc_stats {
    pub assoc_id: assoc_t,
    pub obs_rto_ipaddr: sockaddr_storage,
    pub maxrto: u64,
    pub isacks: u64,
    pub osacks: u64,
    pub opackets: u64,
    pub ipackets: u64,
    pub rtxchunks: u64,
    pub outofseqtsns: u64,
    pub idupchunks: u64,
    pub gapcnt: u64,
    pub ouodchunks: u64,
    pub iuodchunks: u64,
    pub oodchunks: u64,
    pub iodchunks: u64,
    pub octrlchunks: u64,
    pub ictrlchunks: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_getaddrs_old {
    pub assoc_id: assoc_t,
    pub addr_num: c_int,
    pub addrs: *mut sockaddr,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_peeloff_arg {
    pub assoc_id: assoc_t,
    pub sd: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_event {
    pub assoc_id: assoc_t,
    pub type_: u16,
    pub on: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_add_streams {
    pub assoc_id: assoc_t,
    pub instrms: u16,
    pub outstrms: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_stream_value {
    pub assoc_id: assoc_t,
    pub stream_id: u16,
    pub stream_value: u16,
}

// --- Notification prefixes ---

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_notification_header {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_assoc_change {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub state: u16,
    pub error: u16,
    pub outbound_streams: u16,
    pub inbound_streams: u16,
    pub assoc_id: assoc_t,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_paddr_change {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub address: sockaddr_storage,
    pub state: i32,
    pub error: i32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_remote_error {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub error: u16,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_send_failed {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub error: u32,
    pub info: sctp_sndrcvinfo,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_send_failed_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub error: u32,
    pub info: sctp_sndinfo,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_shutdown_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_adaptation_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub adaptation_ind: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_pdapi_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub indication: u32,
    pub assoc_id: assoc_t,
    pub stream: u32,
    pub seq: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_authkey_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub keynumber: u16,
    pub altkeynumber: u16,
    pub indication: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_sender_dry_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_stream_reset_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub assoc_id: assoc_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_assoc_reset_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub assoc_id: assoc_t,
    pub local_tsn: u32,
    pub remote_tsn: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct sctp_stream_change_event {
    pub type_: u16,
    pub flags: u16,
    pub length: u32,
    pub assoc_id: assoc_t,
    pub instrms: u16,
    pub outstrms: u16,
}

/// `struct sctp_event_subscribe` is an array of one byte per notification type.
pub(crate) type sctp_event_subscribe = [u8; EVENT_COUNT];

// Compile-time ABI checks for 64-bit targets.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::size_of;

    assert!(size_of::<sctp_initmsg>() == 8);
    assert!(size_of::<sctp_rtoinfo>() == 16);
    assert!(size_of::<sctp_assocparams>() == 20);
    assert!(size_of::<sctp_sack_info>() == 12);
    assert!(size_of::<sctp_assoc_value>() == 8);
    assert!(size_of::<sctp_setadaptation>() == 4);
    assert!(size_of::<sctp_prim>() == 132);
    assert!(size_of::<sctp_setpeerprim>() == 132);
    assert!(size_of::<sctp_paddrparams>() == 156);
    assert!(size_of::<sctp_paddrthlds>() == 144);
    assert!(size_of::<sctp_sndinfo>() == 16);
    assert!(size_of::<sctp_rcvinfo>() == 28);
    assert!(size_of::<sctp_nxtinfo>() == 16);
    assert!(size_of::<sctp_prinfo>() == 8);
    assert!(size_of::<sctp_sndrcvinfo>() == 32);
    assert!(size_of::<sctp_paddrinfo>() == 152);
    assert!(size_of::<sctp_status>() == 176);
    assert!(size_of::<sctp_assoc_stats>() == 256);
    assert!(size_of::<sctp_getaddrs_old>() == 16);
    assert!(size_of::<sctp_peeloff_arg>() == 8);
    assert!(size_of::<sctp_event>() == 8);
    assert!(size_of::<sctp_add_streams>() == 8);
    assert!(size_of::<sctp_stream_value>() == 8);
    assert!(size_of::<sctp_notification_header>() == 8);
    assert!(size_of::<sctp_assoc_change>() == 20);
    assert!(size_of::<sctp_paddr_change>() == 148);
    assert!(size_of::<sctp_remote_error>() == 16);
    assert!(size_of::<sctp_send_failed>() == 48);
    assert!(size_of::<sctp_send_failed_event>() == 32);
    assert!(size_of::<sctp_shutdown_event>() == 12);
    assert!(size_of::<sctp_adaptation_event>() == 16);
    assert!(size_of::<sctp_pdapi_event>() == 24);
    assert!(size_of::<sctp_authkey_event>() == 20);
    assert!(size_of::<sctp_sender_dry_event>() == 12);
    assert!(size_of::<sctp_stream_reset_event>() == 12);
    assert!(size_of::<sctp_assoc_reset_event>() == 20);
    assert!(size_of::<sctp_stream_change_event>() == 16);
};
