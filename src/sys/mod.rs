use libc::{self, c_int, c_uint, size_t, c_ulong, c_ushort, c_void, ssize_t, sockaddr, socklen_t};

/* The following symbols come from the Sockets API Extensions for
 * SCTP <draft-ietf-tsvwg-sctpsocket-07.txt>.
 */
pub const SCTP_RTOINFO: c_int =    0;
pub const SCTP_ASSOCINFO: c_int =  1;
pub const SCTP_INITMSG: c_int =    2;
pub const SCTP_NODELAY: c_int =    3;              /* Get/set nodelay option. */
pub const SCTP_AUTOCLOSE: c_int =  4;
pub const SCTP_SET_PEER_PRIMARY_ADDR: c_int = 5;
pub const SCTP_PRIMARY_ADDR: c_int =       6;
pub const SCTP_ADAPTATION_LAYER: c_int =   7;
pub const SCTP_DISABLE_FRAGMENTS: c_int =  8;
pub const SCTP_PEER_ADDR_PARAMS: c_int =   9;
pub const SCTP_DEFAULT_SEND_PARAM: c_int = 10;
pub const SCTP_EVENTS: c_int =     11;
pub const SCTP_I_WANT_MAPPED_V4_ADDR: c_int = 12;   /* Turn on/off mapped v4 addresses  */
pub const SCTP_MAXSEG: c_int =     13;              /* Get/set maximum fragment. */
pub const SCTP_STATUS: c_int =     14;
pub const SCTP_GET_PEER_ADDR_INFO: c_int = 15;
pub const SCTP_DELAYED_ACK_TIME: c_int =   16;
pub const SCTP_DELAYED_ACK: c_int  = SCTP_DELAYED_ACK_TIME;
pub const SCTP_DELAYED_SACK: c_int  = SCTP_DELAYED_ACK_TIME;
pub const SCTP_CONTEXT: c_int =    17;
pub const SCTP_FRAGMENT_INTERLEAVE: c_int =        18;
pub const SCTP_PARTIAL_DELIVERY_POINT: c_int =     19; /* Set/Get partial delivery point */
pub const SCTP_MAX_BURST: c_int =  20;              /* Set/Get max burst */
pub const SCTP_AUTH_CHUNK: c_int = 21    ;  /* Set only: add a chunk type to authenticate */
pub const SCTP_HMAC_IDENT: c_int = 22;
pub const SCTP_AUTH_KEY: c_int =   23;
pub const SCTP_AUTH_ACTIVE_KEY: c_int =    24;
pub const SCTP_AUTH_DELETE_KEY: c_int =    25;
pub const SCTP_PEER_AUTH_CHUNKS: c_int =   26;      /* Read only */
pub const SCTP_LOCAL_AUTH_CHUNKS: c_int =  27;      /* Read only */
pub const SCTP_GET_ASSOC_NUMBER: c_int =   28;      /* Read only */

/* Internal Socket Options. Some of the sctp library functions are
 * implemented using these socket options.
 */
pub const SCTP_SOCKOPT_BINDX_ADD: c_int =  100;     /* BINDX requests for adding addrs */
pub const SCTP_SOCKOPT_BINDX_REM: c_int =  101;     /* BINDX requests for removing addrs. */
pub const SCTP_SOCKOPT_PEELOFF: c_int =    102;     /* peel off association. */
/* Options 104-106 are deprecated and removed. Do not use this space */
pub const SCTP_SOCKOPT_CONNECTX_OLD: c_int =       107;     /* CONNECTX old requests. */
pub const SCTP_GET_PEER_ADDRS: c_int =     108;             /* Get all peer addresss. */
pub const SCTP_GET_LOCAL_ADDRS: c_int =    109;             /* Get all local addresss. */
pub const SCTP_SOCKOPT_CONNECTX: c_int =   110;             /* CONNECTX requests. */
pub const SCTP_SOCKOPT_CONNECTX3: c_int =  111;     /* CONNECTX requests (updated) */

/* SCTP socket option used to read per endpoint association statistics. */
pub const SCTP_GET_ASSOC_STATS: c_int =    112;      /* Read only */

/*
 *  sinfo_flags: 16 bits (unsigned integer)
 *
 *   This field may contain any of the following flags and is composed of
 *   a bitwise OR of these values.
 */
pub const SCTP_UNORDERED: c_int = 1;  /* Send/receive message unordered. */
pub const SCTP_ADDR_OVER: c_int = 2;  /* Override the primary destination. */
pub const SCTP_ABORT: c_int = 4;        /* Send an ABORT message to the peer. */
pub const SCTP_SACK_IMMEDIATELY: c_int = 8;      /* SACK should be sent without delay */
pub const SCTP_EOF: c_int = libc::MSG_FIN;    /* Initiate graceful shutdown process. */

/*
 * sctp_bindx()
 *
 * The flags parameter is formed from the bitwise OR of zero or more of the
 * following currently defined flags:
 */
pub const SCTP_BINDX_ADD_ADDR: c_int = 0x01;
pub const SCTP_BINDX_REM_ADDR: c_int = 0x02;

/*
 * SCTP Header Information Structure (SCTP_SNDRCV)
 *
 *   This cmsghdr structure specifies SCTP options for sendmsg() and
 *   describes SCTP header information about a received message through
 *   recvmsg().
 *
 *   cmsg_level    cmsg_type      cmsg_data[]
 *   ------------  ------------   ----------------------
 *   IPPROTO_SCTP  SCTP_SNDRCV    struct sctp_sndrcvinfo
 *
 */

#[allow(non_camel_case_types)]
pub type sctp_assoc_t = c_uint;

pub const SOL_SCTP: c_int = 132;
pub const IPPROTO_SCTP: c_int = 132;
pub const SOCK_SEQPACKET: c_int = 5;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct sctp_sndrcvinfo {
    /// Stream sending to
    pub sinfo_stream: u16,
    /// Valid for recv only
    pub sinfo_ssn: u16,
    /// Flags to control sending
    pub sinfo_flags: u16,
    /// ppid field
    pub sinfo_ppid: u32,
    /// context field
    pub sinfo_context: u32,
    /// timetolive for PR-SCTP
    pub sinfo_timetolive: u32,
    /// valid for recv only
    pub sinfo_tsn: u32,
    /// valid for recv only
    pub sinfo_cumtsn: u32,
    /// The association id
    pub sinfo_assoc_id: sctp_assoc_t
}

extern "system" {
    pub fn sctp_bindx(sock: c_int, sock_addr: *const sockaddr, num: c_int, ty: c_int) -> c_int;
    pub fn sctp_connectx(sock: c_int, sock_addr: *const sockaddr, addrcnt: c_int,  assoc: *mut sctp_assoc_t) -> c_int;
    pub fn sctp_freepaddrs(addrs: *mut sockaddr);
    pub fn sctp_freeladdrs(addrs: *mut sockaddr);
    pub fn sctp_getaddrlen(family: c_int) -> c_int;
    pub fn sctp_getpaddrs(s: c_int, assoc: sctp_assoc_t, addrs: *mut *mut sockaddr) -> c_int;
    pub fn sctp_getladdrs(s: c_int, assoc: sctp_assoc_t, addrs: *mut *mut sockaddr) -> c_int;
    pub fn sctp_opt_info(s: c_int, assoc: sctp_assoc_t, opt: c_int, arg: *mut c_void, size: *mut socklen_t) -> c_int;
    pub fn sctp_peeloff(s: c_int, assoc: sctp_assoc_t) -> c_int;
    pub fn sctp_recvmsg(s: c_int, msg: *mut c_void, len: size_t, from: *mut sockaddr, fromlen: *mut socklen_t, sinfo: *mut sctp_sndrcvinfo, flags: *mut c_int) -> ssize_t;
    pub fn sctp_send(s: c_int, msg: *const c_void, len: size_t, sinfo: *const sctp_sndrcvinfo, flags: c_int) -> ssize_t;
    pub fn sctp_sendmsg(s: c_int, msg: *const c_void, len: size_t, to: *const sockaddr, tolen: socklen_t, ppid: c_ulong, flags: c_ulong, stream_no: c_ushort, ttl: c_ulong, ctx: c_ulong) -> ssize_t;
}
