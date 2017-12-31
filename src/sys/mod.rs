#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use std::marker::PhantomData;
use std::mem::transmute;
use std::slice;
use std::fmt;

use libc;

#[repr(C)]
#[derive(Default)]
pub struct __IncompleteArrayField<T>(PhantomData<T>);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub fn new () -> Self {
        __IncompleteArrayField(PhantomData)
    }

    #[inline]
    pub unsafe fn as_ptr(&self) -> * const T {
        transmute(self)
    }

    #[inline]
    pub unsafe fn as_mut_ptr(&mut self) -> * mut T {
        transmute(self)
    }

    #[inline]
    pub unsafe fn as_slice(&self , len : usize ) -> &[T] {
        slice::from_raw_parts( self.as_ptr(), len)
    }

    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> & mut [T] {
        slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}

impl<T> fmt::Debug for __IncompleteArrayField<T> {
    fn fmt ( & self , fmt: &mut fmt :: Formatter ) -> fmt::Result {
        fmt.write_str( "__IncompleteArrayField" )
    }
}

impl < T > Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl < T > Copy for __IncompleteArrayField <T> {}

#[repr(C)]
pub struct __BindgenUnionField<T>(PhantomData<T>);

impl<T> __BindgenUnionField<T>{
    #[inline]
    pub fn new() -> Self {
        __BindgenUnionField(PhantomData)
    }

    #[inline]
    pub unsafe fn as_ref ( & self ) -> &T {
        transmute(self)
    }

    #[inline]
    pub unsafe fn as_mut(&mut self) -> &mut T {
        transmute(self)
    }
}

impl <T> Default for __BindgenUnionField<T> {
    #[inline]
    fn default() -> Self {
        Self::new ()
    }
}

impl <T> Clone for __BindgenUnionField<T> {
    #[inline]
    fn clone(&self ) -> Self {
        Self::new()
    }
}

impl <T> Copy for __BindgenUnionField < T > {}

impl <T> fmt::Debug for __BindgenUnionField < T > {
    fn fmt (&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str( "__BindgenUnionField")
    }
}

impl <T> ::std::hash::Hash for __BindgenUnionField<T> { fn hash <H: ::std::hash::Hasher> (&self, _state: &mut H) {}}
impl <T> ::std::cmp::PartialEq for __BindgenUnionField<T> { fn eq (&self, _other : & __BindgenUnionField <T>) -> bool { true }}
impl <T> ::std::cmp::Eq for __BindgenUnionField<T> {}

pub const SOL_SCTP: i32 = 132;
pub const IPPROTO_SCTP: i32 = 132;
pub const SCTP_RTOINFO: i32 = 0;
pub const SCTP_ASSOCINFO: i32 = 1;
pub const SCTP_INITMSG: i32 = 2;
pub const SCTP_NODELAY: i32 = 3 ;
pub const SCTP_AUTOCLOSE: i32 = 4;
pub const SCTP_SET_PEER_PRIMARY_ADDR: i32 = 5;
pub const SCTP_PRIMARY_ADDR: i32 = 6;
pub const SCTP_ADAPTATION_LAYER: i32 = 7;
pub const SCTP_DISABLE_FRAGMENTS: i32 = 8;
pub const SCTP_PEER_ADDR_PARAMS: i32 = 9;
pub const SCTP_DEFAULT_SEND_PARAM: i32 = 10;
pub const SCTP_EVENTS: i32 = 11;
pub const SCTP_I_WANT_MAPPED_V4_ADDR: i32 = 12;
pub const SCTP_MAXSEG: i32 = 13;
pub const SCTP_STATUS: i32 = 14;
pub const SCTP_GET_PEER_ADDR_INFO: i32 = 15;
pub const SCTP_DELAYED_ACK_TIME: i32 = 16;
pub const SCTP_DELAYED_ACK: i32 = 16;
pub const SCTP_DELAYED_SACK: i32 = 16;
pub const SCTP_CONTEXT: i32 = 17;
pub const SCTP_FRAGMENT_INTERLEAVE: i32 = 18;
pub const SCTP_PARTIAL_DELIVERY_POINT: i32 = 19;
pub const SCTP_MAX_BURST: i32 = 20;
pub const SCTP_AUTH_CHUNK: i32 = 21;
pub const SCTP_HMAC_IDENT: i32 = 22;
pub const SCTP_AUTH_KEY: i32 = 23;
pub const SCTP_AUTH_ACTIVE_KEY: i32 = 24;
pub const SCTP_AUTH_DELETE_KEY: i32 = 25;
pub const SCTP_PEER_AUTH_CHUNKS: i32 = 26;
pub const SCTP_LOCAL_AUTH_CHUNKS: i32 = 27;
pub const SCTP_GET_ASSOC_NUMBER: i32 = 28;
pub const SCTP_SOCKOPT_BINDX_ADD: i32 = 100;
pub const SCTP_SOCKOPT_BINDX_REM: i32 = 101;
pub const SCTP_SOCKOPT_PEELOFF: i32 = 102;
pub const SCTP_SOCKOPT_CONNECTX_OLD: i32 = 107;
pub const SCTP_GET_PEER_ADDRS: i32 = 108;
pub const SCTP_GET_LOCAL_ADDRS: i32 = 109;
pub const SCTP_SOCKOPT_CONNECTX: i32 = 110;
pub const SCTP_SOCKOPT_CONNECTX3: i32 = 111;
pub const SCTP_GET_ASSOC_STATS: i32 = 112;

pub const SCTP_BINDX_ADD_ADDR: i32 = 1;
pub const SCTP_BINDX_REM_ADDR: i32 = 2;

pub type sctp_assoc_t = i32;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sctp_initmsg {
    pub sinit_num_ostreams: u16,
    pub sinit_max_instreams: u16,
    pub sinit_max_attempts: u16,
    pub sinit_max_init_timeo : u16
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sctp_sndrcvinfo {
    pub sinfo_stream: u16,
    pub sinfo_ssn: u16,
    pub sinfo_flags: u16,
    pub sinfo_ppid: u32,
    pub sinfo_context: u32,
    pub sinfo_timetolive: u32,
    pub sinfo_tsn: u32,
    pub sinfo_cumtsn: u32,
    pub sinfo_assoc_id : sctp_assoc_t
}

pub const sctp_sinfo_flags_SCTP_UNORDERED: sctp_sinfo_flags = 1;
pub const sctp_sinfo_flags_SCTP_ADDR_OVER: sctp_sinfo_flags = 2;
pub const sctp_sinfo_flags_SCTP_ABORT: sctp_sinfo_flags = 4;
pub const sctp_sinfo_flags_SCTP_SACK_IMMEDIATELY: sctp_sinfo_flags = 8;
pub const sctp_sinfo_flags_SCTP_EOF: sctp_sinfo_flags = 512;
pub type sctp_sinfo_flags = u16;

#[repr(C)]
#[derive(Copy, Clone)]
pub union sctp_cmsg_data_t {
    pub raw: u8,
    pub init: sctp_initmsg,
    pub sndrcv: sctp_sndrcvinfo,
}

pub const sctp_cmsg_type_SCTP_INIT : sctp_cmsg_type = 0;
pub const sctp_cmsg_type_SCTP_SNDRCV : sctp_cmsg_type = 1;
pub type sctp_cmsg_type = u32;
pub use self::sctp_cmsg_type as sctp_cmsg_t;

#[repr(C)]
#[derive(Debug)]
pub struct sctp_assoc_change {
    pub sac_type: u16,
    pub sac_flags: u16,
    pub sac_length: u32,
    pub sac_state: u16,
    pub sac_error: u16,
    pub sac_outbound_streams: u16,
    pub sac_inbound_streams: u16,
    pub sac_assoc_id : sctp_assoc_t,
    pub sac_info: __IncompleteArrayField<u8>
}

pub const sctp_sac_state_SCTP_COMM_UP : sctp_sac_state = 0;
pub const sctp_sac_state_SCTP_COMM_LOST : sctp_sac_state = 1;
pub const sctp_sac_state_SCTP_RESTART : sctp_sac_state = 2;
pub const sctp_sac_state_SCTP_SHUTDOWN_COMP : sctp_sac_state = 3;
pub const sctp_sac_state_SCTP_CANT_STR_ASSOC : sctp_sac_state = 4;
pub type sctp_sac_state = u32;

#[repr(C)]
pub struct sctp_paddr_change {
    pub spc_type: u16,
    pub spc_flags: u16,
    pub spc_length: u32,
    pub spc_addr: libc::sockaddr_storage,
    pub spc_state: i32,
    pub spc_error: i32,
    pub spc_assoc_id: sctp_assoc_t
}

pub const sctp_spc_state_SCTP_ADDR_AVAILABLE: sctp_spc_state = 0;
pub const sctp_spc_state_SCTP_ADDR_UNREACHABLE: sctp_spc_state = 1;
pub const sctp_spc_state_SCTP_ADDR_REMOVED: sctp_spc_state = 2;
pub const sctp_spc_state_SCTP_ADDR_ADDED: sctp_spc_state = 3;
pub const sctp_spc_state_SCTP_ADDR_MADE_PRIM: sctp_spc_state = 4;
pub const sctp_spc_state_SCTP_ADDR_CONFIRMED: sctp_spc_state = 5;
pub type sctp_spc_state = u32;

#[repr(C)]
#[derive(Debug)]
pub struct sctp_remote_error {
    pub sre_type: u16,
    pub sre_flags: u16,
    pub sre_length: u32,
    pub sre_error: u16,
    pub sre_assoc_id : sctp_assoc_t ,
    pub sre_data: __IncompleteArrayField<u8>
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_send_failed {
    pub ssf_type: u16,
    pub ssf_flags: u16,
    pub ssf_length: u32,
    pub ssf_error: u32,
    pub ssf_info : sctp_sndrcvinfo,
    pub ssf_assoc_id : sctp_assoc_t,
    pub ssf_data : __IncompleteArrayField<u8>
}

pub const sctp_ssf_flags_SCTP_DATA_UNSENT : sctp_ssf_flags = 0;
pub const sctp_ssf_flags_SCTP_DATA_SENT : sctp_ssf_flags = 1;
pub type sctp_ssf_flags = u16;


#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_shutdown_event {
    pub sse_type: u16,
    pub sse_flags: u16,
    pub sse_length: u32,
    pub sse_assoc_id : sctp_assoc_t
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_adaptation_event {
    pub sai_type: u16,
    pub sai_flags: u16,
    pub sai_length: u32,
    pub sai_adaptation_ind: u32,
    pub sai_assoc_id : sctp_assoc_t
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_pdapi_event {
    pub pdapi_type: u16,
    pub pdapi_flags: u16,
    pub pdapi_length: u32,
    pub pdapi_indication: u32,
    pub pdapi_assoc_id : sctp_assoc_t
}

pub const SCTP_PARTIAL_DELIVERY_ABORTED: u32 = 0;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_authkey_event {
    pub auth_type: u16,
    pub auth_flags: u16,
    pub auth_length: u32,
    pub auth_keynumber: u16,
    pub auth_altkeynumber: u16,
    pub auth_indication: u32,
    pub auth_assoc_id : sctp_assoc_t
}

pub const SCTP_AUTH_NEWKEY: u32 = 0;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_sender_dry_event {
    pub sender_dry_type: u16,
    pub sender_dry_flags: u16,
    pub sender_dry_length: u32,
    pub sender_dry_assoc_id : sctp_assoc_t
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_event_subscribe {
    pub sctp_data_io_event : u8,
    pub sctp_association_event : u8,
    pub sctp_address_event : u8,
    pub sctp_send_failure_event : u8,
    pub sctp_peer_error_event : u8,
    pub sctp_shutdown_event : u8,
    pub sctp_partial_delivery_event : u8,
    pub sctp_adaptation_layer_event : u8,
    pub sctp_authentication_event : u8,
    pub sctp_sender_dry_event : u8
}

#[repr(C)]
#[derive(Clone)]
pub struct sctp_notification {
    pub sn_header: __BindgenUnionField <sctp_notification_header>,
    pub sn_assoc_change: __BindgenUnionField<sctp_assoc_change>,
    pub sn_paddr_change: __BindgenUnionField<sctp_paddr_change>,
    pub sn_remote_error: __BindgenUnionField<sctp_remote_error>,
    pub sn_send_failed: __BindgenUnionField<sctp_send_failed>,
    pub sn_shutdown_event: __BindgenUnionField<sctp_shutdown_event>,
    pub sn_adaptation_event: __BindgenUnionField<sctp_adaptation_event>,
    pub sn_pdapi_event: __BindgenUnionField<sctp_pdapi_event>,
    pub sn_authkey_event: __BindgenUnionField<sctp_authkey_event>,
    pub sn_sender_dry_event: __BindgenUnionField<sctp_sender_dry_event>,
    pub bindgen_union_field: [u32; 37usize]
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_notification_header {
    pub sn_type: u16,
    pub sn_flags: u16,
    pub sn_length : u32
}

pub const sctp_sn_type_SCTP_SN_TYPE_BASE: sctp_sn_type = 32768;
pub const sctp_sn_type_SCTP_ASSOC_CHANGE: sctp_sn_type = 32769;
pub const sctp_sn_type_SCTP_PEER_ADDR_CHANGE: sctp_sn_type = 32770;
pub const sctp_sn_type_SCTP_SEND_FAILED: sctp_sn_type = 32771;
pub const sctp_sn_type_SCTP_REMOTE_ERROR: sctp_sn_type = 32772;
pub const sctp_sn_type_SCTP_SHUTDOWN_EVENT: sctp_sn_type = 32773;
pub const sctp_sn_type_SCTP_PARTIAL_DELIVERY_EVENT: sctp_sn_type = 32774;
pub const sctp_sn_type_SCTP_ADAPTATION_INDICATION: sctp_sn_type = 32775;
pub const sctp_sn_type_SCTP_AUTHENTICATION_INDICATION: sctp_sn_type = 32776;
pub const sctp_sn_type_SCTP_SENDER_DRY_EVENT: sctp_sn_type = 32777;
pub type sctp_sn_type = u16;

pub const sctp_sn_error_SCTP_FAILED_THRESHOLD: sctp_sn_error = 0;
pub const sctp_sn_error_SCTP_RECEIVED_SACK: sctp_sn_error = 1;
pub const sctp_sn_error_SCTP_HEARTBEAT_SUCCESS: sctp_sn_error = 2;
pub const sctp_sn_error_SCTP_RESPONSE_TO_USER_REQ: sctp_sn_error = 3;
pub const sctp_sn_error_SCTP_INTERNAL_ERROR: sctp_sn_error = 4;
pub const sctp_sn_error_SCTP_SHUTDOWN_GUARD_EXPIRES: sctp_sn_error = 5;
pub const sctp_sn_error_SCTP_PEER_FAULTY: sctp_sn_error = 6;
pub type sctp_sn_error = u32;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_rtoinfo {
    pub srto_assoc_id : sctp_assoc_t,
    pub srto_initial: u32,
    pub srto_max: u32,
    pub srto_min : u32
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_assocparams {
    pub sasoc_assoc_id : sctp_assoc_t,
    pub sasoc_asocmaxrxt: u16,
    pub sasoc_number_peer_destinations: u16,
    pub sasoc_peer_rwnd: u32,
    pub sasoc_local_rwnd: u32,
    pub sasoc_cookie_life : u32
}

#[repr(C)]
pub struct sctp_setpeerprim {
    sspp_assoc_id: sctp_assoc_t,
    sspp_addr: libc::sockaddr_storage
}

#[repr(C)]
pub struct sctp_setprim {
    ssp_assoc_id: sctp_assoc_t,
    ssp_addr: libc::sockaddr_storage
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_setadaptation {
    pub ssb_adaptation_ind : u32
}

pub const sctp_spp_flags_SPP_HB_ENABLE: sctp_spp_flags = 1;
pub const sctp_spp_flags_SPP_HB_DISABLE: sctp_spp_flags = 2;
pub const sctp_spp_flags_SPP_HB: sctp_spp_flags = 3;
pub const sctp_spp_flags_SPP_HB_DEMAND: sctp_spp_flags = 4;
pub const sctp_spp_flags_SPP_PMTUD_ENABLE: sctp_spp_flags = 8;
pub const sctp_spp_flags_SPP_PMTUD_DISABLE: sctp_spp_flags = 16;
pub const sctp_spp_flags_SPP_PMTUD: sctp_spp_flags = 24;
pub const sctp_spp_flags_SPP_SACKDELAY_ENABLE: sctp_spp_flags = 32;
pub const sctp_spp_flags_SPP_SACKDELAY_DISABLE: sctp_spp_flags = 64;
pub const sctp_spp_flags_SPP_SACKDELAY: sctp_spp_flags = 96;
pub const sctp_spp_flags_SPP_HB_TIME_IS_ZERO: sctp_spp_flags = 128;
pub type sctp_spp_flags = u32;

#[repr(C)]
pub struct sctp_paddrparams {
    pub spp_assoc_id: sctp_assoc_t,
    pub spp_address: libc::sockaddr_storage,
    pub spp_hbinterval: u32,
    pub spp_pathmaxrxt: u16,
    pub spp_pathmtu: u32,
    pub spp_sackdelay: u32,
    pub spp_flags: u32
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_authchunk {
    pub sauth_chunk : u8
}

pub const SCTP_AUTH_HMAC_ID_SHA1: u32 = 1;
pub const SCTP_AUTH_HMAC_ID_SHA256: u32 = 3;

#[repr(C)]
#[derive(Debug)]
pub struct sctp_hmacalgo {
    pub shmac_number_of_idents: u32,
    pub shmac_idents : __IncompleteArrayField<u16>
}

#[repr(C)]
#[derive(Debug)]
pub struct sctp_authkey {
    pub sca_assoc_id: sctp_assoc_t,
    pub sca_keynumber: u16,
    pub sca_keylength: u16,
    pub sca_key: __IncompleteArrayField<u8>
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_authkeyid {
    pub scact_assoc_id: sctp_assoc_t,
    pub scact_keynumber: u16
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_sack_info {
    pub sack_assoc_id: sctp_assoc_t,
    pub sack_delay: u32,
    pub sack_freq: u32
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_assoc_value {
    pub assoc_id : sctp_assoc_t,
    pub assoc_value : u32
}

#[repr(C)]
pub struct sctp_paddrinfo {
    pub spinfo_assoc_id: sctp_assoc_t,
    pub spinfo_address: libc::sockaddr_storage,
    pub spinfo_state: i32,
    pub spinfo_cwnd: u32,
    pub spinfo_srtt: u32,
    pub spinfo_rto: u32,
    pub spinfo_mtu: u32
}

pub const sctp_spinfo_state_SCTP_INACTIVE : sctp_spinfo_state = 0;
pub const sctp_spinfo_state_SCTP_PF : sctp_spinfo_state = 1;
pub const sctp_spinfo_state_SCTP_ACTIVE : sctp_spinfo_state = 2;
pub const sctp_spinfo_state_SCTP_UNCONFIRMED : sctp_spinfo_state = 3;
pub const sctp_spinfo_state_SCTP_UNKNOWN : sctp_spinfo_state = 65535;
pub type sctp_spinfo_state = u32;

#[repr(C)]
pub struct sctp_status {
    pub sstat_assoc_id : sctp_assoc_t,
    pub sstat_state : i32,
    pub sstat_rwnd: u32,
    pub sstat_unackdata: u16,
    pub sstat_penddata: u16,
    pub sstat_instrms: u16,
    pub sstat_outstrms: u16,
    pub sstat_fragmentation_point: u32,
    pub sstat_primary : sctp_paddrinfo
}

#[repr(C)]
#[derive(Debug)]
pub struct sctp_authchunks {
    pub gauth_assoc_id: sctp_assoc_t,
    pub gauth_number_of_chunks: u32,
    pub gauth_chunks: __IncompleteArrayField <u8>
}

pub const sctp_sstat_state_SCTP_EMPTY: sctp_sstat_state = 0;
pub const sctp_sstat_state_SCTP_CLOSED: sctp_sstat_state = 1;
pub const sctp_sstat_state_SCTP_COOKIE_WAIT: sctp_sstat_state = 2;
pub const sctp_sstat_state_SCTP_COOKIE_ECHOED: sctp_sstat_state = 3;
pub const sctp_sstat_state_SCTP_ESTABLISHED: sctp_sstat_state = 4;
pub const sctp_sstat_state_SCTP_SHUTDOWN_PENDING: sctp_sstat_state = 5;
pub const sctp_sstat_state_SCTP_SHUTDOWN_SENT: sctp_sstat_state = 6;
pub const sctp_sstat_state_SCTP_SHUTDOWN_RECEIVED: sctp_sstat_state = 7;
pub const sctp_sstat_state_SCTP_SHUTDOWN_ACK_SENT: sctp_sstat_state = 8;
pub type sctp_sstat_state = u32;

#[repr(C)]#[derive(Debug, Clone)]
pub struct sctp_getaddrs_old {
    pub assoc_id : sctp_assoc_t,
    pub addr_num: libc::c_int,
    pub addrs : *mut libc::sockaddr,
}

#[repr(C)]
#[derive(Debug)]
pub struct sctp_getaddrs {
    pub assoc_id: sctp_assoc_t,
    pub addr_num: u32,
    pub addrs: __IncompleteArrayField<u8>
}

#[repr(C)]
#[derive(Clone)]
pub struct sctp_assoc_stats {
    pub sas_assoc_id: sctp_assoc_t,
    pub sas_obs_rto_ipaddr: libc::sockaddr_storage,
    pub sas_maxrto: u64,
    pub sas_isacks: u64,
    pub sas_osacks: u64,
    pub sas_opackets: u64,
    pub sas_ipackets: u64,
    pub sas_rtxchunks: u64,
    pub sas_outofseqtsns: u64,
    pub sas_idupchunks: u64,
    pub sas_gapcnt: u64,
    pub sas_ouodchunks: u64,
    pub sas_iuodchunks: u64,
    pub sas_oodchunks: u64,
    pub sas_iodchunks: u64,
    pub sas_octrlchunks: u64,
    pub sas_ictrlchunks: u64
}

pub const sctp_msg_flags_MSG_NOTIFICATION : sctp_msg_flags = 32768;
pub type sctp_msg_flags = u16;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct sctp_peeloff_arg_t {
    pub associd : sctp_assoc_t,
    pub sd : libc::c_int
}

extern "C" {

    pub fn sctp_bindx (
        sd: libc::c_int,
        addrs: *const libc::sockaddr,
        addrcnt: libc::c_int,
        flags: libc::c_int
    ) -> libc::c_int;

    pub fn sctp_connectx(
        sd: libc::c_int,
        addrs: *const libc::sockaddr,
        addrcnt: libc::c_int,
        id: * mut sctp_assoc_t
    ) -> libc::c_int;

    pub fn sctp_peeloff(
        sd: libc::c_int,
        assoc_id: sctp_assoc_t
    ) -> libc::c_int;

    pub fn sctp_opt_info(
        sd: libc::c_int,
        id: sctp_assoc_t,
        opt: libc::c_int,
        arg: *mut libc::c_void,
        size: * mut libc::socklen_t
    ) -> libc::c_int;

    pub fn sctp_getpaddrs(
        sd: libc::c_int,
        id: sctp_assoc_t,
        addrs: *mut *mut libc::sockaddr
    ) -> libc::c_int;

    pub fn sctp_freepaddrs(
        addrs: *mut libc::sockaddr
    ) -> libc::c_int;

    pub fn sctp_getladdrs(
        sd: libc::c_int,
        id: sctp_assoc_t,
        addrs: *mut *mut libc::sockaddr
    ) -> libc::c_int;

    pub fn sctp_freeladdrs(
        addrs: *mut libc::sockaddr
    ) -> libc::c_int;

    pub fn sctp_sendmsg(
        sd: libc::c_int,
        msg: *const libc::c_void,
        len: usize,
        to: *const libc::sockaddr,
        tolen: libc::socklen_t,
        ppid: u32,
        flags: u32,
        stream_no: u16,
        timetolive: u32,
        context: u32
    ) -> libc::c_int;

    pub fn sctp_send(sd: libc::c_int,
        msg : *const libc::c_void,
        len : usize,
        sinfo : * const sctp_sndrcvinfo,
        flags: libc::c_int
    ) -> libc::c_int;

    pub fn sctp_recvmsg(
        sd: libc::c_int,
         msg : * mut libc::c_void,
         len : usize,
         from : * mut libc::sockaddr,
         fromlen : * mut libc::socklen_t,
         sinfo : * mut sctp_sndrcvinfo,
         msg_flags : * mut libc::c_int
    ) -> libc::c_int;

    pub fn sctp_getaddrlen(family: libc::sa_family_t) -> libc::c_int;
}
