use std::mem;
use std::net::SocketAddr;
use std::io;

use sys::*;

use net::addr;

pub fn notification_parse(buf: &[u8]) -> io::Result<Option<Notification>> {

    let notification: &sctp_notification = unsafe { mem::transmute(buf.as_ptr()) };

    let header = unsafe { notification.sn_header };

    if header.sn_length as usize != buf.len() {
        return Ok(None)
    }

    let sn_type = match sctp_sn_type::from_u16(header.sn_type) {
        Some(sn_type) => sn_type,
        None => return Ok(None)
    };

    match sn_type {
        sctp_sn_type::SCTP_SN_TYPE_BASE => {
            return Ok(None)
        }
        sctp_sn_type::SCTP_ASSOC_CHANGE => {
            let n = unsafe { notification.sn_assoc_change };

            let state = match n.sac_state {
                0 => AssocChangeState::CommUp,
                1 => AssocChangeState::CommLost,
                2 => AssocChangeState::Restart,
                3 => AssocChangeState::ShoutdownComp,
                4 => AssocChangeState::CantStrAssoc,
                _ => AssocChangeState::Unkown
            };

            let error = notification_error_parse(n.sac_error);

            let data_length = n.sac_length as usize - mem::size_of::<u16>() * 6 - mem::size_of::<u32>() - mem::size_of::<i32>();

            let data: Vec<u8> = unsafe { n.sac_info.as_slice(data_length).to_vec() };

            let assoc_change = AssocChange {
                state: state,
                error: error,
                outbound_streams: n.sac_outbound_streams,
                inbound_streams: n.sac_inbound_streams,
                assoc_id: n.sac_assoc_id,
                data: data
            };

            return Ok(Some(Notification::AssocChange(assoc_change)))

        }
        sctp_sn_type::SCTP_PEER_ADDR_CHANGE => {
            let n = unsafe { notification.sn_paddr_change };

            let addr = addr::sockaddr_to_addr(&n.spc_addr, 128)?;

            let state = match n.spc_state {
                0 => PaddrChangeState::AddrAvaliable,
                1 => PaddrChangeState::AddrUnreachable,
                2 => PaddrChangeState::AddrRemove,
                3 => PaddrChangeState::AddrAdded,
                4 => PaddrChangeState::AddrMadePrim,
                5 => PaddrChangeState::AddrConfirmed,
                _ => PaddrChangeState::Unkown
            };

            let error = notification_error_parse(n.spc_error as u16);

            let paddr_change = PaddrChange {
                addr: addr,
                state: state,
                error: error,
                assoc_id: n.spc_assoc_id
            };

            return Ok(Some(Notification::PaddrChange(paddr_change)))
        }
        sctp_sn_type::SCTP_REMOTE_ERROR => {
            let n = unsafe { notification.sn_remote_error };

            let error = notification_error_parse(n.sre_error);

            let data_length = n.sre_length as usize - mem::size_of::<u16>() * 3 - mem::size_of::<u32>() - mem::size_of::<i32>();

            let data: Vec<u8> = unsafe { n.sre_data.as_slice(data_length).to_vec() };

            let remote_error = RemoteError {
                error: error,
                assoc_id: n.sre_assoc_id,
                data: data
            };

            return Ok(Some(Notification::RemoteError(remote_error)))
        }
        sctp_sn_type::SCTP_SEND_FAILED => {
            let n = unsafe { notification.sn_send_failed };

            let state = match n.ssf_flags {
                0 => SendFailedState::DataUnsent,
                1 => SendFailedState::DataSent,
                _ => SendFailedState::Unkown
            };

            let error = notification_error_parse(n.ssf_error as u16);

            let data_length = n.ssf_length as usize - mem::size_of::<u16>() * 2 - mem::size_of::<u32>() * 2 - mem::size_of::<sctp_sndrcvinfo>() - mem::size_of::<i32>();

            let data: Vec<u8> = unsafe { n.ssf_data.as_slice(data_length).to_vec() };

            let send_failed = SendFailed {
                state: state,
                error: error,
                info: n.ssf_info,
                assoc_id: n.ssf_assoc_id,
                data: data
            };

            return Ok(Some(Notification::SendFailed(send_failed)))
        }
        sctp_sn_type::SCTP_SHUTDOWN_EVENT => {
            let n = unsafe { notification.sn_shutdown_event };

            let shutdown = Shutdown {
                assoc_id: n.sse_assoc_id
            };

            return Ok(Some(Notification::Shutdown(shutdown)))
        }
        sctp_sn_type::SCTP_PARTIAL_DELIVERY_EVENT => {
            let n = unsafe { notification.sn_pdapi_event };

            let partial_delivery = PartialDelivery {
                indication: n.pdapi_indication,
                assoc_id: n.pdapi_assoc_id
            };

            return Ok(Some(Notification::PartialDelivery(partial_delivery)))
        }
        sctp_sn_type::SCTP_ADAPTATION_INDICATION => {
            let n = unsafe { notification.sn_adaptation_event };

            let adaptation = Adaptation {
                adaptation_ind: n.sai_adaptation_ind,
                assoc_id: n.sai_assoc_id
            };

            return Ok(Some(Notification::Adaptation(adaptation)))
        }
        sctp_sn_type::SCTP_AUTHENTICATION_INDICATION => {
            let n = unsafe { notification.sn_authkey_event };

            let authkey = Authkey {
                keynumber: n.auth_keynumber,
                altkeynumber: n.auth_altkeynumber,
                indication: n.auth_indication,
                assoc_id: n.auth_assoc_id
            };

            return Ok(Some(Notification::Authkey(authkey)))
        }
        sctp_sn_type::SCTP_SENDER_DRY_EVENT => {
            let n = unsafe { notification.sn_sender_dry_event };

            let sender_dry = SenderDry {
                assoc_id: n.sender_dry_assoc_id
            };

            return Ok(Some(Notification::SenderDry(sender_dry)))
        }
    }
}

pub fn notification_error_parse(error: u16) -> NotificationError {
    match error {
        0 => NotificationError::FailedThreshold,
        1 => NotificationError::ReceivedSack,
        2 => NotificationError::HeartbeatSuccess,
        3 => NotificationError::ResponseToUserReq,
        4 => NotificationError::InternalError,
        5 => NotificationError::ShutdownGuardExpires,
        6 => NotificationError::PeerFaulty,
        _ => NotificationError::Unkown
    }
}

impl sctp_sn_type {
    fn from_u16(t: u16) -> Option<sctp_sn_type> {
        if sctp_sn_type::SCTP_SN_TYPE_BASE as u16 == t {
            return Some(sctp_sn_type::SCTP_SN_TYPE_BASE)
        }

        if sctp_sn_type::SCTP_ASSOC_CHANGE as u16 == t {
            return Some(sctp_sn_type::SCTP_ASSOC_CHANGE)
        }

        if sctp_sn_type::SCTP_PEER_ADDR_CHANGE as u16 == t {
            return Some(sctp_sn_type::SCTP_PEER_ADDR_CHANGE)
        }

        if sctp_sn_type::SCTP_SEND_FAILED as u16 == t {
            return Some(sctp_sn_type::SCTP_SEND_FAILED)
        }

        if sctp_sn_type::SCTP_REMOTE_ERROR as u16 == t {
            return Some(sctp_sn_type::SCTP_REMOTE_ERROR)
        }

        if sctp_sn_type::SCTP_SHUTDOWN_EVENT as u16 == t {
            return Some(sctp_sn_type::SCTP_SHUTDOWN_EVENT)
        }

        if sctp_sn_type::SCTP_PARTIAL_DELIVERY_EVENT as u16 == t {
            return Some(sctp_sn_type::SCTP_PARTIAL_DELIVERY_EVENT)
        }

        if sctp_sn_type::SCTP_ADAPTATION_INDICATION as u16 == t {
            return Some(sctp_sn_type::SCTP_ADAPTATION_INDICATION)
        }

        if sctp_sn_type::SCTP_AUTHENTICATION_INDICATION as u16 == t {
            return Some(sctp_sn_type::SCTP_AUTHENTICATION_INDICATION)
        }

        if sctp_sn_type::SCTP_SENDER_DRY_EVENT as u16 == t {
            return Some(sctp_sn_type::SCTP_SENDER_DRY_EVENT)
        }

        None
    }
}

#[derive(Debug, Clone)]
pub enum Notification {
    AssocChange(AssocChange),
    PaddrChange(PaddrChange),
    RemoteError(RemoteError),
    SendFailed(SendFailed),
    Shutdown(Shutdown),
    Adaptation(Adaptation),
    PartialDelivery(PartialDelivery),
    Authkey(Authkey),
    SenderDry(SenderDry)
}


#[derive(Debug, Clone)]
pub enum NotificationError {
    FailedThreshold,
    ReceivedSack,
    HeartbeatSuccess,
    ResponseToUserReq,
    InternalError,
    ShutdownGuardExpires,
    PeerFaulty,
    Unkown
}

#[derive(Debug, Clone)]
pub struct AssocChange {
    state: AssocChangeState,
    error: NotificationError,
    outbound_streams: u16,
    inbound_streams: u16,
    assoc_id: i32,
    data: Vec<u8>
}

#[derive(Debug, Clone)]
pub enum AssocChangeState {
    CommUp,
    CommLost,
    Restart,
    ShoutdownComp,
    CantStrAssoc,
    Unkown
}

#[derive(Debug, Clone)]
pub struct PaddrChange {
    addr: SocketAddr,
    state: PaddrChangeState,
    error: NotificationError,
    assoc_id: i32,
}

#[derive(Debug, Clone)]
pub enum PaddrChangeState {
    AddrAvaliable,
    AddrUnreachable,
    AddrRemove,
    AddrAdded,
    AddrMadePrim,
    AddrConfirmed,
    Unkown
}

#[derive(Debug, Clone)]
pub struct RemoteError {
    error: NotificationError,
    assoc_id: i32,
    data: Vec<u8>
}

#[derive(Debug, Clone)]
pub struct SendFailed {
    state: SendFailedState,
    error: NotificationError,
    info: sctp_sndrcvinfo,
    assoc_id: i32,
    data: Vec<u8>
}

#[derive(Debug, Clone)]
pub enum SendFailedState {
    DataUnsent,
    DataSent,
    Unkown
}

#[derive(Debug, Clone)]
pub struct Shutdown {
    assoc_id: i32
}

#[derive(Debug, Clone)]
pub struct Adaptation {
    adaptation_ind: u32,
    assoc_id: i32
}

#[derive(Debug, Clone)]
pub struct PartialDelivery {
    indication: u32,
    assoc_id: i32
}

#[derive(Debug, Clone)]
pub struct Authkey {
    keynumber: u16,
    altkeynumber: u16,
    indication: u32,
    assoc_id: i32
}

#[derive(Debug, Clone)]
pub struct SenderDry {
    assoc_id: i32
}
