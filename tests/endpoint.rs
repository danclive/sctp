//! Integration tests for one-to-many style sockets.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use sctp::{AssociationState, Event, MessageFlags, Notification, Received, SctpEndpoint, SendInfo};

fn sctp_supported() -> bool {
    match SctpEndpoint::bind("127.0.0.1:0") {
        Ok(_) => true,
        Err(error) => {
            eprintln!("skipping test: SCTP is not available ({error})");
            false
        }
    }
}

fn endpoint_pair() -> io::Result<(SctpEndpoint, SctpEndpoint, i32, i32)> {
    let server = SctpEndpoint::bind("127.0.0.1:0")?;
    server.set_events(Event::ASSOCIATION | Event::SHUTDOWN)?;
    let client = SctpEndpoint::bind("127.0.0.1:0")?;
    client.set_events(Event::ASSOCIATION | Event::SHUTDOWN)?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;

    let client_assoc = client.connect(server.local_addr()?)?;

    let server_assoc = loop {
        let mut buf = [0; 64];
        match server.recv(&mut buf)? {
            Received::Notification(Notification::AssociationChange(change)) => {
                assert_eq!(change.state, AssociationState::CommUp);
                break change.association_id;
            }
            Received::Data(_) => continue,
            other => panic!("expected association notification, got {other:?}"),
        }
    };

    Ok((server, client, server_assoc, client_assoc))
}

#[test]
fn one_to_many_roundtrip() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, server_assoc, client_assoc) = endpoint_pair()?;
    assert_ne!(server_assoc, 0);
    assert_ne!(client_assoc, 0);
    assert_eq!(client.default_association(), client_assoc);
    assert!(client.association_ids()?.contains(&client_assoc));
    assert_eq!(client.association_count()?, 1);

    let peer = client.local_addr()?;
    assert!(server.peer_addrs(server_assoc)?.contains(&peer));
    assert_eq!(server.association_id(&peer)?, server_assoc);
    server.set_context(server_assoc, 11)?;

    let status = server.status(server_assoc)?;
    assert_eq!(status.state, sctp::ConnectionState::Established);
    assert_ne!(status.primary.mtu, 0);

    client.send_with(b"hello endpoint", &SendInfo::new(3).with_ppid(0x55))?;

    let mut buf = [0; 64];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"hello endpoint");
    assert_eq!(data.info.stream_id, 3);
    assert_eq!(data.info.ppid, 0x55);
    assert_eq!(data.info.context, 11);
    assert_eq!(data.info.association_id, server_assoc);
    assert_eq!(data.address, Some(peer));

    // Sending with an explicit association needs no default.
    server.send_with(
        b"reply",
        &SendInfo::new(0).with_association_id(server_assoc),
    )?;
    let (len, from, info) = client.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"reply");
    assert_eq!(from, server.local_addr()?);
    assert_eq!(info.association_id, client_assoc);

    // `recv_from` skips notifications, so nothing is pending.
    Ok(())
}

#[test]
fn send_to_creates_association() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let server = SctpEndpoint::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;

    let client = SctpEndpoint::bind("127.0.0.1:0")?;
    client.send_to(b"unsolicited", server.local_addr()?)?;

    let mut buf = [0; 64];
    let (len, from, _) = server.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"unsolicited");
    assert_eq!(from, client.local_addr()?);

    // The client can now answer without an explicit destination.
    server.send_to(b"answer", from)?;
    let (len, _, _) = client.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"answer");

    Ok(())
}

#[test]
fn peeloff_moves_association_to_its_own_socket() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, server_assoc, _) = endpoint_pair()?;

    client.send(b"before peel")?;
    let mut buf = [0; 64];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"before peel");

    let stream = server.peeloff(server_assoc)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    client.send_with(b"after peel", &SendInfo::new(8))?;
    let Received::Data(data) = stream.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"after peel");
    assert_eq!(data.info.stream_id, 8);
    assert_eq!(stream.peer_addr()?, client.local_addr()?);

    Ok(())
}

#[test]
fn shutdown() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, server_assoc, client_assoc) = endpoint_pair()?;

    client.shutdown(client_assoc)?;
    let mut buf = [0; 64];
    let notification = loop {
        match server.recv(&mut buf)? {
            Received::Notification(notification) => break notification,
            Received::Data(_) => continue,
        }
    };
    match notification {
        Notification::Shutdown(event) => assert_eq!(event.association_id, server_assoc),
        Notification::AssociationChange(change) => {
            assert!(matches!(
                change.state,
                AssociationState::ShutdownComplete | AssociationState::CommLost
            ));
        }
        other => panic!("unexpected notification {other:?}"),
    }

    let _ = server_assoc;
    Ok(())
}

#[test]
fn abort() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, server_assoc, client_assoc) = endpoint_pair()?;
    client.abort(client_assoc)?;

    let mut buf = [0; 64];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "no abort notification"
        );
        match server.recv(&mut buf) {
            Ok(Received::Notification(Notification::AssociationChange(change))) => {
                assert_eq!(change.association_id, server_assoc);
                assert!(matches!(
                    change.state,
                    AssociationState::CommLost | AssociationState::ShutdownComplete
                ));
                break;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[test]
fn association_options() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, _client, server_assoc, _) = endpoint_pair()?;

    server.set_rto_info(
        server_assoc,
        &sctp::RtoInfo {
            initial: Duration::from_millis(2000),
            max: Duration::from_millis(50_000),
            min: Duration::from_millis(500),
        },
    )?;
    let rto = server.rto_info(server_assoc)?;
    assert_eq!(rto.initial, Duration::from_millis(2000));
    assert_eq!(rto.max, Duration::from_millis(50_000));
    assert_eq!(rto.min, Duration::from_millis(500));

    server.set_context(server_assoc, 123)?;
    assert_eq!(server.context(server_assoc)?, 123);

    server.set_max_burst(server_assoc, 2)?;
    assert_eq!(server.max_burst(server_assoc)?, 2);

    server.set_max_segment(server_assoc, 1000)?;
    assert_eq!(server.max_segment(server_assoc)?, 1000);

    server.set_reconfig_supported(true)?;
    assert!(server.reconfig_supported()?);
    server.enable_stream_reset(server_assoc, sctp::StreamResetOptions::INCOMING)?;

    // Stream reconfiguration is gated by the `net.sctp.reconf_enable` sysctl;
    // only assert on the request when the kernel supports it.
    match server.add_streams(server_assoc, 1, 1) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::ENOPROTOOPT) => {
            eprintln!("stream reconfiguration is disabled on this system");
        }
        Err(error) => return Err(error),
    }

    let peer_addrs = server.peer_addrs(server_assoc)?;
    let params = server.peer_addr_params(server_assoc, Some(&peer_addrs[0]))?;
    assert!(params.path_max_retransmits > 0);

    let info = server.peer_addr_info(server_assoc, &peer_addrs[0])?;
    assert_eq!(info.association_id, server_assoc);

    let stats = server.assoc_stats(server_assoc)?;
    assert_eq!(stats.association_id, server_assoc);

    server.set_default_send_info(server_assoc, &SendInfo::new(6).with_ppid(0x66))?;
    let default = server.default_send_info(server_assoc)?;
    assert_eq!(default.stream_id, 6);
    assert_eq!(default.ppid, 0x66);

    server.set_stream_scheduler(server_assoc, sctp::StreamScheduler::Priority)?;
    assert_eq!(
        server.stream_scheduler(server_assoc)?,
        sctp::StreamScheduler::Priority
    );

    server.set_peer_addr_params(
        server_assoc,
        Some(&peer_addrs[0]),
        &sctp::PeerAddressParams {
            path_max_retransmits: 9,
            flags: sctp::PeerAddressFlags::empty(),
            ..sctp::PeerAddressParams::default()
        },
    )?;
    assert_eq!(
        server
            .peer_addr_params(server_assoc, Some(&peer_addrs[0]))?
            .path_max_retransmits,
        9
    );

    // Reconfiguration requests depend on the peer and the kernel configuration.
    match server.reset_streams(server_assoc, sctp::StreamResetFlags::OUTGOING, &[0]) {
        Ok(()) => {}
        Err(error) if is_unsupported(&error) => {}
        Err(error) => return Err(error),
    }
    match server.reset_association(server_assoc) {
        Ok(()) => {}
        Err(error) if is_unsupported(&error) => {}
        Err(error) => return Err(error),
    }

    Ok(())
}

fn is_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOPROTOOPT) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL)
    )
}

#[test]
fn autoclose_option() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let endpoint = SctpEndpoint::bind("127.0.0.1:0")?;
    endpoint.set_autoclose(30)?;
    assert_eq!(endpoint.autoclose()?, 30);
    endpoint.set_autoclose(0)?;
    assert_eq!(endpoint.autoclose()?, 0);
    Ok(())
}

#[test]
fn multi_homed_endpoint() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 0)),
        SocketAddr::from(([127, 0, 0, 2], 0)),
    ];
    let server = SctpEndpoint::bindx(&addrs)?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    let bound = server.local_addrs(0)?;
    assert_eq!(bound.len(), 2);

    let port = bound[0].port();
    let client = SctpEndpoint::bind("127.0.0.1:0")?;
    let assoc = client.connectx(&[
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([127, 0, 0, 2], port)),
    ])?;
    assert_ne!(assoc, 0);
    assert_eq!(client.peer_addrs(assoc)?.len(), 2);

    client.send(b"multi-homed")?;
    let mut buf = [0; 32];
    let (len, _, info) = server.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"multi-homed");
    assert_eq!(server.local_addrs(info.association_id)?.len(), 2);

    Ok(())
}

#[test]
fn sender_dry_notification() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, _, _) = endpoint_pair()?;
    client.set_event(client.default_association(), Event::SENDER_DRY, true)?;
    client.send_with(b"drain", &SendInfo::new(1))?;

    let mut buf = [0; 64];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(std::time::Instant::now() < deadline, "no SENDER_DRY event");
        match client.recv(&mut buf) {
            Ok(Received::Notification(Notification::SenderDry(event))) => {
                assert_ne!(event.association_id, 0);
                break;
            }
            Ok(Received::Notification(_)) => continue,
            Ok(Received::Data(_)) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }

    let _ = server;
    Ok(())
}

#[test]
fn message_flags_abort() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (server, client, server_assoc, _) = endpoint_pair()?;
    client.send_with(b"abort", &SendInfo::new(0).with_flags(MessageFlags::ABORT))?;

    let mut buf = [0; 64];
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "no abort notification"
        );
        match server.recv(&mut buf) {
            Ok(Received::Notification(Notification::AssociationChange(change))) => {
                assert_eq!(change.association_id, server_assoc);
                assert!(matches!(
                    change.state,
                    AssociationState::CommLost | AssociationState::ShutdownComplete
                ));
                break;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(())
}
