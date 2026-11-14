//! Integration tests for one-to-one style sockets.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr};
use std::time::Duration;

use sctp::{
    Event, MessageFlags, PeerAddressFlags, PeerAddressParams, Received, SctpListener, SctpStream,
    SendInfo, StreamScheduler,
};

fn sctp_supported() -> bool {
    match SctpListener::bind("127.0.0.1:0") {
        Ok(_) => true,
        Err(error) => {
            eprintln!("skipping test: SCTP is not available ({error})");
            false
        }
    }
}

fn connected_pair() -> io::Result<(SctpListener, SctpStream, SctpStream)> {
    let listener = SctpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::thread::spawn(move || SctpStream::connect(addr));
    let (server, _) = listener.accept()?;
    let client = client.join().expect("connect thread panicked")?;
    server.set_read_timeout(Some(Duration::from_secs(5)))?;
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok((listener, client, server))
}

#[test]
fn roundtrip_with_stream_and_ppid() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, server) = connected_pair()?;

    assert_eq!(client.peer_addr()?, server.local_addr()?);
    assert_eq!(server.peer_addr()?, client.local_addr()?);

    // The receive context is a local association setting, not wire data.
    server.set_context(7)?;

    let info = SendInfo::new(5).with_ppid(0xdead_beef).with_context(1);
    client.send_with(b"hello sctp", &info)?;

    let mut buf = [0; 64];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };

    assert_eq!(&buf[..data.len], b"hello sctp");
    assert!(data.complete);
    assert_eq!(data.info.stream_id, 5);
    assert_eq!(data.info.ppid, 0xdead_beef);
    assert_eq!(data.info.context, 7);
    assert_eq!(data.address, Some(client.local_addr()?));

    server.send_with(
        b"pong",
        &SendInfo::new(9).with_flags(MessageFlags::UNORDERED),
    )?;
    let Received::Data(data) = client.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"pong");
    assert_eq!(data.info.stream_id, 9);
    assert!(data.info.flags.contains(MessageFlags::UNORDERED));

    Ok(())
}

#[test]
fn read_and_write_traits() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, mut client, mut server) = connected_pair()?;

    client.write_all(b"trait based")?;
    let mut buf = [0; 32];
    let n = server.read(&mut buf)?;
    assert_eq!(&buf[..n], b"trait based");

    server.write_all(b"response")?;
    let n = client.read(&mut buf)?;
    assert_eq!(&buf[..n], b"response");

    Ok(())
}

#[test]
fn peek_does_not_consume() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, server) = connected_pair()?;
    client.send(b"peek me")?;

    let mut buf = [0; 32];
    let n = server.peek(&mut buf)?;
    assert_eq!(&buf[..n], b"peek me");

    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"peek me");
    Ok(())
}

#[test]
fn graceful_shutdown_delivers_end_of_file() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, mut server) = connected_pair()?;
    client.send(b"last message")?;
    client.shutdown(Shutdown::Write)?;

    let mut buf = [0; 32];
    let n = server.read(&mut buf)?;
    assert_eq!(&buf[..n], b"last message");

    loop {
        match server.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // A missed shutdown is a kernel behaviour change, report it.
                panic!("no end of file after SHUTDOWN: {error}");
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

#[test]
fn socket_options() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let listener = SctpListener::bind("127.0.0.1:0")?;
    listener.set_init_params(&sctp::InitParams {
        outbound_streams: 3,
        inbound_streams: 4,
        max_attempts: 5,
        init_timeout: Duration::from_millis(3000),
    })?;
    listener.set_reconfig_supported(true)?;
    assert!(listener.reconfig_supported()?);

    let addr = listener.local_addr()?;
    let client_thread = std::thread::spawn(move || SctpStream::connect(addr));
    let (server, _) = listener.accept()?;
    let client = client_thread.join().unwrap()?;

    for stream in [&client, &server] {
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        assert_eq!(stream.read_timeout()?, Some(Duration::from_secs(5)));
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        assert_eq!(stream.write_timeout()?, Some(Duration::from_secs(2)));

        stream.set_nodelay(true)?;
        assert!(stream.nodelay()?);
        stream.set_nodelay(false)?;
        assert!(!stream.nodelay()?);

        stream.set_rto_info(&sctp::RtoInfo {
            initial: Duration::from_millis(3000),
            max: Duration::from_millis(60_000),
            min: Duration::from_millis(1000),
        })?;
        let rto = stream.rto_info()?;
        assert_eq!(rto.initial, Duration::from_millis(3000));
        assert_eq!(rto.max, Duration::from_millis(60_000));
        assert_eq!(rto.min, Duration::from_millis(1000));

        stream.set_assoc_info(&sctp::AssocInfo {
            max_retransmits: 7,
            cookie_life: Duration::from_millis(30_000),
            ..sctp::AssocInfo::default()
        })?;
        let assoc = stream.assoc_info()?;
        assert_eq!(assoc.max_retransmits, 7);
        assert_eq!(assoc.cookie_life, Duration::from_millis(30_000));

        stream.set_max_segment(1200)?;
        assert_eq!(stream.max_segment()?, 1200);

        stream.set_context(42)?;
        assert_eq!(stream.context()?, 42);

        stream.set_max_burst(4)?;
        assert_eq!(stream.max_burst()?, 4);

        stream.set_adaptation_layer(7)?;
        assert_eq!(stream.adaptation_layer()?, 7);

        stream.set_partial_delivery_point(4096)?;
        assert_eq!(stream.partial_delivery_point()?, 4096);

        stream.set_fragment_interleave(true)?;
        assert!(stream.fragment_interleave()?);
        stream.set_fragment_interleave(false)?;
        assert!(!stream.fragment_interleave()?);

        stream.set_delayed_sack(&sctp::DelayedSack {
            delay: Some(Duration::from_millis(200)),
            frequency: 2,
        })?;
        let sack = stream.delayed_sack()?;
        assert_eq!(sack.delay, Some(Duration::from_millis(200)));
        assert_eq!(sack.frequency, 2);

        stream.set_stream_scheduler(StreamScheduler::RoundRobin)?;
        assert_eq!(stream.stream_scheduler()?, StreamScheduler::RoundRobin);
        stream.set_stream_scheduler(StreamScheduler::FirstComeFirstServed)?;

        // Scheduler values are only meaningful for some schedulers.
        stream.set_stream_scheduler(StreamScheduler::Priority)?;
        if let Err(error) = stream.set_stream_scheduler_value(0, 5) {
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        }
        stream.set_stream_scheduler(StreamScheduler::FirstComeFirstServed)?;

        let params = PeerAddressParams {
            heartbeat_interval: Some(Duration::from_millis(5000)),
            path_max_retransmits: 6,
            flags: PeerAddressFlags::HEARTBEATS | PeerAddressFlags::PATH_MTU_DISCOVERY,
            ..PeerAddressParams::default()
        };
        stream.set_peer_addr_params(None, &params)?;
        let params = stream.peer_addr_params(None)?;
        assert_eq!(params.heartbeat_interval, Some(Duration::from_millis(5000)));
        assert_eq!(params.path_max_retransmits, 6);
        assert!(params.flags.contains(PeerAddressFlags::HEARTBEATS));

        let status = stream.status()?;
        assert_eq!(status.state, sctp::ConnectionState::Established);

        let local_addrs = stream.local_addrs()?;
        assert!(!local_addrs.is_empty());
        let peer_addrs = stream.peer_addrs()?;
        assert!(!peer_addrs.is_empty());
        assert!(peer_addrs.contains(&stream.primary_addr()?));

        let info = stream.peer_addr_info(&peer_addrs[0])?;
        assert_eq!(info.address, peer_addrs[0]);
        assert_eq!(info.state, sctp::PeerAddressStatus::Active);
        assert!(info.mtu > 0);

        stream.set_peer_addr_thresholds(
            Some(&peer_addrs[0]),
            &sctp::PeerAddressThresholds {
                path_max_retransmits: 8,
                potentially_failed_threshold: 3,
            },
        )?;
        let thresholds = stream.peer_addr_thresholds(Some(&peer_addrs[0]))?;
        assert_eq!(thresholds.path_max_retransmits, 8);
        assert_eq!(thresholds.potentially_failed_threshold, 3);

        // ASCONF requests need `net.sctp.addip_enable`; the ABI must still work.
        if let Err(error) = stream.set_peer_primary_addr(&stream.local_addrs()?[0]) {
            assert!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::EPERM) | Some(libc::EINVAL) | Some(libc::ENOPROTOOPT)
                ),
                "unexpected error: {error:?}"
            );
        }

        stream.set_send_buffer_size(64 * 1024)?;
        assert!(stream.send_buffer_size()? >= 64 * 1024);
        stream.set_recv_buffer_size(64 * 1024)?;
        assert!(stream.recv_buffer_size()? >= 64 * 1024);
    }

    // The listener's INITMSG parameters are inherited by accepted sockets.
    let status = server.status()?;
    assert_eq!(status.inbound_streams, 4);
    assert_eq!(status.outbound_streams, 3);
    let params = listener.init_params()?;
    assert_eq!(params.outbound_streams, 3);
    assert_eq!(params.inbound_streams, 4);
    assert_eq!(params.max_attempts, 5);

    // With an association, the option reports whether the *peer* announced
    // support, which depends on `net.sctp.reconf_enable`; the calls must work.
    let _ = server.reconfig_supported()?;
    let _ = client.reconfig_supported()?;

    Ok(())
}

#[test]
fn default_send_info_is_applied() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, server) = connected_pair()?;

    client.set_default_send_info(&SendInfo::new(4).with_ppid(0x1234))?;
    let default = client.default_send_info()?;
    assert_eq!(default.stream_id, 4);
    assert_eq!(default.ppid, 0x1234);

    client.send(b"defaults")?;
    let mut buf = [0; 32];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(data.info.stream_id, 4);
    assert_eq!(data.info.ppid, 0x1234);

    Ok(())
}

#[test]
fn partial_reliability() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, server) = connected_pair()?;

    let info = SendInfo::new(2).with_partial_reliability(sctp::PrPolicy::Ttl, 5000);
    client.send_with(b"may be abandoned", &info)?;

    let mut buf = [0; 64];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"may be abandoned");

    // A retransmission-limited message is delivered the same way.
    let info = SendInfo::new(2).with_partial_reliability(sctp::PrPolicy::Retransmissions, 3);
    client.send_with(b"limited", &info)?;
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"limited");

    Ok(())
}

#[test]
fn association_statistics() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, server) = connected_pair()?;
    client.send(b"count me")?;

    let mut buf = [0; 32];
    let _ = server.recv(&mut buf)?;
    server.send(b"ack")?;
    let _ = client.recv(&mut buf)?;

    let stats = client.assoc_stats()?;
    assert!(stats.packets_sent > 0);
    assert!(stats.packets_received > 0);

    Ok(())
}

#[test]
fn events_roundtrip() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let (_listener, client, _server) = connected_pair()?;
    client.set_events(Event::ASSOCIATION | Event::SENDER_DRY)?;
    assert_eq!(client.events()?, Event::ASSOCIATION | Event::SENDER_DRY);
    assert!(client.event(Event::SENDER_DRY)?);

    client.set_event(Event::SENDER_DRY, false)?;
    assert!(!client.event(Event::SENDER_DRY)?);

    Ok(())
}

#[test]
fn nonblocking_accept_and_read() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let listener = SctpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;

    match listener.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        other => panic!("expected WouldBlock, got {other:?}"),
    }

    Ok(())
}

#[test]
fn ipv6_roundtrip() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let listener = match SctpListener::bind("[::1]:0") {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("skipping IPv6 test: {error}");
            return Ok(());
        }
    };
    let addr = listener.local_addr()?;
    assert!(addr.is_ipv6());

    let client_thread = std::thread::spawn(move || SctpStream::connect(addr));
    let (server, _) = listener.accept()?;
    let client = client_thread.join().unwrap()?;

    client.send(b"over ipv6")?;
    let mut buf = [0; 32];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"over ipv6");
    assert!(client.local_addr()?.is_ipv6());
    assert!(server.peer_addrs()?.iter().all(SocketAddr::is_ipv6));

    Ok(())
}

#[test]
fn connect_timeout_to_loopback() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let listener = SctpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client =
        std::thread::spawn(move || SctpStream::connect_timeout(&addr, Duration::from_secs(5)));
    let (server, _) = listener.accept()?;
    let client = client.join().unwrap()?;
    client.send(b"timed")?;

    let mut buf = [0; 16];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"timed");
    Ok(())
}

#[test]
fn multi_homed_listener_and_connectx() -> io::Result<()> {
    if !sctp_supported() {
        return Ok(());
    }

    let addrs = [
        SocketAddr::from(([127, 0, 0, 1], 0)),
        SocketAddr::from(([127, 0, 0, 2], 0)),
    ];
    let listener = SctpListener::bindx(&addrs)?;
    let bound = listener.local_addrs()?;
    assert_eq!(bound.len(), 2);

    let port = bound[0].port();
    let peer_addrs = [
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([127, 0, 0, 2], port)),
    ];

    let thread = std::thread::spawn(move || SctpStream::connectx(&peer_addrs));
    let (server, _) = listener.accept()?;
    let client = thread.join().unwrap()?;

    assert_eq!(server.local_addrs()?.len(), 2);
    assert_eq!(server.peer_addrs()?.len(), 2);
    assert_eq!(client.local_addrs()?.len(), 2);

    client.send(b"multi")?;
    let mut buf = [0; 16];
    let Received::Data(data) = server.recv(&mut buf)? else {
        panic!("expected data");
    };
    assert_eq!(&buf[..data.len], b"multi");

    Ok(())
}
