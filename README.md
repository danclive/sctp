# sctp

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Stream Control Transmission Protocol (SCTP) sockets for Rust, in the style of
[`std::net`](https://doc.rust-lang.org/std/net/).

The crate talks to the Linux kernel directly through
`getsockopt(2)`/`setsockopt(2)` and `sendmsg(2)`/`recvmsg(2)`, so it does **not**
depend on `libsctp` (lksctp-tools). The only dependency is [`libc`].

## Features

- **One-to-one style** (`SOCK_STREAM`): `SctpListener` and `SctpStream`, the
  direct counterparts of `TcpListener` and `TcpStream`, including `Read`/`Write`
  implementations.
- **One-to-many style** (`SOCK_SEQPACKET`): `SctpEndpoint` multiplexes any
  number of associations over a single socket, identified by an
  `AssociationId`.
- **Messages, not bytes**: every send and receive preserves message boundaries,
  stream identifiers and payload protocol identifiers (`SendInfo`/`RecvInfo`).
- **Notifications**: association changes, peer address changes, send failures,
  shutdowns, stream resets, sender-dry events and more, delivered as a typed
  `Notification` enum.
- **Partial reliability (PR-SCTP)**: messages can be given a lifetime, a
  retransmission limit or a priority with `PrPolicy`.
- **Multi-homing**: `connectx`/`bindx` attach several addresses to one
  association, and the full local/peer address lists are queryable.
- **Socket options**: RTO, association parameters, heartbeats and path
  parameters, delayed `SACK`, maximum segment/burst, stream schedulers, stream
  reconfiguration, event subscription and association statistics.
- **Interoperable descriptors**: `AsFd`, `AsRawFd`, `FromRawFd`, `IntoRawFd` and
  `From<OwnedFd>` are implemented for all socket types.

## Example

```rust
use std::io::{Read, Write};
use sctp::{SendInfo, SctpListener, SctpStream};

fn main() -> std::io::Result<()> {
    let listener = SctpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let client = std::thread::spawn(move || -> std::io::Result<()> {
        let stream = SctpStream::connect(addr)?;
        stream.send_with(b"hello", &SendInfo::new(7))?;
        Ok(())
    });

    let (mut stream, peer) = listener.accept()?;
    let mut buf = [0; 64];
    let n = stream.read(&mut buf)?;
    assert_eq!(&buf[..n], b"hello");
    stream.write_all(b"world")?;

    client.join().unwrap()?;
    println!("served {peer}");
    Ok(())
}
```

The one-to-many style multiplexes associations:

```rust
use sctp::{Event, Received, SctpEndpoint};

fn main() -> std::io::Result<()> {
    let server = SctpEndpoint::bind("127.0.0.1:0")?;
    server.set_events(Event::ASSOCIATION)?;

    let client = SctpEndpoint::bind("127.0.0.1:0")?;
    let association = client.connect(server.local_addr()?)?;
    client.send(b"hi")?;

    let mut buf = [0; 64];
    loop {
        match server.recv(&mut buf)? {
            Received::Notification(notification) => println!("{notification:?}"),
            Received::Data(data) => {
                println!("{:?} on stream {}", &buf[..data.len], data.info.stream_id);
                break;
            }
        }
    }

    client.shutdown(association)?;
    Ok(())
}
```

## Platform support

Linux only. SCTP must be available (`CONFIG_IP_SCTP`, either built in or loaded
as a module), which can be checked with:

```console
$ cat /proc/net/protocols | grep -i sctp
```

The crate is developed against a recent kernel (5.x and newer); features that
the kernel does not implement are reported as `io::Error`s. Run the test suite
with `cargo test`; tests that need SCTP skip themselves when the protocol is
unavailable.

## Minimum supported Rust version

Rust 1.85 (edition 2024).

## License

MIT
