//! Stream Control Transmission Protocol (SCTP) sockets.
//!
//! This crate exposes the Linux SCTP socket API in the style of [`std::net`].
//! It talks to the kernel directly through `getsockopt(2)`/`setsockopt(2)` and
//! `recvmsg(2)`/`sendmsg(2)`, so it does not require `libsctp`.
//!
//! Two socket styles are available:
//!
//! * [`SctpStream`] and [`SctpListener`] are the *one-to-one* style
//!   (`SOCK_STREAM`): every association has its own socket, like TCP. This is
//!   the style to pick for most applications.
//! * [`SctpEndpoint`] is the *one-to-many* style (`SOCK_SEQPACKET`): a single
//!   socket multiplexes any number of associations, like UDP.
//!
//! Both styles send and receive whole messages. Each message belongs to a
//! stream, which can be selected with [`SendInfo`] and is reported on reception
//! in [`RecvInfo`].
//!
//! # Examples
//!
//! A one-to-one server and client:
//!
//! ```no_run
//! use std::io::{Read, Write};
//! use sctp::{SendInfo, SctpListener, SctpStream};
//!
//! # fn main() -> std::io::Result<()> {
//! let listener = SctpListener::bind("127.0.0.1:0")?;
//! let addr = listener.local_addr()?;
//!
//! let client = std::thread::spawn(move || -> std::io::Result<()> {
//!     let stream = SctpStream::connect(addr)?;
//!     stream.send_with(b"hello", &SendInfo::new(7))?;
//!     Ok(())
//! });
//!
//! let (mut stream, peer) = listener.accept()?;
//! let mut buf = [0; 64];
//! let n = stream.read(&mut buf)?;
//! assert_eq!(&buf[..n], b"hello");
//! stream.write_all(b"world")?;
//! client.join().unwrap()?;
//! # let _ = peer;
//! # Ok(())
//! # }
//! ```
//!
//! A one-to-many endpoint with notifications:
//!
//! ```no_run
//! use sctp::{Event, Received, SctpEndpoint};
//!
//! # fn main() -> std::io::Result<()> {
//! let server = SctpEndpoint::bind("127.0.0.1:0")?;
//! server.set_events(Event::ASSOCIATION)?;
//!
//! let client = SctpEndpoint::bind("127.0.0.1:0")?;
//! let association = client.connect(server.local_addr()?)?;
//! client.send(b"hi")?;
//!
//! let mut buf = [0; 64];
//! loop {
//!     match server.recv(&mut buf)? {
//!         Received::Notification(notification) => {
//!             println!("{notification:?}");
//!         }
//!         Received::Data(data) => {
//!             println!("{:?} on stream {}", &buf[..data.len], data.info.stream_id);
//!             break;
//!         }
//!     }
//! }
//! # let _ = association;
//! # Ok(())
//! # }
//! ```
//!
//! # Platform support
//!
//! Only Linux is supported, and only kernels with SCTP enabled
//! (`CONFIG_IP_SCTP`). On other platforms the crate does not compile.
//!
//! # Raw descriptors
//!
//! All socket types implement [`AsFd`](std::os::fd::AsFd),
//! [`AsRawFd`](std::os::fd::AsRawFd), [`FromRawFd`](std::os::fd::FromRawFd) and
//! [`From<OwnedFd>`](From), so they can be mixed with other I/O code. Sockets
//! created from a descriptor are used as-is: enable `SCTP_RECVRCVINFO` yourself
//! if [`RecvInfo`] needs to be populated for them.

#![deny(missing_debug_implementations)]
#![warn(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!("the `sctp` crate only supports Linux");

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

/// The identifier of an SCTP association.
///
/// One-to-one sockets always use 0. One-to-many sockets use the identifiers
/// reported by [`SctpEndpoint::connect`] and by
/// [`Notification::AssociationChange`].
pub type AssociationId = i32;

/// Passed to socket options to change the defaults for future associations.
pub const FUTURE_ASSOCIATION: AssociationId = 0;

/// The backlog used by [`SctpListener::bind`] and [`SctpEndpoint::bind`].
pub(crate) const DEFAULT_BACKLOG: libc::c_int = 128;

#[macro_use]
mod macros;

mod addr;
mod endpoint;
mod event;
mod listener;
mod message;
mod notification;
mod option;
mod socket;
mod stream;
mod sys;

pub use crate::endpoint::SctpEndpoint;
pub use crate::event::Event;
pub use crate::listener::{Incoming, SctpListener};
pub use crate::message::{
    MessageFlags, NextInfo, PrPolicy, Received, ReceivedData, RecvInfo, SendInfo,
};
pub use crate::notification::{
    AdaptationEvent, AssociationChange, AssociationResetEvent, AssociationState,
    AuthenticationEvent, AuthenticationIndication, ErrorCause, FailedMessageInfo, Notification,
    PartialDeliveryEvent, PartialDeliveryIndication, PeerAddressChange, PeerAddressError,
    PeerAddressState, RemoteError, SendFailed, SendFailedEvent, SendFailedState, SenderDryEvent,
    ShutdownEvent, StreamChangeEvent, StreamResetEvent, StreamResetFlags,
};
pub use crate::option::{
    AssocInfo, AssociationStats, AssociationStatus, ConnectionState, DelayedSack, InitParams,
    PeerAddressFlags, PeerAddressInfo, PeerAddressParams, PeerAddressStatus, PeerAddressThresholds,
    RtoInfo, StreamResetOptions, StreamScheduler,
};
pub use crate::stream::SctpStream;

use crate::addr::resolve_all;

/// Resolves `addr` and returns the first address.
pub(crate) fn first_addr<A: ToSocketAddrs>(addr: A) -> io::Result<SocketAddr> {
    resolve_all(addr)?.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "could not resolve to any addresses",
        )
    })
}

/// Checks that `addrs` is non-empty and that all addresses share a family.
pub(crate) fn single_family(addrs: &[SocketAddr]) -> io::Result<libc::c_int> {
    let Some(first) = addrs.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no addresses given",
        ));
    };

    let family = addr::family(first);
    if addrs.iter().any(|addr| addr::family(addr) != family) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "addresses belong to different address families",
        ));
    }
    Ok(family)
}
