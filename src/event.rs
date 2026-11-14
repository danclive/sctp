use std::fmt;
use std::ops;

use crate::sys;

/// The SCTP events a socket can subscribe to.
///
/// Subscription is done with the [`SCTP_EVENTS`] socket option; events that are
/// not subscribed to are never delivered, which keeps [`recv`] free of
/// notifications for applications that do not need them.
///
/// # Examples
///
/// ```
/// use sctp::{Event, SctpEndpoint};
///
/// # fn main() -> std::io::Result<()> {
/// # if let Ok(endpoint) = SctpEndpoint::bind("127.0.0.1:0") {
/// endpoint.set_events(Event::ASSOCIATION | Event::SHUTDOWN)?;
/// # }
/// # Ok(())
/// # }
/// ```
///
/// [`recv`]: crate::SctpStream::recv
/// [`SCTP_EVENTS`]: https://www.kernel.org/doc/html/latest/networking/sctp.html
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Event(u16);

impl Event {
    /// Delivery of ancillary data describing each received message.
    pub const DATA_IO: Event = Event(1 << 0);
    /// Association state changes.
    pub const ASSOCIATION: Event = Event(1 << 1);
    /// Peer address state changes.
    pub const ADDRESS: Event = Event(1 << 2);
    /// Failed sends.
    pub const SEND_FAILURE: Event = Event(1 << 3);
    /// Remote error causes.
    pub const PEER_ERROR: Event = Event(1 << 4);
    /// The peer shut the association down.
    pub const SHUTDOWN: Event = Event(1 << 5);
    /// Partial delivery of an oversized message was aborted.
    pub const PARTIAL_DELIVERY: Event = Event(1 << 6);
    /// The peer's adaptation layer indication.
    pub const ADAPTATION_LAYER: Event = Event(1 << 7);
    /// Authentication key changes.
    pub const AUTHENTICATION: Event = Event(1 << 8);
    /// The send queue became empty.
    pub const SENDER_DRY: Event = Event(1 << 9);
    /// Stream reset requests completed (requires stream reset to be enabled).
    pub const STREAM_RESET: Event = Event(1 << 10);
    /// Association reset requests completed.
    pub const ASSOC_RESET: Event = Event(1 << 11);
    /// Streams were added to the association.
    pub const STREAM_CHANGE: Event = Event(1 << 12);
    /// Failed sends carrying the newer `sctp_sndinfo` payload.
    pub const SEND_FAILURE_EVENT: Event = Event(1 << 13);

    /// The empty set.
    pub const fn empty() -> Event {
        Event(0)
    }

    /// Every event supported by this crate.
    pub const fn all() -> Event {
        Event((1 << sys::EVENT_COUNT) - 1)
    }

    /// The raw bit representation.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Builds a set from raw bits, dropping unknown bits.
    pub const fn from_bits_truncate(bits: u16) -> Event {
        Event(bits & Event::all().0)
    }

    /// Returns `true` if no event is contained in `self`.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if `self` contains every event in `other`.
    pub const fn contains(self, other: Event) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `true` if `self` and `other` share at least one event.
    pub const fn intersects(self, other: Event) -> bool {
        self.0 & other.0 != 0
    }

    /// The union of two sets.
    pub const fn union(self, other: Event) -> Event {
        Event(self.0 | other.0)
    }

    /// The intersection of two sets.
    pub const fn intersection(self, other: Event) -> Event {
        Event(self.0 & other.0)
    }

    /// Adds `other` to the set.
    pub fn insert(&mut self, other: Event) {
        self.0 |= other.0;
    }

    /// Removes `other` from the set.
    pub fn remove(&mut self, other: Event) {
        self.0 &= !other.0;
    }

    /// The `SCTP_EVENTS` payload selecting exactly these events.
    pub(crate) fn to_subscribe(self) -> sys::sctp_event_subscribe {
        let mut bytes = [0; sys::EVENT_COUNT];
        for (index, byte) in bytes.iter_mut().enumerate() {
            if self.0 & (1 << index) != 0 {
                *byte = 1;
            }
        }
        bytes
    }

    /// Reconstructs a set from an `SCTP_EVENTS` payload.
    pub(crate) fn from_subscribe(bytes: &[u8]) -> Event {
        let mut bits = 0;
        for (index, byte) in bytes.iter().take(sys::EVENT_COUNT).enumerate() {
            if *byte != 0 {
                bits |= 1 << index;
            }
        }
        Event(bits)
    }

    /// The notification type corresponding to a single event.
    pub(crate) fn notification_type(self) -> Option<u16> {
        if self.0 == 0 || !self.0.is_power_of_two() {
            return None;
        }
        Some(sys::SCTP_DATA_IO_EVENT + self.0.trailing_zeros() as u16)
    }
}

const NAMES: [(Event, &str); sys::EVENT_COUNT] = [
    (Event::DATA_IO, "DATA_IO"),
    (Event::ASSOCIATION, "ASSOCIATION"),
    (Event::ADDRESS, "ADDRESS"),
    (Event::SEND_FAILURE, "SEND_FAILURE"),
    (Event::PEER_ERROR, "PEER_ERROR"),
    (Event::SHUTDOWN, "SHUTDOWN"),
    (Event::PARTIAL_DELIVERY, "PARTIAL_DELIVERY"),
    (Event::ADAPTATION_LAYER, "ADAPTATION_LAYER"),
    (Event::AUTHENTICATION, "AUTHENTICATION"),
    (Event::SENDER_DRY, "SENDER_DRY"),
    (Event::STREAM_RESET, "STREAM_RESET"),
    (Event::ASSOC_RESET, "ASSOC_RESET"),
    (Event::STREAM_CHANGE, "STREAM_CHANGE"),
    (Event::SEND_FAILURE_EVENT, "SEND_FAILURE_EVENT"),
];

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 {
            return f.write_str("Event(empty)");
        }

        f.write_str("Event(")?;
        let mut first = true;
        for (event, name) in NAMES {
            if !self.contains(event) {
                continue;
            }
            if !first {
                f.write_str(" | ")?;
            }
            first = false;
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

impl ops::BitOr for Event {
    type Output = Event;

    fn bitor(self, rhs: Event) -> Event {
        Event(self.0 | rhs.0)
    }
}

impl ops::BitOrAssign for Event {
    fn bitor_assign(&mut self, rhs: Event) {
        self.0 |= rhs.0;
    }
}

impl ops::BitAnd for Event {
    type Output = Event;

    fn bitand(self, rhs: Event) -> Event {
        Event(self.0 & rhs.0)
    }
}

impl ops::BitAndAssign for Event {
    fn bitand_assign(&mut self, rhs: Event) {
        self.0 &= rhs.0;
    }
}

impl ops::BitXor for Event {
    type Output = Event;

    fn bitxor(self, rhs: Event) -> Event {
        Event(self.0 ^ rhs.0)
    }
}

impl ops::BitXorAssign for Event {
    fn bitxor_assign(&mut self, rhs: Event) {
        self.0 ^= rhs.0;
    }
}

impl ops::Sub for Event {
    type Output = Event;

    fn sub(self, rhs: Event) -> Event {
        Event(self.0 & !rhs.0)
    }
}

impl ops::Not for Event {
    type Output = Event;

    fn not(self) -> Event {
        Event(!self.0 & Event::all().0)
    }
}

impl From<Event> for u16 {
    fn from(event: Event) -> u16 {
        event.0
    }
}

#[cfg(test)]
mod tests {
    use super::Event;

    #[test]
    fn set_operations() {
        let set = Event::ASSOCIATION | Event::SHUTDOWN;
        assert!(set.contains(Event::ASSOCIATION));
        assert!(set.contains(Event::ASSOCIATION | Event::SHUTDOWN));
        assert!(!set.contains(Event::ADDRESS));
        assert!(set.intersects(Event::SHUTDOWN | Event::ADDRESS));
        assert_eq!((set - Event::SHUTDOWN), Event::ASSOCIATION);
        assert_eq!((!Event::empty()), Event::all());
    }

    #[test]
    fn subscribe_roundtrip() {
        let events = Event::DATA_IO | Event::STREAM_RESET | Event::SEND_FAILURE_EVENT;
        let bytes = events.to_subscribe();
        assert_eq!(bytes.iter().filter(|byte| **byte != 0).count(), 3);
        assert_eq!(Event::from_subscribe(&bytes), events);
    }

    #[test]
    fn debug_lists_names() {
        assert_eq!(
            format!("{:?}", Event::DATA_IO | Event::SHUTDOWN),
            "Event(DATA_IO | SHUTDOWN)"
        );
    }
}
