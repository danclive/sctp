use std::ops;

const DATA_IO: usize            = 0b0000000001;
const ASSOCIATION: usize        = 0b0000000010;
const ADDRESS: usize            = 0b0000000100;
const SEND_FAILURE: usize       = 0b0000001000;
const PEER_ERROR: usize         = 0b0000010000;
const SHUTDOWN: usize           = 0b0000100000;
const PARTIAL_DELIVERY: usize   = 0b0001000000;
const ADAPTATION_LAYER: usize   = 0b0010000000;
const AUTHENTICATION: usize     = 0b0100000000;
const SENDER_DRY: usize         = 0b1000000000;

#[derive(Debug, Copy, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Event(usize);

impl Event {
    #[inline]
    pub fn empty() -> Event {
        Event(0)
    }

    #[inline]
    pub fn data_io() -> Event {
        Event(DATA_IO)
    }

    #[inline]
    pub fn association() -> Event {
        Event(ASSOCIATION)
    }

    #[inline]
    pub fn address() -> Event {
        Event(ADDRESS)
    }

    #[inline]
    pub fn send_failure() -> Event {
        Event(SEND_FAILURE)
    }

    #[inline]
    pub fn peer_error() -> Event {
        Event(PEER_ERROR)
    }

    #[inline]
    pub fn shutdown() -> Event {
        Event(SHUTDOWN)
    }

    #[inline]
    pub fn partial_delivery() -> Event {
        Event(PARTIAL_DELIVERY)
    }

    #[inline]
    pub fn adaptation_layer() -> Event {
        Event(ADAPTATION_LAYER)
    }

    #[inline]
    pub fn authentication() -> Event {
        Event(AUTHENTICATION)
    }

    #[inline]
    pub fn sender_dry() -> Event {
        Event(SENDER_DRY)
    }

    #[inline]
    pub fn insert(&mut self, other: Event) {
        self.0 |= other.0
    }

    #[inline]
    pub fn remove(&mut self, other: Event) {
        self.0 &= !other.0
    }

    #[inline]
    pub fn contains(&self, other: Event) -> bool {
        (*self & other) == other
    }

    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl ops::BitOr for Event {
    type Output = Event;

    #[inline]
    fn bitor(self, other: Event) -> Event {
        Event(self.0 | other.0)
    }
}

impl ops::BitXor for Event {
    type Output = Event;

    #[inline]
    fn bitxor(self, other: Event) -> Event {
        Event(self.0 ^ other.0)
    }
}

impl ops::BitAnd for Event {
    type Output = Event;

    #[inline]
    fn bitand(self, other: Event) -> Event {
        Event(self.0 & other.0)
    }
}

impl ops::Sub for Event {
    type Output = Event;

    #[inline]
    fn sub(self, other: Event) -> Event {
        Event(self.0 & !other.0)
    }
}

impl ops::Not for Event {
    type Output = Event;

    #[inline]
    fn not(self) -> Event {
        Event(!self.0)
    }
}

impl From<usize> for Event {
    fn from(event: usize) -> Event {
        Event(event)
    }
}
