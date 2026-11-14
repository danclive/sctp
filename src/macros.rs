//! Internal macros.

/// Options that do not depend on a particular association.
macro_rules! impl_common_socket_options {
    ($ty:ty) => {
        impl $ty {
            /// Returns whether "no delay" mode is enabled (`SCTP_NODELAY`).
            pub fn nodelay(&self) -> std::io::Result<bool> {
                self.socket().nodelay()
            }

            /// Enables or disables "no delay" mode (`SCTP_NODELAY`).
            pub fn set_nodelay(&self, nodelay: bool) -> std::io::Result<()> {
                self.socket().set_nodelay(nodelay)
            }

            /// Returns the parameters used for `INIT` chunks (`SCTP_INITMSG`).
            pub fn init_params(&self) -> std::io::Result<crate::InitParams> {
                self.socket().init_params()
            }

            /// Sets the parameters used for `INIT` chunks (`SCTP_INITMSG`).
            pub fn set_init_params(&self, params: &crate::InitParams) -> std::io::Result<()> {
                self.socket().set_init_params(params)
            }

            /// Returns whether message fragmentation is disabled
            /// (`SCTP_DISABLE_FRAGMENTS`).
            pub fn disable_fragments(&self) -> std::io::Result<bool> {
                self.socket().disable_fragments()
            }

            /// Enables or disables message fragmentation
            /// (`SCTP_DISABLE_FRAGMENTS`).
            pub fn set_disable_fragments(&self, disable: bool) -> std::io::Result<()> {
                self.socket().set_disable_fragments(disable)
            }

            /// Returns the adaptation layer indication
            /// (`SCTP_ADAPTATION_LAYER`).
            pub fn adaptation_layer(&self) -> std::io::Result<u32> {
                self.socket().adaptation_layer()
            }

            /// Sets the adaptation layer indication
            /// (`SCTP_ADAPTATION_LAYER`).
            pub fn set_adaptation_layer(&self, indication: u32) -> std::io::Result<()> {
                self.socket().set_adaptation_layer(indication)
            }

            /// Returns the fragment interleaving mode
            /// (`SCTP_FRAGMENT_INTERLEAVE`).
            pub fn fragment_interleave(&self) -> std::io::Result<bool> {
                self.socket().fragment_interleave()
            }

            /// Sets the fragment interleaving mode
            /// (`SCTP_FRAGMENT_INTERLEAVE`).
            pub fn set_fragment_interleave(&self, interleave: bool) -> std::io::Result<()> {
                self.socket().set_fragment_interleave(interleave)
            }

            /// Returns the partial delivery point in bytes
            /// (`SCTP_PARTIAL_DELIVERY_POINT`).
            pub fn partial_delivery_point(&self) -> std::io::Result<u32> {
                self.socket().partial_delivery_point()
            }

            /// Sets the partial delivery point in bytes
            /// (`SCTP_PARTIAL_DELIVERY_POINT`).
            pub fn set_partial_delivery_point(&self, point: u32) -> std::io::Result<()> {
                self.socket().set_partial_delivery_point(point)
            }

            /// Returns whether `SCTP_NXTINFO` ancillary data is requested.
            pub fn receive_next_info(&self) -> std::io::Result<bool> {
                self.socket().receive_next_info()
            }

            /// Enables or disables `SCTP_NXTINFO` ancillary data, which
            /// populates [`ReceivedData::next`](crate::ReceivedData::next).
            pub fn set_receive_next_info(&self, enable: bool) -> std::io::Result<()> {
                self.socket().set_receive_next_info(enable)
            }

            /// Returns the send buffer size (`SO_SNDBUF`).
            pub fn send_buffer_size(&self) -> std::io::Result<usize> {
                self.socket().send_buffer_size()
            }

            /// Sets the send buffer size (`SO_SNDBUF`).
            pub fn set_send_buffer_size(&self, size: usize) -> std::io::Result<()> {
                self.socket().set_send_buffer_size(size)
            }

            /// Returns the receive buffer size (`SO_RCVBUF`).
            pub fn recv_buffer_size(&self) -> std::io::Result<usize> {
                self.socket().recv_buffer_size()
            }

            /// Sets the receive buffer size (`SO_RCVBUF`).
            pub fn set_recv_buffer_size(&self, size: usize) -> std::io::Result<()> {
                self.socket().set_recv_buffer_size(size)
            }

            /// Returns the subscribed events (`SCTP_EVENTS`).
            pub fn events(&self) -> std::io::Result<crate::Event> {
                self.socket().events()
            }

            /// Subscribes to events (`SCTP_EVENTS`).
            ///
            /// Subscribed events are delivered as
            /// [`Received::Notification`](crate::Received::Notification) values
            /// by `recv` and are discarded by the `Read` implementations.
            pub fn set_events(&self, events: crate::Event) -> std::io::Result<()> {
                self.socket().set_events(events)
            }

            /// Moves the socket between blocking and non-blocking mode.
            pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
                self.socket().set_nonblocking(nonblocking)
            }

            /// Takes and clears the pending socket error.
            pub fn take_error(&self) -> std::io::Result<Option<std::io::Error>> {
                self.socket().take_error()
            }

            /// Returns whether stream reconfiguration is enabled
            /// (`SCTP_RECONFIG_SUPPORTED`).
            pub fn reconfig_supported(&self) -> std::io::Result<bool> {
                self.socket().reconfig_supported()
            }

            /// Enables or disables stream reconfiguration
            /// (`SCTP_RECONFIG_SUPPORTED`).
            pub fn set_reconfig_supported(&self, enable: bool) -> std::io::Result<()> {
                self.socket().set_reconfig_supported(enable)
            }
        }
    };
}
