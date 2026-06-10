use crate::error::McrxError;
use crate::platform::{
    RawReceiveSocket, join_raw_multicast_group, leave_raw_multicast_group, recv_raw_packet,
};
use crate::raw::{RawPacket, RawSubscriptionConfig};
use crate::subscription::{SubscriptionId, SubscriptionState};

/// Represents a registered raw multicast subscription stored inside a context.
#[derive(Debug)]
pub struct RawSubscription {
    id: SubscriptionId,
    config: RawSubscriptionConfig,
    socket: RawReceiveSocket,
    state: SubscriptionState,
}

impl RawSubscription {
    pub(crate) fn new(
        id: SubscriptionId,
        config: RawSubscriptionConfig,
        socket: RawReceiveSocket,
    ) -> Self {
        Self {
            id,
            config,
            socket,
            state: SubscriptionState::Bound,
        }
    }

    /// Returns the subscription's ID.
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Returns a read-only reference to the raw subscription configuration.
    pub fn config(&self) -> &RawSubscriptionConfig {
        &self.config
    }

    /// Returns the receive descriptor used by this raw subscription.
    ///
    /// Most platforms use a real socket here. Some backends, such as macOS
    /// BPF, wrap a non-socket file descriptor for ownership and readiness.
    /// Prefer `as_raw_fd()` / `as_raw_socket()` for event-loop registration.
    pub fn socket(&self) -> &socket2::Socket {
        self.socket.socket()
    }

    /// Returns the current lifecycle state of the subscription.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Returns `true` if the subscription is currently joined to its multicast group.
    pub fn is_joined(&self) -> bool {
        matches!(self.state, SubscriptionState::Joined)
    }

    /// Attempts to receive a single complete multicast IP datagram without blocking.
    pub fn try_recv(&self) -> Result<Option<RawPacket>, McrxError> {
        if !self.is_joined() {
            return Err(McrxError::SubscriptionNotJoined);
        }

        recv_raw_packet(&self.socket, self.id, &self.config)
    }

    /// Joins the multicast group for this raw subscription.
    pub fn join(&mut self) -> Result<(), McrxError> {
        if self.is_joined() {
            return Err(McrxError::SubscriptionAlreadyJoined);
        }

        join_raw_multicast_group(&self.socket, &self.config)?;
        self.state = SubscriptionState::Joined;
        Ok(())
    }

    /// Leaves the multicast group for this raw subscription while keeping the socket open.
    pub fn leave(&mut self) -> Result<(), McrxError> {
        if !self.is_joined() {
            return Err(McrxError::SubscriptionNotJoined);
        }

        leave_raw_multicast_group(&self.socket, &self.config)?;
        self.state = SubscriptionState::Bound;
        Ok(())
    }

    /// Returns the raw Unix file descriptor of the underlying receive socket.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket().as_raw_fd()
    }

    /// Returns the raw Windows socket handle of the underlying receive socket.
    #[cfg(windows)]
    pub fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket().as_raw_socket()
    }
}
