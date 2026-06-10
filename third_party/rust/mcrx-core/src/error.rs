use std::io;
use thiserror::Error;

/// Errors returned by the multicast receiver core.
#[derive(Debug, Error)]
pub enum McrxError {
    /// The configured destination port is invalid.
    #[error("MCRX: invalid destination port")]
    InvalidDestinationPort,

    /// The configured group address is not a valid multicast IP address.
    #[error("MCRX: group must be a multicast IP address")]
    InvalidMulticastGroup,

    /// The configured SSM source address is invalid.
    #[error("MCRX: invalid source address")]
    InvalidSourceAddress,

    /// The configured IPv6 SSM group is not in the IPv6 SSM range.
    #[error("MCRX: IPv6 SSM groups must use the ff3x:: prefix")]
    InvalidIpv6SsmGroup,

    /// The configured IPv4 SSM group is not in the IPv4 SSM range.
    #[error("MCRX: IPv4 SSM groups must use the 232.0.0.0/8 range")]
    InvalidIpv4SsmGroup,

    /// The configured SSM source address family does not match the group family.
    #[error("MCRX: source address family must match group address family")]
    SourceAddressFamilyMismatch,

    /// The configured interface address family does not match the group family.
    #[error("MCRX: interface address family must match group address family")]
    InterfaceAddressFamilyMismatch,

    /// The configured interface index is invalid.
    #[error("MCRX: interface index must be greater than 0")]
    InvalidInterfaceIndex,

    /// The configured interface index is only valid for IPv6 subscriptions.
    #[error("MCRX: interface index is only supported for IPv6 subscriptions")]
    InterfaceIndexRequiresIpv6,

    /// A subscription with the same configuration already exists.
    #[error("MCRX: subscription already exists")]
    DuplicateSubscription,

    /// No subscription with the requested ID exists.
    #[error("MCRX: subscription not found")]
    SubscriptionNotFound,

    /// The subscription is not currently joined to its multicast group.
    #[error("MCRX: subscription not joined")]
    SubscriptionNotJoined,

    /// The subscription is already joined to its multicast group.
    #[error("MCRX: subscription already joined")]
    SubscriptionAlreadyJoined,

    /// Creating the UDP socket failed.
    #[error("MCRX: failed to create UDP socket: {0}")]
    SocketCreateFailed(io::Error),

    /// Setting a socket option failed.
    #[error("MCRX: failed to set socket option: {0}")]
    SocketOptionFailed(io::Error),

    /// Binding the UDP socket failed.
    #[error("MCRX: failed to bind UDP socket: {0}")]
    SocketBindFailed(io::Error),

    /// Creating the raw receive socket failed.
    #[error("MCRX: failed to create raw receive socket: {0}")]
    RawSocketCreateFailed(io::Error),

    /// Binding the raw receive socket failed.
    #[error("MCRX: failed to bind raw receive socket: {0}")]
    RawSocketBindFailed(io::Error),

    /// Raw multicast receive is not supported on this platform in this build.
    #[error("MCRX: raw multicast receive is not supported on this platform: {0}")]
    RawPacketReceiveUnsupported(String),

    /// The requested IPv6 functionality is not implemented yet.
    #[error("MCRX: requested IPv6 functionality is not implemented yet")]
    Ipv6NotYetImplemented,

    /// Reading the local address of an existing socket failed.
    #[error("MCRX: failed to read local address from existing socket: {0}")]
    SocketLocalAddrFailed(io::Error),

    /// Looking up a socket extension function failed.
    #[error("MCRX: failed to look up socket extension function: {0}")]
    SocketIoctlFailed(io::Error),

    /// The provided existing socket family does not match the subscription configuration.
    #[error("MCRX: existing socket address family does not match the subscription configuration")]
    ExistingSocketAddressFamilyMismatch,

    /// The provided existing socket is bound to a different UDP port than the subscription.
    #[error("MCRX: existing socket is bound to UDP port {actual}, expected {expected}")]
    ExistingSocketPortMismatch { expected: u16, actual: u16 },

    /// Joining a multicast group failed.
    #[error("MCRX: failed to join multicast group: {0}")]
    MulticastJoinFailed(io::Error),

    /// Leaving a multicast group failed.
    #[error("MCRX: failed to leave multicast group: {0}")]
    MulticastLeaveFailed(io::Error),

    /// Source-specific multicast is not supported on this platform.
    #[error("MCRX: source-specific multicast is not supported on this platform")]
    SourceSpecificMulticastUnsupported,

    /// IPv6 source-specific multicast requires explicit interface selection.
    #[error(
        "MCRX: IPv6 source-specific multicast requires an explicit interface address or interface index"
    )]
    Ipv6SourceSpecificMulticastRequiresInterface,

    /// IPv6 source-specific multicast has not been wired into the receiver yet.
    #[error("MCRX: IPv6 source-specific multicast is not implemented yet")]
    Ipv6SourceSpecificMulticastNotYetImplemented,

    /// Binding the interface probe socket failed.
    #[error("MCRX: failed to bind interface probe socket: {0}")]
    InterfaceProbeBindFailed(io::Error),

    /// Connecting the interface probe socket failed.
    #[error("MCRX: failed to connect interface probe socket: {0}")]
    InterfaceProbeConnectFailed(io::Error),

    /// Reading the local address from the interface probe socket failed.
    #[error("MCRX: failed to read local address from interface probe socket: {0}")]
    InterfaceProbeLocalAddrFailed(io::Error),

    /// Discovering the local network interface failed.
    #[error("MCRX: failed to discover local interface: {0}")]
    InterfaceDiscoveryFailed(String),

    /// The received packet came from a non-IP socket address.
    #[error("MCRX: received packet from non-IP socket address")]
    NonIpSocketAddress,

    /// Receiving a packet failed.
    #[error("MCRX: receive failed: {0}")]
    ReceiveFailed(io::Error),
}
