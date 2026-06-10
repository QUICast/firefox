use crate::config::SubscriptionConfig;
use crate::error::McrxError;
#[cfg(feature = "metrics")]
use crate::metrics::SubscriptionMetricsSnapshot;
use crate::packet::{Packet, PacketWithMetadata};
use crate::platform::{ReceiveSocket, recv_packet, recv_packet_with_metadata, socket_local_addr};
use socket2::Socket;
use std::net::SocketAddr;
#[cfg(feature = "metrics")]
use std::sync::Mutex;
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(feature = "metrics")]
use std::time::SystemTime;

/// Identifies a subscription within a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriptionId(pub u64);

/// Represents the lifecycle state of a subscription.
///
/// A subscription is always associated with a bound socket, but may or may not
/// currently be joined to a multicast group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// Socket is bound but multicast group is not joined.
    Bound,
    /// Multicast group is joined.
    Joined,
}

/// Owned subscription state that can be extracted from a context and moved into
/// another event loop or runtime.
#[derive(Debug)]
pub struct SubscriptionParts {
    /// The subscription's ID inside the originating context.
    pub id: SubscriptionId,
    /// The multicast configuration associated with the socket.
    pub config: SubscriptionConfig,
    /// The owned socket for external integration.
    pub socket: Socket,
    /// The lifecycle state at the time of extraction.
    pub state: SubscriptionState,
}

#[cfg(feature = "metrics")]
#[derive(Debug)]
struct LastPacketMetrics {
    source: Option<SocketAddr>,
    receive_at: Option<SystemTime>,
}

#[cfg(feature = "metrics")]
#[derive(Debug)]
struct SubscriptionMetricsInner {
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    would_block_count: AtomicU64,
    receive_errors: AtomicU64,
    join_count: AtomicU64,
    leave_count: AtomicU64,
    last_payload_len: AtomicUsize,
    last_packet: Mutex<LastPacketMetrics>,
}

#[cfg(feature = "metrics")]
impl Default for SubscriptionMetricsInner {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            would_block_count: AtomicU64::new(0),
            receive_errors: AtomicU64::new(0),
            join_count: AtomicU64::new(0),
            leave_count: AtomicU64::new(0),
            last_payload_len: AtomicUsize::new(usize::MAX),
            last_packet: Mutex::new(LastPacketMetrics {
                source: None,
                receive_at: None,
            }),
        }
    }
}

/// Represents a registered subscription stored inside a context.
#[derive(Debug)]
pub struct Subscription {
    id: SubscriptionId,
    config: SubscriptionConfig,
    socket: ReceiveSocket,
    state: SubscriptionState,
    #[cfg(feature = "metrics")]
    metrics: SubscriptionMetricsInner,
}

impl Subscription {
    #[cfg(feature = "metrics")]
    fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn with_socket(id: SubscriptionId, config: SubscriptionConfig, socket: ReceiveSocket) -> Self {
        Self {
            id,
            config,
            socket,
            state: SubscriptionState::Bound,
            #[cfg(feature = "metrics")]
            metrics: SubscriptionMetricsInner::default(),
        }
    }

    #[cfg(feature = "metrics")]
    fn record_received_packet(&self, packet: &Packet) {
        self.metrics
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .bytes_received
            .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
        self.metrics
            .last_payload_len
            .store(packet.payload.len(), Ordering::Relaxed);
        let mut last_packet = Self::lock_unpoisoned(&self.metrics.last_packet);
        last_packet.source = Some(packet.source);
        last_packet.receive_at = Some(SystemTime::now());
    }

    #[cfg(feature = "metrics")]
    fn record_would_block(&self) {
        self.metrics
            .would_block_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "metrics")]
    fn record_receive_error(&self) {
        self.metrics.receive_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Creates a new subscription from an ID, configuration, and socket.
    ///
    /// This is a low-level constructor. Callers are responsible for providing a
    /// socket that is compatible with the subscription configuration. For the
    /// checked convenience path, prefer `Context::add_subscription_with_socket()`.
    pub fn new(id: SubscriptionId, config: SubscriptionConfig, socket: Socket) -> Self {
        Self::with_socket(id, config, ReceiveSocket::adopt(socket))
    }

    pub(crate) fn from_receive_socket(
        id: SubscriptionId,
        config: SubscriptionConfig,
        socket: ReceiveSocket,
    ) -> Self {
        Self::with_socket(id, config, socket)
    }

    /// Returns the subscription's ID.
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Returns a read-only reference to the subscription's configuration.
    pub fn config(&self) -> &SubscriptionConfig {
        &self.config
    }

    /// Returns a read-only reference to the subscription's socket.
    pub fn socket(&self) -> &Socket {
        self.socket.socket()
    }

    /// Returns a mutable reference to the subscription's socket.
    ///
    /// This is useful when an external event loop or registry needs mutable
    /// socket access during registration.
    pub fn socket_mut(&mut self) -> &mut Socket {
        self.socket.socket_mut()
    }

    /// Attempts to receive a single packet without blocking.
    ///
    /// Returns:
    /// - `Ok(Some(packet))` if a packet was received,
    /// - `Ok(None)` if no packet is currently available,
    /// - `Err(...)` on an actual receive failure.
    pub fn try_recv(&self) -> Result<Option<Packet>, McrxError> {
        if !self.is_joined() {
            return Err(McrxError::SubscriptionNotJoined);
        }
        match recv_packet(&self.socket, self.id, &self.config) {
            Ok(Some(packet)) => {
                #[cfg(feature = "metrics")]
                self.record_received_packet(&packet);

                Ok(Some(packet))
            }
            Ok(None) => {
                #[cfg(feature = "metrics")]
                self.record_would_block();

                Ok(None)
            }
            Err(err) => {
                #[cfg(feature = "metrics")]
                self.record_receive_error();

                Err(err)
            }
        }
    }

    /// Attempts to receive a single packet together with richer receive metadata
    /// without blocking.
    pub fn try_recv_with_metadata(&self) -> Result<Option<PacketWithMetadata>, McrxError> {
        if !self.is_joined() {
            return Err(McrxError::SubscriptionNotJoined);
        }

        match recv_packet_with_metadata(&self.socket, self.id, &self.config) {
            Ok(Some(packet)) => {
                #[cfg(feature = "metrics")]
                self.record_received_packet(&packet.packet);

                Ok(Some(packet))
            }
            Ok(None) => {
                #[cfg(feature = "metrics")]
                self.record_would_block();

                Ok(None)
            }
            Err(err) => {
                #[cfg(feature = "metrics")]
                self.record_receive_error();

                Err(err)
            }
        }
    }

    /// Returns the raw Unix file descriptor of the underlying socket.
    ///
    /// This is useful for integrating subscriptions into external event loops.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd;
        self.socket().as_raw_fd()
    }

    /// Returns the raw Windows socket handle of the underlying socket.
    ///
    /// This is useful for integrating subscriptions into external event loops.
    #[cfg(windows)]
    pub fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        use std::os::windows::io::AsRawSocket;
        self.socket().as_raw_socket()
    }

    /// Returns the local socket address currently bound by this subscription.
    pub fn local_addr(&self) -> Result<SocketAddr, McrxError> {
        self.socket
            .local_addr()
            .or_else(|_| socket_local_addr(self.socket()))
    }

    /// Consumes the subscription and returns its owned socket.
    ///
    /// This is useful when handing a joined or bound socket off to an external
    /// event loop or async runtime.
    pub fn into_socket(self) -> Socket {
        self.socket.into_socket()
    }

    /// Consumes the subscription and returns all owned parts.
    pub fn into_parts(self) -> SubscriptionParts {
        SubscriptionParts {
            id: self.id,
            config: self.config,
            socket: self.socket.into_socket(),
            state: self.state,
        }
    }

    /// Returns the current lifecycle state of the subscription.
    ///
    /// This can be used by callers to inspect whether the subscription is
    /// currently joined to its multicast group or only bound.
    pub fn state(&self) -> SubscriptionState {
        self.state
    }

    /// Returns a snapshot of the subscription's current metrics.
    ///
    /// Counter values in the returned snapshot are cumulative and can be
    /// compared against a later snapshot using `delta_since()`.
    #[cfg(feature = "metrics")]
    pub fn metrics_snapshot(&self) -> SubscriptionMetricsSnapshot {
        let last_payload_len = match self.metrics.last_payload_len.load(Ordering::Relaxed) {
            usize::MAX => None,
            payload_len => Some(payload_len),
        };
        let last_packet = Self::lock_unpoisoned(&self.metrics.last_packet);

        SubscriptionMetricsSnapshot {
            packets_received: self.metrics.packets_received.load(Ordering::Relaxed),
            bytes_received: self.metrics.bytes_received.load(Ordering::Relaxed),
            would_block_count: self.metrics.would_block_count.load(Ordering::Relaxed),
            receive_errors: self.metrics.receive_errors.load(Ordering::Relaxed),
            join_count: self.metrics.join_count.load(Ordering::Relaxed),
            leave_count: self.metrics.leave_count.load(Ordering::Relaxed),
            last_payload_len,
            last_source: last_packet.source,
            last_receive_at: last_packet.receive_at,
            captured_at: SystemTime::now(),
        }
    }

    /// Returns `true` if the subscription is currently joined to its multicast group.
    ///
    /// This is a convenience helper for checking whether the subscription is in
    /// the `SubscriptionState::Joined` state.
    pub fn is_joined(&self) -> bool {
        matches!(self.state, SubscriptionState::Joined)
    }

    /// Marks the subscription as joined.
    ///
    /// This should be called after a successful multicast join operation on the
    /// underlying socket.
    ///
    /// Returns an error if the subscription is already in the joined state.
    pub fn mark_joined(&mut self) -> Result<(), McrxError> {
        if self.state == SubscriptionState::Joined {
            return Err(McrxError::SubscriptionAlreadyJoined);
        }

        self.state = SubscriptionState::Joined;

        #[cfg(feature = "metrics")]
        self.metrics.join_count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Marks the subscription as bound (not joined).
    ///
    /// This should be called after leaving a multicast group, while keeping the
    /// underlying socket open and bound.
    ///
    /// Returns an error if the subscription is already in the bound state.
    pub fn mark_bound(&mut self) -> Result<(), McrxError> {
        if self.state == SubscriptionState::Bound {
            return Err(McrxError::SubscriptionNotJoined);
        }

        self.state = SubscriptionState::Bound;

        #[cfg(feature = "metrics")]
        self.metrics.leave_count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for Subscription {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.socket().as_fd()
    }
}

#[cfg(unix)]
impl std::os::fd::AsRawFd for Subscription {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.socket().as_raw_fd()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsSocket for Subscription {
    fn as_socket(&self) -> std::os::windows::io::BorrowedSocket<'_> {
        self.socket().as_socket()
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawSocket for Subscription {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.socket().as_raw_socket()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SourceFilter, SubscriptionConfig};
    use crate::platform;
    use crate::test_support::{
        ipv6_group_socket_addr, make_multicast_sender, make_multicast_sender_v6,
        make_multicast_sender_v6_for_source, sample_config_on_unused_port,
        sample_config_v6_on_unused_port, sample_ssm_receive_config_v6_on_unused_port,
        unused_udp_port_v4,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
    use std::time::{Duration, Instant};

    fn test_ssm_config(port: u16, interface: Ipv4Addr) -> SubscriptionConfig {
        SubscriptionConfig {
            group: IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
            source: SourceFilter::Source(IpAddr::V4(interface)),
            dst_port: port,
            interface: Some(IpAddr::V4(interface)),
            interface_index: None,
        }
    }

    fn ipv4_group(config: &SubscriptionConfig) -> Ipv4Addr {
        config.ipv4_membership().unwrap().group
    }

    fn ipv4_group_socket_addr(config: &SubscriptionConfig) -> SocketAddrV4 {
        SocketAddrV4::new(ipv4_group(config), config.dst_port)
    }

    fn primary_ipv4() -> Ipv4Addr {
        let probe = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        probe
            .connect(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 9))
            .unwrap();

        match probe.local_addr().unwrap() {
            SocketAddr::V4(addr) => *addr.ip(),
            SocketAddr::V6(_) => panic!("expected an IPv4 local address for SSM test"),
        }
    }

    fn recv_next_subscription_packet(subscription: &Subscription, deadline: Instant) -> Packet {
        loop {
            match subscription.try_recv().unwrap() {
                Some(packet) => return packet,
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => panic!("timed out waiting for packet"),
            }
        }
    }

    fn assert_pktinfo_metadata(packet: &PacketWithMetadata, expected_destination: IpAddr) {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            windows,
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        {
            assert_eq!(
                packet.metadata.destination_local_ip,
                Some(expected_destination)
            );
            assert!(packet.metadata.ingress_interface_index.is_some());
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            windows,
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        {
            let _ = expected_destination;
            assert_eq!(packet.metadata.destination_local_ip, None);
            assert_eq!(packet.metadata.ingress_interface_index, None);
        }
    }

    #[test]
    fn try_recv_returns_none_when_no_packet_is_available() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription = Subscription::from_receive_socket(SubscriptionId(1), config, socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let result = subscription.try_recv().unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn try_recv_receives_packet_sent_to_bound_port() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let payload = b"hello multicast core";

        sender
            .send_to(
                payload,
                SocketAddrV4::new(Ipv4Addr::LOCALHOST, config.dst_port),
            )
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_subscription_packet(&subscription, deadline);

        assert_eq!(packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.group, IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
        assert_eq!(packet.source.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn try_recv_with_metadata_exposes_current_socket_context() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = make_multicast_sender();
        let payload = b"hello detailed receive";

        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = loop {
            match subscription.try_recv_with_metadata().unwrap() {
                Some(packet) => break packet,
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => panic!("timed out waiting for packet with metadata"),
            }
        };

        assert_eq!(packet.packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.packet.group, IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.packet.dst_port, config.dst_port);
        assert_eq!(&packet.packet.payload[..], payload);
        assert_pktinfo_metadata(&packet, IpAddr::V4(ipv4_group(&config)));
        assert_eq!(
            packet.metadata.socket_local_addr,
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                config.dst_port,
            )))
        );
        assert_eq!(packet.metadata.configured_interface, None);
    }

    #[test]
    fn try_recv_with_metadata_exposes_current_ipv6_socket_context() {
        let config = sample_config_v6_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = make_multicast_sender_v6(Ipv6Addr::LOCALHOST);
        let payload = b"hello detailed receive ipv6";

        sender
            .send_to(payload, ipv6_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = loop {
            match subscription.try_recv_with_metadata().unwrap() {
                Some(packet) => break packet,
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => panic!("timed out waiting for IPv6 packet with metadata"),
            }
        };

        assert_eq!(packet.packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.packet.group, config.group);
        assert_eq!(packet.packet.dst_port, config.dst_port);
        assert_eq!(&packet.packet.payload[..], payload);
        assert_pktinfo_metadata(&packet, config.group);
        assert_eq!(
            packet.metadata.socket_local_addr,
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                config.dst_port,
                0,
                0,
            )))
        );
        assert_eq!(packet.metadata.configured_interface, config.interface);
        assert_eq!(
            packet.metadata.configured_interface_index,
            config.interface_index
        );
    }

    #[test]
    fn try_recv_receives_multicast_packet_from_joined_group() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = make_multicast_sender();

        let sender_port = sender.local_addr().unwrap().port();
        let payload = b"hello real asm multicast";

        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_subscription_packet(&subscription, deadline);

        assert_eq!(packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.group, IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
        assert_eq!(packet.source.port(), sender_port);
    }

    #[test]
    fn try_recv_receives_ssm_packet_from_allowed_source() {
        let interface = primary_ipv4();
        let config = test_ssm_config(unused_udp_port_v4(), interface);
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = UdpSocket::bind(SocketAddrV4::new(interface, 0)).unwrap();
        sender.set_multicast_loop_v4(true).unwrap();
        sender.set_multicast_ttl_v4(1).unwrap();

        let sender_port = sender.local_addr().unwrap().port();
        let payload = b"hello real ssm multicast";

        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_subscription_packet(&subscription, deadline);

        assert_eq!(packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.group, IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
        assert_eq!(packet.source.port(), sender_port);
        assert_eq!(packet.source.ip(), IpAddr::V4(interface));
    }

    #[test]
    fn try_recv_receives_ipv6_ssm_packet_from_allowed_source() {
        let Some(config) = sample_ssm_receive_config_v6_on_unused_port() else {
            return;
        };
        let interface = match config.source_addr().unwrap() {
            IpAddr::V6(source) => source,
            IpAddr::V4(_) => panic!("expected an IPv6 source for IPv6 SSM test"),
        };
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);
        platform::join_multicast_group(subscription.socket(), subscription.config()).unwrap();
        subscription.mark_joined().unwrap();

        let sender = make_multicast_sender_v6_for_source(interface);
        let sender_port = sender.local_addr().unwrap().port();
        let payload = b"hello real ipv6 ssm multicast";

        sender
            .send_to(payload, ipv6_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_subscription_packet(&subscription, deadline);

        assert_eq!(packet.subscription_id, SubscriptionId(1));
        assert_eq!(packet.group, config.group);
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
        assert_eq!(packet.source.port(), sender_port);
        assert_eq!(packet.source.ip(), IpAddr::V6(interface));
    }

    #[test]
    fn mark_joined_transitions_bound_to_joined_state() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription = Subscription::from_receive_socket(SubscriptionId(1), config, socket);

        subscription.mark_joined().unwrap();

        assert_eq!(subscription.state(), SubscriptionState::Joined);
    }

    #[test]
    fn mark_joined_rejects_already_joined_subscription() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription = Subscription::from_receive_socket(SubscriptionId(1), config, socket);

        subscription.mark_joined().unwrap();
        let result = subscription.mark_joined();

        assert!(matches!(result, Err(McrxError::SubscriptionAlreadyJoined)));
    }

    #[test]
    fn mark_bound_transitions_joined_to_bound_state() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription = Subscription::from_receive_socket(SubscriptionId(1), config, socket);

        subscription.mark_joined().unwrap();
        subscription.mark_bound().unwrap();

        assert_eq!(subscription.state(), SubscriptionState::Bound);
    }

    #[test]
    fn mark_bound_rejects_already_bound_subscription() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let mut subscription = Subscription::from_receive_socket(SubscriptionId(1), config, socket);

        let result = subscription.mark_bound();

        assert!(matches!(result, Err(McrxError::SubscriptionNotJoined)));
    }

    #[test]
    fn local_addr_returns_bound_socket_address() {
        let config = sample_config_on_unused_port();
        let socket = platform::open_bound_socket(&config).unwrap();
        let subscription =
            Subscription::from_receive_socket(SubscriptionId(1), config.clone(), socket);

        let local_addr = subscription.local_addr().unwrap();

        assert_eq!(
            local_addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, config.dst_port))
        );
    }
}
