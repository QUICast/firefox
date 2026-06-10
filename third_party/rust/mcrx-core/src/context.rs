use crate::config::SubscriptionConfig;
use crate::error::McrxError;
use crate::packet::{Packet, PacketWithMetadata};
use crate::platform::{
    ReceiveSocket, join_multicast_group, leave_multicast_group, open_bound_socket,
    prepare_existing_socket,
};
use crate::subscription::{Subscription, SubscriptionId};
use socket2::Socket;

#[cfg(feature = "metrics")]
use crate::metrics::ContextMetricsSnapshot;
#[cfg(feature = "metrics")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "metrics")]
use std::time::SystemTime;

#[cfg(feature = "metrics")]
#[derive(Debug, Default)]
struct ContextMetricsInner {
    subscriptions_added: AtomicU64,
    subscriptions_removed: AtomicU64,
    total_packets_received: AtomicU64,
    total_bytes_received: AtomicU64,
    total_would_block_count: AtomicU64,
    total_receive_errors: AtomicU64,
    total_join_count: AtomicU64,
    total_leave_count: AtomicU64,
    batch_calls: AtomicU64,
    batch_packets_received: AtomicU64,
}

/// Owns and manages the set of active subscriptions.
#[derive(Debug, Default)]
pub struct Context {
    subscriptions: Vec<Subscription>,
    next_subscription_id: u64,
    next_recv_index: usize,
    #[cfg(feature = "metrics")]
    metrics: ContextMetricsInner,
}

impl Context {
    #[cfg(feature = "metrics")]
    fn record_received_packet(&self, payload_len: usize) {
        self.metrics
            .total_packets_received
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_bytes_received
            .fetch_add(payload_len as u64, Ordering::Relaxed);
    }

    #[cfg(feature = "metrics")]
    fn record_would_block(&self) {
        self.metrics
            .total_would_block_count
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "metrics")]
    fn record_receive_error(&self) {
        self.metrics
            .total_receive_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "metrics")]
    fn record_batch_call(&self) {
        self.metrics.batch_calls.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(feature = "metrics")]
    fn record_batch_packets_received(&self, packet_count: usize) {
        self.metrics
            .batch_packets_received
            .fetch_add(packet_count as u64, Ordering::Relaxed);
    }

    fn ensure_subscription_config_is_unique(
        &self,
        config: &SubscriptionConfig,
    ) -> Result<(), McrxError> {
        if self
            .subscriptions
            .iter()
            .any(|subscription| subscription.config() == config)
        {
            return Err(McrxError::DuplicateSubscription);
        }

        Ok(())
    }

    fn insert_subscription(
        &mut self,
        config: SubscriptionConfig,
        socket: ReceiveSocket,
    ) -> SubscriptionId {
        let id = SubscriptionId(self.next_subscription_id);
        self.next_subscription_id += 1;

        let subscription = Subscription::from_receive_socket(id, config, socket);
        self.subscriptions.push(subscription);

        #[cfg(feature = "metrics")]
        self.metrics
            .subscriptions_added
            .fetch_add(1, Ordering::Relaxed);

        id
    }

    fn finish_subscription_removal(&mut self, index: usize) -> Subscription {
        let removed = self.subscriptions.swap_remove(index);

        if self.subscriptions.is_empty() {
            self.next_recv_index = 0;
        } else {
            self.next_recv_index %= self.subscriptions.len();
        }

        #[cfg(feature = "metrics")]
        self.metrics
            .subscriptions_removed
            .fetch_add(1, Ordering::Relaxed);

        removed
    }

    /// Creates an empty context with no subscriptions.
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
            next_subscription_id: 1,
            next_recv_index: 0,
            #[cfg(feature = "metrics")]
            metrics: ContextMetricsInner::default(),
        }
    }

    /// Returns the number of active subscriptions currently stored in the context.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns a snapshot of the context's current metrics.
    ///
    /// Counter fields such as `total_packets_received` are cumulative for the
    /// lifetime of the context and are not reduced when subscriptions are
    /// removed.
    #[cfg(feature = "metrics")]
    pub fn metrics_snapshot(&self) -> ContextMetricsSnapshot {
        let mut joined_subscriptions = 0usize;

        for subscription in &self.subscriptions {
            if subscription.is_joined() {
                joined_subscriptions += 1;
            }
        }

        ContextMetricsSnapshot {
            subscriptions_added: self.metrics.subscriptions_added.load(Ordering::Relaxed),
            subscriptions_removed: self.metrics.subscriptions_removed.load(Ordering::Relaxed),
            active_subscriptions: self.subscriptions.len(),
            joined_subscriptions,
            total_packets_received: self.metrics.total_packets_received.load(Ordering::Relaxed),
            total_bytes_received: self.metrics.total_bytes_received.load(Ordering::Relaxed),
            total_would_block_count: self.metrics.total_would_block_count.load(Ordering::Relaxed),
            total_receive_errors: self.metrics.total_receive_errors.load(Ordering::Relaxed),
            total_join_count: self.metrics.total_join_count.load(Ordering::Relaxed),
            total_leave_count: self.metrics.total_leave_count.load(Ordering::Relaxed),
            batch_calls: self.metrics.batch_calls.load(Ordering::Relaxed),
            batch_packets_received: self.metrics.batch_packets_received.load(Ordering::Relaxed),
            captured_at: SystemTime::now(),
        }
    }

    /// Returns true if a subscription with the given ID exists.
    pub fn contains_subscription(&self, id: SubscriptionId) -> bool {
        self.subscriptions
            .iter()
            .any(|subscription| subscription.id() == id)
    }

    /// Returns a read-only reference to the subscription with the given ID, if it exists.
    pub fn get_subscription(&self, id: SubscriptionId) -> Option<&Subscription> {
        self.subscriptions
            .iter()
            .find(|subscription| subscription.id() == id)
    }

    /// Returns a mutable reference to the subscription with the given ID, if it exists.
    pub fn get_subscription_mut(&mut self, id: SubscriptionId) -> Option<&mut Subscription> {
        self.subscriptions
            .iter_mut()
            .find(|subscription| subscription.id() == id)
    }

    /// Adds a new subscription to the context.
    ///
    /// The configuration is validated before insertion. If an identical subscription
    /// already exists, an error is returned instead of creating a duplicate.
    ///
    /// This function creates and binds the underlying socket, but does not join the
    /// multicast group yet. Call `join_subscription()` to activate multicast reception.
    pub fn add_subscription(
        &mut self,
        config: SubscriptionConfig,
    ) -> Result<SubscriptionId, McrxError> {
        config.validate()?;
        self.ensure_subscription_config_is_unique(&config)?;

        let socket = open_bound_socket(&config)?;
        Ok(self.insert_subscription(config, socket))
    }

    /// Adds a new subscription using a caller-provided socket.
    ///
    /// The socket must already be bound to the destination port from `config`.
    /// This method preserves the existing lifecycle model: the context will still
    /// perform multicast join/leave operations later via `join_subscription()` and
    /// `leave_subscription()`.
    ///
    /// The supplied socket is switched to non-blocking mode so the receive APIs keep
    /// their usual non-blocking behavior.
    pub fn add_subscription_with_socket(
        &mut self,
        config: SubscriptionConfig,
        socket: Socket,
    ) -> Result<SubscriptionId, McrxError> {
        config.validate()?;
        self.ensure_subscription_config_is_unique(&config)?;

        let socket = prepare_existing_socket(socket, &config)?;

        Ok(self.insert_subscription(config, socket))
    }

    /// Removes the subscription with the given ID.
    ///
    /// Returns true if a subscription was removed and false if no matching
    /// subscription was found.
    ///
    /// This uses `swap_remove`, so subscription order is not preserved.
    pub fn remove_subscription(&mut self, id: SubscriptionId) -> bool {
        self.take_subscription(id).is_some()
    }

    /// Removes the subscription with the given ID and returns it to the caller.
    ///
    /// This preserves the current socket ownership and lifecycle state, which is
    /// useful when moving a subscription into an external event loop or runtime.
    ///
    /// This uses `swap_remove`, so subscription order is not preserved.
    pub fn take_subscription(&mut self, id: SubscriptionId) -> Option<Subscription> {
        let index = self
            .subscriptions
            .iter()
            .position(|subscription| subscription.id() == id)?;

        Some(self.finish_subscription_removal(index))
    }

    /// Joins the multicast group for the given subscription.
    pub fn join_subscription(&mut self, id: SubscriptionId) -> Result<(), McrxError> {
        let subscription = self
            .get_subscription_mut(id)
            .ok_or(McrxError::SubscriptionNotFound)?;

        if subscription.is_joined() {
            return Err(McrxError::SubscriptionAlreadyJoined);
        }

        join_multicast_group(subscription.socket(), subscription.config())?;
        subscription.mark_joined()?;

        #[cfg(feature = "metrics")]
        self.metrics
            .total_join_count
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn try_recv_from_joined<T>(
        &mut self,
        mut recv: impl FnMut(&Subscription) -> Result<Option<T>, McrxError>,
        _packet_len: impl Fn(&T) -> usize,
    ) -> Result<Option<T>, McrxError> {
        let subscription_count = self.subscriptions.len();

        if subscription_count == 0 {
            return Ok(None);
        }

        let mut index = self.next_recv_index;

        for _ in 0..subscription_count {
            let subscription = &self.subscriptions[index];

            if !subscription.is_joined() {
                index += 1;
                if index == subscription_count {
                    index = 0;
                }
                continue;
            }

            match recv(subscription) {
                Ok(Some(packet)) => {
                    self.next_recv_index = (index + 1) % subscription_count;

                    #[cfg(feature = "metrics")]
                    self.record_received_packet(_packet_len(&packet));

                    return Ok(Some(packet));
                }
                Ok(None) => {
                    #[cfg(feature = "metrics")]
                    self.record_would_block();
                }
                Err(err) => {
                    #[cfg(feature = "metrics")]
                    self.record_receive_error();

                    return Err(err);
                }
            }

            index += 1;
            if index == subscription_count {
                index = 0;
            }
        }

        Ok(None)
    }

    /// Leaves the multicast group for the given subscription while keeping the socket bound.
    pub fn leave_subscription(&mut self, id: SubscriptionId) -> Result<(), McrxError> {
        let subscription = self
            .get_subscription_mut(id)
            .ok_or(McrxError::SubscriptionNotFound)?;

        if !subscription.is_joined() {
            return Err(McrxError::SubscriptionNotJoined);
        }

        leave_multicast_group(subscription.socket(), subscription.config())?;
        subscription.mark_bound()?;

        #[cfg(feature = "metrics")]
        self.metrics
            .total_leave_count
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Returns a read-only slice of all subscriptions currently stored in the context.
    pub fn subscriptions(&self) -> &[Subscription] {
        &self.subscriptions
    }

    /// Returns a mutable slice of all subscriptions currently stored in the context.
    pub fn subscriptions_mut(&mut self) -> &mut [Subscription] {
        &mut self.subscriptions
    }

    /// Attempts to receive a single packet from any joined subscription without blocking.
    ///
    /// Subscriptions are scanned using round-robin style fairness so that repeated
    /// calls do not always favor the first subscription.
    ///
    /// Returns the first available packet, if any joined subscription currently has
    /// one ready to be read.
    pub fn try_recv_any(&mut self) -> Result<Option<Packet>, McrxError> {
        self.try_recv_from_joined(Subscription::try_recv, |packet| packet.payload.len())
    }

    /// Attempts to receive a single packet with richer receive metadata from any
    /// joined subscription without blocking.
    ///
    /// This uses the same round-robin fairness logic as `try_recv_any()`.
    pub fn try_recv_any_with_metadata(&mut self) -> Result<Option<PacketWithMetadata>, McrxError> {
        self.try_recv_from_joined(Subscription::try_recv_with_metadata, |packet| {
            packet.packet.payload.len()
        })
    }

    /// Attempts to receive up to `max_packets` packets from any subscriptions without blocking.
    ///
    /// This method repeatedly calls `try_recv_any()` using the same round-robin fairness logic
    /// and pushes received packets into the provided `out` vector.
    ///
    /// Returns the number of packets that were added to `out`.
    ///
    /// Behavior:
    /// - Stops early if no more packets are available
    /// - Does not block or wait for new packets
    /// - Preserves fairness across subscriptions
    pub fn try_recv_batch_into(
        &mut self,
        out: &mut Vec<Packet>,
        max_packets: usize,
    ) -> Result<usize, McrxError> {
        #[cfg(feature = "metrics")]
        self.record_batch_call();

        self.try_recv_batch_into_impl(out, max_packets)
    }

    fn try_recv_batch_into_impl(
        &mut self,
        out: &mut Vec<Packet>,
        max_packets: usize,
    ) -> Result<usize, McrxError> {
        let mut received = 0;

        for _ in 0..max_packets {
            match self.try_recv_any()? {
                Some(packet) => {
                    out.push(packet);
                    received += 1;
                }
                None => break,
            }
        }

        #[cfg(feature = "metrics")]
        self.record_batch_packets_received(received);

        Ok(received)
    }

    /// Attempts to receive up to `max_packets` packets with richer receive
    /// metadata from any subscriptions without blocking.
    pub fn try_recv_batch_with_metadata_into(
        &mut self,
        out: &mut Vec<PacketWithMetadata>,
        max_packets: usize,
    ) -> Result<usize, McrxError> {
        #[cfg(feature = "metrics")]
        self.record_batch_call();

        self.try_recv_batch_with_metadata_into_impl(out, max_packets)
    }

    fn try_recv_batch_with_metadata_into_impl(
        &mut self,
        out: &mut Vec<PacketWithMetadata>,
        max_packets: usize,
    ) -> Result<usize, McrxError> {
        let mut received = 0;

        for _ in 0..max_packets {
            match self.try_recv_any_with_metadata()? {
                Some(packet) => {
                    out.push(packet);
                    received += 1;
                }
                None => break,
            }
        }

        #[cfg(feature = "metrics")]
        self.record_batch_packets_received(received);

        Ok(received)
    }

    /// Attempts to receive all currently available packets without blocking.
    ///
    /// This is a convenience wrapper around `try_recv_batch_into` that continues
    /// draining until no more packets are available.
    ///
    /// Note: this only drains packets that are currently available without blocking.
    /// It may result in unbounded growth of `out` if a large number of packets are queued,
    /// so callers should ensure capacity if needed.
    pub fn try_recv_all_into(&mut self, out: &mut Vec<Packet>) -> Result<usize, McrxError> {
        #[cfg(feature = "metrics")]
        self.record_batch_call();

        self.try_recv_batch_into_impl(out, usize::MAX)
    }

    /// Attempts to receive all currently available packets with richer receive
    /// metadata without blocking.
    pub fn try_recv_all_with_metadata_into(
        &mut self,
        out: &mut Vec<PacketWithMetadata>,
    ) -> Result<usize, McrxError> {
        #[cfg(feature = "metrics")]
        self.record_batch_call();

        self.try_recv_batch_with_metadata_into_impl(out, usize::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SourceFilter;
    use crate::subscription::SubscriptionState;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::test_support::{
        ipv6_group_socket_addr, make_multicast_sender, make_multicast_sender_v6, recv_next_packet,
        sample_config_on_unused_port, sample_config_v6_on_unused_port,
    };

    fn make_bound_external_socket(port: u16) -> Socket {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket
            .bind(&SockAddr::from(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                port,
            )))
            .unwrap();
        socket
    }

    fn ipv4_group(config: &SubscriptionConfig) -> Ipv4Addr {
        config.ipv4_membership().unwrap().group
    }

    fn ipv4_group_socket_addr(config: &SubscriptionConfig) -> SocketAddrV4 {
        SocketAddrV4::new(ipv4_group(config), config.dst_port)
    }

    fn assert_pktinfo_metadata(
        packet: &PacketWithMetadata,
        expected_destination: std::net::IpAddr,
    ) {
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

    fn send_round_robin_test_packets(
        first_config: &SubscriptionConfig,
        second_config: &SubscriptionConfig,
    ) {
        let sender = make_multicast_sender();

        sender
            .send_to(b"first-1", ipv4_group_socket_addr(first_config))
            .unwrap();
        sender
            .send_to(b"second-1", ipv4_group_socket_addr(second_config))
            .unwrap();
        sender
            .send_to(b"first-2", ipv4_group_socket_addr(first_config))
            .unwrap();
    }

    #[test]
    fn new_context_starts_empty() {
        let context = Context::new();

        assert_eq!(context.subscription_count(), 0);
        assert!(context.subscriptions().is_empty());
    }

    #[test]
    fn add_subscription_returns_id_and_increases_count() {
        let mut context = Context::new();

        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        assert_eq!(id, SubscriptionId(1));
        assert_eq!(context.subscription_count(), 1);
        assert_eq!(context.subscriptions()[0].id(), id);
    }

    #[test]
    fn adding_two_subscriptions_generates_different_ids() {
        let mut context = Context::new();

        let first = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();
        let second = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(first, SubscriptionId(1));
        assert_eq!(second, SubscriptionId(2));
    }

    #[test]
    fn invalid_subscription_is_rejected() {
        let mut context = Context::new();

        let invalid_config = SubscriptionConfig {
            group: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            source: SourceFilter::Any,
            dst_port: 5000,
            interface: None,
            interface_index: None,
        };

        let result = context.add_subscription(invalid_config);

        assert!(matches!(result, Err(McrxError::InvalidMulticastGroup)));
        assert_eq!(context.subscription_count(), 0);
    }

    #[test]
    fn try_recv_any_returns_packet_from_ready_ipv6_subscription() {
        let mut context = Context::new();
        let config = sample_config_v6_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender_v6(std::net::Ipv6Addr::LOCALHOST);
        let payload = b"context try_recv_any ipv6 asm";
        sender
            .send_to(payload, ipv6_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);

        assert_eq!(packet.subscription_id, id);
        assert_eq!(packet.group, config.group);
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
    }

    #[test]
    fn try_recv_any_with_metadata_returns_packet_from_ready_ipv6_subscription() {
        let mut context = Context::new();
        let config = sample_config_v6_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender_v6(std::net::Ipv6Addr::LOCALHOST);

        let payload = b"context try_recv_any_with_metadata ipv6 asm";
        sender
            .send_to(payload, ipv6_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = loop {
            match context.try_recv_any_with_metadata().unwrap() {
                Some(packet) => break packet,
                None if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                None => panic!("timed out waiting for IPv6 packet with metadata from context"),
            }
        };

        assert_eq!(packet.packet.subscription_id, id);
        assert_eq!(packet.packet.group, config.group);
        assert_eq!(packet.packet.dst_port, config.dst_port);
        assert_eq!(&packet.packet.payload[..], payload);
        assert_pktinfo_metadata(&packet, config.group);
        assert_eq!(packet.metadata.configured_interface, config.interface);
        assert_eq!(
            packet.metadata.configured_interface_index,
            config.interface_index
        );
        assert_eq!(
            packet.metadata.socket_local_addr,
            Some(std::net::SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                config.dst_port,
                0,
                0,
            )))
        );
    }

    #[test]
    fn remove_existing_subscription_returns_true() {
        let mut context = Context::new();

        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        let removed = context.remove_subscription(id);

        assert!(removed);
        assert_eq!(context.subscription_count(), 0);
    }

    #[test]
    fn remove_missing_subscription_returns_false() {
        let mut context = Context::new();

        let removed = context.remove_subscription(SubscriptionId(999));

        assert!(!removed);
    }

    #[test]
    fn take_subscription_returns_owned_subscription_and_removes_it() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let subscription = context.take_subscription(id).unwrap();

        assert_eq!(subscription.id(), id);
        assert_eq!(subscription.config(), &config);
        assert_eq!(subscription.state(), SubscriptionState::Joined);
        assert_eq!(context.subscription_count(), 0);
        assert!(!context.contains_subscription(id));
    }

    #[test]
    fn taken_subscription_can_be_split_into_owned_parts() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let subscription = context.take_subscription(id).unwrap();
        let parts = subscription.into_parts();

        assert_eq!(parts.id, id);
        assert_eq!(parts.config, config);
        assert_eq!(parts.state, SubscriptionState::Joined);

        let local_addr = parts.socket.local_addr().unwrap().as_socket().unwrap();
        assert_eq!(local_addr.port(), parts.config.dst_port);
    }

    #[test]
    fn taken_joined_subscription_can_still_receive_packets() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let subscription = context.take_subscription(id).unwrap();
        let sender = make_multicast_sender();
        let payload = b"context take_subscription handoff";

        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = loop {
            match subscription.try_recv().unwrap() {
                Some(packet) => break packet,
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => panic!("timed out waiting for packet after subscription handoff"),
            }
        };

        assert_eq!(packet.subscription_id, id);
        assert_eq!(packet.group, std::net::IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
    }

    #[test]
    fn three_subscriptions_have_len_3() {
        let mut context = Context::new();

        context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();
        context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();
        context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        assert_eq!(context.subscription_count(), 3);
    }

    #[test]
    fn duplicate_subscription_is_rejected() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();

        let first = context.add_subscription(config.clone());
        let second = context.add_subscription(config);

        assert!(first.is_ok());
        assert!(matches!(second, Err(McrxError::DuplicateSubscription)));
        assert_eq!(context.subscription_count(), 1);
    }

    #[test]
    fn add_subscription_with_socket_returns_id_and_increases_count() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let socket = make_bound_external_socket(config.dst_port);

        let id = context
            .add_subscription_with_socket(config, socket)
            .unwrap();

        assert_eq!(id, SubscriptionId(1));
        assert_eq!(context.subscription_count(), 1);
        assert_eq!(context.subscriptions()[0].id(), id);
    }

    #[test]
    fn add_subscription_with_socket_rejects_port_mismatch() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let expected_port = config.dst_port;
        let socket = make_bound_external_socket(0);

        let result = context.add_subscription_with_socket(config, socket);

        assert!(matches!(
            result,
            Err(McrxError::ExistingSocketPortMismatch { expected, .. })
                if expected == expected_port
        ));
    }

    #[test]
    fn contains_subscription_returns_true_for_existing_id() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        assert!(context.contains_subscription(id));
    }

    #[test]
    fn contains_subscription_returns_false_for_missing_id() {
        let context = Context::new();

        assert!(!context.contains_subscription(SubscriptionId(999)));
    }

    #[test]
    fn get_subscription_returns_matching_subscription() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        let subscription = context.get_subscription(id);

        assert!(subscription.is_some());
        assert_eq!(subscription.unwrap().id(), id);
    }

    #[test]
    fn get_subscription_returns_none_for_missing_id() {
        let context = Context::new();

        let subscription = context.get_subscription(SubscriptionId(999));

        assert!(subscription.is_none());
    }

    #[test]
    fn get_subscription_mut_returns_matching_subscription() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        let subscription = context.get_subscription_mut(id);

        assert!(subscription.is_some());
        assert_eq!(subscription.unwrap().id(), id);
    }

    #[test]
    fn get_subscription_mut_returns_none_for_missing_id() {
        let mut context = Context::new();

        let subscription = context.get_subscription_mut(SubscriptionId(999));

        assert!(subscription.is_none());
    }

    #[test]
    fn try_recv_any_returns_none_when_no_packet_is_available() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();
        context.join_subscription(id).unwrap();

        let result = context.try_recv_any().unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn try_recv_any_returns_packet_from_ready_subscription() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();

        let payload = b"context try_recv_any";
        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);

        assert_eq!(packet.group, std::net::IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
    }

    #[test]
    fn try_recv_any_with_metadata_returns_packet_from_ready_subscription() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();

        let payload = b"context try_recv_any_with_metadata";
        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = loop {
            match context.try_recv_any_with_metadata().unwrap() {
                Some(packet) => break packet,
                None if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                None => panic!("timed out waiting for packet with metadata from context"),
            }
        };

        assert_eq!(packet.packet.subscription_id, id);
        assert_eq!(
            packet.packet.group,
            std::net::IpAddr::V4(ipv4_group(&config))
        );
        assert_eq!(packet.packet.dst_port, config.dst_port);
        assert_eq!(&packet.packet.payload[..], payload);
        assert_pktinfo_metadata(&packet, std::net::IpAddr::V4(ipv4_group(&config)));
        assert_eq!(
            packet.metadata.socket_local_addr,
            Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                config.dst_port,
            )))
        );
    }

    #[test]
    fn try_recv_any_works_with_caller_provided_socket() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let socket = make_bound_external_socket(config.dst_port);
        let id = context
            .add_subscription_with_socket(config.clone(), socket)
            .unwrap();
        context.join_subscription(id).unwrap();

        let sender = make_multicast_sender();

        let payload = b"context add_subscription_with_socket";
        sender
            .send_to(payload, ipv4_group_socket_addr(&config))
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        let packet = recv_next_packet(&mut context, deadline);

        assert_eq!(packet.subscription_id, id);
        assert_eq!(packet.group, std::net::IpAddr::V4(ipv4_group(&config)));
        assert_eq!(packet.dst_port, config.dst_port);
        assert_eq!(&packet.payload[..], payload);
    }

    #[test]
    fn try_recv_any_round_robins_between_ready_subscriptions() {
        let mut context = Context::new();
        let first_config = sample_config_on_unused_port();
        let second_config = sample_config_on_unused_port();

        let first_id = context.add_subscription(first_config.clone()).unwrap();
        context.join_subscription(first_id).unwrap();
        let second_id = context.add_subscription(second_config.clone()).unwrap();
        context.join_subscription(second_id).unwrap();

        send_round_robin_test_packets(&first_config, &second_config);

        let deadline = Instant::now() + Duration::from_secs(1);

        let first_packet = recv_next_packet(&mut context, deadline);
        let second_packet = recv_next_packet(&mut context, deadline);
        let third_packet = recv_next_packet(&mut context, deadline);

        assert_eq!(
            (first_packet.subscription_id, &first_packet.payload[..]),
            (first_id, b"first-1".as_slice())
        );

        assert_eq!(
            (second_packet.subscription_id, &second_packet.payload[..]),
            (second_id, b"second-1".as_slice())
        );

        assert_eq!(
            (third_packet.subscription_id, &third_packet.payload[..]),
            (first_id, b"first-2".as_slice())
        );
    }

    #[test]
    fn try_recv_batch_into_returns_zero_when_no_packet_is_available() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();
        context.join_subscription(id).unwrap();

        let mut packets = Vec::new();
        let received = context.try_recv_batch_into(&mut packets, 8).unwrap();

        assert_eq!(received, 0);
        assert!(packets.is_empty());
    }

    #[test]
    fn try_recv_batch_into_receives_up_to_max_packets() {
        let mut context = Context::new();
        let first_config = sample_config_on_unused_port();
        let second_config = sample_config_on_unused_port();

        let first_id = context.add_subscription(first_config.clone()).unwrap();
        context.join_subscription(first_id).unwrap();
        let second_id = context.add_subscription(second_config.clone()).unwrap();
        context.join_subscription(second_id).unwrap();

        send_round_robin_test_packets(&first_config, &second_config);

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut packets = Vec::new();

        while packets.len() < 2 && Instant::now() < deadline {
            let before = packets.len();
            let received = context.try_recv_batch_into(&mut packets, 2).unwrap();
            assert!(received <= 2);
            assert_eq!(packets.len(), before + received);

            if packets.len() < 2 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        assert!(packets.len() >= 2);

        assert_eq!(
            (packets[0].subscription_id, &packets[0].payload[..]),
            (first_id, b"first-1".as_slice())
        );

        assert_eq!(
            (packets[1].subscription_id, &packets[1].payload[..]),
            (second_id, b"second-1".as_slice())
        );
    }

    #[test]
    fn try_recv_batch_with_metadata_into_receives_up_to_max_packets() {
        let mut context = Context::new();
        let first_config = sample_config_on_unused_port();
        let second_config = sample_config_on_unused_port();

        let first_id = context.add_subscription(first_config.clone()).unwrap();
        context.join_subscription(first_id).unwrap();
        let second_id = context.add_subscription(second_config.clone()).unwrap();
        context.join_subscription(second_id).unwrap();

        send_round_robin_test_packets(&first_config, &second_config);

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut packets = Vec::new();

        while packets.len() < 2 && Instant::now() < deadline {
            let before = packets.len();
            let received = context
                .try_recv_batch_with_metadata_into(&mut packets, 2)
                .unwrap();
            assert!(received <= 2);
            assert_eq!(packets.len(), before + received);

            if packets.len() < 2 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        assert!(packets.len() >= 2);

        assert_eq!(
            (
                packets[0].packet.subscription_id,
                &packets[0].packet.payload[..]
            ),
            (first_id, b"first-1".as_slice())
        );

        assert_eq!(
            (
                packets[1].packet.subscription_id,
                &packets[1].packet.payload[..]
            ),
            (second_id, b"second-1".as_slice())
        );

        assert_eq!(
            packets[0].metadata.socket_local_addr,
            Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                first_config.dst_port,
            )))
        );
        assert_eq!(
            packets[1].metadata.socket_local_addr,
            Some(std::net::SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                second_config.dst_port,
            )))
        );
    }

    #[test]
    fn try_recv_all_into_drains_all_available_packets() {
        let mut context = Context::new();
        let first_config = sample_config_on_unused_port();
        let second_config = sample_config_on_unused_port();

        let first_id = context.add_subscription(first_config.clone()).unwrap();
        context.join_subscription(first_id).unwrap();
        let second_id = context.add_subscription(second_config.clone()).unwrap();
        context.join_subscription(second_id).unwrap();

        send_round_robin_test_packets(&first_config, &second_config);

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut packets = Vec::new();

        while packets.len() < 3 && Instant::now() < deadline {
            context.try_recv_all_into(&mut packets).unwrap();

            if packets.len() < 3 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        assert_eq!(packets.len(), 3);

        assert_eq!(
            (packets[0].subscription_id, &packets[0].payload[..]),
            (first_id, b"first-1".as_slice())
        );

        assert_eq!(
            (packets[1].subscription_id, &packets[1].payload[..]),
            (second_id, b"second-1".as_slice())
        );

        assert_eq!(
            (packets[2].subscription_id, &packets[2].payload[..]),
            (first_id, b"first-2".as_slice())
        );
    }

    #[test]
    fn try_recv_all_with_metadata_into_drains_all_available_packets() {
        let mut context = Context::new();
        let first_config = sample_config_on_unused_port();
        let second_config = sample_config_on_unused_port();

        let first_id = context.add_subscription(first_config.clone()).unwrap();
        context.join_subscription(first_id).unwrap();
        let second_id = context.add_subscription(second_config.clone()).unwrap();
        context.join_subscription(second_id).unwrap();

        send_round_robin_test_packets(&first_config, &second_config);

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut packets = Vec::new();

        while packets.len() < 3 && Instant::now() < deadline {
            context
                .try_recv_all_with_metadata_into(&mut packets)
                .unwrap();

            if packets.len() < 3 {
                thread::sleep(Duration::from_millis(10));
            }
        }

        assert_eq!(packets.len(), 3);

        assert_eq!(
            (
                packets[0].packet.subscription_id,
                &packets[0].packet.payload[..]
            ),
            (first_id, b"first-1".as_slice())
        );

        assert_eq!(
            (
                packets[1].packet.subscription_id,
                &packets[1].packet.payload[..]
            ),
            (second_id, b"second-1".as_slice())
        );

        assert_eq!(
            (
                packets[2].packet.subscription_id,
                &packets[2].packet.payload[..]
            ),
            (first_id, b"first-2".as_slice())
        );
    }

    #[test]
    fn add_subscription_creates_bound_subscription() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        let subscription = context.get_subscription(id).unwrap();
        assert_eq!(subscription.state(), SubscriptionState::Bound);
    }

    #[test]
    fn join_subscription_transitions_bound_to_joined() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        context.join_subscription(id).unwrap();

        let subscription = context.get_subscription(id).unwrap();
        assert_eq!(subscription.state(), SubscriptionState::Joined);
    }

    #[test]
    fn leave_subscription_transitions_joined_to_bound() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        context.join_subscription(id).unwrap();
        context.leave_subscription(id).unwrap();

        let subscription = context.get_subscription(id).unwrap();
        assert_eq!(subscription.state(), SubscriptionState::Bound);
    }

    #[test]
    fn join_subscription_rejects_already_joined_subscription() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        context.join_subscription(id).unwrap();
        let result = context.join_subscription(id);

        assert!(matches!(result, Err(McrxError::SubscriptionAlreadyJoined)));
    }

    #[test]
    fn leave_subscription_rejects_not_joined_subscription() {
        let mut context = Context::new();
        let id = context
            .add_subscription(sample_config_on_unused_port())
            .unwrap();

        let result = context.leave_subscription(id);

        assert!(matches!(result, Err(McrxError::SubscriptionNotJoined)));
    }
}
