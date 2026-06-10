use crate::error::McrxError;
use crate::platform::open_raw_socket;
use crate::raw::{RawPacket, RawSubscription, RawSubscriptionConfig};
use crate::subscription::SubscriptionId;

/// Owns and manages the set of active raw multicast subscriptions.
#[derive(Debug, Default)]
pub struct RawContext {
    subscriptions: Vec<RawSubscription>,
    next_subscription_id: u64,
    next_recv_index: usize,
}

impl RawContext {
    /// Creates an empty raw context with no subscriptions.
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
            next_subscription_id: 1,
            next_recv_index: 0,
        }
    }

    /// Returns the number of active raw subscriptions currently stored in the context.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Returns true if a raw subscription with the given ID exists.
    pub fn contains_subscription(&self, id: SubscriptionId) -> bool {
        self.subscriptions
            .iter()
            .any(|subscription| subscription.id() == id)
    }

    /// Returns a read-only reference to the raw subscription with the given ID, if it exists.
    pub fn get_subscription(&self, id: SubscriptionId) -> Option<&RawSubscription> {
        self.subscriptions
            .iter()
            .find(|subscription| subscription.id() == id)
    }

    /// Returns a mutable reference to the raw subscription with the given ID, if it exists.
    pub fn get_subscription_mut(&mut self, id: SubscriptionId) -> Option<&mut RawSubscription> {
        self.subscriptions
            .iter_mut()
            .find(|subscription| subscription.id() == id)
    }

    fn ensure_subscription_config_is_unique(
        &self,
        config: &RawSubscriptionConfig,
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

    /// Adds a new raw multicast subscription to the context.
    pub fn add_subscription(
        &mut self,
        config: RawSubscriptionConfig,
    ) -> Result<SubscriptionId, McrxError> {
        config.validate()?;
        self.ensure_subscription_config_is_unique(&config)?;

        let socket = open_raw_socket(&config)?;
        let id = SubscriptionId(self.next_subscription_id);
        self.next_subscription_id += 1;

        self.subscriptions
            .push(RawSubscription::new(id, config, socket));
        Ok(id)
    }

    /// Removes the raw subscription with the given ID.
    pub fn remove_subscription(&mut self, id: SubscriptionId) -> bool {
        let Some(index) = self
            .subscriptions
            .iter()
            .position(|subscription| subscription.id() == id)
        else {
            return false;
        };

        self.subscriptions.swap_remove(index);
        if self.subscriptions.is_empty() {
            self.next_recv_index = 0;
        } else {
            self.next_recv_index %= self.subscriptions.len();
        }
        true
    }

    /// Joins the multicast group for the given raw subscription.
    pub fn join_subscription(&mut self, id: SubscriptionId) -> Result<(), McrxError> {
        self.get_subscription_mut(id)
            .ok_or(McrxError::SubscriptionNotFound)?
            .join()
    }

    /// Leaves the multicast group for the given raw subscription while keeping the socket open.
    pub fn leave_subscription(&mut self, id: SubscriptionId) -> Result<(), McrxError> {
        self.get_subscription_mut(id)
            .ok_or(McrxError::SubscriptionNotFound)?
            .leave()
    }

    /// Attempts to receive a single complete multicast IP datagram from any joined
    /// raw subscription without blocking.
    pub fn try_recv_any(&mut self) -> Result<Option<RawPacket>, McrxError> {
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

            if let Some(packet) = subscription.try_recv()? {
                self.next_recv_index = (index + 1) % subscription_count;
                return Ok(Some(packet));
            }

            index += 1;
            if index == subscription_count {
                index = 0;
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn add_invalid_raw_subscription_is_rejected_before_socket_setup() {
        let mut ctx = RawContext::new();
        let config = RawSubscriptionConfig::ssm_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );

        let err = ctx.add_subscription(config).unwrap_err();
        assert!(matches!(err, McrxError::InvalidMulticastGroup));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn raw_subscriptions_return_unsupported_when_platform_requirements_are_not_met() {
        let mut ctx = RawContext::new();
        let config = RawSubscriptionConfig::asm_v6("ff3e::8000:1234".parse::<Ipv6Addr>().unwrap());

        let err = ctx.add_subscription(config).unwrap_err();
        assert!(matches!(err, McrxError::RawPacketReceiveUnsupported(_)));
    }
}
