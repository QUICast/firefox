use crate::{McrxError, Packet, PacketWithMetadata, Subscription};
use std::io;
#[cfg(not(unix))]
use std::time::Duration;
use thiserror::Error;

/// Errors returned by the Tokio adapter.
#[derive(Debug, Error)]
pub enum TokioReceiveError {
    /// Waiting for Tokio readiness failed.
    #[error("MCRX: tokio readiness failed: {0}")]
    Readiness(io::Error),

    /// The underlying multicast receiver returned an error.
    #[error(transparent)]
    Receive(#[from] McrxError),
}

/// Thin Tokio wrapper around an owned subscription.
///
/// On Unix this uses `tokio::io::unix::AsyncFd` to wait for read readiness.
/// On other platforms it falls back to an async sleep-and-poll loop.
///
/// The async receive methods take `&mut self` because the adapter is designed
/// for a single receiving task at a time. This also keeps the Tokio receive
/// future `Send` when the optional `metrics` feature is enabled.
#[derive(Debug)]
pub struct TokioSubscription {
    #[cfg(unix)]
    inner: tokio::io::unix::AsyncFd<Subscription>,
    #[cfg(not(unix))]
    inner: Subscription,
    #[cfg(not(unix))]
    poll_interval: Duration,
}

impl TokioSubscription {
    /// Wraps an owned subscription for use with Tokio.
    pub fn new(subscription: Subscription) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: tokio::io::unix::AsyncFd::new(subscription)?,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                inner: subscription,
                poll_interval: Duration::from_millis(10),
            })
        }
    }

    /// Returns a shared reference to the wrapped subscription.
    pub fn subscription(&self) -> &Subscription {
        #[cfg(unix)]
        {
            self.inner.get_ref()
        }

        #[cfg(not(unix))]
        {
            &self.inner
        }
    }

    /// Consumes the adapter and returns the wrapped subscription.
    pub fn into_subscription(self) -> Subscription {
        #[cfg(unix)]
        {
            self.inner.into_inner()
        }

        #[cfg(not(unix))]
        {
            self.inner
        }
    }

    /// Overrides the async poll interval used on platforms without `AsyncFd`.
    #[cfg(not(unix))]
    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    /// Waits for the next packet and returns it.
    pub async fn recv(&mut self) -> Result<Packet, TokioReceiveError> {
        #[cfg(unix)]
        {
            loop {
                let mut readiness = self
                    .inner
                    .readable_mut()
                    .await
                    .map_err(TokioReceiveError::Readiness)?;

                match readiness.get_inner_mut().try_recv()? {
                    Some(packet) => return Ok(packet),
                    None => readiness.clear_ready(),
                }
            }
        }

        #[cfg(not(unix))]
        {
            loop {
                match self.inner.try_recv()? {
                    Some(packet) => return Ok(packet),
                    None => tokio::time::sleep(self.poll_interval).await,
                }
            }
        }
    }

    /// Waits for the next packet with richer receive metadata and returns it.
    pub async fn recv_with_metadata(&mut self) -> Result<PacketWithMetadata, TokioReceiveError> {
        #[cfg(unix)]
        {
            loop {
                let mut readiness = self
                    .inner
                    .readable_mut()
                    .await
                    .map_err(TokioReceiveError::Readiness)?;

                match readiness.get_inner_mut().try_recv_with_metadata()? {
                    Some(packet) => return Ok(packet),
                    None => readiness.clear_ready(),
                }
            }
        }

        #[cfg(not(unix))]
        {
            loop {
                match self.inner.try_recv_with_metadata()? {
                    Some(packet) => return Ok(packet),
                    None => tokio::time::sleep(self.poll_interval).await,
                }
            }
        }
    }
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;
    use crate::test_support::sample_config_on_unused_port;
    use crate::{Context, SubscriptionConfig};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::time::{Duration, timeout};

    fn ipv4_group(config: &SubscriptionConfig) -> Ipv4Addr {
        config.ipv4_membership().unwrap().group
    }

    fn make_multicast_sender() -> std::net::UdpSocket {
        std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).unwrap()
    }

    #[tokio::test]
    async fn tokio_subscription_receives_metadata_packet() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let subscription = context.take_subscription(id).unwrap();
        let mut subscription = TokioSubscription::new(subscription).unwrap();

        let sender = make_multicast_sender();
        let payload = b"tokio adapter packet";
        sender
            .send_to(
                payload,
                SocketAddrV4::new(ipv4_group(&config), config.dst_port),
            )
            .unwrap();

        let packet = timeout(Duration::from_secs(1), subscription.recv_with_metadata())
            .await
            .expect("timed out waiting for tokio packet")
            .unwrap();

        assert_eq!(packet.packet.subscription_id, id);
        assert_eq!(&packet.packet.payload[..], payload);
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn tokio_subscription_with_metrics_is_spawn_safe() {
        let mut context = Context::new();
        let config = sample_config_on_unused_port();
        let id = context.add_subscription(config.clone()).unwrap();
        context.join_subscription(id).unwrap();

        let subscription = context.take_subscription(id).unwrap();
        let sender = make_multicast_sender();
        let payload = b"tokio metrics packet";

        let handle = tokio::spawn(async move {
            let mut subscription = TokioSubscription::new(subscription).unwrap();
            let packet = timeout(Duration::from_secs(1), subscription.recv_with_metadata())
                .await
                .expect("timed out waiting for spawned tokio packet")
                .unwrap();
            let metrics = subscription.subscription().metrics_snapshot();
            (packet, metrics)
        });

        sender
            .send_to(
                payload,
                SocketAddrV4::new(ipv4_group(&config), config.dst_port),
            )
            .unwrap();

        let (packet, metrics) = handle.await.unwrap();

        assert_eq!(packet.packet.subscription_id, id);
        assert_eq!(&packet.packet.payload[..], payload);
        assert_eq!(metrics.packets_received, 1);
        assert_eq!(metrics.bytes_received, payload.len() as u64);
        assert_eq!(metrics.last_payload_len, Some(payload.len()));
    }
}
