pub mod config;
pub mod context;
pub mod error;
#[cfg(feature = "metrics")]
pub mod jsonl;
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod packet;
mod platform;
#[cfg(feature = "raw-packets")]
pub mod raw;
pub mod subscription;
#[cfg(test)]
mod test_support;
#[cfg(feature = "tokio")]
pub mod tokio_adapter;

pub use config::{SourceFilter, SubscriptionAddressFamily, SubscriptionConfig};
pub use context::Context;
pub use error::McrxError;
pub use packet::{Packet, PacketWithMetadata, ReceiveMetadata};
#[cfg(feature = "raw-packets")]
pub use raw::{RawContext, RawPacket, RawSubscription, RawSubscriptionConfig};
pub use subscription::{Subscription, SubscriptionId, SubscriptionParts, SubscriptionState};
#[cfg(feature = "tokio")]
pub use tokio_adapter::{TokioReceiveError, TokioSubscription};

#[cfg(feature = "metrics")]
pub use metrics::{
    ContextMetricsDelta, ContextMetricsSampler, ContextMetricsSnapshot, HardwareMetricsDelta,
    HardwareMetricsSampler, HardwareMetricsSnapshot, SubscriptionMetricsDelta,
    SubscriptionMetricsSampler, SubscriptionMetricsSnapshot,
};
