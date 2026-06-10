use crate::subscription::SubscriptionId;
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};

/// A received packet together with the metadata needed by the receiver core.
#[derive(Debug, Clone)]
pub struct Packet {
    /// The subscription through which this packet was received.
    pub subscription_id: SubscriptionId,
    /// The remote sender's source address and source port.
    pub source: SocketAddr,
    /// The destination multicast group address.
    pub group: IpAddr,
    /// The destination UDP port on which the packet was received.
    pub dst_port: u16,
    /// The raw UDP payload bytes.
    pub payload: Bytes,
}

/// Structured receive metadata that can grow as the platform layer learns more
/// about the packet delivery context.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceiveMetadata {
    /// The local socket address currently bound by the receiving socket, if known.
    pub socket_local_addr: Option<SocketAddr>,
    /// The local interface requested by the subscription configuration, if any.
    ///
    /// This reflects configured intent, not pktinfo-derived ingress state.
    pub configured_interface: Option<IpAddr>,
    /// The local IPv6 interface index requested by the subscription configuration, if any.
    pub configured_interface_index: Option<u32>,
    /// The local destination IP address from pktinfo-style metadata, if available.
    pub destination_local_ip: Option<IpAddr>,
    /// The ingress interface index from pktinfo-style metadata, if available.
    pub ingress_interface_index: Option<u32>,
}

impl ReceiveMetadata {
    #[cfg_attr(not(feature = "raw-packets"), allow(dead_code))]
    pub(crate) fn empty() -> Self {
        Self {
            socket_local_addr: None,
            configured_interface: None,
            configured_interface_index: None,
            destination_local_ip: None,
            ingress_interface_index: None,
        }
    }
}

/// A received packet together with richer receive metadata.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PacketWithMetadata {
    /// The packet payload and core addressing information.
    pub packet: Packet,
    /// Additional receive context supplied by the platform layer.
    pub metadata: ReceiveMetadata,
}

impl Packet {
    /// Returns the length of the payload in bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl PacketWithMetadata {
    /// Returns a read-only reference to the inner packet.
    pub fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Returns a read-only reference to the receive metadata.
    pub fn metadata(&self) -> &ReceiveMetadata {
        &self.metadata
    }

    /// Discards the richer metadata and returns the inner packet.
    pub fn into_packet(self) -> Packet {
        self.packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    #[test]
    fn packet_payload_len_returns_correct_length() {
        let packet = Packet {
            subscription_id: SubscriptionId(1),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            dst_port: 5000,
            payload: Bytes::from_static(&[1, 2, 3]),
        };

        assert_eq!(packet.payload_len(), 3);
    }

    #[test]
    fn subscription_id_equality_works() {
        let a = SubscriptionId(7);
        let b = SubscriptionId(7);
        let c = SubscriptionId(8);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn packet_with_metadata_into_packet_discards_metadata() {
        let packet = Packet {
            subscription_id: SubscriptionId(1),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            group: IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            dst_port: 5000,
            payload: Bytes::from_static(&[1, 2, 3]),
        };

        let detailed = PacketWithMetadata {
            packet: packet.clone(),
            metadata: ReceiveMetadata {
                socket_local_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
                    5000,
                ))),
                configured_interface: None,
                configured_interface_index: None,
                destination_local_ip: None,
                ingress_interface_index: None,
            },
        };

        let stripped = detailed.into_packet();

        assert_eq!(stripped.subscription_id, packet.subscription_id);
        assert_eq!(stripped.source, packet.source);
        assert_eq!(stripped.group, packet.group);
        assert_eq!(stripped.dst_port, packet.dst_port);
        assert_eq!(stripped.payload, packet.payload);
    }
}
