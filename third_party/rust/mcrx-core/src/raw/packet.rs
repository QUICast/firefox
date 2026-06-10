use crate::packet::ReceiveMetadata;
use crate::subscription::SubscriptionId;
use bytes::Bytes;
use std::net::IpAddr;

/// A received raw multicast IP datagram.
#[derive(Debug, Clone)]
pub struct RawPacket {
    /// The subscription through which this datagram was received.
    pub subscription_id: SubscriptionId,
    /// The complete received IP datagram bytes, including the IP header.
    pub datagram: Bytes,
    /// The parsed source IP address, if it was cheaply available.
    pub source_ip: Option<IpAddr>,
    /// The parsed destination/group IP address, if it was cheaply available.
    pub group: Option<IpAddr>,
    /// The parsed IP protocol / next-header value, if it was cheaply available.
    pub ip_protocol: Option<u8>,
    /// Additional receive context supplied by the platform layer.
    pub metadata: ReceiveMetadata,
}

impl RawPacket {
    /// Returns the length of the complete datagram in bytes.
    pub fn datagram_len(&self) -> usize {
        self.datagram.len()
    }

    /// Returns the received datagram bytes.
    pub fn datagram(&self) -> &[u8] {
        &self.datagram
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_packet_datagram_len_returns_correct_length() {
        let packet = RawPacket {
            subscription_id: SubscriptionId(1),
            datagram: Bytes::from_static(&[0x45, 0, 0, 1]),
            source_ip: None,
            group: None,
            ip_protocol: Some(17),
            metadata: ReceiveMetadata::empty(),
        };

        assert_eq!(packet.datagram_len(), 4);
    }
}
