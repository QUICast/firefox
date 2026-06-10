// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Experimental QUICast/MCQUIC multicast QUIC support.
//!
//! This module implements draft-jholland-quic-multicast-08 style wire formats
//! for transport parameters and multicast control frames. It is transport-only:
//! Neqo does not join multicast sockets, expose this to web content, or
//! interpret multicast DATAGRAM payloads as media objects.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use neqo_common::{Buffer, Decoder, Encoder};
use nss::{
    Cipher, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    TLS_VERSION_1_3,
    hash::{self, HashAlgorithm},
    hkdf,
};

use crate::{
    ConnectionId, Error, Res,
    crypto::{CryptoDxDirection, CryptoDxState, Epoch},
    frame::{Frame as QuicFrame, FrameType},
    stream_id::StreamId,
    version::Version,
};

const IP_FLAG_V4_ALLOWED: u8 = 0x01;
const IP_FLAG_V6_ALLOWED: u8 = 0x02;
const MAX_ACK_RANGE_COUNT: u64 = 32 * 1024;
const MCQUIC_VERSION: Version = Version::Version1;
const SHORT_HEADER_FIXED_BIT: u8 = 0x40;
const SHORT_HEADER_FORM_BIT: u8 = 0x80;
const SHORT_HEADER_KEY_PHASE_BIT: u8 = 0x04;
const SHORT_HEADER_HP_MASK: u8 = 0x1f;
const PACKET_NUMBER_LEN: usize = 4;
const HP_SAMPLE_SIZE: usize = 16;
const HP_SAMPLE_OFFSET: usize = 4;

/// Experimental transport parameter ID for client multicast capabilities.
pub const CLIENT_PARAMS_TRANSPORT_PARAMETER_ID: u64 = 0xff3e800;
/// Experimental transport parameter ID for server multicast support.
pub const SERVER_SUPPORT_TRANSPORT_PARAMETER_ID: u64 = 0xff3e808;

/// Experimental frame type for `MC_KEY`.
pub const FRAME_TYPE_KEY: u64 = 0xff3e801;
/// Experimental frame type for `MC_JOIN`.
pub const FRAME_TYPE_JOIN: u64 = 0xff3e802;
/// Experimental frame type for `MC_LEAVE`.
pub const FRAME_TYPE_LEAVE: u64 = 0xff3e803;
/// Experimental frame type for `MC_INTEGRITY`.
pub const FRAME_TYPE_INTEGRITY: u64 = 0xff3e804;
/// Experimental frame type for `MC_INTEGRITY_WITH_LENGTH`.
pub const FRAME_TYPE_INTEGRITY_WITH_LENGTH: u64 = 0xff3e805;
/// Experimental frame type for `MC_ACK`.
pub const FRAME_TYPE_ACK: u64 = 0xff3e806;
/// Experimental frame type for `MC_ACK_ECN`.
pub const FRAME_TYPE_ACK_ECN: u64 = 0xff3e807;
/// Experimental frame type for `MC_LIMITS`.
pub const FRAME_TYPE_LIMITS: u64 = 0xff3e809;
/// Experimental frame type for `MC_RETIRE`.
pub const FRAME_TYPE_RETIRE: u64 = 0xff3e80a;
/// Experimental frame type for transport-scoped `MC_STATE`.
pub const FRAME_TYPE_STATE: u64 = 0xff3e80b;
/// Experimental frame type for application-scoped `MC_STATE`.
pub const FRAME_TYPE_STATE_APPLICATION: u64 = 0xff3e80c;
/// Experimental frame type for IPv4 `MC_ANNOUNCE`.
pub const FRAME_TYPE_ANNOUNCE_V4: u64 = 0xff3e811;
/// Experimental frame type for IPv6 `MC_ANNOUNCE`.
pub const FRAME_TYPE_ANNOUNCE_V6: u64 = 0xff3e812;

/// Transport-scoped `MC_STATE` reason used for server-requested transitions.
pub const STATE_REASON_REQUESTED_BY_SERVER: u64 = 0x1;

/// Client multicast limits shared by the client transport parameter and
/// `MC_LIMITS`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientLimits {
    /// Whether the client is willing to join IPv4 multicast channels.
    pub ipv4_channels_allowed: bool,
    /// Whether the client is willing to join IPv6 multicast channels.
    pub ipv6_channels_allowed: bool,
    /// Maximum aggregate channel receive rate, in KiB/s.
    pub max_aggregate_rate_kibps: u64,
    /// Maximum number of channel IDs the client is willing to track.
    pub max_channel_ids: u64,
}

impl ClientLimits {
    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.ipv4_channels_allowed {
            flags |= IP_FLAG_V4_ALLOWED;
        }
        if self.ipv6_channels_allowed {
            flags |= IP_FLAG_V6_ALLOWED;
        }
        flags
    }

    fn encode<B: Buffer>(&self, enc: &mut Encoder<B>) {
        enc.encode_byte(self.flags())
            .encode_varint(self.max_aggregate_rate_kibps)
            .encode_varint(self.max_channel_ids);
    }

    fn decode(dec: &mut Decoder) -> Res<Self> {
        let flags = dec.decode_uint::<u8>().ok_or(Error::NoMoreData)?;
        Ok(Self {
            ipv4_channels_allowed: flags & IP_FLAG_V4_ALLOWED != 0,
            ipv6_channels_allowed: flags & IP_FLAG_V6_ALLOWED != 0,
            max_aggregate_rate_kibps: decode_varint(dec)?,
            max_channel_ids: decode_varint(dec)?,
        })
    }
}

/// Client multicast transport parameter payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientTransportParams {
    /// The client's initial multicast limits.
    pub limits: ClientLimits,
    /// Supported packet hash algorithms, in preference order.
    pub hash_algorithms: Vec<u16>,
    /// Supported packet protection algorithms, in preference order.
    pub encryption_algorithms: Vec<u16>,
}

impl ClientTransportParams {
    /// Encode this transport parameter value.
    pub fn encode<B: Buffer>(&self, enc: &mut Encoder<B>) {
        self.limits.encode(enc);
        enc.encode_varint(usize_to_u64(self.hash_algorithms.len()))
            .encode_varint(usize_to_u64(self.encryption_algorithms.len()));
        encode_u16_list(enc, &self.hash_algorithms);
        encode_u16_list(enc, &self.encryption_algorithms);
    }

    /// Decode a client multicast transport parameter value.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is malformed.
    pub fn decode(dec: &mut Decoder) -> Res<Self> {
        let limits = ClientLimits::decode(dec)?;
        let hash_algorithm_count = decode_varint(dec)?;
        let encryption_algorithm_count = decode_varint(dec)?;
        let hash_algorithms = decode_u16_list(dec, hash_algorithm_count, true)?;
        let encryption_algorithms = decode_u16_list(dec, encryption_algorithm_count, true)?;

        if dec.remaining() > 0 {
            return Err(Error::TooMuchData);
        }

        Ok(Self {
            limits,
            hash_algorithms,
            encryption_algorithms,
        })
    }

    /// Encode this transport parameter value into a fresh vector.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut enc = Encoder::default();
        self.encode(&mut enc);
        enc.as_ref().to_vec()
    }

    /// Decode a client multicast transport parameter value from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is malformed.
    pub fn from_slice(buf: &[u8]) -> Res<Self> {
        Self::decode(&mut Decoder::new(buf))
    }
}

/// A full `MC_ANNOUNCE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announce {
    /// The channel ID being announced.
    pub channel_id: Vec<u8>,
    /// The multicast source address.
    pub source: IpAddr,
    /// The multicast group address.
    pub group: IpAddr,
    /// The UDP port used for the channel.
    pub udp_port: u16,
    /// Header protection algorithm from the TLS cipher suite registry.
    pub header_protection_algorithm: u16,
    /// Header protection secret.
    pub header_secret: Vec<u8>,
    /// AEAD algorithm from the TLS cipher suite registry.
    pub aead_algorithm: u16,
    /// Packet integrity hash algorithm identifier.
    pub integrity_hash_algorithm: u16,
    /// Maximum multicast payload rate, in KiB/s.
    pub max_rate_kibps: u64,
    /// Maximum delay before sending `MC_ACK`, in milliseconds.
    pub max_ack_delay_ms: u64,
}

/// A full `MC_KEY` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// The channel ID being updated.
    pub channel_id: Vec<u8>,
    /// The key sequence number.
    pub key_sequence: u64,
    /// First packet number to which the secret applies.
    pub from_packet_number: u64,
    /// Packet protection secret.
    pub secret: Vec<u8>,
}

/// A full `MC_JOIN` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Join {
    /// The channel ID to join.
    pub channel_id: Vec<u8>,
    /// Latest `MC_LIMITS` sequence processed by the server.
    pub mc_limits_sequence: u64,
    /// Latest `MC_STATE` sequence processed by the server.
    pub mc_state_sequence: u64,
    /// Latest `MC_KEY` sequence processed by the server.
    pub mc_key_sequence: u64,
}

/// A full `MC_LEAVE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leave {
    /// The channel ID to leave.
    pub channel_id: Vec<u8>,
    /// Latest `MC_STATE` sequence processed by the server.
    pub mc_state_sequence: u64,
    /// Packet number after which the client should leave.
    pub after_packet_number: u64,
}

/// A full `MC_INTEGRITY` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Integrity {
    /// The channel ID covered by the hashes.
    pub channel_id: Vec<u8>,
    /// First packet number described by `packet_hashes`.
    pub packet_number_start: u64,
    /// Explicit packet hash count for `MC_INTEGRITY_WITH_LENGTH`.
    pub packet_hash_count: Option<u64>,
    /// Concatenated packet hashes.
    pub packet_hashes: Vec<u8>,
}

/// A non-initial ACK block from `MC_ACK`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// Gap from the previous ACK block.
    pub gap: u64,
    /// Encoded length of this ACK block.
    pub ack_range_length: u64,
}

/// ECN counters carried by `MC_ACK_ECN`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckEcnCounts {
    /// Count of ECT(0) packets.
    pub ect0_count: u64,
    /// Count of ECT(1) packets.
    pub ect1_count: u64,
    /// Count of CE-marked packets.
    pub ecn_ce_count: u64,
}

/// A full `MC_ACK` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    /// The acknowledged channel ID.
    pub channel_id: Vec<u8>,
    /// Largest acknowledged multicast packet number.
    pub largest_acknowledged: u64,
    /// Encoded ACK delay.
    pub ack_delay: u64,
    /// Length of the first ACK range.
    pub first_ack_range: u64,
    /// Additional ACK ranges.
    pub ack_ranges: Vec<AckRange>,
    /// Optional ECN counters.
    pub ecn_counts: Option<AckEcnCounts>,
}

/// A full `MC_LIMITS` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Client limits sequence number.
    pub sequence: u64,
    /// Current client limits.
    pub limits: ClientLimits,
    /// Maximum number of concurrently joined channels.
    pub max_joined_count: u64,
}

/// A full `MC_RETIRE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retire {
    /// The retired channel ID.
    pub channel_id: Vec<u8>,
    /// Packet number after which retirement should happen.
    pub after_packet_number: u64,
}

/// State values carried by `MC_STATE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// `LEFT`
    Left = 0x1,
    /// `DECLINED_JOIN`
    DeclinedJoin = 0x2,
    /// `JOINED`
    Joined = 0x3,
    /// `RETIRED`
    Retired = 0x4,
}

impl ChannelState {
    fn decode(v: u8) -> Res<Self> {
        match v {
            0x1 => Ok(Self::Left),
            0x2 => Ok(Self::DeclinedJoin),
            0x3 => Ok(Self::Joined),
            0x4 => Ok(Self::Retired),
            _ => Err(Error::FrameEncoding),
        }
    }
}

impl From<ChannelState> for u8 {
    fn from(value: ChannelState) -> Self {
        match value {
            ChannelState::Left => 0x1,
            ChannelState::DeclinedJoin => 0x2,
            ChannelState::Joined => 0x3,
            ChannelState::Retired => 0x4,
        }
    }
}

/// Whether an `MC_STATE` reason is transport-defined or application-defined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateReasonScope {
    /// Transport-defined reason.
    Transport,
    /// Application-defined reason.
    Application,
}

/// A full `MC_STATE` frame payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The channel ID whose state changed.
    pub channel_id: Vec<u8>,
    /// Client channel state sequence number.
    pub sequence: u64,
    /// The new channel state.
    pub state: ChannelState,
    /// Reason-code namespace.
    pub reason_scope: StateReasonScope,
    /// Reason code.
    pub reason_code: u64,
    /// Free-form reason phrase bytes.
    pub reason_phrase: Vec<u8>,
}

/// A decoded multicast DATAGRAM payload delivered by a channel packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelDatagram {
    /// The channel ID that delivered the DATAGRAM.
    pub channel_id: Vec<u8>,
    /// The multicast packet number that carried the DATAGRAM.
    pub packet_number: u64,
    /// The DATAGRAM payload bytes.
    pub data: Vec<u8>,
}

/// A multicast channel frame carried in a multicast 1-RTT packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelFrame {
    /// `PADDING`
    Padding {
        /// Number of padding bytes.
        len: usize,
    },
    /// `PING`
    Ping,
    /// `RESET_STREAM`
    ResetStream {
        /// Stream ID.
        stream_id: u64,
        /// Application error code.
        error_code: u64,
        /// Final stream size.
        final_size: u64,
    },
    /// `STREAM`
    Stream {
        /// Stream ID.
        stream_id: u64,
        /// Stream offset.
        offset: u64,
        /// FIN bit.
        fin: bool,
        /// Stream data.
        data: Vec<u8>,
    },
    /// `DATAGRAM`
    Datagram {
        /// DATAGRAM payload.
        data: Vec<u8>,
    },
    /// A permitted multicast control frame carried by the channel packet.
    Multicast(Frame),
}

/// A decoded multicast 1-RTT packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelPacket {
    /// Channel ID from the packet DCID field.
    pub channel_id: Vec<u8>,
    /// Decoded channel packet number.
    pub packet_number: u64,
    /// Key sequence used to decrypt the payload.
    pub key_sequence: u64,
    /// Short-header key phase bit.
    pub key_phase: bool,
    /// Decoded and validated channel frames.
    pub frames: Vec<ChannelFrame>,
}

/// The result of encoding one encrypted multicast channel packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSendOutput {
    /// The packet number used in the encoded channel packet.
    pub packet_number: u64,
    /// The key sequence used to encrypt the packet.
    pub key_sequence: u64,
    /// The short-header key phase bit encoded into the packet.
    pub key_phase: bool,
    /// The number of bytes written into the caller's output buffer.
    pub packet_len: usize,
    /// The matching `MC_INTEGRITY` payload for the encoded packet.
    pub integrity: Integrity,
}

/// Send-side state for encrypted multicast channel packets.
#[derive(Clone, Debug)]
pub struct ChannelSendState {
    announce: Announce,
    key: Key,
    integrity_hash: IntegrityHashAlgorithm,
    next_packet_number: u64,
}

impl ChannelSendState {
    /// Create send state for an announced channel and active `MC_KEY`.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel ID or algorithms are invalid.
    pub fn new(announce: Announce, key: Key) -> Res<Self> {
        validate_channel_id(&announce.channel_id)?;
        validate_encryption_algorithm(announce.header_protection_algorithm)?;
        validate_encryption_algorithm(announce.aead_algorithm)?;
        if announce.header_protection_algorithm != announce.aead_algorithm {
            return Err(Error::NotAvailable);
        }
        if key.channel_id != announce.channel_id {
            return Err(Error::FrameEncoding);
        }
        let integrity_hash = IntegrityHashAlgorithm::from_id(announce.integrity_hash_algorithm)?;
        let next_packet_number = key.from_packet_number;

        Ok(Self {
            announce,
            key,
            integrity_hash,
            next_packet_number,
        })
    }

    /// Return the announced channel properties used by this sender.
    #[must_use]
    pub const fn announce(&self) -> &Announce {
        &self.announce
    }

    /// Return the active payload-protection key.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.key
    }

    /// Return the next packet number that will be assigned.
    #[must_use]
    pub const fn next_packet_number(&self) -> u64 {
        self.next_packet_number
    }

    /// Update the active payload-protection key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is for another channel or rewinds the packet
    /// number space.
    pub fn update_key(&mut self, key: Key) -> Res<()> {
        if key.channel_id != self.announce.channel_id {
            return Err(Error::FrameEncoding);
        }
        if key.key_sequence < self.key.key_sequence
            || key.from_packet_number < self.key.from_packet_number
        {
            return Err(Error::FrameEncoding);
        }
        if self.next_packet_number < key.from_packet_number {
            self.next_packet_number = key.from_packet_number;
        }
        self.key = key;
        Ok(())
    }

    /// Encode one encrypted multicast packet into `out`.
    ///
    /// # Errors
    ///
    /// Returns an error if the output buffer is too small, the frames are not
    /// valid channel frames, or packet protection fails.
    pub fn write_packet(
        &mut self,
        frames: &[ChannelFrame],
        out: &mut [u8],
    ) -> Res<ChannelSendOutput> {
        let packet_number = self.next_packet_number;
        let key_phase = self.key.key_sequence % 2 == 1;
        let packet = encode_protected_channel_packet(
            &self.announce,
            &self.key,
            packet_number,
            key_phase,
            frames,
        )?;
        if packet.len() > out.len() {
            return Err(Error::NoMoreData);
        }

        let packet_len = packet.len();
        out[..packet_len].copy_from_slice(&packet);
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(Error::IntegerOverflow)?;

        Ok(ChannelSendOutput {
            packet_number,
            key_sequence: self.key.key_sequence,
            key_phase,
            packet_len,
            integrity: Integrity {
                channel_id: self.announce.channel_id.clone(),
                packet_number_start: packet_number,
                packet_hash_count: Some(1),
                packet_hashes: self.integrity_hash.hash(&packet)?,
            },
        })
    }
}

/// Receive-side state for one multicast channel.
///
/// This is intentionally socket-free. The caller owns multicast socket joins
/// and supplies channel packet material to Neqo.
#[derive(Clone, Debug)]
pub struct ChannelReceiveState {
    announce: Announce,
    keys: BTreeMap<u64, Key>,
    integrity_hash: IntegrityHashAlgorithm,
    integrity_hashes: BTreeMap<u64, Vec<u8>>,
    pending_packets: BTreeMap<u64, PendingChannelPacket>,
    accepted_packets: BTreeSet<u64>,
    largest_observed_packet_number: u64,
    ack_tracker: AckTracker,
    datagrams: VecDeque<ChannelDatagram>,
}

impl ChannelReceiveState {
    /// Create receive state for an announced channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the channel ID is malformed or algorithms are not
    /// supported by this experimental implementation.
    pub fn new(announce: Announce) -> Res<Self> {
        validate_channel_id(&announce.channel_id)?;
        validate_encryption_algorithm(announce.header_protection_algorithm)?;
        validate_encryption_algorithm(announce.aead_algorithm)?;
        let integrity_hash = IntegrityHashAlgorithm::from_id(announce.integrity_hash_algorithm)?;

        Ok(Self {
            announce,
            keys: BTreeMap::new(),
            integrity_hash,
            integrity_hashes: BTreeMap::new(),
            pending_packets: BTreeMap::new(),
            accepted_packets: BTreeSet::new(),
            largest_observed_packet_number: 0,
            ack_tracker: AckTracker::default(),
            datagrams: VecDeque::new(),
        })
    }

    /// Return the channel ID for this receive state.
    #[must_use]
    pub fn channel_id(&self) -> &[u8] {
        &self.announce.channel_id
    }

    /// Insert an `MC_KEY` for this channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is for another channel.
    pub fn insert_key(&mut self, key: Key) -> Res<Vec<ChannelDatagram>> {
        self.check_channel_id(&key.channel_id)?;
        if let Some(existing) = self.keys.get(&key.key_sequence)
            && (existing.from_packet_number != key.from_packet_number
                || existing.secret != key.secret)
        {
            return Err(Error::FrameEncoding);
        }
        self.keys.insert(key.key_sequence, key);
        self.release_ready_packets()
    }

    /// Insert an `MC_INTEGRITY` frame for this channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is for another channel or its hash payload
    /// does not align with the announced hash algorithm.
    pub fn insert_integrity(&mut self, integrity: Integrity) -> Res<Vec<ChannelDatagram>> {
        self.check_channel_id(&integrity.channel_id)?;
        let hash_len = self.integrity_hash.output_len();
        let hash_count = if let Some(hash_count) = integrity.packet_hash_count {
            let expected_len = hash_count
                .checked_mul(u64::try_from(hash_len)?)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(Error::FrameEncoding)?;
            if integrity.packet_hashes.len() != expected_len {
                return Err(Error::FrameEncoding);
            }
            hash_count
        } else {
            if !integrity.packet_hashes.len().is_multiple_of(hash_len) {
                return Err(Error::FrameEncoding);
            }
            u64::try_from(integrity.packet_hashes.len() / hash_len)?
        };

        for offset in 0..hash_count {
            let start = usize::try_from(offset)? * hash_len;
            let end = start + hash_len;
            let packet_number = integrity
                .packet_number_start
                .checked_add(offset)
                .ok_or(Error::IntegerOverflow)?;
            self.integrity_hashes
                .insert(packet_number, integrity.packet_hashes[start..end].to_vec());
        }
        self.release_ready_packets()
    }

    /// Process one protected multicast UDP payload for this channel.
    ///
    /// If the matching `MC_KEY` and `MC_INTEGRITY` are available, this
    /// validates, decrypts, decodes, and releases DATAGRAM frames immediately.
    /// Otherwise the packet is buffered until later control frames make it
    /// releasable.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed or for another channel.
    pub fn process_protected_packet(
        &mut self,
        protected_packet: &[u8],
    ) -> Res<Vec<ChannelDatagram>> {
        let parsed = parse_channel_packet_metadata(
            &self.announce,
            protected_packet,
            self.largest_observed_packet_number,
        )?;
        self.largest_observed_packet_number = self
            .largest_observed_packet_number
            .max(parsed.packet_number);

        if self.accepted_packets.contains(&parsed.packet_number)
            || self.pending_packets.contains_key(&parsed.packet_number)
        {
            return Ok(Vec::new());
        }

        self.pending_packets.insert(
            parsed.packet_number,
            PendingChannelPacket {
                protected_packet: protected_packet.to_vec(),
                key_phase: parsed.key_phase,
            },
        );

        self.try_release_packet(parsed.packet_number)
            .map(Option::unwrap_or_default)
    }

    /// Validate an already-decoded channel packet and release any DATAGRAMs.
    ///
    /// `protected_packet` must be the protected UDP payload bytes that
    /// correspond to `packet.packet_number`. This method validates those bytes
    /// against prior `MC_INTEGRITY` state, then releases decoded DATAGRAM frames
    /// upward and records ACK state.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is for another channel, no matching key or
    /// integrity is available, or the integrity hash does not match.
    pub fn process_authenticated_packet(
        &mut self,
        packet: ChannelPacket,
        protected_packet: &[u8],
    ) -> Res<Vec<ChannelDatagram>> {
        self.check_channel_id(&packet.channel_id)?;
        if !self.keys.contains_key(&packet.key_sequence) {
            return Err(Error::NotAvailable);
        }
        self.validate_integrity(packet.packet_number, protected_packet)?;

        let released = self.release_packet_datagrams(packet);
        Ok(released)
    }

    /// Pop a released channel DATAGRAM.
    pub fn pop_datagram(&mut self) -> Option<ChannelDatagram> {
        self.datagrams.pop_front()
    }

    /// Build a pending `MC_ACK`, if any newly validated packets are waiting.
    #[must_use]
    pub fn pending_ack(&self) -> Option<Ack> {
        self.ack_tracker.pending_ack(&self.announce.channel_id)
    }

    /// Mark pending ACK state as sent.
    pub fn mark_ack_sent(&mut self) {
        self.ack_tracker.mark_sent();
    }

    fn check_channel_id(&self, channel_id: &[u8]) -> Res<()> {
        validate_channel_id(channel_id)?;
        if channel_id != self.announce.channel_id {
            return Err(Error::FrameEncoding);
        }
        Ok(())
    }

    fn validate_integrity(&self, packet_number: u64, protected_packet: &[u8]) -> Res<()> {
        let expected = self
            .integrity_hashes
            .get(&packet_number)
            .ok_or(Error::NotAvailable)?;
        let actual = self.integrity_hash.hash(protected_packet)?;
        if actual.as_slice() == expected {
            Ok(())
        } else {
            Err(Error::Decrypt)
        }
    }

    fn release_ready_packets(&mut self) -> Res<Vec<ChannelDatagram>> {
        let packet_numbers = self.pending_packets.keys().copied().collect::<Vec<_>>();
        let mut released = Vec::new();
        for packet_number in packet_numbers {
            if let Some(mut datagrams) = self.try_release_packet(packet_number)? {
                released.append(&mut datagrams);
            }
        }
        Ok(released)
    }

    fn try_release_packet(&mut self, packet_number: u64) -> Res<Option<Vec<ChannelDatagram>>> {
        let Some(pending) = self.pending_packets.get(&packet_number) else {
            return Ok(None);
        };
        if !self.integrity_hashes.contains_key(&packet_number) {
            return Ok(None);
        }
        let Some(key) = self.select_key(packet_number, pending.key_phase).cloned() else {
            return Ok(None);
        };

        self.validate_integrity(packet_number, &pending.protected_packet)?;
        let pending = self
            .pending_packets
            .remove(&packet_number)
            .expect("pending packet exists");
        let packet = decrypt_channel_packet(
            &self.announce,
            &key,
            packet_number,
            &pending.protected_packet,
            self.largest_observed_packet_number,
        )?;
        self.accepted_packets.insert(packet_number);
        Ok(Some(self.release_packet_datagrams(packet)))
    }

    fn select_key(&self, packet_number: u64, key_phase: bool) -> Option<&Key> {
        self.keys.values().rev().find(|key| {
            key.from_packet_number <= packet_number
                && (key.key_sequence % 2 == if key_phase { 1 } else { 0 })
        })
    }

    fn release_packet_datagrams(&mut self, packet: ChannelPacket) -> Vec<ChannelDatagram> {
        let packet_number = packet.packet_number;
        let mut released = Vec::new();
        for frame in packet.frames {
            if let ChannelFrame::Datagram { data } = frame {
                let datagram = ChannelDatagram {
                    channel_id: self.announce.channel_id.clone(),
                    packet_number,
                    data,
                };
                self.datagrams.push_back(datagram.clone());
                released.push(datagram);
            }
        }
        self.ack_tracker.record_packet(packet_number);
        released
    }
}

#[derive(Clone, Debug)]
struct PendingChannelPacket {
    protected_packet: Vec<u8>,
    key_phase: bool,
}

#[derive(Clone, Copy, Debug)]
struct ParsedChannelPacket {
    packet_number: u64,
    key_phase: bool,
}

fn encode_protected_channel_packet(
    announce: &Announce,
    key: &Key,
    packet_number: u64,
    key_phase: bool,
    frames: &[ChannelFrame],
) -> Res<Vec<u8>> {
    validate_channel_id(&announce.channel_id)?;
    let mut payload = Encoder::default();
    encode_channel_frames(&mut payload, frames)?;

    let mut packet =
        Vec::with_capacity(1 + announce.channel_id.len() + PACKET_NUMBER_LEN + payload.len() + 16);
    let first = SHORT_HEADER_FIXED_BIT
        | (((key_phase as u8) << 2) & SHORT_HEADER_KEY_PHASE_BIT)
        | (u8::try_from(PACKET_NUMBER_LEN)? - 1);
    packet.push(first);
    packet.extend_from_slice(&announce.channel_id);
    encode_packet_number(packet_number, PACKET_NUMBER_LEN, &mut packet)?;
    let payload_offset = packet.len();
    packet.extend_from_slice(payload.as_ref());

    let cipher = cipher_from_id(announce.aead_algorithm)?;
    let mut seal =
        crypto_state_from_secret(&key.secret, cipher, CryptoDxDirection::Write, packet_number)?;
    packet.resize(packet.len() + seal.expansion(), 0);
    let encrypted_len = seal.encrypt(packet_number, 0..payload_offset, &mut packet)?;
    packet.truncate(payload_offset + encrypted_len);

    apply_header_protection(announce, &mut packet)?;
    Ok(packet)
}

fn parse_channel_packet_metadata(
    announce: &Announce,
    protected_packet: &[u8],
    largest_observed_packet_number: u64,
) -> Res<ParsedChannelPacket> {
    let mut packet = protected_packet.to_vec();
    let header = decrypt_channel_header(announce, &mut packet, largest_observed_packet_number)?;
    Ok(ParsedChannelPacket {
        packet_number: header.packet_number,
        key_phase: header.key_phase,
    })
}

fn decrypt_channel_packet(
    announce: &Announce,
    key: &Key,
    packet_number: u64,
    protected_packet: &[u8],
    largest_observed_packet_number: u64,
) -> Res<ChannelPacket> {
    if key.channel_id != announce.channel_id {
        return Err(Error::FrameEncoding);
    }

    let mut packet = protected_packet.to_vec();
    let header = decrypt_channel_header(announce, &mut packet, largest_observed_packet_number)?;
    if header.packet_number != packet_number {
        return Err(Error::InvalidPacket);
    }

    let cipher = cipher_from_id(announce.aead_algorithm)?;
    let mut open = crypto_state_from_secret(
        &key.secret,
        cipher,
        CryptoDxDirection::Read,
        key.from_packet_number,
    )?;
    let plaintext_len = open.decrypt(packet_number, 0..header.header_end, &mut packet)?;
    if plaintext_len == 0 {
        return Err(Error::InvalidPacket);
    }

    let plaintext_end = header
        .header_end
        .checked_add(plaintext_len)
        .ok_or(Error::IntegerOverflow)?;
    let frames = decode_channel_frames(announce, &packet[header.header_end..plaintext_end])?;

    Ok(ChannelPacket {
        channel_id: announce.channel_id.clone(),
        packet_number,
        key_sequence: key.key_sequence,
        key_phase: header.key_phase,
        frames,
    })
}

#[derive(Clone, Copy, Debug)]
struct DecryptedChannelHeader {
    packet_number: u64,
    key_phase: bool,
    header_end: usize,
}

fn decrypt_channel_header(
    announce: &Announce,
    packet: &mut [u8],
    largest_observed_packet_number: u64,
) -> Res<DecryptedChannelHeader> {
    validate_channel_id(&announce.channel_id)?;
    let packet_number_offset = 1_usize
        .checked_add(announce.channel_id.len())
        .ok_or(Error::IntegerOverflow)?;
    let sample_offset = packet_number_offset
        .checked_add(HP_SAMPLE_OFFSET)
        .ok_or(Error::IntegerOverflow)?;
    let sample_end = sample_offset
        .checked_add(HP_SAMPLE_SIZE)
        .ok_or(Error::IntegerOverflow)?;

    if packet.len() < sample_end
        || packet.first().is_none_or(|first| {
            first & SHORT_HEADER_FORM_BIT != 0 || first & SHORT_HEADER_FIXED_BIT == 0
        })
        || packet.get(1..packet_number_offset) != Some(announce.channel_id.as_slice())
    {
        return Err(Error::InvalidPacket);
    }

    let sample = <[u8; HP_SAMPLE_SIZE]>::try_from(&packet[sample_offset..sample_end])?;
    let header_open = header_crypto_state(announce)?;
    let mask = header_open.compute_mask(&sample)?;

    let first = packet[0] ^ (mask[0] & SHORT_HEADER_HP_MASK);
    if first & SHORT_HEADER_FORM_BIT != 0 || first & SHORT_HEADER_FIXED_BIT == 0 {
        return Err(Error::InvalidPacket);
    }
    let packet_number_len = usize::from((first & 0x03) + 1);
    let header_end = packet_number_offset
        .checked_add(packet_number_len)
        .ok_or(Error::IntegerOverflow)?;
    if packet.len() < header_end {
        return Err(Error::InvalidPacket);
    }

    packet[0] = first;
    let mut truncated_packet_number = 0;
    for idx in 0..packet_number_len {
        let packet_number_byte = packet_number_offset + idx;
        packet[packet_number_byte] ^= mask[1 + idx];
        truncated_packet_number =
            (truncated_packet_number << 8) | u64::from(packet[packet_number_byte]);
    }

    Ok(DecryptedChannelHeader {
        packet_number: decode_packet_number(
            largest_observed_packet_number,
            truncated_packet_number,
            packet_number_len,
        ),
        key_phase: first & SHORT_HEADER_KEY_PHASE_BIT != 0,
        header_end,
    })
}

fn apply_header_protection(announce: &Announce, packet: &mut [u8]) -> Res<()> {
    validate_channel_id(&announce.channel_id)?;
    let packet_number_offset = 1_usize
        .checked_add(announce.channel_id.len())
        .ok_or(Error::IntegerOverflow)?;
    let sample_offset = packet_number_offset
        .checked_add(HP_SAMPLE_OFFSET)
        .ok_or(Error::IntegerOverflow)?;
    let sample_end = sample_offset
        .checked_add(HP_SAMPLE_SIZE)
        .ok_or(Error::IntegerOverflow)?;
    if packet.len() < sample_end {
        return Err(Error::NoMoreData);
    }

    let sample = <[u8; HP_SAMPLE_SIZE]>::try_from(&packet[sample_offset..sample_end])?;
    let header_open = header_crypto_state(announce)?;
    let mask = header_open.compute_mask(&sample)?;

    packet[0] ^= mask[0] & SHORT_HEADER_HP_MASK;
    for idx in 0..PACKET_NUMBER_LEN {
        packet[packet_number_offset + idx] ^= mask[1 + idx];
    }
    Ok(())
}

fn encode_packet_number(
    packet_number: u64,
    packet_number_len: usize,
    out: &mut Vec<u8>,
) -> Res<()> {
    if packet_number_len > PACKET_NUMBER_LEN {
        return Err(Error::FrameEncoding);
    }
    for shift in (0..packet_number_len).rev() {
        out.push(u8::try_from(packet_number >> (shift * 8) & 0xff)?);
    }
    Ok(())
}

fn decode_packet_number(expected: u64, truncated: u64, packet_number_len: usize) -> u64 {
    let window = 1_u64 << (packet_number_len * 8);
    let candidate = (expected & !(window - 1)) | truncated;
    if candidate + (window / 2) <= expected {
        candidate + window
    } else if candidate > expected + (window / 2) {
        candidate.checked_sub(window).unwrap_or(candidate)
    } else {
        candidate
    }
}

fn encode_channel_frames<B: Buffer>(enc: &mut Encoder<B>, frames: &[ChannelFrame]) -> Res<()> {
    if frames.is_empty() {
        return Err(Error::FrameEncoding);
    }

    for frame in frames {
        encode_channel_frame(enc, frame)?;
    }
    Ok(())
}

fn encode_channel_frame<B: Buffer>(enc: &mut Encoder<B>, frame: &ChannelFrame) -> Res<()> {
    match frame {
        ChannelFrame::Padding { len } => {
            for _ in 0..*len {
                enc.encode_varint(FrameType::Padding);
            }
        }
        ChannelFrame::Ping => {
            enc.encode_varint(FrameType::Ping);
        }
        ChannelFrame::ResetStream {
            stream_id,
            error_code,
            final_size,
        } => {
            enc.encode_varint(FrameType::ResetStream)
                .encode_varint(*stream_id)
                .encode_varint(*error_code)
                .encode_varint(*final_size);
        }
        ChannelFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
        } => {
            validate_channel_stream_id(*stream_id)?;
            let mut frame_type = u64::from(FrameType::StreamWithLen);
            if *fin {
                frame_type |= 0x01;
            }
            if *offset > 0 {
                frame_type |= 0x04;
            }
            enc.encode_varint(frame_type).encode_varint(*stream_id);
            if *offset > 0 {
                enc.encode_varint(*offset);
            }
            enc.encode_vvec(data);
        }
        ChannelFrame::Datagram { data } => {
            encode_datagram_with_two_byte_length(enc, data)?;
        }
        ChannelFrame::Multicast(frame) => {
            validate_channel_control_frame(frame)?;
            frame.encode(enc)?;
        }
    }
    Ok(())
}

fn encode_datagram_with_two_byte_length<B: Buffer>(enc: &mut Encoder<B>, data: &[u8]) -> Res<()> {
    if data.len() >= (1 << 14) {
        return Err(Error::FrameEncoding);
    }
    let len = u16::try_from(data.len())? | 0x4000;
    enc.encode_varint(FrameType::DatagramWithLen)
        .encode(len.to_be_bytes())
        .encode(data);
    Ok(())
}

fn decode_channel_frames(announce: &Announce, payload: &[u8]) -> Res<Vec<ChannelFrame>> {
    let mut dec = Decoder::new(payload);
    let mut frames = Vec::new();
    while dec.remaining() > 0 {
        let frame = QuicFrame::decode(&mut dec)?;
        frames.push(decode_channel_frame(announce, frame)?);
    }
    if frames.is_empty() {
        return Err(Error::InvalidPacket);
    }
    Ok(frames)
}

fn decode_channel_frame(announce: &Announce, frame: QuicFrame) -> Res<ChannelFrame> {
    Ok(match frame {
        QuicFrame::Padding(len) => ChannelFrame::Padding {
            len: usize::from(len),
        },
        QuicFrame::Ping => ChannelFrame::Ping,
        QuicFrame::ResetStream {
            stream_id,
            application_error_code,
            final_size,
        } => ChannelFrame::ResetStream {
            stream_id: stream_id.as_u64(),
            error_code: application_error_code,
            final_size,
        },
        QuicFrame::Stream {
            stream_id,
            offset,
            fin,
            data,
            ..
        } => {
            validate_channel_stream_id(stream_id.as_u64())?;
            ChannelFrame::Stream {
                stream_id: stream_id.as_u64(),
                offset,
                fin,
                data: data.to_vec(),
            }
        }
        QuicFrame::Datagram { data, .. } => ChannelFrame::Datagram {
            data: data.to_vec(),
        },
        QuicFrame::Mcquic(frame) => {
            validate_channel_control_frame(&frame)?;
            if let Frame::Integrity(integrity) = &frame
                && integrity.channel_id == announce.channel_id
            {
                return Err(Error::FrameEncoding);
            }
            ChannelFrame::Multicast(frame)
        }
        _ => return Err(Error::FrameEncoding),
    })
}

fn validate_channel_stream_id(stream_id: u64) -> Res<()> {
    let stream_id = StreamId::from(stream_id);
    if stream_id.is_uni() && stream_id.is_server_initiated() {
        Ok(())
    } else {
        Err(Error::FrameEncoding)
    }
}

fn validate_channel_control_frame(frame: &Frame) -> Res<()> {
    match frame {
        Frame::Key(_) | Frame::Leave(_) | Frame::Integrity(_) | Frame::Retire(_) => Ok(()),
        _ => Err(Error::FrameEncoding),
    }
}

fn header_crypto_state(announce: &Announce) -> Res<CryptoDxState> {
    crypto_state_from_secret(
        &announce.header_secret,
        cipher_from_id(announce.header_protection_algorithm)?,
        CryptoDxDirection::Read,
        0,
    )
}

fn crypto_state_from_secret(
    secret: &[u8],
    cipher: Cipher,
    direction: CryptoDxDirection,
    min_pn: u64,
) -> Res<CryptoDxState> {
    let secret = hkdf::import_key(TLS_VERSION_1_3, secret)?;
    CryptoDxState::new(
        MCQUIC_VERSION,
        direction,
        Epoch::ApplicationData,
        &secret,
        cipher,
        min_pn,
    )
}

fn cipher_from_id(id: u16) -> Res<Cipher> {
    match id {
        0x1301 => Ok(TLS_AES_128_GCM_SHA256),
        0x1302 => Ok(TLS_AES_256_GCM_SHA384),
        0x1303 => Ok(TLS_CHACHA20_POLY1305_SHA256),
        _ => Err(Error::NotAvailable),
    }
}

/// Multicast control frames defined by the draft.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// `MC_ANNOUNCE`
    Announce(Announce),
    /// `MC_KEY`
    Key(Key),
    /// `MC_JOIN`
    Join(Join),
    /// `MC_LEAVE`
    Leave(Leave),
    /// `MC_INTEGRITY`
    Integrity(Integrity),
    /// `MC_ACK`
    Ack(Ack),
    /// `MC_LIMITS`
    Limits(Limits),
    /// `MC_RETIRE`
    Retire(Retire),
    /// `MC_STATE`
    State(State),
}

impl Frame {
    /// Decode a multicast frame, including the frame type.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or not a multicast frame.
    pub fn decode(dec: &mut Decoder) -> Res<Self> {
        let frame_type = decode_varint(dec)?;
        Self::decode_payload(frame_type, dec, None)
    }

    /// Decode a multicast frame payload after the frame type has already been
    /// consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame is malformed or not a multicast frame.
    pub fn decode_payload(
        frame_type: u64,
        dec: &mut Decoder,
        integrity_hash_len: Option<usize>,
    ) -> Res<Self> {
        let frame = match frame_type {
            FRAME_TYPE_ANNOUNCE_V4 | FRAME_TYPE_ANNOUNCE_V6 => Self::Announce(Announce {
                channel_id: decode_channel_id(dec)?,
                source: decode_ip_addr(dec, frame_type)?,
                group: decode_ip_addr(dec, frame_type)?,
                udp_port: decode_uint(dec)?,
                header_protection_algorithm: decode_uint(dec)?,
                header_secret: decode_vvec(dec)?,
                aead_algorithm: decode_uint(dec)?,
                integrity_hash_algorithm: decode_uint(dec)?,
                max_rate_kibps: decode_varint(dec)?,
                max_ack_delay_ms: decode_varint(dec)?,
            }),
            FRAME_TYPE_KEY => Self::Key(Key {
                channel_id: decode_channel_id(dec)?,
                key_sequence: decode_varint(dec)?,
                from_packet_number: decode_varint(dec)?,
                secret: decode_vvec(dec)?,
            }),
            FRAME_TYPE_JOIN => Self::Join(Join {
                channel_id: decode_channel_id(dec)?,
                mc_limits_sequence: decode_varint(dec)?,
                mc_state_sequence: decode_varint(dec)?,
                mc_key_sequence: decode_varint(dec)?,
            }),
            FRAME_TYPE_LEAVE => Self::Leave(Leave {
                channel_id: decode_channel_id(dec)?,
                mc_state_sequence: decode_varint(dec)?,
                after_packet_number: decode_varint(dec)?,
            }),
            FRAME_TYPE_INTEGRITY | FRAME_TYPE_INTEGRITY_WITH_LENGTH => {
                decode_integrity(frame_type, dec, integrity_hash_len)?
            }
            FRAME_TYPE_ACK | FRAME_TYPE_ACK_ECN => decode_ack(frame_type, dec)?,
            FRAME_TYPE_LIMITS => {
                let sequence = decode_varint(dec)?;
                let limits = ClientLimits::decode(dec)?;
                Self::Limits(Limits {
                    sequence,
                    limits,
                    max_joined_count: decode_varint(dec)?,
                })
            }
            FRAME_TYPE_RETIRE => Self::Retire(Retire {
                channel_id: decode_channel_id(dec)?,
                after_packet_number: decode_varint(dec)?,
            }),
            FRAME_TYPE_STATE | FRAME_TYPE_STATE_APPLICATION => {
                let state = State {
                    channel_id: decode_channel_id(dec)?,
                    sequence: decode_varint(dec)?,
                    state: ChannelState::decode(dec.decode_uint::<u8>().ok_or(Error::NoMoreData)?)?,
                    reason_scope: if frame_type == FRAME_TYPE_STATE {
                        StateReasonScope::Transport
                    } else {
                        StateReasonScope::Application
                    },
                    reason_code: decode_varint(dec)?,
                    reason_phrase: decode_vvec(dec)?,
                };
                validate_state_reason(state.state, state.reason_code)?;
                Self::State(state)
            }
            _ => return Err(Error::UnknownFrameType),
        };

        Ok(frame)
    }

    /// Encode this multicast frame, including the frame type.
    ///
    /// # Errors
    ///
    /// Returns an error if this frame contains invalid values.
    pub fn encode<B: Buffer>(&self, enc: &mut Encoder<B>) -> Res<()> {
        enc.encode_varint(self.frame_type()?);
        match self {
            Self::Announce(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                encode_ip_addr(enc, &frame.source);
                encode_ip_addr(enc, &frame.group);
                enc.encode_uint(2, frame.udp_port)
                    .encode_uint(2, frame.header_protection_algorithm)
                    .encode_vvec(&frame.header_secret)
                    .encode_uint(2, frame.aead_algorithm)
                    .encode_uint(2, frame.integrity_hash_algorithm)
                    .encode_varint(frame.max_rate_kibps)
                    .encode_varint(frame.max_ack_delay_ms);
            }
            Self::Key(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.key_sequence)
                    .encode_varint(frame.from_packet_number)
                    .encode_vvec(&frame.secret);
            }
            Self::Join(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.mc_limits_sequence)
                    .encode_varint(frame.mc_state_sequence)
                    .encode_varint(frame.mc_key_sequence);
            }
            Self::Leave(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.mc_state_sequence)
                    .encode_varint(frame.after_packet_number);
            }
            Self::Integrity(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.packet_number_start);
                if let Some(packet_hash_count) = frame.packet_hash_count {
                    enc.encode_varint(packet_hash_count);
                }
                enc.encode(&frame.packet_hashes);
            }
            Self::Ack(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.largest_acknowledged)
                    .encode_varint(frame.ack_delay)
                    .encode_varint(usize_to_u64(frame.ack_ranges.len()))
                    .encode_varint(frame.first_ack_range);
                for range in &frame.ack_ranges {
                    enc.encode_varint(range.gap)
                        .encode_varint(range.ack_range_length);
                }
                if let Some(ecn_counts) = &frame.ecn_counts {
                    enc.encode_varint(ecn_counts.ect0_count)
                        .encode_varint(ecn_counts.ect1_count)
                        .encode_varint(ecn_counts.ecn_ce_count);
                }
            }
            Self::Limits(frame) => {
                enc.encode_varint(frame.sequence);
                frame.limits.encode(enc);
                enc.encode_varint(frame.max_joined_count);
            }
            Self::Retire(frame) => {
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.after_packet_number);
            }
            Self::State(frame) => {
                validate_state_reason(frame.state, frame.reason_code)?;
                encode_channel_id(enc, &frame.channel_id)?;
                enc.encode_varint(frame.sequence)
                    .encode_byte(frame.state.into())
                    .encode_varint(frame.reason_code)
                    .encode_vvec(&frame.reason_phrase);
            }
        }
        Ok(())
    }

    /// Encode this multicast frame into a fresh vector.
    ///
    /// # Errors
    ///
    /// Returns an error if this frame contains invalid values.
    pub fn to_vec(&self) -> Res<Vec<u8>> {
        let mut enc = Encoder::default();
        self.encode(&mut enc)?;
        Ok(enc.as_ref().to_vec())
    }

    /// Decode a multicast frame from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are malformed.
    pub fn from_slice(buf: &[u8]) -> Res<Self> {
        let mut dec = Decoder::new(buf);
        let frame = Self::decode(&mut dec)?;
        if dec.remaining() > 0 {
            return Err(Error::TooMuchData);
        }
        Ok(frame)
    }

    /// Return the draft frame type used to encode this frame.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame cannot select a valid wire type.
    pub fn frame_type(&self) -> Res<u64> {
        Ok(match self {
            Self::Announce(frame) => match (&frame.source, &frame.group) {
                (IpAddr::V4(_), IpAddr::V4(_)) => FRAME_TYPE_ANNOUNCE_V4,
                (IpAddr::V6(_), IpAddr::V6(_)) => FRAME_TYPE_ANNOUNCE_V6,
                _ => return Err(Error::FrameEncoding),
            },
            Self::Key(_) => FRAME_TYPE_KEY,
            Self::Join(_) => FRAME_TYPE_JOIN,
            Self::Leave(_) => FRAME_TYPE_LEAVE,
            Self::Integrity(frame) => {
                if frame.packet_hash_count.is_some() {
                    FRAME_TYPE_INTEGRITY_WITH_LENGTH
                } else {
                    FRAME_TYPE_INTEGRITY
                }
            }
            Self::Ack(frame) => {
                if frame.ecn_counts.is_some() {
                    FRAME_TYPE_ACK_ECN
                } else {
                    FRAME_TYPE_ACK
                }
            }
            Self::Limits(_) => FRAME_TYPE_LIMITS,
            Self::Retire(_) => FRAME_TYPE_RETIRE,
            Self::State(frame) => match frame.reason_scope {
                StateReasonScope::Transport => FRAME_TYPE_STATE,
                StateReasonScope::Application => FRAME_TYPE_STATE_APPLICATION,
            },
        })
    }

    /// Return which endpoint is allowed to send this frame.
    #[must_use]
    pub const fn sender(&self) -> Sender {
        match self {
            Self::Announce(_)
            | Self::Key(_)
            | Self::Join(_)
            | Self::Leave(_)
            | Self::Integrity(_)
            | Self::Retire(_) => Sender::Server,
            Self::Ack(_) | Self::Limits(_) | Self::State(_) => Sender::Client,
        }
    }

    /// Whether this frame causes an ACK of the unicast QUIC packet.
    #[must_use]
    pub const fn ack_eliciting(&self) -> bool {
        !matches!(self, Self::Ack(_))
    }

    /// Whether this frame should be retransmitted on loss.
    #[must_use]
    pub const fn retransmit_on_loss(&self) -> bool {
        !matches!(self, Self::Ack(_))
    }

    /// Whether this frame consumes the remainder of the packet.
    #[must_use]
    pub const fn requires_packet_end(&self) -> bool {
        matches!(
            self,
            Self::Integrity(Integrity {
                packet_hash_count: None,
                ..
            })
        )
    }
}

/// Sender direction for multicast control frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sender {
    /// Client-to-server frame.
    Client,
    /// Server-to-client frame.
    Server,
}

/// Tracks cumulative multicast packet acknowledgments for one channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AckTracker {
    ranges: Vec<AckSpan>,
    pending: bool,
}

impl AckTracker {
    /// Record a validated multicast packet number.
    pub fn record_packet(&mut self, packet_number: u64) {
        let mut start = packet_number;
        let mut end = packet_number;
        let mut insert_at = 0;

        while insert_at < self.ranges.len() {
            let existing = self.ranges[insert_at];

            if end.saturating_add(1) < existing.start {
                break;
            }
            if existing.end.saturating_add(1) < start {
                insert_at += 1;
                continue;
            }

            start = start.min(existing.start);
            end = end.max(existing.end);
            self.ranges.remove(insert_at);
        }

        self.ranges.insert(insert_at, AckSpan { start, end });
        self.pending = true;
    }

    /// Build a pending `MC_ACK`, if newly recorded packets are waiting.
    #[must_use]
    pub fn pending_ack(&self, channel_id: &[u8]) -> Option<Ack> {
        if !self.pending || self.ranges.is_empty() {
            return None;
        }

        let newest = self.ranges.last().copied()?;
        let mut smallest_ack = newest.start;
        let mut ack_ranges = Vec::with_capacity(self.ranges.len().saturating_sub(1));

        for span in self.ranges[..self.ranges.len().saturating_sub(1)]
            .iter()
            .rev()
        {
            let gap = smallest_ack
                .checked_sub(span.end)
                .and_then(|delta| delta.checked_sub(2))
                .expect("ack spans are ordered and disjoint");
            ack_ranges.push(AckRange {
                gap,
                ack_range_length: span.end - span.start,
            });
            smallest_ack = span.start;
        }

        Some(Ack {
            channel_id: channel_id.to_vec(),
            largest_acknowledged: newest.end,
            ack_delay: 0,
            first_ack_range: newest.end - newest.start,
            ack_ranges,
            ecn_counts: None,
        })
    }

    /// Mark pending ACK state as sent.
    pub fn mark_sent(&mut self) {
        self.pending = false;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AckSpan {
    start: u64,
    end: u64,
}

/// Returns whether `frame_type` is an MCQUIC frame type.
#[must_use]
pub const fn is_frame_type(frame_type: u64) -> bool {
    matches!(
        frame_type,
        FRAME_TYPE_KEY
            | FRAME_TYPE_JOIN
            | FRAME_TYPE_LEAVE
            | FRAME_TYPE_INTEGRITY
            | FRAME_TYPE_INTEGRITY_WITH_LENGTH
            | FRAME_TYPE_ACK
            | FRAME_TYPE_ACK_ECN
            | FRAME_TYPE_LIMITS
            | FRAME_TYPE_RETIRE
            | FRAME_TYPE_STATE
            | FRAME_TYPE_STATE_APPLICATION
            | FRAME_TYPE_ANNOUNCE_V4
            | FRAME_TYPE_ANNOUNCE_V6
    )
}

fn decode_ack(frame_type: u64, dec: &mut Decoder) -> Res<Frame> {
    let channel_id = decode_channel_id(dec)?;
    let largest_acknowledged = decode_varint(dec)?;
    let ack_delay = decode_varint(dec)?;
    let ack_range_count = decode_varint(dec)?;
    if ack_range_count > MAX_ACK_RANGE_COUNT {
        return Err(Error::TooMuchData);
    }
    let first_ack_range = decode_varint(dec)?;
    let ack_ranges = decode_ack_ranges(dec, ack_range_count)?;
    let ecn_counts = if frame_type == FRAME_TYPE_ACK_ECN {
        Some(AckEcnCounts {
            ect0_count: decode_varint(dec)?,
            ect1_count: decode_varint(dec)?,
            ecn_ce_count: decode_varint(dec)?,
        })
    } else {
        None
    };

    Ok(Frame::Ack(Ack {
        channel_id,
        largest_acknowledged,
        ack_delay,
        first_ack_range,
        ack_ranges,
        ecn_counts,
    }))
}

fn decode_integrity(
    frame_type: u64,
    dec: &mut Decoder,
    integrity_hash_len: Option<usize>,
) -> Res<Frame> {
    let channel_id = decode_channel_id(dec)?;
    let packet_number_start = decode_varint(dec)?;
    let packet_hash_count = if frame_type == FRAME_TYPE_INTEGRITY_WITH_LENGTH {
        Some(decode_varint(dec)?)
    } else {
        None
    };

    let packet_hashes =
        if let (Some(count), Some(hash_len)) = (packet_hash_count, integrity_hash_len) {
            let len = count
                .checked_mul(u64::try_from(hash_len)?)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(Error::FrameEncoding)?;
            dec.decode(len).ok_or(Error::NoMoreData)?.to_vec()
        } else {
            dec.decode_remainder().to_vec()
        };

    Ok(Frame::Integrity(Integrity {
        channel_id,
        packet_number_start,
        packet_hash_count,
        packet_hashes,
    }))
}

fn decode_ack_ranges(dec: &mut Decoder, ack_range_count: u64) -> Res<Vec<AckRange>> {
    let ack_range_count = usize::try_from(ack_range_count)?;
    if ack_range_count > dec.remaining() / 2 {
        return Err(Error::FrameEncoding);
    }

    let mut ack_ranges = Vec::with_capacity(ack_range_count);
    for _ in 0..ack_range_count {
        ack_ranges.push(AckRange {
            gap: decode_varint(dec)?,
            ack_range_length: decode_varint(dec)?,
        });
    }
    Ok(ack_ranges)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntegrityHashAlgorithm {
    Sha256 { output_len: usize },
    Sha384,
    Sha512,
}

impl IntegrityHashAlgorithm {
    fn from_id(id: u16) -> Res<Self> {
        match id {
            1 => Ok(Self::Sha256 { output_len: 32 }),
            2 => Ok(Self::Sha256 { output_len: 16 }),
            3 => Ok(Self::Sha256 { output_len: 15 }),
            4 => Ok(Self::Sha256 { output_len: 12 }),
            5 => Ok(Self::Sha256 { output_len: 8 }),
            6 => Ok(Self::Sha256 { output_len: 4 }),
            7 => Ok(Self::Sha384),
            8 => Ok(Self::Sha512),
            _ => Err(Error::NotAvailable),
        }
    }

    const fn output_len(self) -> usize {
        match self {
            Self::Sha256 { output_len } => output_len,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn hash(self, data: &[u8]) -> Res<Vec<u8>> {
        let (algorithm, output_len) = match self {
            Self::Sha256 { output_len } => (HashAlgorithm::SHA2_256, output_len),
            Self::Sha384 => (HashAlgorithm::SHA2_384, 48),
            Self::Sha512 => (HashAlgorithm::SHA2_512, 64),
        };
        let mut digest = hash::hash(&algorithm, data)?;
        digest.truncate(output_len);
        Ok(digest)
    }
}

/// Return the packet integrity hash length for a draft hash algorithm ID.
///
/// # Errors
///
/// Returns `NotAvailable` for unsupported IDs.
pub fn integrity_hash_len_from_id(id: u16) -> Res<usize> {
    Ok(IntegrityHashAlgorithm::from_id(id)?.output_len())
}

/// Return whether a draft encryption algorithm ID is supported.
#[must_use]
pub const fn encryption_algorithm_supported(id: u16) -> bool {
    matches!(id, 0x1301 | 0x1302 | 0x1303)
}

fn validate_encryption_algorithm(id: u16) -> Res<()> {
    if encryption_algorithm_supported(id) {
        Ok(())
    } else {
        Err(Error::NotAvailable)
    }
}

fn decode_channel_id(dec: &mut Decoder) -> Res<Vec<u8>> {
    let channel_id_len = dec.decode_uint::<u8>().ok_or(Error::NoMoreData)?;
    if !(1..=ConnectionId::MAX_LEN).contains(&usize::from(channel_id_len)) {
        return Err(Error::FrameEncoding);
    }
    Ok(dec
        .decode(usize::from(channel_id_len))
        .ok_or(Error::NoMoreData)?
        .to_vec())
}

fn encode_channel_id<B: Buffer>(enc: &mut Encoder<B>, channel_id: &[u8]) -> Res<()> {
    validate_channel_id(channel_id)?;
    let len = u8::try_from(channel_id.len()).map_err(|_| Error::FrameEncoding)?;
    enc.encode_byte(len).encode(channel_id);
    Ok(())
}

fn validate_channel_id(channel_id: &[u8]) -> Res<()> {
    if channel_id.is_empty() || channel_id.len() > ConnectionId::MAX_LEN {
        return Err(Error::FrameEncoding);
    }
    Ok(())
}

fn decode_ip_addr(dec: &mut Decoder, frame_type: u64) -> Res<IpAddr> {
    match frame_type {
        FRAME_TYPE_ANNOUNCE_V4 => {
            let addr = dec.decode(4).ok_or(Error::NoMoreData)?;
            Ok(IpAddr::V4(Ipv4Addr::new(
                addr[0], addr[1], addr[2], addr[3],
            )))
        }
        FRAME_TYPE_ANNOUNCE_V6 => {
            let addr = dec.decode(16).ok_or(Error::NoMoreData)?;
            let mut octets = [0; 16];
            octets.copy_from_slice(addr);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(Error::FrameEncoding),
    }
}

fn encode_ip_addr<B: Buffer>(enc: &mut Encoder<B>, addr: &IpAddr) {
    match addr {
        IpAddr::V4(addr) => {
            enc.encode(addr.octets());
        }
        IpAddr::V6(addr) => {
            enc.encode(addr.octets());
        }
    }
}

fn decode_u16_list(dec: &mut Decoder, count: u64, transport_parameter: bool) -> Res<Vec<u16>> {
    let count = usize::try_from(count).map_err(|_| {
        if transport_parameter {
            Error::TransportParameter
        } else {
            Error::FrameEncoding
        }
    })?;
    if count > dec.remaining() / 2 {
        return Err(if transport_parameter {
            Error::TransportParameter
        } else {
            Error::FrameEncoding
        });
    }

    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decode_uint(dec)?);
    }
    Ok(values)
}

fn encode_u16_list<B: Buffer>(enc: &mut Encoder<B>, values: &[u16]) {
    for value in values {
        enc.encode_uint(2, *value);
    }
}

fn validate_state_reason(state: ChannelState, reason_code: u64) -> Res<()> {
    match state {
        ChannelState::Joined | ChannelState::Retired
            if reason_code != STATE_REASON_REQUESTED_BY_SERVER =>
        {
            Err(Error::FrameEncoding)
        }
        _ => Ok(()),
    }
}

fn decode_vvec(dec: &mut Decoder) -> Res<Vec<u8>> {
    Ok(dec.decode_vvec().ok_or(Error::NoMoreData)?.to_vec())
}

fn decode_varint(dec: &mut Decoder) -> Res<u64> {
    dec.decode_varint().ok_or(Error::NoMoreData)
}

fn decode_uint<T>(dec: &mut Decoder) -> Res<T>
where
    T: TryFrom<u64>,
{
    dec.decode_uint::<T>().ok_or(Error::NoMoreData)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).expect("usize fits in u64 on supported targets")
}

#[cfg(test)]
mod tests {
    use test_fixture::fixture_init;

    use super::*;

    fn roundtrip(frame: Frame) {
        let encoded = frame.to_vec().expect("encode frame");
        let decoded = Frame::from_slice(&encoded).expect("decode frame");
        assert_eq!(frame, decoded);
    }

    fn channel_id() -> Vec<u8> {
        b"channel-1".to_vec()
    }

    #[test]
    fn client_transport_params_roundtrip() {
        let params = ClientTransportParams {
            limits: ClientLimits {
                ipv4_channels_allowed: true,
                ipv6_channels_allowed: false,
                max_aggregate_rate_kibps: 100_000,
                max_channel_ids: 32,
            },
            hash_algorithms: vec![1, 2, 8],
            encryption_algorithms: vec![0x1301, 0x1303],
        };

        let encoded = params.to_vec();
        assert_eq!(
            ClientTransportParams::from_slice(&encoded).expect("decode params"),
            params
        );
    }

    #[test]
    fn client_transport_params_reject_trailing_bytes() {
        let mut encoded = ClientTransportParams {
            limits: ClientLimits {
                ipv4_channels_allowed: true,
                ipv6_channels_allowed: true,
                max_aggregate_rate_kibps: 1,
                max_channel_ids: 1,
            },
            hash_algorithms: vec![1],
            encryption_algorithms: vec![0x1301],
        }
        .to_vec();
        encoded.push(0);

        assert_eq!(
            ClientTransportParams::from_slice(&encoded).unwrap_err(),
            Error::TooMuchData
        );
    }

    #[test]
    fn frame_roundtrips() {
        roundtrip(Frame::Announce(Announce {
            channel_id: channel_id(),
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            group: IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1)),
            udp_port: 4433,
            header_protection_algorithm: 0x1301,
            header_secret: vec![1, 2, 3, 4],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 10_000,
            max_ack_delay_ms: 25,
        }));
        roundtrip(Frame::Announce(Announce {
            channel_id: channel_id(),
            source: IpAddr::V6(Ipv6Addr::LOCALHOST),
            group: IpAddr::V6(Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 1)),
            udp_port: 4433,
            header_protection_algorithm: 0x1301,
            header_secret: vec![1, 2, 3, 4],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 10_000,
            max_ack_delay_ms: 25,
        }));
        roundtrip(Frame::Key(Key {
            channel_id: channel_id(),
            key_sequence: 7,
            from_packet_number: 9,
            secret: vec![0xaa; 32],
        }));
        roundtrip(Frame::Join(Join {
            channel_id: channel_id(),
            mc_limits_sequence: 1,
            mc_state_sequence: 2,
            mc_key_sequence: 3,
        }));
        roundtrip(Frame::Leave(Leave {
            channel_id: channel_id(),
            mc_state_sequence: 3,
            after_packet_number: 100,
        }));
        roundtrip(Frame::Integrity(Integrity {
            channel_id: channel_id(),
            packet_number_start: 42,
            packet_hash_count: None,
            packet_hashes: vec![0xbb; 16],
        }));
        roundtrip(Frame::Integrity(Integrity {
            channel_id: channel_id(),
            packet_number_start: 42,
            packet_hash_count: Some(2),
            packet_hashes: vec![0xbb; 16],
        }));
        roundtrip(Frame::Ack(Ack {
            channel_id: channel_id(),
            largest_acknowledged: 10,
            ack_delay: 0,
            first_ack_range: 3,
            ack_ranges: vec![AckRange {
                gap: 1,
                ack_range_length: 2,
            }],
            ecn_counts: None,
        }));
        roundtrip(Frame::Ack(Ack {
            channel_id: channel_id(),
            largest_acknowledged: 10,
            ack_delay: 0,
            first_ack_range: 3,
            ack_ranges: vec![],
            ecn_counts: Some(AckEcnCounts {
                ect0_count: 1,
                ect1_count: 2,
                ecn_ce_count: 3,
            }),
        }));
        roundtrip(Frame::Limits(Limits {
            sequence: 1,
            limits: ClientLimits {
                ipv4_channels_allowed: true,
                ipv6_channels_allowed: true,
                max_aggregate_rate_kibps: 20_000,
                max_channel_ids: 8,
            },
            max_joined_count: 4,
        }));
        roundtrip(Frame::Retire(Retire {
            channel_id: channel_id(),
            after_packet_number: 100,
        }));
        roundtrip(Frame::State(State {
            channel_id: channel_id(),
            sequence: 1,
            state: ChannelState::DeclinedJoin,
            reason_scope: StateReasonScope::Application,
            reason_code: 404,
            reason_phrase: b"not found".to_vec(),
        }));
        roundtrip(Frame::State(State {
            channel_id: channel_id(),
            sequence: 2,
            state: ChannelState::Joined,
            reason_scope: StateReasonScope::Transport,
            reason_code: STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: b"joined".to_vec(),
        }));
    }

    #[test]
    fn invalid_channel_id_is_rejected() {
        let frame = Frame::Key(Key {
            channel_id: vec![],
            key_sequence: 0,
            from_packet_number: 0,
            secret: vec![],
        });
        assert_eq!(frame.to_vec().unwrap_err(), Error::FrameEncoding);
    }

    #[test]
    fn sender_direction() {
        assert_eq!(
            Frame::Announce(Announce {
                channel_id: channel_id(),
                source: IpAddr::V4(Ipv4Addr::LOCALHOST),
                group: IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                udp_port: 4433,
                header_protection_algorithm: 0x1301,
                header_secret: vec![],
                aead_algorithm: 0x1301,
                integrity_hash_algorithm: 1,
                max_rate_kibps: 1,
                max_ack_delay_ms: 1,
            })
            .sender(),
            Sender::Server
        );
        assert_eq!(
            Frame::Limits(Limits {
                sequence: 1,
                limits: ClientLimits::default(),
                max_joined_count: 1,
            })
            .sender(),
            Sender::Client
        );
    }

    #[test]
    fn ack_tracker_merges_ranges() {
        let mut tracker = AckTracker::default();
        tracker.record_packet(1);
        tracker.record_packet(2);
        tracker.record_packet(5);

        let ack = tracker.pending_ack(b"ch").expect("pending ack");
        assert_eq!(ack.largest_acknowledged, 5);
        assert_eq!(ack.first_ack_range, 0);
        assert_eq!(
            ack.ack_ranges,
            vec![AckRange {
                gap: 1,
                ack_range_length: 1
            }]
        );

        tracker.mark_sent();
        assert!(tracker.pending_ack(b"ch").is_none());
    }

    #[test]
    fn explicit_integrity_can_use_hash_len_to_leave_following_frame() {
        let frame = Frame::Integrity(Integrity {
            channel_id: channel_id(),
            packet_number_start: 4,
            packet_hash_count: Some(2),
            packet_hashes: vec![0xaa; 8],
        });
        let mut encoded = Encoder::default();
        frame.encode(&mut encoded).expect("encode integrity");
        let ack = Frame::Ack(Ack {
            channel_id: channel_id(),
            largest_acknowledged: 4,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: vec![],
            ecn_counts: None,
        });
        ack.encode(&mut encoded).expect("encode ack");

        let mut dec = encoded.as_decoder();
        assert_eq!(
            Frame::decode_payload(decode_varint(&mut dec).expect("type"), &mut dec, Some(4))
                .expect("decode integrity"),
            frame
        );
        assert_eq!(Frame::decode(&mut dec).expect("decode ack"), ack);
    }

    #[test]
    fn state_joined_requires_server_request_reason() {
        let frame = Frame::State(State {
            channel_id: channel_id(),
            sequence: 1,
            state: ChannelState::Joined,
            reason_scope: StateReasonScope::Transport,
            reason_code: 99,
            reason_phrase: vec![],
        });
        assert_eq!(frame.to_vec().unwrap_err(), Error::FrameEncoding);
    }

    #[test]
    fn recognizes_mcquic_frame_types() {
        assert!(is_frame_type(FRAME_TYPE_KEY));
        assert!(is_frame_type(FRAME_TYPE_ANNOUNCE_V6));
        assert!(!is_frame_type(0x1));
    }

    fn announce() -> Announce {
        fixture_init();
        Announce {
            channel_id: channel_id(),
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            group: IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1)),
            udp_port: 4433,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0x11; 32],
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 10_000,
            max_ack_delay_ms: 25,
        }
    }

    #[test]
    fn channel_receive_releases_valid_datagram_and_ack() {
        let mut state = ChannelReceiveState::new(announce()).expect("receive state");
        state
            .insert_key(Key {
                channel_id: channel_id(),
                key_sequence: 7,
                from_packet_number: 0,
                secret: vec![0xcc; 32],
            })
            .expect("insert key");

        let protected_packet = b"protected packet bytes";
        let packet_hash = IntegrityHashAlgorithm::from_id(1)
            .expect("hash algorithm")
            .hash(protected_packet)
            .expect("packet hash");
        state
            .insert_integrity(Integrity {
                channel_id: channel_id(),
                packet_number_start: 10,
                packet_hash_count: Some(1),
                packet_hashes: packet_hash,
            })
            .expect("insert integrity");

        let released = state
            .process_authenticated_packet(
                ChannelPacket {
                    channel_id: channel_id(),
                    packet_number: 10,
                    key_sequence: 7,
                    key_phase: false,
                    frames: vec![ChannelFrame::Datagram {
                        data: b"payload".to_vec(),
                    }],
                },
                protected_packet,
            )
            .expect("process packet");

        assert_eq!(released.len(), 1);
        assert_eq!(released[0].data, b"payload");
        assert!(state.pending_ack().is_some());
        assert_eq!(state.pop_datagram(), released.into_iter().next());
    }

    #[test]
    fn protected_channel_packet_releases_after_key_and_integrity() {
        let announce = announce();
        let key = Key {
            channel_id: channel_id(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0x22; 32],
        };
        let mut sender = ChannelSendState::new(announce.clone(), key.clone()).expect("send state");
        let mut out = vec![0; 1200];
        let sent = sender
            .write_packet(
                &[ChannelFrame::Datagram {
                    data: b"payload".to_vec(),
                }],
                &mut out,
            )
            .expect("write channel packet");
        let protected_packet = &out[..sent.packet_len];

        let mut receiver = ChannelReceiveState::new(announce).expect("receive state");
        assert!(
            receiver
                .process_protected_packet(protected_packet)
                .expect("buffer packet")
                .is_empty()
        );
        assert!(receiver.insert_key(key).expect("insert key").is_empty());
        let released = receiver
            .insert_integrity(sent.integrity)
            .expect("insert integrity releases");

        assert_eq!(released.len(), 1);
        assert_eq!(released[0].packet_number, sent.packet_number);
        assert_eq!(released[0].data, b"payload");
        assert_eq!(receiver.pop_datagram(), released.into_iter().next());
        assert!(receiver.pending_ack().is_some());
    }

    #[test]
    fn protected_channel_packet_without_integrity_waits() {
        let announce = announce();
        let key = Key {
            channel_id: channel_id(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0x22; 32],
        };
        let mut sender = ChannelSendState::new(announce.clone(), key.clone()).expect("send state");
        let mut out = vec![0; 1200];
        let sent = sender
            .write_packet(
                &[ChannelFrame::Datagram {
                    data: b"payload".to_vec(),
                }],
                &mut out,
            )
            .expect("write channel packet");

        let mut receiver = ChannelReceiveState::new(announce).expect("receive state");
        receiver.insert_key(key).expect("insert key");
        assert!(
            receiver
                .process_protected_packet(&out[..sent.packet_len])
                .expect("packet waits for integrity")
                .is_empty()
        );
        assert!(receiver.pop_datagram().is_none());
        assert!(receiver.pending_ack().is_none());
    }

    #[test]
    fn protected_channel_packet_rejects_integrity_mismatch() {
        let announce = announce();
        let key = Key {
            channel_id: channel_id(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0x22; 32],
        };
        let mut sender = ChannelSendState::new(announce.clone(), key.clone()).expect("send state");
        let mut out = vec![0; 1200];
        let sent = sender
            .write_packet(
                &[ChannelFrame::Datagram {
                    data: b"payload".to_vec(),
                }],
                &mut out,
            )
            .expect("write channel packet");
        out[sent.packet_len - 1] ^= 0x01;

        let mut receiver = ChannelReceiveState::new(announce).expect("receive state");
        receiver.insert_key(key).expect("insert key");
        receiver
            .insert_integrity(sent.integrity)
            .expect("insert integrity");
        assert_eq!(
            receiver
                .process_protected_packet(&out[..sent.packet_len])
                .unwrap_err(),
            Error::Decrypt
        );
        assert!(receiver.pop_datagram().is_none());
    }

    #[test]
    fn channel_receive_without_integrity_does_not_release() {
        let mut state = ChannelReceiveState::new(announce()).expect("receive state");
        state
            .insert_key(Key {
                channel_id: channel_id(),
                key_sequence: 7,
                from_packet_number: 0,
                secret: vec![0xcc; 32],
            })
            .expect("insert key");

        assert_eq!(
            state
                .process_authenticated_packet(
                    ChannelPacket {
                        channel_id: channel_id(),
                        packet_number: 10,
                        key_sequence: 7,
                        key_phase: false,
                        frames: vec![ChannelFrame::Datagram {
                            data: b"payload".to_vec(),
                        }],
                    },
                    b"protected packet bytes",
                )
                .unwrap_err(),
            Error::NotAvailable
        );
        assert!(state.pop_datagram().is_none());
    }

    #[test]
    fn unsupported_algorithms_are_rejected() {
        let mut unsupported_hash = announce();
        unsupported_hash.integrity_hash_algorithm = 99;
        assert_eq!(
            ChannelReceiveState::new(unsupported_hash).unwrap_err(),
            Error::NotAvailable
        );

        let mut unsupported_aead = announce();
        unsupported_aead.aead_algorithm = 99;
        assert_eq!(
            ChannelReceiveState::new(unsupported_aead).unwrap_err(),
            Error::NotAvailable
        );
    }
}
