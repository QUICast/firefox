// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// the MIT license <LICENSE-MIT>, at your option.

use std::net::{IpAddr, Ipv4Addr};

use neqo_common::event::Provider as _;

use super::{
    super::{
        MAX_AUTHORIZED_MCQUIC_STREAMS, MAX_MCQUIC_ACTIVE_CONTROL_AGE,
        MAX_MCQUIC_ACTIVE_CONTROL_BYTES, MAX_MCQUIC_ACTIVE_CONTROL_FRAMES,
        MAX_MCQUIC_CONNECTION_DATAGRAM_BYTES, MAX_MCQUIC_CONNECTION_DATAGRAMS,
        MAX_MCQUIC_CONNECTION_INTEGRITY_BYTES, MAX_MCQUIC_CONNECTION_INTEGRITY_HASHES,
        MAX_MCQUIC_CONNECTION_KEY_BYTES, MAX_MCQUIC_CONNECTION_KEYS,
        MAX_MCQUIC_CONNECTION_PENDING_PACKET_BYTES, MAX_MCQUIC_CONNECTION_PENDING_PACKETS,
        MAX_MCQUIC_OWNER_EXPIRIES_PER_TURN, MAX_MCQUIC_PENDING_CHANNEL_OWNER_LINKS,
        MAX_MCQUIC_PENDING_CONTROL_AGE, MAX_MCQUIC_RESOURCE_LIMIT_NOTICES,
        MAX_MCQUIC_RETIRED_CHANNEL_AGE, MAX_MCQUIC_RETIRED_CHANNEL_BYTES,
        MAX_MCQUIC_RETIRED_CHANNELS, MAX_MCQUIC_SEND_BYTES, MAX_MCQUIC_SEND_FRAMES,
        MAX_MCQUIC_UNKNOWN_CONTROL_BYTES, MAX_MCQUIC_UNKNOWN_CONTROL_FRAMES,
        MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL, MAX_PENDING_MCQUIC_OPERATION_CONTROL_BYTES,
        MAX_PENDING_MCQUIC_OPERATION_CONTROL_FRAMES, MAX_PENDING_MCQUIC_STREAM_BYTES,
        MAX_PENDING_MCQUIC_STREAM_FRAMES, MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER,
        MAX_PENDING_MCQUIC_STREAM_OWNERS,
    },
    connect, new_client, new_server,
};
use crate::{
    Connection, ConnectionId, ConnectionParameters, Error, StreamId, StreamType,
    frame::{Frame, FrameType},
    mcquic::{
        Announce, ChannelFrame, ChannelPacket, ChannelReceiveState, ChannelSendState, ClientLimits,
        ClientTransportParams, Integrity, Join, Key, OperationState, take_secret_erasure_summary,
    },
    stats::FrameStats,
};

const SERVER_UNI_STREAM: StreamId = StreamId::new(3);
const PREFIX: &[u8; 10] = b"0123456789";

fn active_client() -> Connection {
    let mut client = new_client(
        ConnectionParameters::default()
            .max_data(1024)
            .max_streams(StreamType::UniDi, 16)
            .max_stream_data(StreamType::UniDi, true, 1024)
            .mcquic_client_params(Some(ClientTransportParams::default())),
    );
    client.mcquic_operation_state = OperationState::Active;
    client
}

fn bounded_client(max_channel_ids: u64, max_rate_kibps: u64, max_streams: u64) -> Connection {
    bounded_client_with_families(max_channel_ids, max_rate_kibps, max_streams, true, false)
}

fn bounded_client_with_families(
    max_channel_ids: u64,
    max_rate_kibps: u64,
    max_streams: u64,
    ipv4_channels_allowed: bool,
    ipv6_channels_allowed: bool,
) -> Connection {
    let mut client = new_client(
        ConnectionParameters::default()
            .max_data(32 * 1024 * 1024)
            .max_streams(StreamType::UniDi, max_streams)
            .max_stream_data(StreamType::UniDi, true, 32 * 1024 * 1024)
            .mcquic_client_params(Some(ClientTransportParams {
                limits: ClientLimits {
                    ipv4_channels_allowed,
                    ipv6_channels_allowed,
                    max_aggregate_rate_kibps: max_rate_kibps,
                    max_channel_ids,
                },
                hash_algorithms: vec![1, 8],
                encryption_algorithms: vec![0x1301],
            })),
    );
    client.mcquic_operation_state = OperationState::Active;
    client
}

fn negotiated_bounded_client(
    max_channel_ids: u64,
    max_rate_kibps: u64,
    max_streams: u64,
) -> Connection {
    let mut client = bounded_client(max_channel_ids, max_rate_kibps, max_streams);
    let mut server = new_server(ConnectionParameters::default().mcquic_server_support(true));
    connect(&mut client, &mut server);
    client.mcquic_operation_state = OperationState::Active;
    client
}

fn announce(channel_id: Vec<u8>, max_rate_kibps: u64) -> Announce {
    Announce {
        channel_id,
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        group: IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1)),
        udp_port: 4433,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0x11; 32].into(),
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps,
        max_ack_delay_ms: 25,
    }
}

fn input_unicast(client: &mut Connection, offset: u64, data: &[u8], fin: bool) {
    client
        .streams
        .input_frame(
            &Frame::Stream {
                fin,
                stream_id: SERVER_UNI_STREAM,
                offset,
                data,
                fill: false,
            },
            &mut FrameStats::default(),
        )
        .unwrap();
}

fn multicast_body(data: &[u8]) -> ChannelFrame {
    ChannelFrame::Stream {
        stream_id: SERVER_UNI_STREAM.as_u64(),
        offset: 10,
        fin: true,
        data: data.to_vec(),
    }
}

fn state_frame(channel_id: Vec<u8>, phrase_len: usize) -> crate::mcquic::Frame {
    crate::mcquic::Frame::State(crate::mcquic::State {
        channel_id,
        sequence: 1,
        state: crate::mcquic::ChannelState::Joined,
        reason_scope: crate::mcquic::StateReasonScope::Transport,
        reason_code: crate::mcquic::STATE_REASON_REQUESTED_BY_SERVER,
        reason_phrase: vec![0; phrase_len],
    })
}

fn join_frame(channel_id: Vec<u8>, sequence: u64) -> crate::mcquic::Frame {
    crate::mcquic::Frame::Join(Join {
        channel_id,
        mc_limits_sequence: sequence,
        mc_state_sequence: 0,
        mc_key_sequence: 0,
    })
}

fn key(channel_id: &[u8], key_sequence: u64, secret_len: usize) -> Key {
    Key {
        channel_id: channel_id.to_vec(),
        key_sequence,
        from_packet_number: 0,
        secret: vec![u8::try_from(key_sequence).unwrap_or(0xaa); secret_len].into(),
    }
}

fn integrity_frame_with_encoded_len(channel_id: &[u8], target: usize) -> crate::mcquic::Frame {
    let mut hash_bytes = target;
    loop {
        let frame = crate::mcquic::Frame::Integrity(Integrity {
            channel_id: channel_id.to_vec(),
            packet_number_start: 0,
            packet_hash_count: None,
            packet_hashes: vec![0; hash_bytes],
        });
        let encoded = frame.encoded_len_erasing().expect("encoded integrity");
        if encoded == target {
            return frame;
        }
        hash_bytes = if encoded > target {
            hash_bytes
                .checked_sub(encoded - target)
                .expect("target can hold integrity framing")
        } else {
            hash_bytes
                .checked_add(target - encoded)
                .expect("integrity frame length")
        };
    }
}

fn state_frame_with_encoded_len(channel_id: &[u8], target: usize) -> crate::mcquic::Frame {
    let mut phrase_len = target;
    loop {
        let frame = state_frame(channel_id.to_vec(), phrase_len);
        let encoded = frame.encoded_len_erasing().expect("encoded state");
        if encoded == target {
            return frame;
        }
        phrase_len = if encoded > target {
            phrase_len
                .checked_sub(encoded - target)
                .expect("target can hold state framing")
        } else {
            phrase_len
                .checked_add(target - encoded)
                .expect("state frame length")
        };
    }
}

fn write_padding_packet(sender: &mut ChannelSendState, target: usize) -> Vec<u8> {
    let mut padding = target.saturating_sub(64);
    loop {
        let mut candidate = sender.clone();
        let mut packet = vec![0; target + 64];
        let sent = candidate
            .write_packet(&[ChannelFrame::Padding { len: padding }], &mut packet)
            .expect("encode protected padding packet");
        if sent.packet_len == target {
            *sender = candidate;
            packet.truncate(sent.packet_len);
            return packet;
        }
        padding = if sent.packet_len > target {
            padding
                .checked_sub(sent.packet_len - target)
                .expect("target can hold protected packet framing")
        } else {
            padding
                .checked_add(target - sent.packet_len)
                .expect("padding length")
        };
    }
}

fn pending_packet_channel(channel_id: Vec<u8>, now: std::time::Instant) -> ChannelReceiveState {
    let announcement = announce(channel_id.clone(), 1);
    let mut sender =
        ChannelSendState::new(announcement.clone(), key(&channel_id, 0, 32)).expect("sender");
    let mut receiver = ChannelReceiveState::new(announcement).expect("receiver");
    for _ in 0..1024 {
        let packet = write_padding_packet(&mut sender, 4096);
        assert!(
            receiver
                .process_protected_packet_for_connection(&packet, now)
                .expect("buffer unauthenticated packet")
                .is_empty()
        );
    }
    receiver
}

fn datagram_channel(
    channel_id: Vec<u8>,
    datagram_count: usize,
    datagram_len: usize,
    now: std::time::Instant,
) -> ChannelReceiveState {
    let announcement = announce(channel_id.clone(), 1);
    let key = key(&channel_id, 0, 32);
    let mut sender =
        ChannelSendState::new(announcement.clone(), key.clone()).expect("channel sender");
    let frames = (0..datagram_count)
        .map(|_| ChannelFrame::Datagram {
            data: vec![0x5a; datagram_len],
        })
        .collect::<Vec<_>>();
    let mut receiver = ChannelReceiveState::new(announcement).expect("channel receiver");
    receiver
        .insert_key_for_connection(key, now)
        .expect("install channel key");
    for frame_chunk in frames.chunks(8) {
        let mut packet = vec![0; frame_chunk.len() * (datagram_len + 8) + 128];
        let sent = sender
            .write_packet(frame_chunk, &mut packet)
            .expect("encode DATAGRAM packet");
        packet.truncate(sent.packet_len);
        receiver
            .insert_integrity_for_connection(&sent.integrity, now)
            .expect("install packet integrity");
        assert_eq!(
            receiver
                .process_protected_packet_for_connection(&packet, now)
                .expect("release authenticated DATAGRAMs")
                .len(),
            1
        );
    }
    receiver
}

fn aggregate_channel_usage(
    client: &Connection,
) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
    client
        .mcquic_channels
        .values()
        .map(ChannelReceiveState::resource_usage)
        .fold((0, 0, 0, 0, 0, 0, 0, 0), |mut total, usage| {
            total.0 += usage.keys;
            total.1 += usage.key_bytes;
            total.2 += usage.integrity_hashes;
            total.3 += usage.integrity_bytes;
            total.4 += usage.pending_packets;
            total.5 += usage.pending_packet_bytes;
            total.6 += usage.datagrams;
            total.7 += usage.datagram_bytes;
            total
        })
}

fn assert_recorded_secrets_erased(context: &str) {
    let (count, all_zero) = take_secret_erasure_summary();
    assert!(count > 0, "{context}: expected secret storage to be erased");
    assert!(
        all_zero,
        "{context}: every erased allocation must be zeroed"
    );
}

#[test]
fn stream_waits_for_operation_binding() {
    let mut client = active_client();
    client
        .input_mcquic_channel_frame(multicast_body(b"body"), test_fixture::now())
        .unwrap();

    assert!(client.mcquic_has_pending_stream(SERVER_UNI_STREAM));
    assert!(client.next_event().is_none());

    input_unicast(&mut client, 0, PREFIX, false);
    client
        .mcquic_authorize_stream(SERVER_UNI_STREAM, test_fixture::now())
        .unwrap();

    let mut received = [0; 32];
    let (amount, fin) = client
        .stream_recv(SERVER_UNI_STREAM, &mut received)
        .unwrap();
    assert_eq!(&received[..amount], b"0123456789body");
    assert!(fin);
    assert!(!client.mcquic_has_pending_stream(SERVER_UNI_STREAM));
}

#[test]
fn identical_unicast_overlap_deduplicates_after_binding() {
    let mut client = active_client();
    client
        .input_mcquic_channel_frame(multicast_body(b"same"), test_fixture::now())
        .unwrap();
    input_unicast(&mut client, 0, b"0123456789same", true);

    client
        .mcquic_authorize_stream(SERVER_UNI_STREAM, test_fixture::now())
        .unwrap();
    let mut received = [0; 32];
    let (amount, fin) = client
        .stream_recv(SERVER_UNI_STREAM, &mut received)
        .unwrap();
    assert_eq!(&received[..amount], b"0123456789same");
    assert!(fin);
}

#[test]
fn conflicting_unicast_overlap_fails_at_binding() {
    let mut client = active_client();
    client
        .input_mcquic_channel_frame(multicast_body(b"mc!!"), test_fixture::now())
        .unwrap();
    input_unicast(&mut client, 0, b"0123456789uni!", true);

    assert_eq!(
        client.mcquic_authorize_stream(SERVER_UNI_STREAM, test_fixture::now()),
        Err(Error::ProtocolViolation)
    );
}

#[test]
fn ineligible_stream_ids_revoke_transactionally_and_preserve_unicast() {
    let ineligible_frames = [
        ChannelFrame::Stream {
            stream_id: 2,
            offset: 0,
            fin: false,
            data: b"local-uni".to_vec(),
        },
        ChannelFrame::Stream {
            stream_id: 1,
            offset: 0,
            fin: false,
            data: b"remote-bidi".to_vec(),
        },
        ChannelFrame::ResetStream {
            stream_id: 0,
            error_code: 77,
            final_size: 0,
        },
    ];

    for ineligible in ineligible_frames {
        let now = test_fixture::now();
        let mut client = active_client();
        input_unicast(&mut client, 0, PREFIX, false);
        client
            .mcquic_authorize_stream(SERVER_UNI_STREAM, now)
            .expect("authorize ordinary WebTransport prefix");

        let body = b"ordinary-fallback";
        client
            .process_mcquic_released_packets_with_ownership(
                vec![ChannelPacket {
                    channel_id: b"ownership".to_vec(),
                    packet_number: 0,
                    key_sequence: 0,
                    key_phase: false,
                    frames: vec![
                        ChannelFrame::Stream {
                            stream_id: SERVER_UNI_STREAM.as_u64(),
                            offset: 10,
                            fin: false,
                            data: body.to_vec(),
                        },
                        ineligible,
                    ],
                }],
                now,
            )
            .expect("ownership violation is nonfatal to QUIC");

        assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);
        assert!(client.mcquic_take_ownership_violation());
        assert!(!client.mcquic_take_ownership_violation());

        let mut received = [0; 64];
        assert_eq!(
            client
                .stream_recv(SERVER_UNI_STREAM, &mut received)
                .expect("ordinary prefix remains readable"),
            (PREFIX.len(), false)
        );
        assert_eq!(&received[..PREFIX.len()], PREFIX);

        input_unicast(&mut client, 10, body, true);
        assert_eq!(
            client
                .stream_recv(SERVER_UNI_STREAM, &mut received)
                .expect("ordinary unicast fallback remains usable"),
            (body.len(), true)
        );
        assert_eq!(&received[..body.len()], body);
    }
}

#[test]
fn revocation_discards_unbound_stream_frames() {
    let mut client = active_client();
    client
        .input_mcquic_channel_frame(multicast_body(b"discard"), test_fixture::now())
        .unwrap();
    assert!(client.mcquic_has_pending_stream(SERVER_UNI_STREAM));

    client.mcquic_revoke_operation();

    assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);
    assert!(!client.mcquic_has_pending_stream(SERVER_UNI_STREAM));
    assert_eq!(
        client.mcquic_authorize_stream(SERVER_UNI_STREAM, test_fixture::now()),
        Err(Error::NotAvailable)
    );
}

#[test]
fn retire_discards_only_the_named_channels_unbound_frames_and_secrets() {
    let now = test_fixture::now();
    let mut client = active_client();
    let retired_channel = b"retired-channel".to_vec();
    let other_channel = b"other-channel".to_vec();
    let announce = Announce {
        channel_id: retired_channel.clone(),
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        group: IpAddr::V4(Ipv4Addr::new(233, 252, 0, 1)),
        udp_port: 4433,
        header_protection_algorithm: 0x1301,
        header_secret: vec![0x11; 32].into(),
        aead_algorithm: 0x1301,
        integrity_hash_algorithm: 1,
        max_rate_kibps: 10_000,
        max_ack_delay_ms: 25,
    };
    client.mcquic_channels.insert(
        retired_channel.clone(),
        ChannelReceiveState::new(announce).unwrap(),
    );
    client
        .mcquic_integrity_hash_lens
        .insert(retired_channel.clone(), 32);
    client
        .mcquic_pending_channel_controls
        .entry(retired_channel.clone())
        .or_default()
        .push_back(crate::mcquic::Frame::Integrity(Integrity {
            channel_id: retired_channel.clone(),
            packet_number_start: 0,
            packet_hash_count: Some(1),
            packet_hashes: vec![0x33; 32],
        }));

    client
        .queue_or_input_mcquic_stream_frame(
            multicast_body(b"retire-me"),
            Some(&retired_channel),
            now,
        )
        .unwrap();
    client
        .queue_or_input_mcquic_stream_frame(multicast_body(b"keep-me"), Some(&other_channel), now)
        .unwrap();
    assert_eq!(client.mcquic_pending_channel_owner_links, 2);

    client.retire_mcquic_channel_state(&retired_channel, now);

    assert!(!client.mcquic_channels.contains_key(&retired_channel));
    assert!(
        !client
            .mcquic_integrity_hash_lens
            .contains_key(&retired_channel)
    );
    assert!(
        !client
            .mcquic_pending_channel_controls
            .contains_key(&retired_channel)
    );
    let remaining = client
        .mcquic_pending_stream_frames
        .get(&SERVER_UNI_STREAM)
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].channel_id.as_deref(),
        Some(other_channel.as_slice())
    );
    assert_eq!(client.mcquic_pending_stream_frame_count, 1);
    assert_eq!(client.mcquic_pending_stream_bytes, b"keep-me".len());
    assert_eq!(client.mcquic_pending_channel_owner_links, 1);
    assert!(
        !client
            .mcquic_pending_channel_streams
            .contains_key(&retired_channel)
    );
    assert_eq!(
        client.mcquic_pending_channel_streams[&other_channel],
        [SERVER_UNI_STREAM].into_iter().collect()
    );
}

#[test]
fn channel_count_family_and_aggregate_rate_caps_are_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 16);
    for index in 0..32 {
        client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Announce(announce(
                    format!("channel-{index}").into_bytes(),
                    0,
                )),
                now,
            )
            .expect("channel at cap");
    }
    assert_eq!(client.mcquic_channels.len(), 32);

    let mut with_pending = bounded_client(1, 100_000, 16);
    let pending_channel = b"pending".to_vec();
    with_pending
        .queue_unknown_mcquic_control(
            &pending_channel,
            crate::mcquic::Frame::Key(Key {
                channel_id: pending_channel.clone(),
                key_sequence: 0,
                from_packet_number: 0,
                secret: vec![0x22; 32].into(),
            }),
            now,
        )
        .expect("one pending channel");
    with_pending
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(pending_channel, 1)),
            now,
        )
        .expect("matching announcement must not double-count its pending ID");
    assert_eq!(
        client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Announce(announce(b"channel-over-cap".to_vec(), 0,)),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
    assert_eq!(client.mcquic_channels.len(), 32);

    let mut client = bounded_client(32, 100_000, 16);
    client
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(b"rate-a".to_vec(), 40_000)),
            now,
        )
        .expect("first rate");
    client
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(b"rate-b".to_vec(), 60_000)),
            now,
        )
        .expect("aggregate rate at cap");
    assert_eq!(
        client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Announce(announce(b"rate-c".to_vec(), 1)),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
    assert_eq!(client.mcquic_channels.len(), 2);

    let mut ipv6 = announce(b"ipv6".to_vec(), 1);
    ipv6.source = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    ipv6.group = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    assert_eq!(
        client
            .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(ipv6), now,)
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut mismatched = announce(b"mixed-v4-v6".to_vec(), 1);
    mismatched.group = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    assert_eq!(
        client
            .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(mismatched), now,)
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut mismatched = announce(b"mixed-v6-v4".to_vec(), 1);
    mismatched.source = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
    assert_eq!(
        client
            .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(mismatched), now,)
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut ipv6_client = bounded_client_with_families(32, 100_000, 16, false, true);
    assert_eq!(
        ipv6_client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Announce(announce(b"ipv4-denied".to_vec(), 1)),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
    let mut ipv6 = announce(b"ipv6-allowed".to_vec(), 1);
    ipv6.source = IpAddr::V6("2001:db8::1".parse().expect("IPv6 source"));
    ipv6.group = IpAddr::V6("ff3e::1".parse().expect("IPv6 group"));
    ipv6_client
        .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(ipv6), now)
        .expect("IPv6 policy allows matching source and group");
}

#[test]
fn unknown_control_and_tombstone_caps_are_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 16);
    let channel_id = b"unknown".to_vec();
    for sequence in 0..MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL {
        client
            .queue_unknown_mcquic_control(
                &channel_id,
                crate::mcquic::Frame::Key(Key {
                    channel_id: channel_id.clone(),
                    key_sequence: u64::try_from(sequence).expect("sequence"),
                    from_packet_number: 0,
                    secret: vec![0x22; 32].into(),
                }),
                now,
            )
            .expect("unknown control at per-channel cap");
    }
    assert_eq!(
        client
            .queue_unknown_mcquic_control(
                &channel_id,
                crate::mcquic::Frame::Key(Key {
                    channel_id: channel_id.clone(),
                    key_sequence: u64::try_from(MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL)
                        .expect("sequence"),
                    from_packet_number: 0,
                    secret: vec![0x22; 32].into(),
                }),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut client = bounded_client(32, 100_000, 16);
    for index in 0..MAX_MCQUIC_UNKNOWN_CONTROL_FRAMES {
        let channel = format!(
            "unknown-{}",
            index / MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL
        )
        .into_bytes();
        client
            .queue_unknown_mcquic_control(
                &channel,
                crate::mcquic::Frame::Key(Key {
                    channel_id: channel.clone(),
                    key_sequence: u64::try_from(index).expect("sequence"),
                    from_packet_number: 0,
                    secret: vec![0x22; 32].into(),
                }),
                now,
            )
            .expect("unknown control at aggregate cap");
    }
    assert_eq!(client.mcquic_pending_channel_control_count, 256);
    assert_eq!(
        client
            .queue_unknown_mcquic_control(
                b"unknown-over-cap",
                crate::mcquic::Frame::Key(Key {
                    channel_id: b"unknown-over-cap".to_vec(),
                    key_sequence: 257,
                    from_packet_number: 0,
                    secret: vec![0x22; 32].into(),
                }),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut client = bounded_client(32, 100_000, 16);
    for index in 0..MAX_MCQUIC_RETIRED_CHANNELS {
        client.retire_mcquic_channel_state(format!("retired-{index}").as_bytes(), now);
        assert_eq!(client.mcquic_operation_state(), OperationState::Active);
    }
    assert_eq!(
        client.mcquic_retired_channels.len(),
        MAX_MCQUIC_RETIRED_CHANNELS
    );
    client.retire_mcquic_channel_state(b"retired-over-cap", now);
    assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(Vec::new())
    );

    let mut client = bounded_client(32, 100_000, 16);
    client.retire_mcquic_channel_state(b"expires", now);
    client.expire_mcquic_resources(
        now + MAX_MCQUIC_RETIRED_CHANNEL_AGE - std::time::Duration::from_nanos(1),
    );
    assert_eq!(client.mcquic_operation_state(), OperationState::Active);
    client.expire_mcquic_resources(now + MAX_MCQUIC_RETIRED_CHANNEL_AGE);
    assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);

    assert!(
        MAX_MCQUIC_RETIRED_CHANNELS * ConnectionId::MAX_LEN < MAX_MCQUIC_RETIRED_CHANNEL_BYTES,
        "valid channel IDs hit the tombstone count cap before the byte cap"
    );

    let mut client = bounded_client(32, 100_000, 16);
    for index in 0..MAX_MCQUIC_RESOURCE_LIMIT_NOTICES {
        client.limit_mcquic_channel(format!("notice-{index}").as_bytes(), now);
    }
    assert_eq!(
        client.mcquic_resource_limited_channels.len(),
        MAX_MCQUIC_RESOURCE_LIMIT_NOTICES
    );
    client.limit_mcquic_channel(b"notice-over-cap", now);
    assert_eq!(
        client.mcquic_resource_limited_channels.len(),
        MAX_MCQUIC_RESOURCE_LIMIT_NOTICES
    );
}

#[test]
fn pending_control_byte_caps_and_expiry_are_exact() {
    let now = test_fixture::now();
    let channel_id = b"unknown-bytes";
    let mut client = bounded_client(32, 100_000, 16);
    let at_cap = integrity_frame_with_encoded_len(channel_id, MAX_MCQUIC_UNKNOWN_CONTROL_BYTES);
    client
        .queue_unknown_mcquic_control(channel_id, at_cap, now)
        .expect("unknown control bytes at cap");
    assert_eq!(
        client.mcquic_pending_channel_control_bytes,
        MAX_MCQUIC_UNKNOWN_CONTROL_BYTES
    );
    assert_eq!(
        client
            .queue_unknown_mcquic_control(
                channel_id,
                crate::mcquic::Frame::Key(key(channel_id, 1, 1)),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut client = bounded_client(32, 100_000, 16);
    client
        .queue_unknown_mcquic_control(
            channel_id,
            crate::mcquic::Frame::Key(key(channel_id, 0, 1)),
            now,
        )
        .expect("queue expiring unknown control");
    client.expire_mcquic_resources(
        now + MAX_MCQUIC_PENDING_CONTROL_AGE - std::time::Duration::from_nanos(1),
    );
    assert_eq!(client.mcquic_pending_channel_control_count, 1);
    client.expire_mcquic_resources(now + MAX_MCQUIC_PENDING_CONTROL_AGE);
    assert_eq!(client.mcquic_pending_channel_control_count, 0);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(channel_id.to_vec())
    );

    let mut client = bounded_client(32, 100_000, 16);
    client.mcquic_operation_state = OperationState::Pending;
    let at_cap = state_frame_with_encoded_len(
        b"pending-operation",
        MAX_PENDING_MCQUIC_OPERATION_CONTROL_BYTES,
    );
    client
        .queue_pending_mcquic_operation_control(at_cap, now)
        .expect("pre-accept control bytes at cap");
    assert_eq!(
        client.mcquic_pending_operation_control_bytes,
        MAX_PENDING_MCQUIC_OPERATION_CONTROL_BYTES
    );
    client
        .queue_pending_mcquic_operation_control(state_frame(b"pending-operation".to_vec(), 0), now)
        .expect("overflow declines without failing ordinary transport");
    assert_eq!(client.mcquic_operation_state(), OperationState::Prohibited);
    assert!(client.mcquic_pending_operation_controls.is_empty());
    assert_eq!(client.mcquic_pending_operation_control_bytes, 0);

    let mut client = bounded_client(32, 100_000, 16);
    client.mcquic_operation_state = OperationState::Pending;
    client
        .queue_pending_mcquic_operation_control(state_frame(b"expires".to_vec(), 0), now)
        .expect("queue pre-accept control");
    client.expire_mcquic_resources(
        now + MAX_MCQUIC_PENDING_CONTROL_AGE - std::time::Duration::from_nanos(1),
    );
    assert_eq!(client.mcquic_operation_state(), OperationState::Pending);
    client.expire_mcquic_resources(now + MAX_MCQUIC_PENDING_CONTROL_AGE);
    assert_eq!(client.mcquic_operation_state(), OperationState::Prohibited);
}

#[test]
fn active_receive_control_count_byte_and_expiry_caps_are_exact() {
    let now = test_fixture::now();
    let mut client = negotiated_bounded_client(32, 100_000, 16);
    for sequence in 0..MAX_MCQUIC_ACTIVE_CONTROL_FRAMES {
        client
            .input_mcquic_frame(
                join_frame(
                    b"active-count".to_vec(),
                    u64::try_from(sequence).expect("sequence"),
                ),
                now,
            )
            .expect("active receive control at count cap");
    }
    let bytes_at_count_cap = client.mcquic_recv_bytes;
    assert_eq!(client.mcquic_recv.len(), MAX_MCQUIC_ACTIVE_CONTROL_FRAMES);
    client
        .input_mcquic_frame(join_frame(b"active-count-over".to_vec(), 0), now)
        .expect("over-cap active control is declined channel-locally");
    assert_eq!(client.mcquic_recv.len(), MAX_MCQUIC_ACTIVE_CONTROL_FRAMES);
    assert_eq!(client.mcquic_recv_bytes, bytes_at_count_cap);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(b"active-count-over".to_vec())
    );

    let mut client = negotiated_bounded_client(32, 100_000, 16);
    let at_byte_cap =
        integrity_frame_with_encoded_len(b"active-bytes", MAX_MCQUIC_ACTIVE_CONTROL_BYTES);
    client
        .input_mcquic_frame(at_byte_cap, now)
        .expect("active receive bytes at cap");
    assert_eq!(client.mcquic_recv.len(), 1);
    assert_eq!(client.mcquic_recv_bytes, MAX_MCQUIC_ACTIVE_CONTROL_BYTES);
    client
        .input_mcquic_frame(join_frame(b"active-bytes-over".to_vec(), 0), now)
        .expect("over-cap active bytes are declined channel-locally");
    assert_eq!(client.mcquic_recv.len(), 1);
    assert_eq!(client.mcquic_recv_bytes, MAX_MCQUIC_ACTIVE_CONTROL_BYTES);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(b"active-bytes-over".to_vec())
    );

    let mut client = negotiated_bounded_client(32, 100_000, 16);
    client
        .input_mcquic_frame(join_frame(b"active-expiry".to_vec(), 0), now)
        .expect("queue active receive control");
    client.expire_mcquic_resources(
        now + MAX_MCQUIC_ACTIVE_CONTROL_AGE - std::time::Duration::from_nanos(1),
    );
    assert_eq!(client.mcquic_recv.len(), 1);
    client.expire_mcquic_resources(now + MAX_MCQUIC_ACTIVE_CONTROL_AGE);
    assert!(client.mcquic_recv.is_empty());
    assert_eq!(client.mcquic_recv_bytes, 0);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(b"active-expiry".to_vec())
    );
    input_unicast(&mut client, 0, b"ordinary-unicast", true);
}

#[test]
fn pending_operation_control_count_cap_is_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 16);
    client.mcquic_operation_state = OperationState::Pending;
    for sequence in 0..MAX_PENDING_MCQUIC_OPERATION_CONTROL_FRAMES {
        client
            .queue_pending_mcquic_operation_control(
                state_frame(
                    b"pending-count".to_vec(),
                    usize::from(u8::try_from(sequence % 2).expect("small phrase")),
                ),
                now,
            )
            .expect("pending operation control at count cap");
    }
    assert_eq!(
        client.mcquic_pending_operation_controls.len(),
        MAX_PENDING_MCQUIC_OPERATION_CONTROL_FRAMES
    );
    client
        .queue_pending_mcquic_operation_control(state_frame(b"pending-count-over".to_vec(), 0), now)
        .expect("overflow declines the optimization");
    assert_eq!(client.mcquic_operation_state(), OperationState::Prohibited);
    assert!(client.mcquic_pending_operation_controls.is_empty());
    assert_eq!(client.mcquic_pending_operation_control_bytes, 0);
    input_unicast(&mut client, 0, b"ordinary-unicast", true);
}

#[test]
fn aggregate_key_and_integrity_caps_are_exact_and_channel_local() {
    let now = test_fixture::now();
    let mut client = negotiated_bounded_client(32, 100_000, 16);
    for channel_index in 0..16 {
        let channel_id = format!("key-{channel_index}").into_bytes();
        client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Announce(announce(channel_id.clone(), 1)),
                now,
            )
            .expect("announce key channel");
        for sequence in 0..4 {
            client
                .apply_mcquic_channel_control(
                    &crate::mcquic::Frame::Key(key(&channel_id, sequence, 64)),
                    now,
                )
                .expect("key at aggregate cap");
        }
    }
    let key_usage = client
        .mcquic_channels
        .values()
        .map(ChannelReceiveState::resource_usage)
        .fold((0, 0), |(keys, bytes), usage| {
            (keys + usage.keys, bytes + usage.key_bytes)
        });
    assert_eq!(
        key_usage,
        (MAX_MCQUIC_CONNECTION_KEYS, MAX_MCQUIC_CONNECTION_KEY_BYTES)
    );
    assert!(client.mcquic_channel_resources_within_limits());
    let usage_at_key_cap = aggregate_channel_usage(&client);

    let over_key_channel = b"key-over".to_vec();
    client
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(over_key_channel.clone(), 1)),
            now,
        )
        .expect("announce over-cap key channel");
    client
        .input_mcquic_frame(
            crate::mcquic::Frame::Key(key(&over_key_channel, 0, 64)),
            now,
        )
        .expect("public control path declines only the over-cap key channel");
    assert!(client.mcquic_channel_resources_within_limits());
    assert!(!client.mcquic_channels.contains_key(&over_key_channel));
    assert_eq!(aggregate_channel_usage(&client), usage_at_key_cap);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(over_key_channel)
    );

    let mut client = negotiated_bounded_client(32, 100_000, 16);
    for channel_index in 0..8 {
        let channel_id = format!("integrity-{channel_index}").into_bytes();
        let mut announcement = announce(channel_id.clone(), 1);
        announcement.integrity_hash_algorithm = 8;
        client
            .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(announcement), now)
            .expect("announce integrity channel");
        client
            .apply_mcquic_channel_control(
                &crate::mcquic::Frame::Integrity(Integrity {
                    channel_id,
                    packet_number_start: 0,
                    packet_hash_count: Some(4096),
                    packet_hashes: vec![0; 4096 * 64],
                }),
                now,
            )
            .expect("integrity hashes at aggregate cap");
    }
    let integrity_usage = client
        .mcquic_channels
        .values()
        .map(ChannelReceiveState::resource_usage)
        .fold((0, 0), |(hashes, bytes), usage| {
            (
                hashes + usage.integrity_hashes,
                bytes + usage.integrity_bytes,
            )
        });
    assert_eq!(
        integrity_usage,
        (
            MAX_MCQUIC_CONNECTION_INTEGRITY_HASHES,
            MAX_MCQUIC_CONNECTION_INTEGRITY_BYTES
        )
    );
    assert!(client.mcquic_channel_resources_within_limits());
    let usage_at_integrity_cap = aggregate_channel_usage(&client);

    let over_integrity_channel = b"integrity-over".to_vec();
    let mut announcement = announce(over_integrity_channel.clone(), 1);
    announcement.integrity_hash_algorithm = 8;
    client
        .apply_mcquic_channel_control(&crate::mcquic::Frame::Announce(announcement), now)
        .expect("announce over-cap integrity channel");
    client
        .input_mcquic_frame(
            crate::mcquic::Frame::Integrity(Integrity {
                channel_id: over_integrity_channel.clone(),
                packet_number_start: 0,
                packet_hash_count: Some(1),
                packet_hashes: vec![0; 64],
            }),
            now,
        )
        .expect("public control path declines only the over-cap integrity channel");
    assert!(client.mcquic_channel_resources_within_limits());
    assert!(!client.mcquic_channels.contains_key(&over_integrity_channel));
    assert_eq!(aggregate_channel_usage(&client), usage_at_integrity_cap);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(over_integrity_channel)
    );
}

#[test]
fn aggregate_packet_and_datagram_caps_are_exact_and_channel_local() {
    let now = test_fixture::now();
    let mut client = negotiated_bounded_client(32, 100_000, 16);
    for channel_index in 0..4 {
        let channel_id = format!("packets-{channel_index}").into_bytes();
        client
            .mcquic_channels
            .insert(channel_id.clone(), pending_packet_channel(channel_id, now));
    }
    let pending_usage = client
        .mcquic_channels
        .values()
        .map(ChannelReceiveState::resource_usage)
        .fold((0, 0), |(packets, bytes), usage| {
            (
                packets + usage.pending_packets,
                bytes + usage.pending_packet_bytes,
            )
        });
    assert_eq!(
        pending_usage,
        (
            MAX_MCQUIC_CONNECTION_PENDING_PACKETS,
            MAX_MCQUIC_CONNECTION_PENDING_PACKET_BYTES
        )
    );
    assert!(client.mcquic_channel_resources_within_limits());
    let usage_at_packet_cap = aggregate_channel_usage(&client);
    let over_packet_channel = b"packets-over".to_vec();
    let announcement = announce(over_packet_channel.clone(), 1);
    let mut sender = ChannelSendState::new(announcement.clone(), key(&over_packet_channel, 0, 32))
        .expect("over-cap sender");
    let over_state = ChannelReceiveState::new(announcement).expect("over-cap receiver");
    let packet = write_padding_packet(&mut sender, 4096);
    client
        .mcquic_channels
        .insert(over_packet_channel.clone(), over_state);
    assert_eq!(
        client.mcquic_process_channel_packet(&over_packet_channel, &packet, now),
        Err(Error::McquicResourceLimit)
    );
    assert!(client.mcquic_channel_resources_within_limits());
    assert!(!client.mcquic_channels.contains_key(&over_packet_channel));
    assert_eq!(aggregate_channel_usage(&client), usage_at_packet_cap);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(over_packet_channel)
    );

    let mut client = negotiated_bounded_client(32, 100_000, 16);
    for channel_index in 0..4 {
        let channel_id = format!("datagrams-{channel_index}").into_bytes();
        client.mcquic_channels.insert(
            channel_id.clone(),
            datagram_channel(channel_id, 64, 4096, now),
        );
    }
    let datagram_usage = client
        .mcquic_channels
        .values()
        .map(ChannelReceiveState::resource_usage)
        .fold((0, 0), |(datagrams, bytes), usage| {
            (datagrams + usage.datagrams, bytes + usage.datagram_bytes)
        });
    assert_eq!(
        datagram_usage,
        (
            MAX_MCQUIC_CONNECTION_DATAGRAMS,
            MAX_MCQUIC_CONNECTION_DATAGRAM_BYTES
        )
    );
    assert!(client.mcquic_channel_resources_within_limits());
    let usage_at_datagram_cap = aggregate_channel_usage(&client);
    let over_datagram_channel = b"datagrams-over".to_vec();
    let over_announcement = announce(over_datagram_channel.clone(), 1);
    let over_key = key(&over_datagram_channel, 0, 32);
    let mut sender =
        ChannelSendState::new(over_announcement.clone(), over_key.clone()).expect("sender");
    let mut packet = vec![0; 1200];
    let sent = sender
        .write_packet(&[ChannelFrame::Datagram { data: vec![0x5a] }], &mut packet)
        .expect("encode over-cap datagram");
    packet.truncate(sent.packet_len);
    let mut over_state =
        ChannelReceiveState::new(over_announcement).expect("over-cap datagram receiver");
    over_state
        .insert_key_for_connection(over_key, now)
        .expect("install over-cap datagram key");
    over_state
        .insert_integrity_for_connection(&sent.integrity, now)
        .expect("install over-cap datagram integrity");
    client
        .mcquic_channels
        .insert(over_datagram_channel.clone(), over_state);
    assert_eq!(
        client.mcquic_process_channel_packet(&over_datagram_channel, &packet, now),
        Err(Error::McquicResourceLimit)
    );
    assert!(client.mcquic_channel_resources_within_limits());
    assert!(!client.mcquic_channels.contains_key(&over_datagram_channel));
    assert_eq!(aggregate_channel_usage(&client), usage_at_datagram_cap);
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(over_datagram_channel)
    );
}

#[test]
fn connection_secret_lifecycle_erases_every_queue_and_channel_owner() {
    let now = test_fixture::now();

    let mut client = bounded_client(32, 100_000, 16);
    let revoke_channel = b"secret-revoke".to_vec();
    client
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(revoke_channel.clone(), 1)),
            now,
        )
        .expect("announce revoke channel");
    client
        .apply_mcquic_channel_control(&crate::mcquic::Frame::Key(key(&revoke_channel, 0, 32)), now)
        .expect("install revoke key");
    let _ = take_secret_erasure_summary();
    client.mcquic_revoke_operation();
    assert!(client.mcquic_channels.is_empty());
    assert_recorded_secrets_erased("operation revoke");

    let mut client = bounded_client(32, 100_000, 16);
    let retire_channel = b"secret-retire".to_vec();
    client
        .apply_mcquic_channel_control(
            &crate::mcquic::Frame::Announce(announce(retire_channel.clone(), 1)),
            now,
        )
        .expect("announce retire channel");
    client
        .apply_mcquic_channel_control(&crate::mcquic::Frame::Key(key(&retire_channel, 0, 32)), now)
        .expect("install retire key");
    let _ = take_secret_erasure_summary();
    client.retire_mcquic_channel_state(&retire_channel, now);
    assert!(!client.mcquic_channels.contains_key(&retire_channel));
    assert_recorded_secrets_erased("channel retirement");

    let mut client = bounded_client(32, 100_000, 16);
    client.mcquic_operation_state = OperationState::Pending;
    let pending_channel = b"secret-pending".to_vec();
    client
        .queue_pending_mcquic_operation_control(
            crate::mcquic::Frame::Announce(announce(pending_channel.clone(), 1)),
            now,
        )
        .expect("queue pending announcement");
    client
        .queue_pending_mcquic_operation_control(
            crate::mcquic::Frame::Key(key(&pending_channel, 0, 32)),
            now,
        )
        .expect("queue pending key");
    let _ = take_secret_erasure_summary();
    client.decline_pending_mcquic_operation();
    assert!(client.mcquic_pending_operation_controls.is_empty());
    assert_recorded_secrets_erased("pre-accept decline");

    let mut client = bounded_client(32, 100_000, 16);
    let unknown_channel = b"secret-unknown".to_vec();
    client
        .queue_unknown_mcquic_control(
            &unknown_channel,
            crate::mcquic::Frame::Key(key(&unknown_channel, 0, 32)),
            now,
        )
        .expect("queue unknown key");
    let _ = take_secret_erasure_summary();
    client.limit_mcquic_channel(&unknown_channel, now);
    assert!(client.mcquic_pending_channel_controls.is_empty());
    assert_recorded_secrets_erased("unknown control retirement");

    let mut server = new_server(ConnectionParameters::default().mcquic_server_support(true));
    let mut client = new_client(
        ConnectionParameters::default()
            .mcquic_client_params(Some(ClientTransportParams::default())),
    );
    connect(&mut client, &mut server);
    server.mcquic_operation_state = OperationState::Active;
    server
        .mcquic_send(crate::mcquic::Frame::Announce(announce(
            b"secret-outbound".to_vec(),
            1,
        )))
        .expect("queue outbound secret-bearing control");
    let _ = take_secret_erasure_summary();
    drop(server);
    assert_recorded_secrets_erased("outbound control drop");
}

#[test]
fn ownership_caps_incremental_queue_and_retirement_are_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(
        32,
        100_000,
        u64::try_from(MAX_AUTHORIZED_MCQUIC_STREAMS + 2).expect("stream count"),
    );

    for ordinal in 0..MAX_PENDING_MCQUIC_STREAM_OWNERS {
        let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::ResetStream {
                    stream_id: stream_id.as_u64(),
                    error_code: 0,
                    final_size: 0,
                },
                Some(b"owners"),
                now,
            )
            .expect("owner at cap");
    }
    assert_eq!(
        client.mcquic_pending_stream_frames.len(),
        MAX_PENDING_MCQUIC_STREAM_OWNERS
    );
    let over_cap =
        StreamId::new(3 + u64::try_from(MAX_PENDING_MCQUIC_STREAM_OWNERS).expect("ordinal") * 4);
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::ResetStream {
                    stream_id: over_cap.as_u64(),
                    error_code: 0,
                    final_size: 0,
                },
                Some(b"owners"),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    for ordinal in 0..MAX_PENDING_MCQUIC_STREAM_OWNERS {
        let expected = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        assert_eq!(client.mcquic_take_pending_stream_owner(), Some(expected));
    }
    assert_eq!(client.mcquic_take_pending_stream_owner(), None);

    client.mcquic_revoke_operation();
    client.mcquic_operation_state = OperationState::Active;
    for ordinal in 0..MAX_AUTHORIZED_MCQUIC_STREAMS {
        let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        client
            .mcquic_authorize_stream(stream_id, now)
            .expect("authorized owner at cap");
    }
    assert_eq!(
        client.mcquic_authorized_streams.len(),
        MAX_AUTHORIZED_MCQUIC_STREAMS
    );
    let over_cap =
        StreamId::new(3 + u64::try_from(MAX_AUTHORIZED_MCQUIC_STREAMS).expect("ordinal") * 4);
    client
        .mcquic_authorize_stream(over_cap, now)
        .expect("ownership exhaustion revokes only the optimization");
    assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);

    let mut client = bounded_client(
        32,
        100_000,
        u64::try_from(MAX_AUTHORIZED_MCQUIC_STREAMS + 2).expect("stream count"),
    );
    for ordinal in 0..MAX_AUTHORIZED_MCQUIC_STREAMS {
        let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        client
            .mcquic_authorize_stream(stream_id, now)
            .expect("authorized owner at cap");
    }
    let retired = StreamId::new(3);
    client.mcquic_retire_stream(retired);
    client
        .mcquic_authorize_stream(over_cap, now)
        .expect("retirement releases one owner slot");
    assert!(!client.mcquic_authorized_streams.contains_key(&retired));

    let expired = StreamId::new(7);
    client
        .set_mcquic_authorized_stream(expired, now - super::super::MAX_MCQUIC_AUTHORIZED_OWNER_AGE)
        .expect("refresh authorized owner with an expired deadline");
    client.expire_mcquic_resources(now);
    assert_eq!(client.mcquic_operation_state(), OperationState::Revoked);
}

#[test]
fn owner_churn_releases_deadlines_checks_and_reverse_links() {
    const CYCLES: usize = 3;
    let now = test_fixture::now();
    let max_streams =
        u64::try_from(CYCLES * MAX_PENDING_MCQUIC_STREAM_OWNERS + 1).expect("stream count");
    let mut client = bounded_client(32, 100_000, max_streams);

    for cycle in 0..CYCLES {
        let channel_id = format!("owner-churn-{cycle}").into_bytes();
        let first_ordinal = cycle * MAX_PENDING_MCQUIC_STREAM_OWNERS;
        for ordinal in first_ordinal..first_ordinal + MAX_PENDING_MCQUIC_STREAM_OWNERS {
            let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
            client
                .queue_or_input_mcquic_stream_frame(
                    ChannelFrame::ResetStream {
                        stream_id: stream_id.as_u64(),
                        error_code: 0,
                        final_size: 0,
                    },
                    Some(&channel_id),
                    now,
                )
                .expect("owner at cap after prior churn");
        }

        assert_eq!(
            client.mcquic_pending_stream_frames.len(),
            MAX_PENDING_MCQUIC_STREAM_OWNERS
        );
        assert_eq!(
            client.mcquic_pending_owner_checks.len(),
            MAX_PENDING_MCQUIC_STREAM_OWNERS
        );
        assert_eq!(
            client.mcquic_pending_owner_expiries.len(),
            MAX_PENDING_MCQUIC_STREAM_OWNERS
        );
        assert_eq!(
            client.mcquic_pending_channel_owner_links,
            MAX_PENDING_MCQUIC_STREAM_OWNERS
        );

        for ordinal in first_ordinal..first_ordinal + MAX_PENDING_MCQUIC_STREAM_OWNERS {
            let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
            client.mcquic_retire_stream(stream_id);
        }
        assert!(client.mcquic_pending_stream_frames.is_empty());
        assert!(client.mcquic_pending_owner_checks.is_empty());
        assert!(client.mcquic_pending_owner_expiries.is_empty());
        assert!(client.mcquic_pending_channel_streams.is_empty());
        assert_eq!(client.mcquic_pending_channel_owner_links, 0);
        assert_eq!(client.mcquic_pending_stream_frame_count, 0);
        assert_eq!(client.mcquic_pending_stream_bytes, 0);
    }
}

#[test]
fn pending_stream_byte_cap_is_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 2);
    client
        .queue_or_input_mcquic_stream_frame(
            ChannelFrame::Stream {
                stream_id: SERVER_UNI_STREAM.as_u64(),
                offset: 10,
                fin: false,
                data: vec![0; MAX_PENDING_MCQUIC_STREAM_BYTES],
            },
            Some(b"stream-bytes"),
            now,
        )
        .expect("pending stream data at byte cap");
    assert_eq!(
        client.mcquic_pending_stream_bytes,
        MAX_PENDING_MCQUIC_STREAM_BYTES
    );
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::Stream {
                    stream_id: SERVER_UNI_STREAM.as_u64(),
                    offset: 10 + u64::try_from(MAX_PENDING_MCQUIC_STREAM_BYTES).expect("offset"),
                    fin: false,
                    data: vec![0],
                },
                Some(b"stream-bytes"),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
}

#[test]
fn pending_stream_transport_flow_control_is_distinct_from_local_cap() {
    let now = test_fixture::now();
    let mut client = new_client(
        ConnectionParameters::default()
            .max_data(1024)
            .max_streams(StreamType::UniDi, 2)
            .max_stream_data(StreamType::UniDi, true, 2048)
            .mcquic_client_params(Some(ClientTransportParams::default())),
    );
    client.mcquic_operation_state = OperationState::Active;
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::Stream {
                    stream_id: SERVER_UNI_STREAM.as_u64(),
                    offset: 10,
                    fin: false,
                    data: vec![0; 1025],
                },
                Some(b"flow-control"),
                now,
            )
            .unwrap_err(),
        Error::FlowControl
    );
}

#[test]
fn pending_stream_per_owner_frame_cap_is_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 2);
    for offset in 0..MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER {
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::Stream {
                    stream_id: SERVER_UNI_STREAM.as_u64(),
                    offset: 10 + u64::try_from(offset).expect("offset"),
                    fin: false,
                    data: vec![0],
                },
                Some(b"frame-count"),
                now,
            )
            .expect("frame at per-owner cap");
    }
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::Stream {
                    stream_id: SERVER_UNI_STREAM.as_u64(),
                    offset: 10
                        + u64::try_from(MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER,)
                            .expect("offset"),
                    fin: false,
                    data: vec![0],
                },
                Some(b"frame-count"),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
}

#[test]
fn pending_stream_aggregate_frame_and_owner_link_caps_are_exact() {
    let now = test_fixture::now();
    let mut client = bounded_client(32, 100_000, 1025);
    let owners_for_frame_cap =
        MAX_PENDING_MCQUIC_STREAM_FRAMES / MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER + 1;
    for ordinal in 0..owners_for_frame_cap {
        let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        let frames = if ordinal + 1 == owners_for_frame_cap {
            MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER
        } else {
            MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER - 1
        };
        for _ in 0..frames {
            client
                .queue_or_input_mcquic_stream_frame(
                    ChannelFrame::ResetStream {
                        stream_id: stream_id.as_u64(),
                        error_code: 0,
                        final_size: 0,
                    },
                    Some(b"frame-cap"),
                    now,
                )
                .expect("pending frame at aggregate cap");
        }
    }
    assert_eq!(
        client.mcquic_pending_stream_frame_count,
        MAX_PENDING_MCQUIC_STREAM_FRAMES
    );
    let owner = StreamId::new(3);
    let frame_state = (
        client.mcquic_pending_stream_frames.len(),
        client.mcquic_pending_stream_frame_count,
        client.mcquic_pending_stream_bytes,
        client.mcquic_pending_channel_owner_links,
    );
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::ResetStream {
                    stream_id: owner.as_u64(),
                    error_code: 0,
                    final_size: 0,
                },
                Some(b"frame-cap"),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
    assert_eq!(
        (
            client.mcquic_pending_stream_frames.len(),
            client.mcquic_pending_stream_frame_count,
            client.mcquic_pending_stream_bytes,
            client.mcquic_pending_channel_owner_links,
        ),
        frame_state
    );

    let mut client = bounded_client(32, 100_000, 1025);
    for channel in 0..32 {
        let channel_id = format!("owner-link-{channel}");
        for ordinal in 0..MAX_PENDING_MCQUIC_STREAM_OWNERS {
            let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
            client
                .queue_or_input_mcquic_stream_frame(
                    ChannelFrame::ResetStream {
                        stream_id: stream_id.as_u64(),
                        error_code: 0,
                        final_size: 0,
                    },
                    Some(channel_id.as_bytes()),
                    now,
                )
                .expect("pending owner link at aggregate cap");
        }
    }
    assert_eq!(
        client.mcquic_pending_channel_owner_links,
        MAX_MCQUIC_PENDING_CHANNEL_OWNER_LINKS
    );
    let link_state = (
        client.mcquic_pending_stream_frame_count,
        client.mcquic_pending_channel_streams.len(),
        client.mcquic_pending_channel_owner_links,
    );
    assert_eq!(
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::ResetStream {
                    stream_id: owner.as_u64(),
                    error_code: 0,
                    final_size: 0,
                },
                Some(b"owner-link-over"),
                now,
            )
            .unwrap_err(),
        Error::McquicResourceLimit
    );
    assert_eq!(
        (
            client.mcquic_pending_stream_frame_count,
            client.mcquic_pending_channel_streams.len(),
            client.mcquic_pending_channel_owner_links,
        ),
        link_state
    );
}

#[test]
fn pending_owner_expiry_work_is_bounded_at_exact_budget() {
    let now = test_fixture::now();
    let inserted_at = now - super::super::MAX_MCQUIC_PENDING_OWNER_AGE;
    let pending = MAX_MCQUIC_OWNER_EXPIRIES_PER_TURN + 1;
    let mut client = bounded_client(32, 100_000, u64::try_from(pending).expect("stream count"));
    for ordinal in 0..pending {
        let stream_id = StreamId::new(3 + u64::try_from(ordinal).expect("ordinal") * 4);
        client
            .queue_or_input_mcquic_stream_frame(
                ChannelFrame::ResetStream {
                    stream_id: stream_id.as_u64(),
                    error_code: 0,
                    final_size: 0,
                },
                Some(format!("expiry-{ordinal}").as_bytes()),
                inserted_at,
            )
            .expect("expired pending owner");
    }

    client.expire_mcquic_resources(now);
    assert_eq!(client.mcquic_pending_stream_frames.len(), 1);
    assert_eq!(client.mcquic_pending_owner_expiries.len(), 1);
    assert_eq!(client.mcquic_pending_owner_checks.len(), 1);
    assert_eq!(client.mcquic_pending_channel_owner_links, 1);
    assert_eq!(
        client.mcquic_resource_limited_channels.len(),
        MAX_MCQUIC_RESOURCE_LIMIT_NOTICES
    );

    client.expire_mcquic_resources(now);
    assert!(client.mcquic_pending_stream_frames.is_empty());
    assert!(client.mcquic_pending_owner_expiries.is_empty());
    assert!(client.mcquic_pending_owner_checks.is_empty());
    assert_eq!(client.mcquic_pending_channel_owner_links, 0);
    input_unicast(&mut client, 0, b"ordinary-unicast", true);
}

#[test]
fn pending_owner_timeout_limits_only_its_channel() {
    let now = test_fixture::now();
    let old = now - super::super::MAX_MCQUIC_PENDING_OWNER_AGE;
    let mut client = bounded_client(32, 100_000, 2);
    client
        .queue_or_input_mcquic_stream_frame(multicast_body(b"expires"), Some(b"owner-timeout"), old)
        .expect("pending owner");

    client.expire_mcquic_resources(now);

    assert_eq!(client.mcquic_operation_state(), OperationState::Active);
    assert!(!client.mcquic_has_pending_stream(SERVER_UNI_STREAM));
    assert_eq!(
        client.mcquic_take_resource_limited_channel(),
        Some(b"owner-timeout".to_vec())
    );
}

#[test]
fn rejected_released_packet_is_not_acknowledged_and_unicast_survives() {
    let now = test_fixture::now();
    let mut client = active_client();
    let channel_id = b"transactional-ack".to_vec();
    client.mcquic_channels.insert(
        channel_id.clone(),
        ChannelReceiveState::new(announce(channel_id.clone(), 1)).expect("receive state"),
    );
    input_unicast(&mut client, 0, b"0123456789unicast", true);
    client
        .mcquic_authorize_stream(SERVER_UNI_STREAM, now)
        .expect("authorize stream");

    let error = client
        .process_mcquic_released_packets(
            vec![ChannelPacket {
                channel_id: channel_id.clone(),
                packet_number: 7,
                key_sequence: 0,
                key_phase: false,
                frames: vec![ChannelFrame::Stream {
                    stream_id: SERVER_UNI_STREAM.as_u64(),
                    offset: 10,
                    fin: true,
                    data: b"conflic".to_vec(),
                }],
            }],
            now,
        )
        .unwrap_err();
    assert_eq!(error, (FrameType::Stream, Error::ProtocolViolation));
    assert!(
        client
            .mcquic_channels
            .get(&channel_id)
            .expect("channel remains")
            .pending_ack()
            .is_none()
    );

    let mut received = [0; 32];
    let (amount, fin) = client
        .stream_recv(SERVER_UNI_STREAM, &mut received)
        .expect("ordinary unicast remains readable");
    assert_eq!(&received[..amount], b"0123456789unicast");
    assert!(fin);
}

#[test]
fn revocation_discards_stale_output_then_accepts_only_new_terminal_output() {
    let mut client = bounded_client(32, 100_000, 16);
    let channel_id = b"terminal-output".to_vec();
    for frame in [
        crate::mcquic::Frame::Ack(crate::mcquic::Ack {
            channel_id: channel_id.clone(),
            largest_acknowledged: 1,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: vec![],
            ecn_counts: None,
        }),
        crate::mcquic::Frame::State(crate::mcquic::State {
            channel_id: channel_id.clone(),
            sequence: 1,
            state: crate::mcquic::ChannelState::Joined,
            reason_scope: crate::mcquic::StateReasonScope::Transport,
            reason_code: crate::mcquic::STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: Vec::new(),
        }),
        crate::mcquic::Frame::Limits(crate::mcquic::Limits {
            sequence: 2,
            limits: ClientLimits {
                ipv4_channels_allowed: false,
                ipv6_channels_allowed: false,
                max_aggregate_rate_kibps: 0,
                max_channel_ids: 0,
            },
            max_joined_count: 0,
        }),
        crate::mcquic::Frame::State(crate::mcquic::State {
            channel_id,
            sequence: 2,
            state: crate::mcquic::ChannelState::Left,
            reason_scope: crate::mcquic::StateReasonScope::Transport,
            reason_code: 0,
            reason_phrase: Vec::new(),
        }),
    ] {
        client.mcquic_send.push_back(frame).expect("queue frame");
    }

    client.mcquic_revoke_operation();

    assert_eq!(client.mcquic_send.len(), 0);

    for frame in [
        crate::mcquic::Frame::Limits(crate::mcquic::Limits {
            sequence: 3,
            limits: ClientLimits {
                ipv4_channels_allowed: false,
                ipv6_channels_allowed: false,
                max_aggregate_rate_kibps: 0,
                max_channel_ids: 0,
            },
            max_joined_count: 0,
        }),
        crate::mcquic::Frame::State(crate::mcquic::State {
            channel_id: b"terminal-output".to_vec(),
            sequence: 3,
            state: crate::mcquic::ChannelState::Left,
            reason_scope: crate::mcquic::StateReasonScope::Transport,
            reason_code: 0,
            reason_phrase: Vec::new(),
        }),
    ] {
        client
            .mcquic_send_terminal(frame)
            .expect("fresh terminal frame");
    }

    assert_eq!(client.mcquic_send.len(), 2);
    assert!(
        client
            .mcquic_send
            .iter()
            .all(Connection::mcquic_terminal_frame)
    );

    let stale_nonterminal = crate::mcquic::Frame::Ack(crate::mcquic::Ack {
        channel_id: b"terminal-output".to_vec(),
        largest_acknowledged: 2,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: vec![],
        ecn_counts: None,
    });
    assert!(!Connection::mcquic_terminal_frame(&stale_nonterminal));
    assert_eq!(
        client.mcquic_send_terminal(stale_nonterminal),
        Err(Error::NotAvailable)
    );
}

#[test]
fn outbound_queue_frame_and_byte_caps_are_exact() {
    let mut count_queue = super::super::McquicSendQueue::default();
    for index in 0..MAX_MCQUIC_SEND_FRAMES {
        count_queue
            .push_back(state_frame(format!("send-{index}").into_bytes(), 0))
            .expect("frame at count cap");
    }
    assert_eq!(count_queue.len(), MAX_MCQUIC_SEND_FRAMES);
    assert_eq!(
        count_queue
            .push_back(state_frame(b"send-over-cap".to_vec(), 0))
            .unwrap_err(),
        Error::McquicResourceLimit
    );

    let mut phrase_len = MAX_MCQUIC_SEND_BYTES;
    let exact_frame = (0..8)
        .find_map(|_| {
            let frame = state_frame(b"send-byte-cap".to_vec(), phrase_len);
            let encoded_len = frame.encoded_len_erasing().expect("encode state");
            if encoded_len == MAX_MCQUIC_SEND_BYTES {
                return Some(frame);
            }
            phrase_len = if encoded_len > MAX_MCQUIC_SEND_BYTES {
                phrase_len - (encoded_len - MAX_MCQUIC_SEND_BYTES)
            } else {
                phrase_len + (MAX_MCQUIC_SEND_BYTES - encoded_len)
            };
            None
        })
        .expect("construct an exactly byte-capped frame");
    let mut byte_queue = super::super::McquicSendQueue::default();
    byte_queue
        .push_back(exact_frame)
        .expect("frame at byte cap");
    assert_eq!(byte_queue.encoded_bytes, MAX_MCQUIC_SEND_BYTES);
    assert_eq!(
        byte_queue
            .push_back(state_frame(b"send-byte-over-cap".to_vec(), 0))
            .unwrap_err(),
        Error::McquicResourceLimit
    );
}

#[test]
fn outbound_queue_ack_replacement_retry_and_retention_account_exactly() {
    let channel_id = b"send-accounting".to_vec();
    let mut queue = super::super::McquicSendQueue::default();
    let first_ack = crate::mcquic::Frame::Ack(crate::mcquic::Ack {
        channel_id: channel_id.clone(),
        largest_acknowledged: 1,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: vec![],
        ecn_counts: None,
    });
    queue.push_back(first_ack).expect("queue first ACK");

    let replacement = crate::mcquic::Frame::Ack(crate::mcquic::Ack {
        channel_id,
        largest_acknowledged: 100,
        ack_delay: 3,
        first_ack_range: 1,
        ack_ranges: vec![
            crate::mcquic::AckRange {
                gap: 1,
                ack_range_length: 1,
            };
            32
        ],
        ecn_counts: None,
    });
    let replacement_len = replacement
        .encoded_len_erasing()
        .expect("encode replacement ACK");
    queue
        .push_back(replacement)
        .expect("replace ACK through common accounting");
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.encoded_bytes, replacement_len);

    let queued = queue.pop_front().expect("pop for packet write");
    assert_eq!(queue.encoded_bytes, 0);
    queue.restore_front(queued);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.encoded_bytes, replacement_len);

    queue.retain(|_| false);
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.encoded_bytes, 0);
}
