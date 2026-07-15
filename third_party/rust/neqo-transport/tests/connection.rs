// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod common;
use common::assert_dscp;
use neqo_common::{Datagram, Decoder, Encoder, Role};
use neqo_transport::{
    CloseReason, ConnectionParameters, Error, MIN_INITIAL_PACKET_SIZE, State, StreamType, Version,
};
use nss::RecordProtectionOps as _;
use test_fixture::{
    CountingConnectionIdGenerator, DEFAULT_ALPN, default_client, default_server,
    header_protection::{self, decode_initial_header, initial_aead_and_hp},
    new_client, new_server, now, split_datagram,
};

#[test]
fn connect() {
    let (client, server) = test_fixture::connect();
    assert_dscp(&client.stats());
    assert_dscp(&server.stats());
}

#[cfg(feature = "mcquic")]
mod mcquic_tests {
    use std::net::{IpAddr, Ipv4Addr};

    use neqo_common::event::Provider as _;
    use neqo_transport::{
        Connection, ConnectionEvent, StreamId,
        mcquic::{
            Ack, Announce, ChannelFrame, ChannelSendState, ChannelState, ClientLimits,
            ClientTransportParams, Frame, Integrity, Join, Key, Limits,
            STATE_REASON_REQUESTED_BY_SERVER, State as McState, StateReasonScope,
        },
    };

    use super::*;

    fn client_params() -> ClientTransportParams {
        ClientTransportParams {
            limits: ClientLimits {
                ipv4_channels_allowed: true,
                ipv6_channels_allowed: false,
                max_aggregate_rate_kibps: 100_000,
                max_channel_ids: 32,
            },
            hash_algorithms: vec![1],
            encryption_algorithms: vec![0x1301],
        }
    }

    fn connected_mcquic() -> (Connection, Connection, ClientTransportParams) {
        let params = client_params();
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default().mcquic_client_params(Some(params.clone())),
        );
        let mut server = new_server::<CountingConnectionIdGenerator, &str>(
            DEFAULT_ALPN,
            ConnectionParameters::default().mcquic_server_support(true),
        );

        test_fixture::handshake(&mut client, &mut server);
        assert_eq!(*client.state(), State::Confirmed);
        assert_eq!(*server.state(), State::Confirmed);

        (client, server, params)
    }

    fn connected_with_params(
        client_params: Option<ClientTransportParams>,
        server_support: bool,
    ) -> (Connection, Connection) {
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default().mcquic_client_params(client_params),
        );
        let mut server = new_server::<CountingConnectionIdGenerator, &str>(
            DEFAULT_ALPN,
            ConnectionParameters::default().mcquic_server_support(server_support),
        );

        test_fixture::handshake(&mut client, &mut server);
        assert_eq!(*client.state(), State::Confirmed);
        assert_eq!(*server.state(), State::Confirmed);

        (client, server)
    }

    fn channel_id() -> Vec<u8> {
        b"demo-channel".to_vec()
    }

    fn announce() -> Announce {
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

    fn announce_frame() -> Frame {
        Frame::Announce(announce())
    }

    fn key() -> Key {
        Key {
            channel_id: channel_id(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0x22; 32],
        }
    }

    fn key_frame() -> Frame {
        Frame::Key(key())
    }

    fn integrity_frame() -> Frame {
        Frame::Integrity(Integrity {
            channel_id: channel_id(),
            packet_number_start: 0,
            packet_hash_count: Some(1),
            packet_hashes: vec![0x33; 32],
        })
    }

    fn join_frame() -> Frame {
        Frame::Join(Join {
            channel_id: channel_id(),
            mc_limits_sequence: 1,
            mc_state_sequence: 0,
            mc_key_sequence: 1,
        })
    }

    fn limits_frame() -> Frame {
        Frame::Limits(Limits {
            sequence: 1,
            limits: client_params().limits,
            max_joined_count: 8,
        })
    }

    fn state_frame() -> Frame {
        Frame::State(McState {
            channel_id: channel_id(),
            sequence: 1,
            state: ChannelState::Joined,
            reason_scope: StateReasonScope::Transport,
            reason_code: STATE_REASON_REQUESTED_BY_SERVER,
            reason_phrase: b"joined".to_vec(),
        })
    }

    fn ack_frame() -> Frame {
        Frame::Ack(Ack {
            channel_id: channel_id(),
            largest_acknowledged: 10,
            ack_delay: 0,
            first_ack_range: 0,
            ack_ranges: vec![],
            ecn_counts: None,
        })
    }

    const WEBTRANSPORT_UNI_PREFIX: [u8; 10] = [
        0x40, 0x54, // stream type 0x54, encoded in two bytes
        0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // session ID 0, eight bytes
    ];

    fn connected_mcquic_with_client_connection_params(
        connection_parameters: ConnectionParameters,
    ) -> (Connection, Connection) {
        let mut client = new_client::<CountingConnectionIdGenerator>(
            connection_parameters.mcquic_client_params(Some(client_params())),
        );
        let mut server = new_server::<CountingConnectionIdGenerator, &str>(
            DEFAULT_ALPN,
            ConnectionParameters::default().mcquic_server_support(true),
        );

        test_fixture::handshake(&mut client, &mut server);
        assert_eq!(*client.state(), State::Confirmed);
        assert_eq!(*server.state(), State::Confirmed);
        (client, server)
    }

    fn send_server_control(client: &mut Connection, server: &mut Connection, frame: Frame) {
        server.mcquic_send(frame).expect("queue server control");
        let datagram = server
            .process_output(now())
            .dgram()
            .expect("server control packet");
        client.process_input(datagram, now());
    }

    fn send_server_stream_data(
        client: &mut Connection,
        server: &mut Connection,
        stream_id: StreamId,
        data: &[u8],
    ) {
        assert_eq!(
            server
                .stream_send(stream_id, data)
                .expect("send stream data"),
            data.len()
        );
        let datagram = server
            .process_output(now())
            .dgram()
            .expect("server stream packet");
        client.process_input(datagram, now());
    }

    fn encode_channel_packet(frames: &[ChannelFrame]) -> (Vec<u8>, Integrity) {
        let mut sender =
            ChannelSendState::new(announce(), key()).expect("create channel send state");
        let mut packet = vec![0; 1200];
        let sent = sender
            .write_packet(frames, &mut packet)
            .expect("encode channel packet");
        packet.truncate(sent.packet_len);
        (packet, sent.integrity)
    }

    fn prepare_channel(client: &mut Connection, server: &mut Connection) {
        send_server_control(client, server, announce_frame());
        send_server_control(client, server, key_frame());
    }

    fn process_channel_packet(client: &mut Connection, packet: &[u8]) -> Result<(), Error> {
        client.mcquic_process_channel_packet(&channel_id(), packet, now())
    }

    fn read_stream(
        client: &mut Connection,
        stream_id: StreamId,
        capacity: usize,
    ) -> (Vec<u8>, bool) {
        let mut data = vec![0; capacity];
        let (read, fin) = client
            .stream_recv(stream_id, &mut data)
            .expect("read receive stream");
        data.truncate(read);
        (data, fin)
    }

    #[test]
    fn transport_params_negotiate() {
        let (client, server, params) = connected_mcquic();

        assert!(client.peer_mcquic_server_support());
        assert_eq!(server.peer_mcquic_client_params(), Some(params));
    }

    #[test]
    fn client_sends_limits_after_negotiation() {
        let (mut client, mut server, _) = connected_mcquic();
        let frame = limits_frame();

        client.mcquic_send(frame.clone()).expect("queue MC_LIMITS");
        let dgram = client.process_output(now()).dgram().expect("MC_LIMITS");
        server.process_input(dgram, now());

        assert!(server.mcquic_readable());
        assert_eq!(server.mcquic_recv(), Some(frame));
        assert_eq!(server.mcquic_recv(), None);
    }

    #[test]
    fn server_frames_reach_client() {
        let (mut client, mut server, _) = connected_mcquic();
        let frames = vec![
            announce_frame(),
            key_frame(),
            integrity_frame(),
            join_frame(),
        ];

        for frame in &frames {
            server
                .mcquic_send(frame.clone())
                .expect("queue server frame");
        }
        let dgram = server.process_output(now()).dgram().expect("server frames");
        client.process_input(dgram, now());

        assert!(client.mcquic_readable());
        for frame in frames {
            assert_eq!(client.mcquic_recv(), Some(frame));
        }
        assert_eq!(client.mcquic_recv(), None);
    }

    #[test]
    fn stream_prefix_over_unicast_body_over_multicast() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        prepare_channel(&mut client, &mut server);

        let body = b"shared-body";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: body.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("authenticated channel packet");

        let (received, fin) = read_stream(&mut client, stream_id, 64);
        assert_eq!(
            received,
            [WEBTRANSPORT_UNI_PREFIX.as_slice(), body].concat()
        );
        assert!(fin);
        assert!(
            client
                .mcquic_send_pending_acks()
                .expect("queue channel ACK")
        );
        assert!(
            !client
                .mcquic_send_pending_acks()
                .expect("ACK state was marked sent")
        );
    }

    #[test]
    fn connection_preserves_legacy_channel_datagram_queue() {
        let (mut client, mut server, _) = connected_mcquic();
        prepare_channel(&mut client, &mut server);
        let payload = b"legacy-datagram";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Datagram {
            data: payload.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("authenticated channel DATAGRAM");

        let released = client
            .mcquic_pop_channel_datagram()
            .expect("legacy DATAGRAM queue");
        assert_eq!(released.channel_id, channel_id());
        assert_eq!(released.packet_number, 0);
        assert_eq!(released.data, payload);
        assert!(client.mcquic_pop_channel_datagram().is_none());
    }

    #[test]
    fn multicast_body_waits_for_unicast_prefix() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        prepare_channel(&mut client, &mut server);

        let body = b"body-first";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: body.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("buffer out-of-order body");
        assert_eq!(read_stream(&mut client, stream_id, 64), (Vec::new(), false));

        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        let (received, fin) = read_stream(&mut client, stream_id, 64);
        assert_eq!(
            received,
            [WEBTRANSPORT_UNI_PREFIX.as_slice(), body].concat()
        );
        assert!(fin);
    }

    #[test]
    fn identical_unicast_multicast_overlap_deduplicates() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        let body = b"identical";
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        send_server_stream_data(&mut client, &mut server, stream_id, body);
        prepare_channel(&mut client, &mut server);

        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: body.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("deduplicate identical overlap");

        let (received, fin) = read_stream(&mut client, stream_id, 64);
        assert_eq!(
            received,
            [WEBTRANSPORT_UNI_PREFIX.as_slice(), body].concat()
        );
        assert!(fin);
    }

    #[test]
    fn conflicting_unicast_multicast_overlap_closes_connection() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        send_server_stream_data(&mut client, &mut server, stream_id, b"unicast");
        prepare_channel(&mut client, &mut server);

        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: false,
            data: b"conflict".to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        assert_eq!(
            process_channel_packet(&mut client, &packet),
            Err(Error::ProtocolViolation)
        );
        assert!(matches!(
            client.state(),
            State::Closing {
                error: CloseReason::Transport(Error::ProtocolViolation),
                ..
            }
        ));
    }

    #[test]
    fn conflicting_multicast_unicast_overlap_closes_connection() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        prepare_channel(&mut client, &mut server);

        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: b"multicast".to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("buffer multicast body");

        let unicast = [WEBTRANSPORT_UNI_PREFIX.as_slice(), b"conflicts"].concat();
        send_server_stream_data(&mut client, &mut server, stream_id, &unicast);
        assert!(matches!(
            client.state(),
            State::Closing {
                error: CloseReason::Transport(Error::ProtocolViolation),
                ..
            }
        ));
    }

    #[test]
    fn multicast_loss_is_recovered_by_unicast_stream_data() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        prepare_channel(&mut client, &mut server);

        let missing = b"lost-";
        let tail = b"tail";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10 + u64::try_from(missing.len()).expect("length fits"),
            fin: true,
            data: tail.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("buffer multicast tail");
        assert_eq!(
            read_stream(&mut client, stream_id, 64),
            (WEBTRANSPORT_UNI_PREFIX.to_vec(), false)
        );

        send_server_stream_data(&mut client, &mut server, stream_id, missing);
        let (received, fin) = read_stream(&mut client, stream_id, 64);
        assert_eq!(received, [missing.as_slice(), tail.as_slice()].concat());
        assert!(fin);
    }

    #[test]
    fn multicast_reset_stream_uses_ordinary_receive_state() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        prepare_channel(&mut client, &mut server);

        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::ResetStream {
            stream_id: stream_id.as_u64(),
            error_code: 42,
            final_size: 10,
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("apply RESET_STREAM");

        assert!(client.events().any(|event| matches!(
            event,
            ConnectionEvent::RecvStreamReset {
                stream_id: id,
                app_error: 42,
            } if id == stream_id
        )));
    }

    #[test]
    fn channel_packet_releases_when_key_arrives() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        send_server_control(&mut client, &mut server, announce_frame());

        let body = b"after-key";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: body.to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        process_channel_packet(&mut client, &packet).expect("packet waits for key");
        assert_eq!(
            read_stream(&mut client, stream_id, 64),
            (WEBTRANSPORT_UNI_PREFIX.to_vec(), false)
        );

        send_server_control(&mut client, &mut server, key_frame());
        assert_eq!(
            read_stream(&mut client, stream_id, 64),
            (body.to_vec(), true)
        );
        assert!(
            client
                .mcquic_send_pending_acks()
                .expect("ACK released packet")
        );
    }

    #[test]
    fn channel_packet_releases_when_integrity_arrives() {
        let (mut client, mut server, _) = connected_mcquic();
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        prepare_channel(&mut client, &mut server);

        let body = b"after-integrity";
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: true,
            data: body.to_vec(),
        }]);
        process_channel_packet(&mut client, &packet).expect("packet waits for integrity");
        assert_eq!(
            read_stream(&mut client, stream_id, 64),
            (WEBTRANSPORT_UNI_PREFIX.to_vec(), false)
        );

        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));
        assert_eq!(
            read_stream(&mut client, stream_id, 64),
            (body.to_vec(), true)
        );
        assert!(
            client
                .mcquic_send_pending_acks()
                .expect("ACK released packet")
        );
    }

    #[test]
    fn multicast_stream_obeys_stream_limits() {
        let (mut client, mut server) = connected_mcquic_with_client_connection_params(
            ConnectionParameters::default().max_streams(StreamType::UniDi, 0),
        );
        prepare_channel(&mut client, &mut server);
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: 3,
            offset: 10,
            fin: false,
            data: b"body".to_vec(),
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));

        assert_eq!(
            process_channel_packet(&mut client, &packet),
            Err(Error::StreamLimit)
        );
        assert!(matches!(
            client.state(),
            State::Closing {
                error: CloseReason::Transport(Error::StreamLimit),
                ..
            }
        ));
    }

    #[test]
    fn multicast_stream_obeys_flow_control() {
        let (mut client, mut server) = connected_mcquic_with_client_connection_params(
            ConnectionParameters::default()
                .max_data(10)
                .max_stream_data(StreamType::UniDi, true, 10),
        );
        let stream_id = server
            .stream_create(StreamType::UniDi)
            .expect("server stream");
        send_server_stream_data(
            &mut client,
            &mut server,
            stream_id,
            &WEBTRANSPORT_UNI_PREFIX,
        );
        prepare_channel(&mut client, &mut server);
        let (packet, integrity) = encode_channel_packet(&[ChannelFrame::Stream {
            stream_id: stream_id.as_u64(),
            offset: 10,
            fin: false,
            data: vec![0xff],
        }]);
        send_server_control(&mut client, &mut server, Frame::Integrity(integrity));

        assert_eq!(
            process_channel_packet(&mut client, &packet),
            Err(Error::FlowControl)
        );
        assert!(matches!(
            client.state(),
            State::Closing {
                error: CloseReason::Transport(Error::FlowControl),
                ..
            }
        ));
    }

    #[test]
    fn client_state_and_ack_reach_server() {
        let (mut client, mut server, _) = connected_mcquic();
        let frames = vec![state_frame(), ack_frame()];

        for frame in &frames {
            client
                .mcquic_send(frame.clone())
                .expect("queue client frame");
        }
        let dgram = client.process_output(now()).dgram().expect("client frames");
        server.process_input(dgram, now());

        assert!(server.mcquic_readable());
        for frame in frames {
            assert_eq!(server.mcquic_recv(), Some(frame));
        }
        assert_eq!(server.mcquic_recv(), None);
    }

    #[test]
    fn wrong_sender_is_rejected_by_send_api() {
        let (mut client, mut server, _) = connected_mcquic();

        assert_eq!(
            client.mcquic_send(announce_frame()),
            Err(Error::ProtocolViolation)
        );
        assert_eq!(
            server.mcquic_send(limits_frame()),
            Err(Error::ProtocolViolation)
        );
    }

    #[test]
    fn client_does_not_negotiate_without_local_params() {
        let (mut client, mut server) = connected_with_params(None, true);

        assert!(client.peer_mcquic_server_support());
        assert_eq!(server.peer_mcquic_client_params(), None);
        assert_eq!(client.mcquic_send(limits_frame()), Err(Error::NotAvailable));
        assert_eq!(
            server.mcquic_send(announce_frame()),
            Err(Error::NotAvailable)
        );
    }

    #[test]
    fn server_does_not_negotiate_without_local_support() {
        let params = client_params();
        let (mut client, mut server) = connected_with_params(Some(params.clone()), false);

        assert!(!client.peer_mcquic_server_support());
        assert_eq!(server.peer_mcquic_client_params(), Some(params));
        assert_eq!(client.mcquic_send(limits_frame()), Err(Error::NotAvailable));
        assert_eq!(
            server.mcquic_send(announce_frame()),
            Err(Error::NotAvailable)
        );
    }
}

#[test]
fn gso() {
    let (mut client, _server) = test_fixture::connect();

    let stream_id2 = client.stream_create(StreamType::UniDi).unwrap();
    client.stream_send(stream_id2, &[42; 2048]).unwrap();
    client.stream_close_send(stream_id2).unwrap();

    let out = client
        .process_multiple_output(now(), 64.try_into().expect(">0"))
        .dgram()
        .unwrap();

    assert_eq!(out.datagram_size().get(), 1232);
    assert!(out.data().len() > out.datagram_size().get());
}

#[test]
fn truncate_long_packet() {
    neqo_common::log::init(None);
    let now = now();

    // This test needs to alter the server handshake, so turn off MLKEM.
    let mut client =
        new_client::<CountingConnectionIdGenerator>(ConnectionParameters::default().mlkem(false));
    let mut server = new_server::<CountingConnectionIdGenerator, &str>(
        DEFAULT_ALPN,
        ConnectionParameters::default().mlkem(false),
    );

    let out = client.process_output(now).dgram().unwrap();
    let out = server.process(Some(out), now);

    // This will truncate the Handshake packet from the server.
    let dupe = out.as_dgram_ref().unwrap().clone();
    // Count the padding in the packet, plus 1.
    let tail = dupe.iter().rev().take_while(|b| **b == 0).count() + 1;
    let truncated = Datagram::new(
        dupe.source(),
        dupe.destination(),
        dupe.tos(),
        &dupe[..(dupe.len() - tail)],
    );
    let hs_probe = client.process(Some(truncated), now).dgram();
    assert!(hs_probe.is_some());

    // Now feed in the untruncated packet.
    let out = client.process(out.dgram(), now);
    assert!(out.as_dgram_ref().is_some()); // Throw this ACK away.
    assert!(test_fixture::maybe_authenticate(&mut client));
    let out = client.process_output(now);
    assert!(out.as_dgram_ref().is_some());

    assert!(client.state().connected());
    let out = server.process(out.dgram(), now);
    assert!(out.as_dgram_ref().is_some());
    assert!(server.state().connected());
}

/// Test that reordering parts of the server Initial doesn't change things.
#[test]
fn reorder_server_initial() {
    // A simple ACK frame for a single packet with packet number 0.
    const ACK_FRAME: &[u8] = &[0x02, 0x00, 0x00, 0x00, 0x00];

    // This test predicts the precise format of an ACK frame, so turn off MLKEM
    // and packet number randomization.
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default()
            .versions(Version::Version1, vec![Version::Version1])
            .mlkem(false)
            .randomize_first_pn(false),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let (_, client_dcid, _, _) =
        decode_initial_header(client_initial.as_dgram_ref().unwrap(), Role::Client).unwrap();
    let client_dcid = client_dcid.to_owned();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let (server_initial, server_hs) = split_datagram(server_packet.as_ref().unwrap());
    let (protected_header, _, _, payload) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Now decrypt the packet.
    let (aead_enc, aead_dec, hp) = initial_aead_and_hp(&client_dcid, Role::Server);
    let (header, pn) = header_protection::remove(&hp, protected_header, payload);
    let pn_len = header.len() - protected_header.len();
    let mut buf = vec![0; payload.len()];
    let mut plaintext = aead_dec
        .decrypt(pn, &header, &payload[pn_len..], &mut buf)
        .unwrap()
        .to_owned();

    // Now we need to find the frames.  Make some really strong assumptions.
    let mut dec = Decoder::new(&plaintext[..]);
    assert_eq!(dec.decode(ACK_FRAME.len()), Some(ACK_FRAME));
    assert_eq!(dec.decode_varint(), Some(0x06)); // CRYPTO
    assert_eq!(dec.decode_varint(), Some(0x00)); // offset
    dec.skip_vvec(); // Skip over the payload.
    let end = dec.offset();

    // Move the ACK frame after the CRYPTO frame.
    plaintext[..end].rotate_left(ACK_FRAME.len());

    // And rebuild a packet.
    let mut packet = header.clone();
    packet.resize(MIN_INITIAL_PACKET_SIZE, 0);
    aead_enc
        .encrypt(pn, &header, &plaintext, &mut packet[header.len()..])
        .unwrap();
    header_protection::apply(&hp, &mut packet, protected_header.len()..header.len());
    let reordered = Datagram::new(
        server_initial.source(),
        server_initial.destination(),
        server_initial.tos(),
        packet,
    );

    // Now a connection can be made successfully.
    // Though we modified the server's Initial packet, we get away with it.
    // TLS only authenticates the content of the CRYPTO frame, which was untouched.
    client.process_input(reordered, now());
    client.process_input(server_hs.unwrap(), now());
    assert!(test_fixture::maybe_authenticate(&mut client));
    let finished = client.process_output(now());
    assert_eq!(*client.state(), State::Connected);

    let done = server.process(finished.dgram(), now());
    assert_eq!(*server.state(), State::Confirmed);

    client.process_input(done.dgram().unwrap(), now());
    assert_eq!(*client.state(), State::Confirmed);
}

#[cfg(test)]
fn set_payload(server_packet: Option<&Datagram>, client_dcid: &[u8], payload: &[u8]) -> Datagram {
    let (server_initial, _server_hs) = split_datagram(server_packet.as_ref().unwrap());
    let (protected_header, _, _, orig_payload) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Now decrypt the packet.
    let (aead, _, hp) = initial_aead_and_hp(client_dcid, Role::Server);
    let (mut header, pn) = header_protection::remove(&hp, protected_header, orig_payload);
    // Re-encode the packet number as four bytes, so we have enough material for the header
    // protection sample if payload is empty.
    let pn_len = usize::from(header[0] & 0b0000_0011) + 1;
    let len_pos = header.len()
        - pn_len
        - Encoder::varint_len(u64::try_from(pn_len + orig_payload.len()).unwrap());
    header.truncate(len_pos);
    let mut enc = Encoder::new_borrowed_vec(&mut header);
    enc.encode_varint(u64::try_from(4 + payload.len() + aead.expansion()).unwrap());
    enc.encode_uint(4, pn);
    header[0] = header[0] & 0xfc | 0b0000_0011; // Set the packet number length to 4.

    // And build a packet containing the given payload.
    let mut packet = header.clone();
    packet.resize(header.len() + payload.len() + aead.expansion(), 0);
    aead.encrypt(pn, &header, payload, &mut packet[header.len()..])
        .unwrap();
    header_protection::apply(&hp, &mut packet, protected_header.len()..header.len());
    Datagram::new(
        server_initial.source(),
        server_initial.destination(),
        server_initial.tos(),
        packet,
    )
}

/// Test that the stack treats a packet without any frames as a protocol violation.
#[test]
fn packet_without_frames() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let client_initial_clone = client_initial.as_dgram_ref().unwrap().clone();
    let (_, client_dcid, _, _) =
        decode_initial_header(&client_initial_clone, Role::Client).unwrap();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let modified = set_payload(server_packet.as_ref(), client_dcid, &[]);
    client.process_input(modified, now());
    assert_eq!(
        client.state(),
        &State::Closed(CloseReason::Transport(Error::ProtocolViolation))
    );
}

/// Test that the stack permits a packet containing only padding.
#[cfg_attr(
    feature = "disable-encryption",
    ignore = "null AEAD accepts the modified packet, so the client stays in WaitInitial rather than WaitVersion"
)]
#[test]
fn packet_with_only_padding() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now());
    let client_initial_clone = client_initial.as_dgram_ref().unwrap().clone();
    let (_, client_dcid, _, _) =
        decode_initial_header(&client_initial_clone, Role::Client).unwrap();

    let server_packet = server.process(client_initial.dgram(), now()).dgram();
    let modified = set_payload(server_packet.as_ref(), client_dcid, &[0]);
    client.process_input(modified, now());
    assert_eq!(client.state(), &State::WaitVersion);
}

/// Overflow the crypto buffer.
#[expect(clippy::similar_names, reason = "scid simiar to dcid.")]
#[test]
fn overflow_crypto() {
    let mut client = new_client::<CountingConnectionIdGenerator>(
        ConnectionParameters::default().versions(Version::Version1, vec![Version::Version1]),
    );
    let mut server = default_server();

    let client_initial = client.process_output(now()).dgram();
    let (_, client_dcid, _, _) =
        decode_initial_header(client_initial.as_ref().unwrap(), Role::Client).unwrap();
    let client_dcid = client_dcid.to_owned();

    let server_packet = server.process(client_initial, now()).dgram();
    let (server_initial, _) = split_datagram(server_packet.as_ref().unwrap());

    // Now decrypt the server packet to get AEAD and HP instances.
    // We won't be using the packet, but making new ones.
    let (aead, _, hp) = initial_aead_and_hp(&client_dcid, Role::Server);
    let (_, server_dcid, server_scid, _) =
        decode_initial_header(&server_initial, Role::Server).unwrap();

    // Send in 100 packets, each with 1000 bytes of crypto frame data each,
    // eventually this will overrun the buffer we keep for crypto data.
    let mut payload = Encoder::with_capacity(1024);
    for pn in 0..100_u64 {
        payload.truncate(0);
        payload
            .encode_varint(0x06_u64) // CRYPTO frame type.
            .encode_varint(pn * 1000 + 1) // offset
            .encode_varint(1000_u64); // length
        let plen = payload.len();
        payload.pad_to(plen + 1000, 44);

        let mut packet = Encoder::with_capacity(MIN_INITIAL_PACKET_SIZE);
        packet
            .encode_byte(0xc1) // Initial with packet number length of 2.
            .encode_uint(4, Version::Version1.wire_version())
            .encode_vec(1, server_dcid)
            .encode_vec(1, server_scid)
            .encode_vvec(&[]) // token
            .encode_varint(u64::try_from(2 + payload.len() + aead.expansion()).unwrap()); // length
        let pn_offset = packet.len();
        packet.encode_uint(2, pn);

        let mut packet = Vec::from(packet);
        let header = packet.clone();
        packet.resize(header.len() + payload.len() + aead.expansion(), 0);
        aead.encrypt(pn, &header, payload.as_ref(), &mut packet[header.len()..])
            .unwrap();
        header_protection::apply(&hp, &mut packet, pn_offset..(pn_offset + 2));
        packet.resize(MIN_INITIAL_PACKET_SIZE, 0); // Initial has to be MIN_INITIAL_PACKET_SIZE bytes!

        let dgram = Datagram::new(
            server_initial.source(),
            server_initial.destination(),
            server_initial.tos(),
            packet,
        );
        client.process_input(dgram, now());
        if let State::Closing { error, .. } | State::Closed(error) = client.state() {
            assert!(
                matches!(error, CloseReason::Transport(Error::CryptoBufferExceeded)),
                "the connection need to abort on crypto buffer"
            );
            assert!(pn > 64, "at least 64000 bytes of data is buffered");
            return;
        }
    }
    panic!("Unable to overflow the crypto buffer: {:?}", client.state());
}

#[test]
fn handshake_mlkem768x25519() {
    let mut client = default_client();
    let mut server = default_server();

    client
        .set_groups(&[nss::TLS_GRP_KEM_MLKEM768X25519])
        .unwrap();
    client.send_additional_key_shares(0).unwrap();

    test_fixture::handshake(&mut client, &mut server);
    assert_eq!(*client.state(), State::Confirmed);
    assert_eq!(*server.state(), State::Confirmed);
    assert_eq!(
        client.tls_info().unwrap().key_exchange(),
        nss::TLS_GRP_KEM_MLKEM768X25519
    );
    assert_eq!(
        server.tls_info().unwrap().key_exchange(),
        nss::TLS_GRP_KEM_MLKEM768X25519
    );
}

#[test]
fn client_initial_packet_number() {
    // Check that the initial packet number is randomized (i.e, > 0) if the `randomize_first_pn`
    // connection parameter is set, and that it is zero when not.
    for randomize in [true, false] {
        // This test needs to decrypt the CI, so turn off MLKEM.
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .mlkem(false)
                .randomize_first_pn(randomize),
        );

        let client_initial = client.process_output(now());
        let (protected_header, client_dcid, _, payload) =
            decode_initial_header(client_initial.as_dgram_ref().unwrap(), Role::Client).unwrap();
        let (_, _, hp) = initial_aead_and_hp(client_dcid, Role::Client);
        let (_, pn) = header_protection::remove(&hp, protected_header, payload);
        assert!(
            randomize && pn > 0 || !randomize && pn == 0,
            "randomize {randomize} = {pn}"
        );
    }
}

#[test]
fn server_initial_packet_number() {
    // Check that the initial packet number is randomized (i.e, > 0) if the `randomize_first_pn`
    // connection parameter is set, and that it is zero when not.
    for randomize in [true, false] {
        // This test needs to decrypt the CI, so turn off MLKEM.
        let mut client = new_client::<CountingConnectionIdGenerator>(
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .mlkem(false),
        );
        let mut server = new_server::<CountingConnectionIdGenerator, &str>(
            DEFAULT_ALPN,
            ConnectionParameters::default()
                .versions(Version::Version1, vec![Version::Version1])
                .randomize_first_pn(randomize),
        );

        let client_initial = client.process_output(now()).dgram();
        let (_protected_header, client_dcid, _scid, _payload) =
            decode_initial_header(client_initial.as_ref().unwrap(), Role::Client).unwrap();

        let (_, _, hp) = initial_aead_and_hp(client_dcid, Role::Server);

        let server_initial = server.process(client_initial, now()).dgram();
        let (protected_header, _dcid, _scid, payload) =
            decode_initial_header(server_initial.as_ref().unwrap(), Role::Server).unwrap();

        let (_, pn) = header_protection::remove(&hp, protected_header, payload);
        println!();
        assert!(
            randomize && pn > 0 || !randomize && pn == 0,
            "randomize {randomize} = {pn}"
        );
    }
}
