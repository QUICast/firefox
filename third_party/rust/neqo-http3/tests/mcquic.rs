// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(feature = "mcquic")]

use std::net::{IpAddr, Ipv4Addr};

use neqo_http3::{
    Http3Client, Http3Parameters, Http3Server, Http3ServerEvent, Http3State,
    mcquic::{
        Ack, Announce, ChannelFrame, ChannelReceiveState, ChannelSendState, ChannelState,
        ClientLimits, ClientTransportParams, Frame, Integrity, Join, Key, Limits,
        STATE_REASON_REQUESTED_BY_SERVER, State as McState, StateReasonScope,
    },
};
use neqo_transport::server::ConnectionRef;
use test_fixture::{
    connect_peers, exchange_packets, http3_client_with_params, http3_server_with_params,
};

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

fn channel_id() -> Vec<u8> {
    b"http3-mcquic".to_vec()
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

fn key() -> Key {
    Key {
        channel_id: channel_id(),
        key_sequence: 1,
        from_packet_number: 0,
        secret: vec![0x22; 32],
    }
}

fn limits_frame() -> Frame {
    Frame::Limits(Limits {
        sequence: 1,
        limits: client_params().limits,
        max_joined_count: 8,
    })
}

fn announce_frame() -> Frame {
    Frame::Announce(announce())
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
        largest_acknowledged: 0,
        ack_delay: 0,
        first_ack_range: 0,
        ack_ranges: vec![],
        ecn_counts: None,
    })
}

fn connected_mcquic() -> (
    Http3Client,
    Http3Server,
    ConnectionRef,
    ClientTransportParams,
) {
    let params = client_params();
    let mut client = http3_client_with_params(
        Http3Parameters::default().mcquic_client_params(Some(params.clone())),
    );
    let mut server =
        http3_server_with_params(Http3Parameters::default().mcquic_server_support(true));
    let out = connect_peers(&mut client, &mut server);
    exchange_packets(&mut client, &mut server, false, out);

    let conn = server
        .events()
        .find_map(|event| match event {
            Http3ServerEvent::StateChange {
                conn,
                state: Http3State::Connected,
            } => Some(conn),
            _ => None,
        })
        .expect("server connection");

    (client, server, conn, params)
}

#[test]
fn http3_negotiates_and_exchanges_mcquic_control_frames() {
    let (mut client, mut server, server_conn, params) = connected_mcquic();

    assert!(client.peer_mcquic_server_support());
    assert_eq!(server.peer_mcquic_client_params(&server_conn), Some(params));

    let limits = limits_frame();
    client.mcquic_send(limits.clone()).expect("queue MC_LIMITS");
    exchange_packets(&mut client, &mut server, false, None);
    assert_eq!(server.mcquic_recv(&server_conn), Some(limits));

    let server_frames = vec![
        announce_frame(),
        key_frame(),
        integrity_frame(),
        join_frame(),
    ];
    for frame in &server_frames {
        server
            .mcquic_send(&server_conn, frame.clone())
            .expect("queue server MCQUIC frame");
    }
    exchange_packets(&mut client, &mut server, false, None);
    for frame in server_frames {
        assert_eq!(client.mcquic_recv(), Some(frame));
    }

    let client_frames = vec![state_frame(), ack_frame()];
    for frame in &client_frames {
        client
            .mcquic_send(frame.clone())
            .expect("queue client MCQUIC frame");
    }
    exchange_packets(&mut client, &mut server, false, None);
    for frame in client_frames {
        assert_eq!(server.mcquic_recv(&server_conn), Some(frame));
    }
}

#[test]
fn http3_reexported_channel_receive_state_releases_datagram() {
    let announce = announce();
    let key = key();
    let mut sender = ChannelSendState::new(announce.clone(), key.clone()).expect("send state");
    let mut out = vec![0; 1200];
    let sent = sender
        .write_packet(
            &[ChannelFrame::Datagram {
                data: b"payload".to_vec(),
            }],
            &mut out,
        )
        .expect("write protected packet");
    let protected_packet = &out[..sent.packet_len];

    let mut receiver = ChannelReceiveState::new(announce).expect("receive state");
    assert!(
        receiver
            .process_protected_packet(protected_packet)
            .expect("buffer protected packet")
            .is_empty()
    );
    assert!(receiver.insert_key(key).expect("insert key").is_empty());
    let released = receiver
        .insert_integrity(sent.integrity)
        .expect("insert integrity");

    assert_eq!(released.len(), 1);
    assert_eq!(released[0].data, b"payload");
    assert_eq!(receiver.pop_datagram(), released.into_iter().next());
    assert!(receiver.pending_ack().is_some());
}
