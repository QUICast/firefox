// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    time::Duration,
};

use neqo_common::{Ecn, datagram, event::Provider as _};
use test_fixture::now;

use super::{
    PingWriter, connect, connect_force_idle, cwnd, cwnd_avail, default_client, default_server,
    exchange_ticket, new_client,
};
use crate::{
    ConnectionParameters, Error, StreamId, StreamType,
    connection::{Connection, OutputBatch, OutputToken},
    events::{ConnectionEvent, OutgoingDatagramOutcome},
    tracking::PacketNumberSpace,
};

const MAX_SEGMENTS: NonZeroUsize = NonZeroUsize::new(8).unwrap();

fn connected() -> (Connection, Connection) {
    let mut client = default_client();
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    (client, server)
}

fn connected_with_client_params(params: ConnectionParameters) -> (Connection, Connection) {
    let mut client = new_client(params);
    let mut server = default_server();
    connect_force_idle(&mut client, &mut server);
    (client, server)
}

fn queue_stream(connection: &mut Connection, data: &[u8]) -> StreamId {
    let stream_id = connection.stream_create(StreamType::UniDi).unwrap();
    assert_eq!(connection.stream_send(stream_id, data).unwrap(), data.len());
    connection.stream_close_send(stream_id).unwrap();
    stream_id
}

fn next_application_pn(connection: &Connection) -> u64 {
    connection
        .crypto
        .states()
        .select_tx(connection.version, PacketNumberSpace::ApplicationData)
        .unwrap()
        .1
        .next_pn()
}

fn next_tracked_batch(
    connection: &mut Connection,
    mut at: std::time::Instant,
) -> (std::time::Instant, datagram::Batch, OutputToken, usize) {
    loop {
        let tracked = connection
            .process_multiple_output_tracked(at, MAX_SEGMENTS)
            .unwrap();
        let segment_count = tracked.segment_count();
        let (output, token) = tracked.into_parts();
        match output {
            OutputBatch::DatagramBatch(batch) => {
                return (at, batch, token.unwrap(), segment_count);
            }
            OutputBatch::Callback(delay) => at += delay.max(Duration::from_micros(1)),
            OutputBatch::None => panic!("connection produced no stream output"),
        }
    }
}

fn next_tracked_datagram_drop_batch(
    connection: &mut Connection,
    mut at: std::time::Instant,
) -> (std::time::Instant, datagram::Batch, OutputToken, usize) {
    loop {
        let tracked = connection
            .process_multiple_output_tracked(at, MAX_SEGMENTS)
            .unwrap();
        let segment_count = tracked.segment_count();
        let (output, token) = tracked.into_parts();
        match output {
            OutputBatch::DatagramBatch(batch) => {
                let mut token = token.unwrap();
                let dropped = connection
                    .output_pending
                    .as_ref()
                    .unwrap()
                    .segments
                    .iter()
                    .map(|segment| segment.quic_datagrams.len())
                    .sum::<usize>();
                if dropped != 0 {
                    return (at, batch, token, segment_count);
                }
                connection
                    .resolve_output(&mut token, segment_count, at)
                    .unwrap();
            }
            OutputBatch::Callback(delay) => at += delay.max(Duration::from_micros(1)),
            OutputBatch::None => panic!("connection produced no datagram disposition"),
        }
    }
}

fn deliver_batch(connection: &mut Connection, batch: &datagram::Batch, at: std::time::Instant) {
    for datagram in batch.iter() {
        connection.process_input(datagram.to_owned(), at);
    }
}

fn read_stream(connection: &mut Connection, stream_id: StreamId) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let (read, fin) = connection.stream_recv(stream_id, &mut buffer).unwrap();
        output.extend_from_slice(&buffer[..read]);
        if fin {
            return output;
        }
        assert_ne!(read, 0, "stream stalled before FIN");
    }
}

fn assert_output_pending_panic<T>(f: impl FnOnce() -> T) {
    let payload = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("operation should panic"),
        Err(payload) => payload,
    };
    assert!(
        payload
            .downcast_ref::<Error>()
            .is_some_and(|error| *error == Error::OutputPending),
        "unexpected panic payload: {payload:?}"
    );
}

#[test]
fn tracked_output_full_send_commits() {
    let (mut client, mut server) = connected();
    let data = vec![0x41; 2048];
    let stream_id = queue_stream(&mut client, &data);
    let tracked_before = client.loss_recovery.tracked_packet_count();

    let (at, batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    assert_eq!(segment_count, batch.num_datagrams());
    assert!(client.output_pending.is_some());
    assert!(client.loss_recovery.tracked_packet_count() > tracked_before);

    client
        .resolve_output(&mut token, segment_count, at)
        .unwrap();
    assert!(client.output_pending.is_none());
    deliver_batch(&mut server, &batch, at);
    assert_eq!(read_stream(&mut server, stream_id), data);
}

#[test]
fn tracked_output_statistics_are_committed_only_until_resolution() {
    let (mut client, _) = connected();
    queue_stream(&mut client, b"committed-statistics");
    let before = client.committed_stats();
    let (at, batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    let tentative = client.stats();
    let committed = client.committed_stats();

    assert!(tentative.packets_tx > before.packets_tx);
    assert_eq!(committed.packets_tx, before.packets_tx);
    assert_eq!(committed.pmtud_tx, before.pmtud_tx);
    assert_eq!(committed.frame_tx, before.frame_tx);
    assert_eq!(committed.ecn_tx, before.ecn_tx);

    client
        .resolve_output(&mut token, segment_count, at)
        .unwrap();
    assert_eq!(client.committed_stats().packets_tx, tentative.packets_tx);
    drop(batch);
}

#[test]
fn tracked_output_full_abandon_restores_state_and_skips_packet_numbers() {
    let (mut client, mut server) = connected();
    let data = vec![0x42; 2048];
    let stream_id = queue_stream(&mut client, &data);
    let stats_before = client.stats.borrow().clone();
    let cwnd_before = cwnd(&client);
    let cwnd_avail_before = cwnd_avail(&client);
    let tracked_before = client.loss_recovery.tracked_packet_count();
    let pn_before = next_application_pn(&client);
    let path = client.paths.primary().unwrap();
    let rtt_before = (
        path.borrow().rtt().estimate(),
        path.borrow().rtt().rttvar(),
        path.borrow().rtt().minimum(),
    );

    let (at, _abandoned_batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    let pn_after_generation = next_application_pn(&client);
    assert!(pn_after_generation > pn_before);
    assert!(cwnd_avail(&client) < cwnd_avail_before);
    client.resolve_output(&mut token, 0, at).unwrap();

    assert_eq!(next_application_pn(&client), pn_after_generation);
    assert_eq!(client.loss_recovery.tracked_packet_count(), tracked_before);
    assert_eq!(cwnd(&client), cwnd_before);
    assert_eq!(cwnd_avail(&client), cwnd_avail_before);
    let stats_after = client.stats.borrow();
    assert_eq!(stats_after.packets_tx, stats_before.packets_tx);
    assert_eq!(stats_after.frame_tx, stats_before.frame_tx);
    assert_eq!(stats_after.lost, stats_before.lost);
    assert_eq!(stats_after.pmtud_lost, stats_before.pmtud_lost);
    assert!(stats_after.cc.congestion_events == stats_before.cc.congestion_events);
    drop(stats_after);
    assert_eq!(
        (
            path.borrow().rtt().estimate(),
            path.borrow().rtt().rttvar(),
            path.borrow().rtt().minimum(),
        ),
        rtt_before
    );

    let (at, batch, mut token, regenerated_segments) = next_tracked_batch(&mut client, at);
    assert!(next_application_pn(&client) > pn_after_generation);
    client
        .resolve_output(&mut token, regenerated_segments, at)
        .unwrap();
    deliver_batch(&mut server, &batch, at);
    assert_eq!(read_stream(&mut server, stream_id), data);
    assert_ne!(segment_count, 0);
}

#[test]
fn tracked_output_partial_gso_accepts_prefix_and_requeues_suffix() {
    let (mut client, mut server) = connected();
    let data = vec![0x43; 8192];
    let stream_id = queue_stream(&mut client, &data);
    let tracked_before = client.loss_recovery.tracked_packet_count();

    let (at, batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    assert!(segment_count > 1, "test requires a GSO batch");
    let accepted_packets = client.output_pending.as_ref().unwrap().segments[0]
        .packets
        .len();
    let first = batch.iter().next().unwrap().to_owned();
    client.resolve_output(&mut token, 1, at).unwrap();
    assert_eq!(
        client.loss_recovery.tracked_packet_count(),
        tracked_before + accepted_packets
    );
    server.process_input(first, at);

    let (at, recovery, mut token, recovery_segments) = next_tracked_batch(&mut client, at);
    client
        .resolve_output(&mut token, recovery_segments, at)
        .unwrap();
    deliver_batch(&mut server, &recovery, at);
    assert_eq!(read_stream(&mut server, stream_id), data);
}

#[test]
fn tracked_output_coalesced_packets_share_one_segment() {
    let mut client = default_client();
    let mut server = default_server();
    connect(&mut client, &mut server);
    let at = now();
    let resumption_token = exchange_ticket(&mut client, &mut server, at);

    let mut client = default_client();
    client.enable_resumption(at, resumption_token).unwrap();
    queue_stream(&mut client, &[0x48; 32]);

    // SNI slicing emits an Initial-only datagram first.  The following output
    // deterministically coalesces the remaining Initial and 0-RTT packets.
    assert!(client.process_output(at).dgram().is_some());

    let tracked_before = client.loss_recovery.tracked_packet_count();
    let (at, _batch, mut token, segment_count) = next_tracked_batch(&mut client, at);
    assert_eq!(segment_count, 1);
    assert!(
        client.output_pending.as_ref().unwrap().segments[0]
            .packets
            .len()
            > 1,
        "resumed client output should coalesce Initial and 0-RTT packets"
    );
    client.resolve_output(&mut token, 0, at).unwrap();
    assert_eq!(client.loss_recovery.tracked_packet_count(), tracked_before);
}

#[test]
fn tracked_output_rejects_invalid_foreign_stale_and_duplicate_tokens() {
    let (mut first, _) = connected();
    queue_stream(&mut first, &[0x44; 32]);
    let (at, _batch, mut token, segment_count) = next_tracked_batch(&mut first, now());
    let connection_id = token.connection_id;
    let generation = token.generation;

    assert_eq!(
        first.resolve_output(&mut token, segment_count + 1, at),
        Err(Error::InvalidInput)
    );
    assert!(first.output_pending.is_some());
    assert!(!token.resolved);

    let (mut second, _) = connected();
    queue_stream(&mut second, &[0x45; 32]);
    let (second_at, _batch, mut second_token, second_segments) =
        next_tracked_batch(&mut second, now());
    assert_eq!(
        second.resolve_output(&mut token, 0, second_at),
        Err(Error::InvalidOutputToken)
    );
    assert!(second.output_pending.is_some());
    assert!(!token.resolved);

    first.resolve_output(&mut token, segment_count, at).unwrap();
    assert!(token.resolved);
    assert_eq!(
        first.resolve_output(&mut token, segment_count, at),
        Err(Error::InvalidOutputToken)
    );

    let mut stale = OutputToken {
        connection_id,
        generation,
        resolved: false,
    };
    assert_eq!(
        first.resolve_output(&mut stale, segment_count, at),
        Err(Error::InvalidOutputToken)
    );
    assert!(!stale.resolved);

    second
        .resolve_output(&mut second_token, second_segments, second_at)
        .unwrap();
}

#[test]
fn tracked_output_abandon_rearms_exact_ack_state() {
    let (mut client, mut server) = connected();
    queue_stream(&mut client, &[0x46; 4096]);
    let (at, batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    client
        .resolve_output(&mut token, segment_count, at)
        .unwrap();
    deliver_batch(&mut server, &batch, at);

    let mut at = at;
    let (before, tracked) = loop {
        let before = server.acks.output_checkpoint();
        let tracked = server
            .process_multiple_output_tracked(at, NonZeroUsize::new(1).unwrap())
            .unwrap();
        if matches!(tracked.output(), OutputBatch::DatagramBatch(_)) {
            break (before, tracked);
        }
        let OutputBatch::Callback(delay) = tracked.output() else {
            panic!("server produced no ACK output");
        };
        at += (*delay).max(Duration::from_micros(1));
    };
    let (output, token) = tracked.into_parts();
    assert!(matches!(output, OutputBatch::DatagramBatch(_)));
    let mut token = token.unwrap();
    server.resolve_output(&mut token, 0, at).unwrap();
    assert_eq!(server.acks.output_checkpoint(), before);

    let regenerated = server
        .process_multiple_output_tracked(at, NonZeroUsize::new(1).unwrap())
        .unwrap();
    assert!(matches!(
        regenerated.output(),
        OutputBatch::DatagramBatch(_)
    ));
    let (_, token) = regenerated.into_parts();
    let mut token = token.unwrap();
    server.resolve_output(&mut token, 0, at).unwrap();
}

#[test]
fn tracked_output_metadata_scales_with_generated_packets_not_payload() {
    let (mut client, _) = connected();
    queue_stream(&mut client, &[0x47; 32 * 1024]);
    let (at, _batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    let pending = client.output_pending.as_ref().unwrap();
    let packet_count = pending
        .segments
        .iter()
        .map(|segment| segment.packets.len())
        .sum::<usize>();
    let undo_count = pending
        .segments
        .iter()
        .map(|segment| segment.streams.len())
        .sum::<usize>();
    assert!(packet_count <= segment_count * 3);
    assert!(undo_count <= packet_count * 8);
    client.resolve_output(&mut token, 0, at).unwrap();
}

#[test]
fn tracked_output_rejects_mutation_until_explicit_resolution() {
    let (mut client, _) = connected();
    let stream_id = queue_stream(&mut client, &[0x49; 2048]);
    let (at, batch, mut token, _segment_count) = next_tracked_batch(&mut client, now());
    let input = batch.iter().next().unwrap().to_owned();

    assert!(matches!(
        client.process_multiple_output_tracked(at, MAX_SEGMENTS),
        Err(Error::OutputPending)
    ));
    assert_output_pending_panic(|| client.process_multiple_output(at, MAX_SEGMENTS));
    assert_output_pending_panic(|| client.process_output(at + Duration::from_secs(1)));
    assert_output_pending_panic(|| client.process_input(input, at));
    assert_eq!(
        client.migrate(None, None, false, at),
        Err(Error::OutputPending)
    );
    assert_eq!(
        client.stream_create(StreamType::UniDi),
        Err(Error::OutputPending)
    );
    assert_eq!(
        client.stream_send(stream_id, b"blocked"),
        Err(Error::OutputPending)
    );
    assert!(client.stream_avail_send_space(stream_id).is_ok());
    assert_output_pending_panic(|| client.next_event());
    assert_output_pending_panic(|| client.close(at, 0, "blocked output"));
    #[cfg(feature = "mcquic")]
    assert_output_pending_panic(|| client.mcquic_revoke_operation());

    client.resolve_output(&mut token, 0, at).unwrap();
    assert!(!client.output_pending());
}

#[test]
fn dropping_tracked_batch_does_not_unlock_connection() {
    let (mut client, _) = connected();
    queue_stream(&mut client, &[0x4a; 32]);
    let tracked = client
        .process_multiple_output_tracked(now(), MAX_SEGMENTS)
        .unwrap();
    assert!(matches!(tracked.output(), OutputBatch::DatagramBatch(_)));

    drop(tracked);

    assert!(client.output_pending());
    assert_eq!(
        client.stream_create(StreamType::UniDi),
        Err(Error::OutputPending)
    );
    drop(client);
}

#[test]
fn abandon_before_ack_removes_phantom_flight_and_requeues_stream_immediately() {
    let (mut client, mut server) = connected();
    let first_stream = queue_stream(&mut client, &[0x4b; 1024]);
    let (at, first_batch, mut first_token, first_segments) = next_tracked_batch(&mut client, now());
    client
        .resolve_output(&mut first_token, first_segments, at)
        .unwrap();
    deliver_batch(&mut server, &first_batch, at);
    assert_eq!(read_stream(&mut server, first_stream), vec![0x4b; 1024]);

    let (ack_at, ack_batch, mut ack_token, ack_segments) = next_tracked_batch(&mut server, at);
    server
        .resolve_output(&mut ack_token, ack_segments, ack_at)
        .unwrap();

    let tracked_before_blocked = client.loss_recovery.tracked_packet_count();
    let cwnd_before_blocked = cwnd_avail(&client);
    let loss_before = client.stats.borrow().lost;
    let second_data = vec![0x4c; 4096];
    let second_stream = queue_stream(&mut client, &second_data);
    let (blocked_at, blocked_batch, mut blocked_token, _) = next_tracked_batch(&mut client, ack_at);
    let blocked_flight = cwnd_avail(&client);
    assert!(blocked_flight < cwnd_before_blocked);

    let ack = ack_batch.iter().next().unwrap().to_owned();
    assert_output_pending_panic(|| client.process_input(ack, blocked_at));
    assert_eq!(cwnd_avail(&client), blocked_flight);
    assert!(client.output_pending());

    client
        .resolve_output(&mut blocked_token, 0, blocked_at)
        .unwrap();
    assert_eq!(
        client.loss_recovery.tracked_packet_count(),
        tracked_before_blocked
    );
    assert_eq!(cwnd_avail(&client), cwnd_before_blocked);
    assert_eq!(client.stats.borrow().lost, loss_before);

    for ack in ack_batch.iter() {
        client.process_input(ack.to_owned(), blocked_at);
    }
    assert!(client.loss_recovery.tracked_packet_count() < tracked_before_blocked);
    assert!(cwnd_avail(&client) > cwnd_before_blocked);

    let (retry_at, retry_batch, mut retry_token, retry_segments) =
        next_tracked_batch(&mut client, blocked_at);
    client
        .resolve_output(&mut retry_token, retry_segments, retry_at)
        .unwrap();
    deliver_batch(&mut server, &retry_batch, retry_at);
    assert_eq!(read_stream(&mut server, second_stream), second_data);
    assert_ne!(blocked_batch.num_datagrams(), 0);
}

#[test]
fn disabled_ecn_is_reflected_in_wire_and_recovery_state() {
    let (mut client, _) = connected_with_client_params(ConnectionParameters::default().ecn(false));
    queue_stream(&mut client, &[0x4d; 2048]);
    let ect0_before = client
        .stats
        .borrow()
        .ecn_tx
        .values()
        .map(|counts| counts[Ecn::Ect0])
        .sum::<u64>();

    let (at, batch, mut token, segment_count) = next_tracked_batch(&mut client, now());
    assert!(
        batch
            .iter()
            .all(|datagram| Ecn::from(datagram.tos()) == Ecn::NotEct)
    );
    client
        .resolve_output(&mut token, segment_count, at)
        .unwrap();

    let stats = client.stats.borrow();
    assert_eq!(
        stats
            .ecn_tx
            .values()
            .map(|counts| counts[Ecn::Ect0])
            .sum::<u64>(),
        ect0_before
    );
}

#[test]
fn oversized_datagram_disposition_is_transactional() {
    let (mut client, _) = connected();
    let estimated_max = client.max_datagram_size().unwrap();
    let oversized = usize::try_from(
        client
            .remote_datagram_size()
            .min(estimated_max.saturating_add(1024)),
    )
    .unwrap();
    assert!(u64::try_from(oversized).unwrap() > estimated_max);
    client
        .send_datagram(vec![0x4e; oversized], Some(77))
        .unwrap();
    client.test_frame_writer = Some(Box::new(PingWriter {}));
    let dropped_before = client.stats.borrow().datagram_tx.dropped_too_big;

    let (at, _batch, mut token, _) = next_tracked_datagram_drop_batch(&mut client, now());
    assert_eq!(
        client
            .output_pending
            .as_ref()
            .unwrap()
            .segments
            .iter()
            .map(|segment| segment.quic_datagrams.len())
            .sum::<usize>(),
        1
    );
    assert_eq!(
        client.stats.borrow().datagram_tx.dropped_too_big,
        dropped_before
    );
    client.resolve_output(&mut token, 0, at).unwrap();
    assert_eq!(
        client.stats.borrow().datagram_tx.dropped_too_big,
        dropped_before
    );

    let (at, _batch, mut token, segment_count) = next_tracked_datagram_drop_batch(&mut client, at);
    client
        .resolve_output(&mut token, segment_count, at)
        .unwrap();
    client.test_frame_writer = None;
    assert_eq!(
        client.stats.borrow().datagram_tx.dropped_too_big,
        dropped_before + 1
    );
    assert!(std::iter::from_fn(|| client.next_event()).any(|event| {
        matches!(
            event,
            ConnectionEvent::OutgoingDatagramOutcome {
                id: 77,
                outcome: OutgoingDatagramOutcome::DroppedTooBig
            }
        )
    }));
}
