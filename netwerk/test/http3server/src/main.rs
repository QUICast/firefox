// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use base64::prelude::*;
use neqo_bin::server::{HttpServer, Runner};
use neqo_common::Bytes;
use neqo_common::{Datagram, Header, event::Provider, qdebug, qerror, qinfo, qtrace};
use neqo_http3::{
    ConnectUdpRequest, ConnectUdpServerEvent, Error, Http3OrWebTransportStream, Http3Parameters,
    Http3Server, Http3ServerEvent, SessionAcceptAction, StreamId, WebTransportRequest,
    WebTransportServerEvent,
};
use neqo_transport::mcquic::{
    Announce as McquicAnnounce, ChannelFrame as McquicChannelFrame,
    ChannelSendState as McquicChannelSendState, ChannelState as McquicChannelState,
    Frame as McquicFrame, Integrity as McquicIntegrity, Join as McquicJoin, Key as McquicKey,
    Leave as McquicLeave, Retire as McquicRetire,
};
use neqo_transport::server::ConnectionRef;
use neqo_transport::{
    ConnectionEvent, ConnectionParameters, OutputBatch, RandomConnectionIdGenerator, StreamType,
};
use nss_rs::{AllowZeroRtt, AntiReplay, generate_ech_keys, init_db};
use std::env;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWriteExt;
use tokio::io::ReadBuf;
use tokio::task::LocalSet;

use std::cell::RefCell;
use std::io;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use cfg_if::cfg_if;

cfg_if! {
  if
#[cfg(not(target_os = "android"))] {
        use std::sync::mpsc::{channel, Receiver, TryRecvError};
        use http_body_util::{BodyExt, Full};
        use hyper::header::{HeaderName, HeaderValue};
        use hyper::Method;
        use hyper_util::client::legacy::Client;
    }
}

use std::cmp::min;
use std::collections::HashSet;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};

const MAX_TABLE_SIZE: u64 = 65536;
const MAX_BLOCKED_STREAMS: u16 = 10;
const PROTOCOLS: &[&str] = &["h3"];
const ECH_CONFIG_ID: u8 = 7;
const ECH_PUBLIC_NAME: &str = "public.example";
const MCQUIC_WEBTRANSPORT_PATH: &[u8] = b"/mcquic_webtransport_stream";
const MCQUIC_REVOCATION_PATH: &[u8] = b"/mcquic_permission_revocation";
const MCQUIC_CONNECTION_ISOLATION_PATH: &[u8] = b"/mcquic_permission_connection";
const MCQUIC_RETRY_ONCE_PATH: &[u8] = b"/mcquic_permission_retry_once";
const MCQUIC_PERMISSION_MISSING_PATH: &[u8] = b"/mcquic_permission_missing";
const MCQUIC_PERMISSION_FALSE_PATH: &[u8] = b"/mcquic_permission_false";
const MCQUIC_PERMISSION_MALFORMED_PATH: &[u8] = b"/mcquic_permission_malformed";
const MCQUIC_PERMISSION_UNSOLICITED_PATH: &[u8] = b"/mcquic_permission_unsolicited";
const MCQUIC_UNSOLICITED_RESPONSE_PATH: &[u8] = b"/mcquic_unsolicited_response";
const MCQUIC_AUTH_CHALLENGE_PATH: &[u8] = b"/mcquic_auth_challenge";
const MCQUIC_AUTH_COUNT_PATH: &[u8] = b"/mcquic_auth_count";
const MCQUIC_NON_SUCCESS_TRUE_PATH: &[u8] = b"/mcquic_non_success_true";
const MCQUIC_RESPONSE_DUPLICATE_PATH: &[u8] = b"/mcquic_response_duplicate";
const MCQUIC_RESPONSE_PARAMETER_PATH: &[u8] = b"/mcquic_response_parameter";
const MCQUIC_REDIRECT_PREFIX: &[u8] = b"/mcquic_redirect_";
const MCQUIC_REDIRECT_TARGET_PREFIX: &[u8] = b"/mcquic_redirect_target_";
const MCQUIC_REDIRECT_COUNT_PREFIX: &[u8] = b"/mcquic_redirect_count_";
const MCQUIC_CHANNEL_ID: &[u8] = b"mcquic-wt-test";
const MCQUIC_SOURCE: Ipv4Addr = Ipv4Addr::LOCALHOST;
const MCQUIC_GROUP: Ipv4Addr = Ipv4Addr::new(232, 0, 0, 1);
const MCQUIC_STREAM_BODY_OFFSET: u64 = 10;
const MCQUIC_LATE_JOIN_STREAM_ID: u64 = 1_000_000 * 4 + 3;
const MCQUIC_LATE_JOIN_RESET_STREAM_ID: u64 = 1_000_001 * 4 + 3;
const MCQUIC_STEP_DELAY: Duration = Duration::from_millis(150);
const MCQUIC_SCENARIO_TIMEOUT: Duration = Duration::from_secs(20);

fn parse_status_path(path: &[u8], prefix: &[u8]) -> Option<u16> {
    let suffix = path.strip_prefix(prefix)?;
    std::str::from_utf8(suffix).ok()?.parse().ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum McquicWebTransportScenarioKind {
    Full,
    Revocation,
}
#[derive(Clone, Debug)]
enum McquicWebTransportPhase {
    AwaitingInitialDecline,
    AwaitingJoin,
    AwaitingRevocationAck {
        packet_number: u64,
    },
    AwaitingRevocation,
    AwaitingHighStreamAck {
        packet_number: u64,
    },
    AwaitingHighResetAck {
        packet_number: u64,
    },
    BeforePrefixDelay {
        release_at: Instant,
    },
    AwaitingBeforePrefixAck {
        stream_id: StreamId,
        packet_number: u64,
    },
    AwaitingRecoveryAck {
        stream_id: StreamId,
        packet_number: u64,
    },
    KeyReleaseDelay {
        release_at: Instant,
        key: McquicKey,
        packet_number: u64,
    },
    AwaitingKeyDelayedAck {
        packet_number: u64,
    },
    IntegrityReleaseDelay {
        release_at: Instant,
        integrity: McquicIntegrity,
        packet_number: u64,
    },
    AwaitingIntegrityDelayedAck {
        packet_number: u64,
    },
    ResetPrefixDelay {
        release_at: Instant,
        stream_id: StreamId,
    },
    AwaitingResetAck {
        packet_number: u64,
    },
    AwaitingLeft,
    RetireDelay {
        release_at: Instant,
    },
    AwaitingRetired,
    Complete,
}

struct McquicWebTransportScenario {
    session: WebTransportRequest,
    kind: McquicWebTransportScenarioKind,
    sender: StdUdpSocket,
    destination: SocketAddrV4,
    announce: McquicAnnounce,
    first_key: McquicKey,
    channel_sender: McquicChannelSendState,
    phase: McquicWebTransportPhase,
    start_at: Instant,
    started: bool,
    deadline: Instant,
    latest_limits_sequence: u64,
    latest_state_sequence: u64,
    latest_packet_number: u64,
    acknowledged_packets: HashSet<u64>,
    ack_frames_seen: usize,
    saw_initial_decline: bool,
    saw_joined: bool,
    saw_left: bool,
    saw_retired: bool,
    saw_zero_limits: bool,
}

fn mcquic_webtransport_prefix(session_id: StreamId) -> Result<[u8; 10], String> {
    let session_id = session_id.as_u64();
    if session_id >= (1 << 62) {
        return Err(format!(
            "WebTransport session ID {session_id} is not a QUIC varint"
        ));
    }

    let mut prefix = [0; 10];
    prefix[..2].copy_from_slice(&[0x40, 0x54]);
    prefix[2..].copy_from_slice(&(session_id | (3 << 62)).to_be_bytes());
    Ok(prefix)
}

fn create_raw_webtransport_unidi_stream(session: &WebTransportRequest) -> Result<StreamId, String> {
    session
        .conn
        .borrow_mut()
        .stream_create(StreamType::UniDi)
        .map_err(|e| format!("create WebTransport unidirectional stream: {e}"))
}

fn send_raw_webtransport_prefix(
    session: &WebTransportRequest,
    stream_id: StreamId,
) -> Result<(), String> {
    let prefix = mcquic_webtransport_prefix(session.stream_id())?;
    send_raw_webtransport_bytes(session, stream_id, &prefix)
}

fn send_raw_webtransport_bytes(
    session: &WebTransportRequest,
    stream_id: StreamId,
    data: &[u8],
) -> Result<(), String> {
    let sent = session
        .conn
        .borrow_mut()
        .stream_send(stream_id, data)
        .map_err(|e| format!("send WebTransport bytes on stream {stream_id}: {e}"))?;
    if sent != data.len() {
        return Err(format!(
            "short WebTransport write on stream {stream_id}: {sent}/{}",
            data.len()
        ));
    }
    Ok(())
}

fn send_raw_webtransport_message(
    session: &WebTransportRequest,
    body: &[u8],
) -> Result<StreamId, String> {
    let stream_id = create_raw_webtransport_unidi_stream(session)?;
    let prefix = mcquic_webtransport_prefix(session.stream_id())?;
    let mut data = Vec::with_capacity(prefix.len() + body.len());
    data.extend_from_slice(&prefix);
    data.extend_from_slice(body);

    let mut conn = session.conn.borrow_mut();
    let sent = conn
        .stream_send(stream_id, &data)
        .map_err(|e| format!("send unicast WebTransport stream {stream_id}: {e}"))?;
    if sent != data.len() {
        return Err(format!(
            "short unicast WebTransport write on stream {stream_id}: {sent}/{}",
            data.len()
        ));
    }
    conn.stream_close_send(stream_id)
        .map_err(|e| format!("finish unicast WebTransport stream {stream_id}: {e}"))?;
    Ok(stream_id)
}

fn create_loopback_ssm_sender() -> io::Result<(StdUdpSocket, u16)> {
    let receiver = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    receiver.set_reuse_address(true)?;
    receiver.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    let port = receiver
        .local_addr()?
        .as_socket_ipv4()
        .ok_or_else(|| io::Error::other("SSM probe did not bind an IPv4 socket"))?
        .port();
    receiver.join_ssm_v4(&MCQUIC_SOURCE, &MCQUIC_GROUP, &MCQUIC_SOURCE)?;
    let receiver: StdUdpSocket = receiver.into();
    receiver.set_read_timeout(Some(Duration::from_millis(500)))?;

    let sender = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sender.bind(&SocketAddrV4::new(MCQUIC_SOURCE, 0).into())?;
    sender.set_multicast_loop_v4(true)?;
    sender.set_multicast_ttl_v4(1)?;
    sender.set_multicast_if_v4(&MCQUIC_SOURCE)?;
    let sender: StdUdpSocket = sender.into();

    const PROBE: &[u8] = b"mcquic-loopback-ssm-probe";
    sender.send_to(PROBE, SocketAddrV4::new(MCQUIC_GROUP, port))?;
    let mut received = [0; 64];
    let (len, source) = receiver.recv_from(&mut received)?;
    if source.ip() != IpAddr::V4(MCQUIC_SOURCE) || &received[..len] != PROBE {
        return Err(io::Error::other(format!(
            "SSM probe received unexpected packet from {source}"
        )));
    }

    Ok((sender, port))
}

impl McquicWebTransportScenario {
    fn new(session: WebTransportRequest, now: Instant) -> io::Result<Self> {
        Self::new_with_kind(session, now, McquicWebTransportScenarioKind::Full)
    }

    fn new_revocation(session: WebTransportRequest, now: Instant) -> io::Result<Self> {
        Self::new_with_kind(session, now, McquicWebTransportScenarioKind::Revocation)
    }

    fn new_with_kind(
        session: WebTransportRequest,
        now: Instant,
        kind: McquicWebTransportScenarioKind,
    ) -> io::Result<Self> {
        let (sender, port) = create_loopback_ssm_sender()?;
        let announce = McquicAnnounce {
            channel_id: MCQUIC_CHANNEL_ID.to_vec(),
            source: IpAddr::V4(MCQUIC_SOURCE),
            group: IpAddr::V4(MCQUIC_GROUP),
            udp_port: port,
            header_protection_algorithm: 0x1301,
            header_secret: vec![0x11; 32].into(),
            aead_algorithm: 0x1301,
            integrity_hash_algorithm: 1,
            max_rate_kibps: 1024,
            max_ack_delay_ms: 10,
        };
        let first_key = McquicKey {
            channel_id: MCQUIC_CHANNEL_ID.to_vec(),
            key_sequence: 1,
            from_packet_number: 0,
            secret: vec![0x22; 32].into(),
        };
        let channel_sender = McquicChannelSendState::new(announce.clone(), first_key.clone())
            .map_err(|e| io::Error::other(format!("create authenticated MCQUIC sender: {e}")))?;

        Ok(Self {
            session,
            kind,
            sender,
            destination: SocketAddrV4::new(MCQUIC_GROUP, port),
            announce,
            first_key,
            channel_sender,
            phase: McquicWebTransportPhase::AwaitingInitialDecline,
            start_at: now + MCQUIC_STEP_DELAY,
            started: false,
            deadline: now + MCQUIC_SCENARIO_TIMEOUT,
            latest_limits_sequence: 0,
            latest_state_sequence: 0,
            latest_packet_number: 0,
            acknowledged_packets: HashSet::new(),
            ack_frames_seen: 0,
            saw_initial_decline: false,
            saw_joined: false,
            saw_left: false,
            saw_retired: false,
            saw_zero_limits: false,
        })
    }

    fn conn(&self) -> ConnectionRef {
        self.session.conn.clone()
    }

    fn start(&mut self, server: &mut Http3Server) -> Result<(), String> {
        let conn = self.conn();
        if server.peer_mcquic_client_params(&conn).is_none() {
            return Err("client did not advertise generic MCQUIC transport parameters".into());
        }

        self.send_control(server, McquicFrame::Announce(self.announce.clone()))?;
        // Deliberately request a key the client has not received. The client must
        // decline this join while ordinary unicast WebTransport remains usable.
        self.send_control(
            server,
            McquicFrame::Join(McquicJoin {
                channel_id: MCQUIC_CHANNEL_ID.to_vec(),
                mc_limits_sequence: 0,
                mc_state_sequence: 0,
                mc_key_sequence: self.first_key.key_sequence,
            }),
        )
    }

    fn send_control(&self, server: &mut Http3Server, frame: McquicFrame) -> Result<(), String> {
        server
            .mcquic_send(&self.conn(), frame)
            .map_err(|e| format!("queue MCQUIC control frame: {e}"))
    }

    fn create_stream_with_prefix(&self) -> Result<StreamId, String> {
        let stream_id = create_raw_webtransport_unidi_stream(&self.session)?;
        send_raw_webtransport_prefix(&self.session, stream_id)?;
        Ok(stream_id)
    }

    fn send_channel_packet(
        &mut self,
        server: &mut Http3Server,
        frame: McquicChannelFrame,
        send_integrity: bool,
    ) -> Result<(u64, McquicIntegrity), String> {
        let mut packet = [0; 1200];
        let output = self
            .channel_sender
            .write_packet(&[frame], &mut packet)
            .map_err(|e| format!("encode authenticated MCQUIC packet: {e}"))?;
        if send_integrity {
            self.send_control(server, McquicFrame::Integrity(output.integrity.clone()))?;
        }
        let sent = self
            .sender
            .send_to(&packet[..output.packet_len], self.destination)
            .map_err(|e| format!("send loopback MCQUIC packet: {e}"))?;
        if sent != output.packet_len {
            return Err(format!(
                "short loopback MCQUIC packet write: {sent}/{}",
                output.packet_len
            ));
        }
        self.latest_packet_number = output.packet_number;
        Ok((output.packet_number, output.integrity))
    }

    fn drain_feedback(&mut self, server: &Http3Server) -> Result<(), String> {
        let conn = self.conn();
        while server.mcquic_readable(&conn) {
            let Some(frame) = server.mcquic_recv(&conn) else {
                return Err("MCQUIC feedback was readable but no frame was returned".into());
            };
            match frame {
                McquicFrame::Ack(ack) => {
                    if ack.channel_id != MCQUIC_CHANNEL_ID {
                        return Err("client ACK named an unexpected MCQUIC channel".into());
                    }
                    qinfo!(
                        "MCQUIC WebTransport test observed ACK for packet {}",
                        ack.largest_acknowledged
                    );
                    self.acknowledged_packets.insert(ack.largest_acknowledged);
                    self.ack_frames_seen += 1;
                }
                McquicFrame::State(state) => {
                    if state.channel_id != MCQUIC_CHANNEL_ID {
                        return Err("client state named an unexpected MCQUIC channel".into());
                    }
                    qinfo!(
                        "MCQUIC WebTransport test observed state {:?} sequence {} reason {}",
                        state.state,
                        state.sequence,
                        state.reason_code
                    );
                    self.latest_state_sequence = self.latest_state_sequence.max(state.sequence);
                    match state.state {
                        McquicChannelState::DeclinedJoin => {
                            if !matches!(
                                self.phase,
                                McquicWebTransportPhase::AwaitingInitialDecline
                            ) {
                                return Err(format!(
                                    "client unexpectedly declined MCQUIC join after key installation: reason {}",
                                    state.reason_code
                                ));
                            }
                            self.saw_initial_decline = true;
                        }
                        McquicChannelState::Joined => {
                            if matches!(self.phase, McquicWebTransportPhase::AwaitingInitialDecline)
                            {
                                return Err(concat!(
                                    "client joined before declining the intentionally ",
                                    "unsynchronized join"
                                )
                                .into());
                            }
                            self.saw_joined = true;
                        }
                        McquicChannelState::Left => self.saw_left = true,
                        McquicChannelState::Retired => self.saw_retired = true,
                    }
                }
                McquicFrame::Limits(limits) => {
                    qinfo!(
                        "MCQUIC WebTransport test observed client limits sequence {}",
                        limits.sequence
                    );
                    self.latest_limits_sequence = self.latest_limits_sequence.max(limits.sequence);
                    if !limits.limits.ipv4_channels_allowed
                        && !limits.limits.ipv6_channels_allowed
                        && limits.limits.max_aggregate_rate_kibps == 0
                        && limits.limits.max_channel_ids == 0
                        && limits.max_joined_count == 0
                    {
                        self.saw_zero_limits = true;
                    }
                }
                other => {
                    return Err(format!(
                        "unexpected client MCQUIC feedback frame: {other:?}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn acknowledged(&self, packet_number: u64) -> bool {
        self.acknowledged_packets.contains(&packet_number)
    }

    fn advance(&mut self, server: &mut Http3Server, now: Instant) -> Result<(), String> {
        if now >= self.deadline {
            return Err(format!(
                "MCQUIC WebTransport scenario timed out in phase {:?}",
                self.phase
            ));
        }
        if !self.started {
            if now < self.start_at {
                return Ok(());
            }
            self.start(server)?;
            self.started = true;
        }
        self.drain_feedback(server)?;

        loop {
            match self.phase.clone() {
                McquicWebTransportPhase::AwaitingInitialDecline => {
                    if !self.saw_initial_decline {
                        break;
                    }
                    send_raw_webtransport_message(&self.session, b"unicast-fallback-before-join")?;
                    self.send_control(server, McquicFrame::Key(self.first_key.clone()))?;
                    self.send_control(
                        server,
                        McquicFrame::Join(McquicJoin {
                            channel_id: MCQUIC_CHANNEL_ID.to_vec(),
                            mc_limits_sequence: self.latest_limits_sequence,
                            mc_state_sequence: self.latest_state_sequence,
                            mc_key_sequence: self.first_key.key_sequence,
                        }),
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingJoin;
                }
                McquicWebTransportPhase::AwaitingJoin => {
                    if !self.saw_joined {
                        break;
                    }
                    if self.kind == McquicWebTransportScenarioKind::Revocation {
                        let stream_id = self.create_stream_with_prefix()?;
                        let (packet_number, _) = self.send_channel_packet(
                            server,
                            McquicChannelFrame::Stream {
                                stream_id: stream_id.as_u64(),
                                offset: MCQUIC_STREAM_BODY_OFFSET,
                                fin: true,
                                data: b"multicast-before-revocation".to_vec(),
                            },
                            true,
                        )?;
                        self.phase =
                            McquicWebTransportPhase::AwaitingRevocationAck { packet_number };
                        break;
                    }
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::Stream {
                            stream_id: MCQUIC_LATE_JOIN_STREAM_ID,
                            offset: MCQUIC_STREAM_BODY_OFFSET,
                            fin: true,
                            data: b"sparse-high-stream".to_vec(),
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingHighStreamAck { packet_number };
                    break;
                }
                McquicWebTransportPhase::AwaitingRevocationAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    self.phase = McquicWebTransportPhase::AwaitingRevocation;
                }
                McquicWebTransportPhase::AwaitingRevocation => {
                    if !self.saw_left || !self.saw_zero_limits {
                        break;
                    }
                    send_raw_webtransport_message(
                        &self.session,
                        b"unicast-fallback-after-revocation",
                    )?;
                    self.phase = McquicWebTransportPhase::Complete;
                    break;
                }
                McquicWebTransportPhase::AwaitingHighStreamAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::ResetStream {
                            stream_id: MCQUIC_LATE_JOIN_RESET_STREAM_ID,
                            error_code: Error::HttpNone.code(),
                            final_size: 0,
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingHighResetAck { packet_number };
                    break;
                }
                McquicWebTransportPhase::AwaitingHighResetAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    self.phase = McquicWebTransportPhase::BeforePrefixDelay {
                        release_at: now + MCQUIC_STEP_DELAY,
                    };
                    break;
                }
                McquicWebTransportPhase::BeforePrefixDelay { release_at } => {
                    if now < release_at {
                        break;
                    }
                    let stream_id = create_raw_webtransport_unidi_stream(&self.session)?;
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::Stream {
                            stream_id: stream_id.as_u64(),
                            offset: MCQUIC_STREAM_BODY_OFFSET,
                            fin: true,
                            data: b"multicast-before-prefix".to_vec(),
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingBeforePrefixAck {
                        stream_id,
                        packet_number,
                    };
                    break;
                }
                McquicWebTransportPhase::AwaitingBeforePrefixAck {
                    stream_id,
                    packet_number,
                } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    send_raw_webtransport_prefix(&self.session, stream_id)?;

                    const MISSING: &[u8] = b"lost-";
                    let stream_id = self.create_stream_with_prefix()?;
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::Stream {
                            stream_id: stream_id.as_u64(),
                            offset: MCQUIC_STREAM_BODY_OFFSET
                                + u64::try_from(MISSING.len())
                                    .map_err(|e| format!("recovery gap length: {e}"))?,
                            fin: true,
                            data: b"tail".to_vec(),
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingRecoveryAck {
                        stream_id,
                        packet_number,
                    };
                    break;
                }
                McquicWebTransportPhase::AwaitingRecoveryAck {
                    stream_id,
                    packet_number,
                } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    send_raw_webtransport_bytes(&self.session, stream_id, b"lost-")?;

                    let key = McquicKey {
                        channel_id: MCQUIC_CHANNEL_ID.to_vec(),
                        key_sequence: 2,
                        from_packet_number: self.channel_sender.next_packet_number(),
                        secret: vec![0x33; 32].into(),
                    };
                    self.channel_sender
                        .update_key(key.clone())
                        .map_err(|e| format!("rotate MCQUIC test key: {e}"))?;
                    let stream_id = self.create_stream_with_prefix()?;
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::Stream {
                            stream_id: stream_id.as_u64(),
                            offset: MCQUIC_STREAM_BODY_OFFSET,
                            fin: true,
                            data: b"multicast-key-delayed".to_vec(),
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::KeyReleaseDelay {
                        release_at: now + MCQUIC_STEP_DELAY,
                        key,
                        packet_number,
                    };
                    break;
                }
                McquicWebTransportPhase::KeyReleaseDelay {
                    release_at,
                    key,
                    packet_number,
                } => {
                    if now < release_at {
                        break;
                    }
                    self.send_control(server, McquicFrame::Key(key))?;
                    self.phase = McquicWebTransportPhase::AwaitingKeyDelayedAck { packet_number };
                    break;
                }
                McquicWebTransportPhase::AwaitingKeyDelayedAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    let stream_id = self.create_stream_with_prefix()?;
                    let (packet_number, integrity) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::Stream {
                            stream_id: stream_id.as_u64(),
                            offset: MCQUIC_STREAM_BODY_OFFSET,
                            fin: true,
                            data: b"multicast-integrity-delayed".to_vec(),
                        },
                        false,
                    )?;
                    self.phase = McquicWebTransportPhase::IntegrityReleaseDelay {
                        release_at: now + MCQUIC_STEP_DELAY,
                        integrity,
                        packet_number,
                    };
                    break;
                }
                McquicWebTransportPhase::IntegrityReleaseDelay {
                    release_at,
                    integrity,
                    packet_number,
                } => {
                    if now < release_at {
                        break;
                    }
                    self.send_control(server, McquicFrame::Integrity(integrity))?;
                    self.phase =
                        McquicWebTransportPhase::AwaitingIntegrityDelayedAck { packet_number };
                    break;
                }
                McquicWebTransportPhase::AwaitingIntegrityDelayedAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    let stream_id = self.create_stream_with_prefix()?;
                    self.phase = McquicWebTransportPhase::ResetPrefixDelay {
                        release_at: now + MCQUIC_STEP_DELAY,
                        stream_id,
                    };
                    break;
                }
                McquicWebTransportPhase::ResetPrefixDelay {
                    release_at,
                    stream_id,
                } => {
                    if now < release_at {
                        break;
                    }
                    let (packet_number, _) = self.send_channel_packet(
                        server,
                        McquicChannelFrame::ResetStream {
                            stream_id: stream_id.as_u64(),
                            error_code: Error::HttpNone.code(),
                            final_size: MCQUIC_STREAM_BODY_OFFSET,
                        },
                        true,
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingResetAck { packet_number };
                    break;
                }
                McquicWebTransportPhase::AwaitingResetAck { packet_number } => {
                    if !self.acknowledged(packet_number) {
                        break;
                    }
                    self.send_control(
                        server,
                        McquicFrame::Leave(McquicLeave {
                            channel_id: MCQUIC_CHANNEL_ID.to_vec(),
                            mc_state_sequence: self.latest_state_sequence,
                            after_packet_number: self.latest_packet_number,
                        }),
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingLeft;
                    break;
                }
                McquicWebTransportPhase::AwaitingLeft => {
                    if !self.saw_left {
                        break;
                    }
                    send_raw_webtransport_message(&self.session, b"unicast-fallback-after-leave")?;
                    self.phase = McquicWebTransportPhase::RetireDelay {
                        release_at: now + MCQUIC_STEP_DELAY,
                    };
                    break;
                }
                McquicWebTransportPhase::RetireDelay { release_at } => {
                    if now < release_at {
                        break;
                    }
                    self.send_control(
                        server,
                        McquicFrame::Retire(McquicRetire {
                            channel_id: MCQUIC_CHANNEL_ID.to_vec(),
                            after_packet_number: self.latest_packet_number,
                        }),
                    )?;
                    self.phase = McquicWebTransportPhase::AwaitingRetired;
                    break;
                }
                McquicWebTransportPhase::AwaitingRetired => {
                    if !self.saw_retired {
                        break;
                    }
                    if self.ack_frames_seen < 7 {
                        return Err(format!(
                            "client retired after only {} MC_ACK frames",
                            self.ack_frames_seen
                        ));
                    }
                    let complete = format!(
                        "mcquic-complete:declined,joined,left,retired;acks={}",
                        self.ack_frames_seen
                    );
                    send_raw_webtransport_message(&self.session, complete.as_bytes())?;
                    self.phase = McquicWebTransportPhase::Complete;
                    break;
                }
                McquicWebTransportPhase::Complete => break,
            }
        }

        Ok(())
    }

    fn is_complete(&self) -> bool {
        matches!(self.phase, McquicWebTransportPhase::Complete)
    }
}

const HTTP_RESPONSE_WITH_WRONG_FRAME: &[u8] = &[
    0x01, 0x06, 0x00, 0x00, 0xd9, 0x54, 0x01, 0x37, // headers
    0x0, 0x3, 0x61, 0x62, 0x63, // the first data frame
    0x3, 0x1, 0x5, // a cancel push frame that is not allowed
];
struct Http3TestServer {
    server: Http3Server,
    // This a map from a post request to amount of data ithas been received
    // on the request. The respons will carry the amount of data received.
    posts: HashMap<Http3OrWebTransportStream, usize>,
    responses: HashMap<Http3OrWebTransportStream, Vec<u8>>,
    connections_to_close: HashMap<Instant, Vec<ConnectionRef>>,
    sessions_to_close: HashMap<Instant, Vec<WebTransportRequest>>,
    sessions_to_create_stream: Vec<(WebTransportRequest, StreamType, Option<Vec<u8>>)>,
    // Server-initiated bidi WebTransport sessions for which we create a
    // stream and then, in a later flight, send STOP_SENDING(0x100).
    // Regression test for bug 2043946.
    sessions_to_create_bidi_and_stop_sending: Vec<WebTransportRequest>,
    streams_to_stop_sending: HashMap<Instant, Vec<Http3OrWebTransportStream>>,
    webtransport_bidi_stream: HashSet<Http3OrWebTransportStream>,
    wt_unidi_conn_to_stream: HashMap<ConnectionRef, Http3OrWebTransportStream>,
    wt_unidi_echo_back: HashMap<Http3OrWebTransportStream, Http3OrWebTransportStream>,
    received_datagram: Option<Bytes>,
    request_counts: HashMap<Vec<u8>, usize>,
    webtransport_sessions_per_connection: HashMap<ConnectionRef, usize>,
    mcquic_retry_first_connection: Option<u64>,
    mcquic_auth_header_count: usize,
    mcquic_webtransport_scenario: Option<McquicWebTransportScenario>,
    mcquic_webtransport_pending_status: Option<(Instant, WebTransportRequest, Vec<u8>)>,
    // When true, server will stop processing datagrams after accepting
    // 0-RTT, simulating a stuck ZERORTT session that never transitions to
    // CONNECTED.
    stuck_0rtt_mode: bool,
    stuck_0rtt_activated: bool,
}

impl ::std::fmt::Display for Http3TestServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.server)
    }
}
impl Http3TestServer {
    pub fn new(server: Http3Server) -> Self {
        Self {
            server,
            posts: HashMap::new(),
            responses: HashMap::new(),
            connections_to_close: HashMap::new(),
            sessions_to_close: HashMap::new(),
            sessions_to_create_stream: Vec::new(),
            sessions_to_create_bidi_and_stop_sending: Vec::new(),
            streams_to_stop_sending: HashMap::new(),
            webtransport_bidi_stream: HashSet::new(),
            wt_unidi_conn_to_stream: HashMap::new(),
            wt_unidi_echo_back: HashMap::new(),
            received_datagram: None,
            request_counts: HashMap::new(),
            webtransport_sessions_per_connection: HashMap::new(),
            mcquic_retry_first_connection: None,
            mcquic_auth_header_count: 0,
            mcquic_webtransport_scenario: None,
            mcquic_webtransport_pending_status: None,
            stuck_0rtt_mode: false,
            stuck_0rtt_activated: false,
        }
    }

    fn new_response(&mut self, stream: Http3OrWebTransportStream, mut data: Vec<u8>, now: Instant) {
        if data.len() == 0 {
            let _ = stream.stream_close_send(now);
            return;
        }
        match stream.send_data(&data, now) {
            Ok(sent) => {
                if sent < data.len() {
                    self.responses.insert(stream, data.split_off(sent));
                } else {
                    let _ = stream.stream_close_send(now);
                }
            }
            Err(e) => {
                eprintln!("error is {:?}", e);
            }
        }
    }

    fn handle_stream_writable(&mut self, stream: Http3OrWebTransportStream, now: Instant) {
        if let Some(data) = self.responses.get_mut(&stream) {
            match stream.send_data(&data, now) {
                Ok(sent) => {
                    if sent < data.len() {
                        let new_d = (*data).split_off(sent);
                        *data = new_d;
                    } else {
                        stream.stream_close_send(now).unwrap();
                        self.responses.remove(&stream);
                    }
                }
                Err(_) => {
                    eprintln!("Unexpected error");
                }
            }
        }
    }

    fn maybe_close_session(&mut self, now: Instant) {
        for (expires, sessions) in self.sessions_to_close.iter_mut() {
            if *expires <= now {
                for s in sessions.iter_mut() {
                    drop(s.close_session(0, "", now));
                }
            }
        }
        self.sessions_to_close.retain(|expires, _| *expires >= now);
    }

    fn maybe_close_connection(&mut self) {
        let now = Instant::now();
        for (expires, connections) in self.connections_to_close.iter_mut() {
            if *expires <= now {
                for c in connections.iter_mut() {
                    c.borrow_mut().close(now, 0x0100, "");
                }
            }
        }
        self.connections_to_close
            .retain(|expires, _| *expires >= now);
    }

    fn maybe_create_wt_stream(&mut self, now: Instant) {
        while let Some(tuple) = self.sessions_to_create_stream.pop() {
            let session = tuple.0;
            let wt_server_stream = session.create_stream(tuple.1).unwrap();
            if tuple.1 == StreamType::UniDi {
                if let Some(data) = tuple.2 {
                    self.new_response(wt_server_stream, data, now);
                } else {
                    self.wt_unidi_conn_to_stream
                        .insert(wt_server_stream.conn.clone(), wt_server_stream);
                }
            } else {
                if let Some(data) = tuple.2 {
                    self.new_response(wt_server_stream, data, now);
                } else {
                    self.webtransport_bidi_stream.insert(wt_server_stream);
                }
            }
        }
    }

    // Regression test for bug 2043946: open a server-initiated bidi WebTransport
    // stream, send a byte so the client registers it in mStreamIdHash, then
    // schedule a STOP_SENDING(0x100) for a later flight.
    fn maybe_create_wt_stream_and_stop_sending(&mut self, now: Instant) {
        if self.sessions_to_create_bidi_and_stop_sending.is_empty() {
            return;
        }
        let session = self.sessions_to_create_bidi_and_stop_sending.pop().unwrap();
        let wt_server_stream = session.create_stream(StreamType::BiDi).unwrap();
        let _ = wt_server_stream.send_data(b"h", now);
        // The STOP_SENDING must arrive after the client has processed the
        // NewStream event, so defer it to a separate flight.
        let expires = now + Duration::from_millis(200);
        self.streams_to_stop_sending
            .entry(expires)
            .or_insert_with(Vec::new)
            .push(wt_server_stream);
    }

    fn maybe_stop_sending(&mut self, now: Instant) {
        for (expires, streams) in self.streams_to_stop_sending.iter_mut() {
            if *expires <= now {
                for s in streams.iter_mut() {
                    let _ = s.stream_stop_sending(Error::HttpNone.code());
                }
            }
        }
        self.streams_to_stop_sending
            .retain(|expires, _| *expires > now);
    }

    fn advance_mcquic_webtransport_scenario(&mut self, now: Instant) {
        let Some(mut scenario) = self.mcquic_webtransport_scenario.take() else {
            return;
        };

        if let Err(error) = scenario.advance(&mut self.server, now) {
            qerror!("MCQUIC WebTransport test failed: {error}");
            let message = format!("MCQUIC-ERROR:{error}");
            if let Err(send_error) =
                send_raw_webtransport_message(&scenario.session, message.as_bytes())
            {
                qerror!("Unable to report MCQUIC WebTransport test failure: {send_error}");
            }
            return;
        }

        if !scenario.is_complete() {
            self.mcquic_webtransport_scenario = Some(scenario);
        }
    }

    fn maybe_send_mcquic_webtransport_status(&mut self, now: Instant) {
        let Some((send_at, _, _)) = self.mcquic_webtransport_pending_status.as_ref() else {
            return;
        };
        if now < *send_at {
            return;
        }

        let (_, session, message) = self
            .mcquic_webtransport_pending_status
            .take()
            .expect("pending MCQUIC WebTransport status exists");
        if let Err(error) = send_raw_webtransport_message(&session, &message) {
            qerror!("Unable to send MCQUIC WebTransport status: {error}");
        }
    }
}

impl HttpServer for Http3TestServer {
    fn process_multiple<'a, D: IntoIterator<Item = Datagram<&'a mut [u8]>>>(
        &mut self,
        dgrams: D,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        // If stuck_0rtt_mode is enabled and we've already processed datagrams once,
        // stop processing to simulate a connection stuck in ZERORTT state.
        if self.stuck_0rtt_mode && self.stuck_0rtt_activated {
            qinfo!("Stuck 0-RTT mode active - ignoring datagrams to keep session in ZERORTT");
            // Return Callback to keep the server loop running but don't process
            // datagrams
            return OutputBatch::Callback(Duration::from_millis(100));
        }

        let output = self.server.process_multiple(dgrams, now, max_datagrams);

        // If we just processed datagrams with stuck mode enabled, mark it as
        // activated
        if self.stuck_0rtt_mode && !self.stuck_0rtt_activated {
            qinfo!("Stuck 0-RTT mode activated - next datagrams will be ignored");
            self.stuck_0rtt_activated = true;
        }

        let output = if self.sessions_to_close.is_empty()
            && self.connections_to_close.is_empty()
            && self.mcquic_webtransport_scenario.is_none()
            && self.mcquic_webtransport_pending_status.is_none()
            && self.streams_to_stop_sending.is_empty()
        {
            output
        } else {
            // In case there are pending sessions to close, use a shorter
            // timeout to make process_events() to be called earlier.
            const MIN_INTERVAL: Duration = Duration::from_millis(100);

            match output {
                OutputBatch::None => OutputBatch::Callback(MIN_INTERVAL),
                o @ OutputBatch::DatagramBatch(_) => o,
                OutputBatch::Callback(d) => OutputBatch::Callback(min(d, MIN_INTERVAL)),
            }
        };

        output
    }

    fn process_events(&mut self, now: Instant) {
        self.maybe_close_connection();
        self.maybe_close_session(now);
        self.maybe_create_wt_stream(now);
        self.maybe_send_mcquic_webtransport_status(now);
        self.advance_mcquic_webtransport_scenario(now);
        self.maybe_create_wt_stream_and_stop_sending(now);
        self.maybe_stop_sending(now);

        while let Some(event) = self.server.next_event() {
            qtrace!("Event: {:?}", event);
            match event {
                Http3ServerEvent::Headers {
                    stream,
                    headers,
                    fin,
                } => {
                    qtrace!("Headers (request={} fin={}): {:?}", stream, fin, headers);

                    let connection_hash = {
                        let mut hasher = DefaultHasher::new();
                        stream.conn.hash(&mut hasher);
                        hasher.finish()
                    };

                    // Some responses do not have content-type. This is on purpose to
                    // exercise UnknownDecoder code.
                    let default_ret = b"Hello World".to_vec();
                    let default_headers = vec![
                        Header::new(":status", "200"),
                        Header::new("cache-control", "no-cache"),
                        Header::new("content-length", default_ret.len().to_string()),
                        Header::new("x-http3-conn-hash", connection_hash.to_string()),
                    ];

                    let path_hdr = headers.iter().find(|&h| h.name() == ":path");
                    match path_hdr {
                        Some(ph) if !ph.value().is_empty() => {
                            let path = ph.value();
                            *self.request_counts.entry(path.to_vec()).or_default() += 1;
                            qtrace!(
                                "Serve request {:?}",
                                ph.value_utf8().unwrap_or("<invalid utf8>")
                            );
                            if path == b"/Response421" {
                                let response_body = b"0123456789".to_vec();
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "421"),
                                        Header::new("cache-control", "no-cache"),
                                        Header::new("content-type", "text/plain"),
                                        Header::new(
                                            "content-length",
                                            response_body.len().to_string(),
                                        ),
                                    ])
                                    .unwrap();
                                self.new_response(stream, response_body, now);
                            } else if path == b"/RequestCancelled" {
                                stream
                                    .stream_stop_sending(Error::HttpRequestCancelled.code())
                                    .unwrap();
                                stream
                                    .stream_reset_send(Error::HttpRequestCancelled.code())
                                    .unwrap();
                            } else if path == b"/VersionFallback" {
                                stream
                                    .stream_stop_sending(Error::HttpVersionFallback.code())
                                    .unwrap();
                                stream
                                    .stream_reset_send(Error::HttpVersionFallback.code())
                                    .unwrap();
                            } else if path == b"/EarlyResponse" {
                                stream.stream_stop_sending(Error::HttpNone.code()).unwrap();
                            } else if path == b"/SetStuckZeroRtt" {
                                qinfo!(
                                    "Enabling stuck 0-RTT mode - next connection will be stuck in ZERORTT"
                                );
                                self.stuck_0rtt_mode = true;
                                let response_body = b"Stuck 0-RTT mode enabled".to_vec();
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                        Header::new("content-type", "text/plain"),
                                        Header::new(
                                            "content-length",
                                            response_body.len().to_string(),
                                        ),
                                    ])
                                    .unwrap();
                                self.new_response(stream, response_body, now);
                            } else if path == b"/RequestRejected" {
                                stream
                                    .stream_stop_sending(Error::HttpRequestRejected.code())
                                    .unwrap();
                                stream
                                    .stream_reset_send(Error::HttpRequestRejected.code())
                                    .unwrap();
                            } else if path == b"/UnknownReset" {
                                // Reset with an unrecognized application error code.
                                stream.stream_stop_sending(0xfe).unwrap();
                                stream.stream_reset_send(0xfe).unwrap();
                            } else if path == b"/closeafter1000ms" {
                                let response_body = b"0123456789".to_vec();
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                        Header::new("content-type", "text/plain"),
                                        Header::new(
                                            "content-length",
                                            response_body.len().to_string(),
                                        ),
                                    ])
                                    .unwrap();
                                let expires = Instant::now() + Duration::from_millis(1000);
                                if !self.connections_to_close.contains_key(&expires) {
                                    self.connections_to_close.insert(expires, Vec::new());
                                }
                                self.connections_to_close
                                    .get_mut(&expires)
                                    .unwrap()
                                    .push(stream.conn.clone());

                                self.new_response(stream, response_body, now);
                            } else if path == b"/.well-known/http-opportunistic" {
                                let host_hdr = headers.iter().find(|&h| h.name() == ":authority");
                                match host_hdr {
                                    Some(host) if !host.value().is_empty() => {
                                        let mut content = b"[\"http://".to_vec();
                                        content.extend(host.value());
                                        content.extend(b"\"]");
                                        stream
                                            .send_headers(&[
                                                Header::new(":status", "200"),
                                                Header::new("cache-control", "no-cache"),
                                                Header::new("content-type", "application/json"),
                                                Header::new(
                                                    "content-length",
                                                    content.len().to_string(),
                                                ),
                                            ])
                                            .unwrap();
                                        self.new_response(stream, content, now);
                                    }
                                    _ => {
                                        stream.send_headers(&default_headers).unwrap();
                                        self.new_response(stream, default_ret, now);
                                    }
                                }
                            } else if path == b"/no_body" {
                                qdebug!("Request for no_body");
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                    ])
                                    .unwrap();
                                stream.stream_close_send(now).unwrap();
                            } else if path == b"/no_content_length" {
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                    ])
                                    .unwrap();
                                self.new_response(stream, vec![b'a'; 4000], now);
                            } else if path == b"/content_length_smaller" {
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                        Header::new("content-type", "text/plain"),
                                        Header::new("content-length", 4000.to_string()),
                                    ])
                                    .unwrap();
                                self.new_response(stream, vec![b'a'; 8000], now);
                            } else if path == b"/post" {
                                // Read all data before responding.
                                self.posts.insert(stream, 0);
                            } else if path == b"/priority_mirror" {
                                if let Some(priority) =
                                    headers.iter().find(|h| h.name() == "priority")
                                {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "200"),
                                            Header::new("cache-control", "no-cache"),
                                            Header::new("content-type", "text/plain"),
                                            Header::new(
                                                "priority-mirror",
                                                priority.value_utf8().unwrap(),
                                            ),
                                            Header::new(
                                                "content-length",
                                                priority.value().len().to_string(),
                                            ),
                                        ])
                                        .unwrap();
                                    self.new_response(stream, priority.value().to_vec(), now);
                                } else {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "200"),
                                            Header::new("cache-control", "no-cache"),
                                        ])
                                        .unwrap();
                                    stream.stream_close_send(now).unwrap();
                                }
                            } else if path == b"/103_response" {
                                if let Some(early_hint) =
                                    headers.iter().find(|h| h.name() == "link-to-set")
                                {
                                    for l in early_hint.value_utf8().unwrap().split(',') {
                                        stream
                                            .send_headers(&[
                                                Header::new(":status", "103"),
                                                Header::new("link", l),
                                            ])
                                            .unwrap();
                                    }
                                }
                                stream
                                    .send_headers(&[
                                        Header::new(":status", "200"),
                                        Header::new("cache-control", "no-cache"),
                                        Header::new("content-length", "0"),
                                    ])
                                    .unwrap();
                                stream.stream_close_send(now).unwrap();
                            } else if path == b"/get_webtransport_datagram" {
                                if let Some(dgram) = self.received_datagram.take() {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "200"),
                                            Header::new("content-length", dgram.len().to_string()),
                                        ])
                                        .unwrap();
                                    self.new_response(stream, dgram.as_ref().to_vec(), now);
                                } else {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "404"),
                                            Header::new("cache-control", "no-cache"),
                                        ])
                                        .unwrap();
                                    stream.stream_close_send(now).unwrap();
                                }
                            } else if path == b"/alt_svc_header" {
                                if let Some(alt_svc) =
                                    headers.iter().find(|h| h.name() == "x-altsvc")
                                {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "200"),
                                            Header::new("cache-control", "no-cache"),
                                            Header::new("content-type", "text/plain"),
                                            Header::new("content-length", 100.to_string()),
                                            Header::new(
                                                "alt-svc",
                                                format!("h3={}", alt_svc.value_utf8().unwrap()),
                                            ),
                                        ])
                                        .unwrap();
                                    self.new_response(stream, vec![b'a'; 100], now);
                                } else {
                                    stream
                                        .send_headers(&[
                                            Header::new(":status", "200"),
                                            Header::new("cache-control", "no-cache"),
                                        ])
                                        .unwrap();
                                    self.new_response(stream, vec![b'a'; 100], now);
                                }
                            } else {
                                match ph.value_utf8().ok().and_then(|s| {
                                    s.trim_matches(|p| p == '/').parse::<usize>().ok()
                                }) {
                                    Some(v) => {
                                        stream
                                            .send_headers(&[
                                                Header::new(":status", "200"),
                                                Header::new("cache-control", "no-cache"),
                                                Header::new("content-type", "text/plain"),
                                                Header::new("content-length", v.to_string()),
                                            ])
                                            .unwrap();
                                        self.new_response(stream, vec![b'a'; v], now);
                                    }
                                    None => {
                                        stream.send_headers(&default_headers).unwrap();
                                        self.new_response(stream, default_ret, now);
                                    }
                                }
                            }
                        }
                        _ => {
                            stream.send_headers(&default_headers).unwrap();
                            self.new_response(stream, default_ret, now);
                        }
                    }
                }
                Http3ServerEvent::Data { stream, data, fin } => {
                    // echo bidirectional input back to client
                    if self.webtransport_bidi_stream.contains(&stream) {
                        if stream.handler.borrow().state().active() {
                            self.new_response(stream, data, now);
                        }
                        break;
                    }

                    // echo unidirectional input to back to client
                    // need to close or we hang
                    if self.wt_unidi_echo_back.contains_key(&stream) {
                        let echo_back = self.wt_unidi_echo_back.remove(&stream).unwrap();
                        echo_back.send_data(&data, now).unwrap();
                        echo_back.stream_close_send(now).unwrap();
                        break;
                    }

                    if let Some(r) = self.posts.get_mut(&stream) {
                        *r += data.len();
                    }
                    if fin {
                        if let Some(r) = self.posts.remove(&stream) {
                            let default_ret = b"Hello World".to_vec();
                            stream
                                .send_headers(&[
                                    Header::new(":status", "200"),
                                    Header::new("cache-control", "no-cache"),
                                    Header::new("x-data-received-length", r.to_string()),
                                    Header::new("content-length", default_ret.len().to_string()),
                                ])
                                .unwrap();
                            self.new_response(stream, default_ret, now);
                        }
                    }
                }
                Http3ServerEvent::DataWritable { stream } => {
                    self.handle_stream_writable(stream, now)
                }
                Http3ServerEvent::StateChange { .. } => {}
                Http3ServerEvent::PriorityUpdate { .. } => {}
                Http3ServerEvent::StreamReset { stream, error } => {
                    qtrace!("Http3ServerEvent::StreamReset {:?} {:?}", stream, error);
                }
                Http3ServerEvent::StreamStopSending { stream, error } => {
                    qtrace!(
                        "Http3ServerEvent::StreamStopSending {:?} {:?}",
                        stream,
                        error
                    );
                }
                Http3ServerEvent::WebTransport(WebTransportServerEvent::NewSession {
                    session,
                    headers,
                }) => {
                    qdebug!(
                        "WebTransportServerEvent::NewSession {:?} {:?}",
                        session,
                        headers
                    );
                    let multicast_requested = headers.iter().any(|header| {
                        header.name().eq_ignore_ascii_case("wt-multicast")
                            && header.value() == b"?1"
                    });
                    *self
                        .webtransport_sessions_per_connection
                        .entry(session.conn.clone())
                        .or_default() += 1;
                    let path_hdr = headers.iter().find(|&h| h.name() == ":path");
                    match path_hdr {
                        Some(ph) if !ph.value().is_empty() => {
                            let path = ph.value();
                            *self.request_counts.entry(path.to_vec()).or_default() += 1;
                            qtrace!(
                                "Serve request {:?}",
                                ph.value_utf8().unwrap_or("<invalid utf8>")
                            );
                            if path == b"/success" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                            } else if path == b"/redirect" {
                                session
                                    .response(
                                        &SessionAcceptAction::Reject(
                                            [
                                                Header::new(":status", "302"),
                                                Header::new("location", "/"),
                                            ]
                                            .to_vec(),
                                        ),
                                        now,
                                    )
                                    .unwrap();
                            } else if path == b"/reject" {
                                session
                                    .response(
                                        &SessionAcceptAction::Reject(
                                            [Header::new(":status", "404")].to_vec(),
                                        ),
                                        now,
                                    )
                                    .unwrap();
                            } else if path == b"/closeafter0ms" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                if !self.sessions_to_close.contains_key(&now) {
                                    self.sessions_to_close.insert(now, Vec::new());
                                }
                                self.sessions_to_close.get_mut(&now).unwrap().push(session);
                            } else if path == b"/closeafter100ms" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                let expires = Instant::now() + Duration::from_millis(100);
                                if !self.sessions_to_close.contains_key(&expires) {
                                    self.sessions_to_close.insert(expires, Vec::new());
                                }
                                self.sessions_to_close
                                    .get_mut(&expires)
                                    .unwrap()
                                    .push(session);
                            } else if path == b"/create_unidi_stream" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    None,
                                ));
                            } else if path == b"/create_unidi_stream_and_hello" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(Vec::from("qwerty")),
                                ));
                            } else if path == b"/create_two_unidi_streams_and_hello" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session.clone(),
                                    StreamType::UniDi,
                                    Some(Vec::from("second")),
                                ));
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(Vec::from("first")),
                                ));
                            } else if path.starts_with(b"/create_unidi_streams/") {
                                let count: usize =
                                    std::str::from_utf8(&path[22..]).unwrap().parse().unwrap();
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                for i in 0..count {
                                    self.sessions_to_create_stream.push((
                                        session.clone(),
                                        StreamType::UniDi,
                                        Some(format!("stream{i}").into_bytes()),
                                    ));
                                }
                            } else if path.starts_with(b"/create_bidi_streams/") {
                                let count: usize =
                                    std::str::from_utf8(&path[21..]).unwrap().parse().unwrap();
                                self.webtransport_bidi_stream.clear();
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                for i in 0..count {
                                    self.sessions_to_create_stream.push((
                                        session.clone(),
                                        StreamType::BiDi,
                                        Some(format!("stream{i}").into_bytes()),
                                    ));
                                }
                            } else if path == b"/create_bidi_stream" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::BiDi,
                                    None,
                                ));
                            } else if path == b"/create_bidi_stream_and_hello" {
                                self.webtransport_bidi_stream.clear();
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::BiDi,
                                    Some(Vec::from("asdfg")),
                                ));
                            } else if path == b"/create_bidi_stream_and_large_data" {
                                self.webtransport_bidi_stream.clear();
                                let data: Vec<u8> = vec![1u8; 32 * 1024 * 1024];
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::BiDi,
                                    Some(data),
                                ));
                            } else if path == MCQUIC_AUTH_CHALLENGE_PATH {
                                if headers.iter().any(|header| {
                                    header.name().eq_ignore_ascii_case("authorization")
                                }) {
                                    self.mcquic_auth_header_count += 1;
                                }
                                session
                                    .response(
                                        &SessionAcceptAction::Reject(vec![
                                            Header::new(":status", "401"),
                                            Header::new(
                                                "www-authenticate",
                                                "Basic realm=\"mcquic-test\"",
                                            ),
                                            Header::new("wt-multicast", "?1"),
                                        ]),
                                        now,
                                    )
                                    .unwrap();
                            } else if path == MCQUIC_AUTH_COUNT_PATH {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                let requests = self
                                    .request_counts
                                    .get(MCQUIC_AUTH_CHALLENGE_PATH)
                                    .copied()
                                    .unwrap_or_default();
                                send_raw_webtransport_message(
                                    &session,
                                    format!(
                                        "requests={requests};authorization={}",
                                        self.mcquic_auth_header_count
                                    )
                                    .as_bytes(),
                                )
                                .unwrap();
                            } else if path == MCQUIC_NON_SUCCESS_TRUE_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::Reject(vec![
                                            Header::new(":status", "404"),
                                            Header::new("wt-multicast", "?1"),
                                        ]),
                                        now,
                                    )
                                    .unwrap();
                            } else if path == MCQUIC_RESPONSE_DUPLICATE_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![
                                            Header::new("wt-multicast", "?1"),
                                            Header::new("wt-multicast", "?1"),
                                        ]),
                                        now,
                                    )
                                    .unwrap();
                                send_raw_webtransport_message(
                                    &session,
                                    b"duplicate-response-unicast",
                                )
                                .unwrap();
                            } else if path == MCQUIC_RESPONSE_PARAMETER_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "?1; ignored=token",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                send_raw_webtransport_message(
                                    &session,
                                    b"parameterized-response-unicast",
                                )
                                .unwrap();
                            } else if let Some(status) =
                                parse_status_path(path, MCQUIC_REDIRECT_TARGET_PREFIX)
                            {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                send_raw_webtransport_message(
                                    &session,
                                    format!("redirect-target-{status}").as_bytes(),
                                )
                                .unwrap();
                            } else if let Some(status) =
                                parse_status_path(path, MCQUIC_REDIRECT_COUNT_PREFIX)
                            {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                let source_path = format!("/mcquic_redirect_{status}").into_bytes();
                                let target_path =
                                    format!("/mcquic_redirect_target_{status}").into_bytes();
                                let source = self
                                    .request_counts
                                    .get(&source_path)
                                    .copied()
                                    .unwrap_or_default();
                                let target = self
                                    .request_counts
                                    .get(&target_path)
                                    .copied()
                                    .unwrap_or_default();
                                send_raw_webtransport_message(
                                    &session,
                                    format!("source={source};target={target}").as_bytes(),
                                )
                                .unwrap();
                            } else if let Some(status) =
                                parse_status_path(path, MCQUIC_REDIRECT_PREFIX)
                            {
                                if (300..400).contains(&status) {
                                    session
                                        .response(
                                            &SessionAcceptAction::Reject(vec![
                                                Header::new(":status", status.to_string()),
                                                Header::new(
                                                    "location",
                                                    format!("/mcquic_redirect_target_{status}"),
                                                ),
                                                Header::new("wt-multicast", "?1"),
                                            ]),
                                            now,
                                        )
                                        .unwrap();
                                } else {
                                    session
                                        .response(
                                            &SessionAcceptAction::Reject(vec![Header::new(
                                                ":status", "404",
                                            )]),
                                            now,
                                        )
                                        .unwrap();
                                }
                            } else if path == MCQUIC_PERMISSION_MISSING_PATH {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(b"permission-missing-unicast".to_vec()),
                                ));
                            } else if path == MCQUIC_PERMISSION_FALSE_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "?0",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(b"permission-false-unicast".to_vec()),
                                ));
                            } else if path == MCQUIC_PERMISSION_MALFORMED_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "not-a-boolean",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(b"permission-malformed-unicast".to_vec()),
                                ));
                            } else if path == MCQUIC_UNSOLICITED_RESPONSE_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "?1",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                self.sessions_to_create_stream.push((
                                    session,
                                    StreamType::UniDi,
                                    Some(b"unsolicited-response-unicast".to_vec()),
                                ));
                            } else if path == MCQUIC_PERMISSION_UNSOLICITED_PATH {
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "?0",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                match McquicWebTransportScenario::new(session.clone(), now) {
                                    Ok(mut scenario) => {
                                        if let Err(error) = scenario.start(&mut self.server) {
                                            qerror!(
                                                "Unable to send unsolicited MCQUIC controls: {error}"
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        qerror!(
                                            "Unable to create unsolicited MCQUIC test: {error}"
                                        );
                                    }
                                }
                                self.mcquic_webtransport_pending_status = Some((
                                    now + Duration::from_millis(400),
                                    session,
                                    b"unsolicited-controls-unicast".to_vec(),
                                ));
                            } else if path == MCQUIC_RETRY_ONCE_PATH {
                                let attempts =
                                    self.request_counts.get(path).copied().unwrap_or_default();
                                let mut hasher = DefaultHasher::new();
                                session.conn.hash(&mut hasher);
                                let connection = hasher.finish();
                                if attempts == 1 {
                                    self.mcquic_retry_first_connection = Some(connection);
                                    session
                                        .response(
                                            &SessionAcceptAction::Reject(vec![Header::new(
                                                ":status", "421",
                                            )]),
                                            now,
                                        )
                                        .unwrap();
                                    continue;
                                }

                                let connection_sessions = self
                                    .webtransport_sessions_per_connection
                                    .get(&session.conn)
                                    .copied()
                                    .unwrap_or_default();
                                let resumed = session
                                    .conn
                                    .borrow()
                                    .tls_info()
                                    .is_some_and(|info| info.resumed());
                                let changed_connection =
                                    self.mcquic_retry_first_connection != Some(connection);
                                let authorized = multicast_requested
                                    && attempts == 2
                                    && changed_connection
                                    && !resumed
                                    && connection_sessions == 1;
                                let action = if authorized {
                                    SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                        "wt-multicast",
                                        "?1",
                                    )])
                                } else {
                                    SessionAcceptAction::Accept
                                };
                                session.response(&action, now).unwrap();
                                send_raw_webtransport_message(
                                    &session,
                                    format!(
                                        "attempts={attempts};connection={connection};\
                                         changed={};sessions={connection_sessions};\
                                         multicast={};resumed={}",
                                        u8::from(changed_connection),
                                        u8::from(multicast_requested),
                                        u8::from(resumed)
                                    )
                                    .as_bytes(),
                                )
                                .unwrap();

                                if authorized {
                                    if self.mcquic_webtransport_scenario.is_some()
                                        || self.mcquic_webtransport_pending_status.is_some()
                                    {
                                        self.mcquic_webtransport_pending_status = Some((
                                            now + MCQUIC_STEP_DELAY,
                                            session,
                                            b"MCQUIC-ERROR:another MCQUIC WebTransport scenario is active"
                                                .to_vec(),
                                        ));
                                    } else {
                                        match McquicWebTransportScenario::new_revocation(
                                            session.clone(),
                                            now,
                                        ) {
                                            Ok(scenario) => {
                                                self.mcquic_webtransport_scenario = Some(scenario);
                                            }
                                            Err(error) => {
                                                self.mcquic_webtransport_pending_status = Some((
                                                    now + MCQUIC_STEP_DELAY,
                                                    session,
                                                    format!(
                                                        "MCQUIC-ERROR:loopback SSM unavailable: {error}"
                                                    )
                                                    .into_bytes(),
                                                ));
                                            }
                                        }
                                    }
                                } else {
                                    send_raw_webtransport_message(
                                        &session,
                                        b"retry-authorization-failed-unicast",
                                    )
                                    .unwrap();
                                }
                            } else if path == MCQUIC_CONNECTION_ISOLATION_PATH {
                                let accept = if multicast_requested {
                                    SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                        "wt-multicast",
                                        "?1",
                                    )])
                                } else {
                                    SessionAcceptAction::Accept
                                };
                                session.response(&accept, now).unwrap();
                                let mut hasher = DefaultHasher::new();
                                session.conn.hash(&mut hasher);
                                let message = format!(
                                    "connection={};multicast={}",
                                    hasher.finish(),
                                    u8::from(multicast_requested)
                                );
                                send_raw_webtransport_message(&session, message.as_bytes())
                                    .unwrap();
                            } else if path == MCQUIC_WEBTRANSPORT_PATH
                                || path == MCQUIC_REVOCATION_PATH
                            {
                                if !multicast_requested {
                                    session.response(&SessionAcceptAction::Accept, now).unwrap();
                                    self.sessions_to_create_stream.push((
                                        session,
                                        StreamType::UniDi,
                                        Some(b"permission-absent-unicast".to_vec()),
                                    ));
                                    continue;
                                }
                                session
                                    .response(
                                        &SessionAcceptAction::AcceptWithHeaders(vec![Header::new(
                                            "wt-multicast",
                                            "?1",
                                        )]),
                                        now,
                                    )
                                    .unwrap();
                                if self.mcquic_webtransport_scenario.is_some()
                                    || self.mcquic_webtransport_pending_status.is_some()
                                {
                                    self.mcquic_webtransport_pending_status = Some((
                                        now + MCQUIC_STEP_DELAY,
                                        session,
                                        concat!(
                                            "MCQUIC-ERROR:another MCQUIC WebTransport ",
                                            "scenario is active"
                                        )
                                        .as_bytes()
                                        .to_vec(),
                                    ));
                                } else {
                                    let scenario = if path == MCQUIC_REVOCATION_PATH {
                                        McquicWebTransportScenario::new_revocation(
                                            session.clone(),
                                            now,
                                        )
                                    } else {
                                        McquicWebTransportScenario::new(session.clone(), now)
                                    };
                                    match scenario {
                                        Ok(scenario) => {
                                            self.mcquic_webtransport_scenario = Some(scenario);
                                        }
                                        Err(error) => {
                                            self.mcquic_webtransport_pending_status = Some((
                                                now + MCQUIC_STEP_DELAY,
                                                session,
                                                format!(
                                                    "MCQUIC-ERROR:loopback SSM unavailable: {error}"
                                                )
                                                .into_bytes(),
                                            ));
                                        }
                                    }
                                }
                            } else if path == b"/create_bidi_stream_and_stop_sending" {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                                self.sessions_to_create_bidi_and_stop_sending.push(session);
                            } else {
                                session.response(&SessionAcceptAction::Accept, now).unwrap();
                            }
                        }
                        _ => {
                            session
                                .response(
                                    &SessionAcceptAction::Reject(
                                        [Header::new(":status", "404")].to_vec(),
                                    ),
                                    now,
                                )
                                .unwrap();
                        }
                    }
                }
                Http3ServerEvent::WebTransport(WebTransportServerEvent::SessionClosed {
                    session,
                    reason,
                    headers: _,
                }) => {
                    qdebug!(
                        "WebTransportServerEvent::SessionClosed {:?} {:?}",
                        session,
                        reason
                    );
                }
                Http3ServerEvent::WebTransport(WebTransportServerEvent::NewStream(stream)) => {
                    // new stream could be from client-outgoing unidirectional
                    // or bidirectional
                    if !stream.stream_info.is_http() {
                        if stream.stream_id().is_bidi() {
                            self.webtransport_bidi_stream.insert(stream);
                        } else {
                            // Newly created stream happens on same connection
                            // as the stream creation for client's incoming stream.
                            // Link the streams with map for echo back
                            if self.wt_unidi_conn_to_stream.contains_key(&stream.conn) {
                                let s = self.wt_unidi_conn_to_stream.remove(&stream.conn).unwrap();
                                self.wt_unidi_echo_back.insert(stream, s);
                            }
                        }
                    }
                }
                Http3ServerEvent::WebTransport(WebTransportServerEvent::Datagram {
                    session,
                    datagram,
                }) => {
                    qdebug!(
                        "WebTransportServerEvent::Datagram {:?} {:?}",
                        session,
                        datagram
                    );
                    self.received_datagram = Some(datagram);
                }
                Http3ServerEvent::ConnectUdp(_) => {
                    unimplemented!()
                }
            }
        }

        self.advance_mcquic_webtransport_scenario(now);
    }

    fn has_events(&self) -> bool {
        self.server.has_events()
    }
}

struct Server(neqo_transport::server::Server);

impl ::std::fmt::Display for Server {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.0.fmt(f)
    }
}

impl HttpServer for Server {
    fn process_multiple<'a, D: IntoIterator<Item = Datagram<&'a mut [u8]>>>(
        &mut self,
        dgrams: D,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        self.0.process_multiple(dgrams, now, max_datagrams)
    }

    fn process_events(&mut self, _now: Instant) {
        let active_conns = self.0.active_connections();
        for acr in active_conns {
            loop {
                let event = match acr.borrow_mut().next_event() {
                    None => break,
                    Some(e) => e,
                };
                match event {
                    ConnectionEvent::RecvStreamReadable { stream_id } => {
                        if stream_id.is_bidi() && stream_id.is_client_initiated() {
                            // We are only interesting in request streams
                            acr.borrow_mut()
                                .stream_send(stream_id, HTTP_RESPONSE_WITH_WRONG_FRAME)
                                .expect("Read should succeed");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    fn has_events(&self) -> bool {
        self.0.has_active_connections()
    }
}

struct Http3ReverseProxyServer {
    server: Http3Server,
    responses: HashMap<Http3OrWebTransportStream, Vec<u8>>,
    server_port: i32,
    requests: HashMap<Http3OrWebTransportStream, (Vec<Header>, Vec<u8>)>,
    #[cfg(not(target_os = "android"))]
    response_to_send: HashMap<Http3OrWebTransportStream, Receiver<(Vec<Header>, Vec<u8>)>>,
}

impl ::std::fmt::Display for Http3ReverseProxyServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.server)
    }
}

impl Http3ReverseProxyServer {
    pub fn new(server: Http3Server, server_port: i32) -> Self {
        Self {
            server,
            responses: HashMap::new(),
            server_port,
            requests: HashMap::new(),
            #[cfg(not(target_os = "android"))]
            response_to_send: HashMap::new(),
        }
    }

    #[cfg(not(target_os = "android"))]
    fn new_response(&mut self, stream: Http3OrWebTransportStream, mut data: Vec<u8>, now: Instant) {
        if data.len() == 0 {
            let _ = stream.stream_close_send(now);
            return;
        }
        match stream.send_data(&data, now) {
            Ok(sent) => {
                if sent < data.len() {
                    self.responses.insert(stream, data.split_off(sent));
                } else {
                    stream.stream_close_send(now).unwrap();
                }
            }
            Err(e) => {
                eprintln!("error is {:?}, stream will be reset", e);
                let _ = stream.stream_reset_send(Error::HttpRequestCancelled.code());
            }
        }
    }

    fn handle_stream_writable(&mut self, stream: Http3OrWebTransportStream, now: Instant) {
        if let Some(data) = self.responses.get_mut(&stream) {
            match stream.send_data(&data, now) {
                Ok(sent) => {
                    if sent < data.len() {
                        let new_d = (*data).split_off(sent);
                        *data = new_d;
                    } else {
                        stream.stream_close_send(now).unwrap();
                        self.responses.remove(&stream);
                    }
                }
                Err(_) => {
                    eprintln!("Unexpected error");
                }
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    async fn fetch_url(
        request: http::Request<Full<hyper::body::Bytes>>,
        out_header: &mut Vec<Header>,
        out_body: &mut Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let client = Client::builder(hyper_util::rt::TokioExecutor::new()).build_http();
        let resp = client.request(request).await?;
        out_header.push(Header::new(":status", resp.status().as_str()));
        for (key, value) in resp.headers() {
            out_header.push(Header::new(
                key.as_str().to_ascii_lowercase(),
                match value.to_str() {
                    Ok(str) => str,
                    _ => "",
                },
            ));
        }

        let mut body = resp.into_body();
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        out_body.extend_from_slice(&data);
                    }
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn fetch(
        &mut self,
        stream: Http3OrWebTransportStream,
        request_headers: &Vec<Header>,
        request_body: Vec<u8>,
    ) {
        let mut request: http::Request<Full<hyper::body::Bytes>> =
            http::Request::new(Full::new(hyper::body::Bytes::new()));
        let mut path = String::new();
        for hdr in request_headers.iter() {
            match hdr.name() {
                ":method" => {
                    *request.method_mut() = Method::from_bytes(hdr.value()).unwrap();
                }
                ":scheme" => {}
                ":authority" => {
                    request.headers_mut().insert(
                        hyper::header::HOST,
                        HeaderValue::from_bytes(hdr.value()).unwrap(),
                    );
                }
                ":path" => {
                    path = hdr.value_utf8().unwrap_or("/").to_string();
                }
                _ => {
                    if let Ok(hdr_name) = HeaderName::from_lowercase(hdr.name().as_bytes()) {
                        request
                            .headers_mut()
                            .insert(hdr_name, HeaderValue::from_bytes(hdr.value()).unwrap());
                    }
                }
            }
        }
        *request.body_mut() = Full::new(hyper::body::Bytes::from(request_body));
        *request.uri_mut() =
            match format!("http://127.0.0.1:{}{}", self.server_port.to_string(), path).parse() {
                Ok(uri) => uri,
                _ => {
                    eprintln!("invalid uri: {}", path);
                    stream
                        .send_headers(&[
                            Header::new(":status", "400"),
                            Header::new("cache-control", "no-cache"),
                            Header::new("content-length", "0"),
                        ])
                        .unwrap();
                    return;
                }
            };
        qtrace!("request header: {:?}", request);

        let (sender, receiver) = channel();
        thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut h: Vec<Header> = Vec::new();
            let mut data: Vec<u8> = Vec::new();
            let _ = rt.block_on(Self::fetch_url(request, &mut h, &mut data));
            qtrace!("response headers: {:?}", h);
            qtrace!("res data: {:02X?}", data);

            match sender.send((h, data)) {
                Ok(()) => {}
                _ => {
                    eprintln!("sender.send failed");
                }
            }
        });
        self.response_to_send.insert(stream, receiver);
    }

    #[cfg(target_os = "android")]
    fn fetch(
        &mut self,
        mut _stream: Http3OrWebTransportStream,
        _request_headers: &Vec<Header>,
        _request_body: Vec<u8>,
    ) {
        // do nothing
    }

    #[cfg(not(target_os = "android"))]
    fn maybe_process_response(&mut self, now: Instant) {
        let mut data_to_send = HashMap::new();
        self.response_to_send
            .retain(|id, receiver| match receiver.try_recv() {
                Ok((headers, body)) => {
                    data_to_send.insert(id.clone(), (headers.clone(), body.clone()));
                    false
                }
                Err(TryRecvError::Empty) => true,
                Err(TryRecvError::Disconnected) => false,
            });
        while let Some(stream) = data_to_send.keys().next().cloned() {
            let (header, data) = data_to_send.remove(&stream).unwrap();
            qtrace!("response headers: {:?}", header);
            match stream.send_headers(&header) {
                Ok(()) => {
                    self.new_response(stream, data, now);
                }
                _ => {}
            }
        }
    }
}

impl HttpServer for Http3ReverseProxyServer {
    fn process_multiple<'a, D: IntoIterator<Item = Datagram<&'a mut [u8]>>>(
        &mut self,
        dgrams: D,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        let output = self.server.process_multiple(dgrams, now, max_datagrams);

        #[cfg(not(target_os = "android"))]
        let output = if self.response_to_send.is_empty() {
            output
        } else {
            // In case there are pending responses to send, make sure a reasonable
            // callback is returned.
            const MIN_INTERVAL: Duration = Duration::from_millis(100);

            match output {
                OutputBatch::None => OutputBatch::Callback(MIN_INTERVAL),
                o @ OutputBatch::DatagramBatch(_) => o,
                OutputBatch::Callback(d) => OutputBatch::Callback(min(d, MIN_INTERVAL)),
            }
        };

        output
    }

    fn process_events(&mut self, now: Instant) {
        #[cfg(not(target_os = "android"))]
        self.maybe_process_response(now);
        while let Some(event) = self.server.next_event() {
            qtrace!("Event: {:?}", event);
            match event {
                Http3ServerEvent::Headers {
                    stream,
                    headers,
                    fin: _,
                } => {
                    qtrace!("Headers {:?}", headers);
                    if self.server_port != -1 {
                        let method_hdr = headers.iter().find(|&h| h.name() == ":method");
                        match method_hdr {
                            Some(method) => match method.value() {
                                b"POST" => {
                                    let content_length =
                                        headers.iter().find(|&h| h.name() == "content-length");
                                    if let Some(length_str) = content_length {
                                        if let Ok(len) =
                                            length_str.value_utf8().unwrap_or("0").parse::<u32>()
                                        {
                                            if len > 0 {
                                                self.requests.insert(stream, (headers, Vec::new()));
                                            } else {
                                                self.fetch(stream, &headers, b"".to_vec());
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    self.fetch(stream, &headers, b"".to_vec());
                                }
                            },
                            _ => {}
                        }
                    } else {
                        let path_hdr = headers.iter().find(|&h| h.name() == ":path");
                        match path_hdr {
                            Some(ph) if !ph.value().is_empty() => {
                                if let Some(path_str) = ph.value_utf8().ok() {
                                    if let Some(port_str) = path_str.strip_prefix("/port?") {
                                        let port = port_str.parse::<i32>().ok();
                                        if let Some(port) = port {
                                            qtrace!("got port {}", port);
                                            self.server_port = port;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                        stream
                            .send_headers(&[
                                Header::new(":status", "200"),
                                Header::new("cache-control", "no-cache"),
                                Header::new("content-length", "0"),
                            ])
                            .unwrap();
                    }
                }
                Http3ServerEvent::Data {
                    stream,
                    mut data,
                    fin,
                } => {
                    if let Some((_, body)) = self.requests.get_mut(&stream) {
                        body.append(&mut data);
                    }
                    if fin {
                        if let Some((headers, body)) = self.requests.remove(&stream) {
                            self.fetch(stream, &headers, body);
                        }
                    }
                }
                Http3ServerEvent::DataWritable { stream } => {
                    self.handle_stream_writable(stream, now)
                }
                Http3ServerEvent::StateChange { .. } | Http3ServerEvent::PriorityUpdate { .. } => {}
                Http3ServerEvent::StreamReset { stream, error } => {
                    qtrace!("Http3ServerEvent::StreamReset {:?} {:?}", stream, error);
                }
                Http3ServerEvent::StreamStopSending { stream, error } => {
                    qtrace!(
                        "Http3ServerEvent::StreamStopSending {:?} {:?}",
                        stream,
                        error
                    );
                }
                Http3ServerEvent::WebTransport(_) => {}
                Http3ServerEvent::ConnectUdp(_) => {}
            }
        }
    }

    fn has_events(&self) -> bool {
        self.server.has_events()
    }
}

struct Http3ConnectProxyServer {
    server: Http3Server,
    tcp_streams: HashMap<StreamId, TcpStream>,
    udp_sockets: HashMap<StreamId, UdpSocket>,
}

impl ::std::fmt::Display for Http3ConnectProxyServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", self.server)
    }
}

impl Http3ConnectProxyServer {
    pub fn new(server: Http3Server) -> Self {
        Self {
            server,
            tcp_streams: HashMap::new(),
            udp_sockets: HashMap::new(),
        }
    }
}

impl HttpServer for Http3ConnectProxyServer {
    fn process_multiple<'a, D: IntoIterator<Item = Datagram<&'a mut [u8]>>>(
        &mut self,
        dgrams: D,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        self.server.process_multiple(dgrams, now, max_datagrams)
    }

    fn process_events(&mut self, now: Instant) {
        while let Some(event) = self.server.next_event() {
            qtrace!("Event: {:?}", event);
            match event {
                Http3ServerEvent::Headers {
                    stream,
                    headers,
                    fin: _,
                } => {
                    qtrace!("Headers {:?}", headers);
                    let method_hdr = headers.iter().find(|&h| h.name() == ":method").unwrap();
                    assert_eq!(
                        method_hdr.value(),
                        b"CONNECT",
                        "{:?} not supported",
                        method_hdr.value_utf8().unwrap_or("<invalid utf8>")
                    );
                    let host_hdr = headers.iter().find(|&h| h.name() == ":authority").unwrap();
                    let host_str = host_hdr.value_utf8().unwrap();

                    // Check if we should fallback to 127.0.0.1 before attempting
                    // connection
                    let host_without_port = if let Some(colon_pos) = host_str.rfind(':') {
                        &host_str[..colon_pos]
                    } else {
                        host_str
                    };

                    let should_fallback = matches!(
                        host_without_port,
                        "foo.example.com" | "alt1.example.com" | "alt2.example.com"
                    );

                    let target = if should_fallback {
                        if let Some(port_start) = host_str.rfind(':') {
                            format!("127.0.0.1:{}", &host_str[port_start + 1..])
                        } else {
                            // No port specified, assume default HTTP port 80
                            "127.0.0.1:80".to_string()
                        }
                    } else {
                        host_str.to_string()
                    };

                    let tcp_stream = match std::net::TcpStream::connect(&target) {
                        Ok(c) => c,
                        Err(_) => {
                            stream
                                .send_headers(&[
                                    Header::new(":status", "502"),
                                    Header::new("cache-control", "no-cache"),
                                ])
                                .unwrap();
                            stream.stream_close_send(now).unwrap();
                            return;
                        }
                    };

                    tcp_stream.set_nonblocking(true).unwrap();
                    qtrace!("tcp_stream to {:?} created", host_hdr);
                    stream
                        .send_headers(&[
                            Header::new(":status", "200"),
                            Header::new("cache-control", "no-cache"),
                        ])
                        .unwrap();
                    self.tcp_streams.insert(
                        stream.stream_id(),
                        TcpStream {
                            send_buffer: VecDeque::new(),
                            recv_buffer: VecDeque::new(),
                            stream: tokio::net::TcpStream::from_std(tcp_stream).unwrap(),
                            send_fin: false,
                            received_fin: false,
                            session: stream,
                        },
                    );
                }
                Http3ServerEvent::Data { stream, data, fin } => {
                    qtrace!("tcp_stream send to server len={}", data.len());
                    let tcp_stream = self.tcp_streams.get_mut(&stream.stream_id()).unwrap();
                    // TODO: extend() effectively breaks backpressure.
                    tcp_stream.send_buffer.extend(data);
                    tcp_stream.send_fin |= fin;
                }
                Http3ServerEvent::DataWritable { stream } => {
                    qtrace!(
                        "Http3ServerEvent::DataWritable streamid={}",
                        stream.stream_id()
                    );
                    let tcp_stream = self.tcp_streams.get_mut(&stream.stream_id()).unwrap();
                    while !tcp_stream.recv_buffer.is_empty() {
                        match stream.send_data(&tcp_stream.recv_buffer.make_contiguous(), now) {
                            Ok(sent) => {
                                qtrace!("tcp_stream send to client sent={}", sent);
                                if sent == 0 {
                                    // no progress possible right now — stop trying to send in
                                    // this loop (could also mark for later retry)
                                    break;
                                }
                                tcp_stream.recv_buffer.drain(0..sent);
                            }
                            Err(e) => {
                                eprintln!("send_data failed: {:?}", e);
                                break;
                            }
                        }
                    }
                }
                Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::NewSession {
                    session,
                    headers,
                }) => {
                    session.response(&SessionAcceptAction::Accept, now).unwrap();

                    let host_hdr = headers.iter().find(|&h| h.name() == ":path").unwrap();
                    let path_str = host_hdr.value_utf8().unwrap();
                    let path_parts: Vec<&str> = path_str.split('/').collect();

                    // Format is /.well-known/masque/udp/{target_host}/{target_port}/
                    if path_parts.len() < 6 {
                        panic!("{}", path_str)
                    }

                    let target_host = path_parts[4];
                    let target_port = match path_parts[5].trim_end_matches('/').parse::<u16>() {
                        Ok(port) => port,
                        Err(_) => {
                            panic!("{}", path_str)
                        }
                    };

                    // Replace target_host with 127.0.0.1 for specific hosts
                    let actual_host = match target_host {
                        "foo.example.com" | "alt1.example.com" | "alt2.example.com" => "127.0.0.1",
                        _ => target_host,
                    };

                    let host_port = format!("{}:{}", actual_host, target_port);
                    qdebug!("CONNECT-UDP to {}", host_port);

                    let socket = {
                        let s =
                            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
                                .unwrap();
                        s.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())
                            .unwrap();
                        let s: std::net::UdpSocket = s.into();
                        s.connect((actual_host, target_port)).unwrap();
                        s.set_nonblocking(true).unwrap();
                        s.into()
                    };

                    self.udp_sockets.insert(
                        session.stream_id(),
                        UdpSocket {
                            session,
                            send_buffer: VecDeque::new(),
                            socket: tokio::net::UdpSocket::from_std(socket).unwrap(),
                        },
                    );
                }
                Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::Datagram {
                    session,
                    datagram,
                }) => {
                    let udp_socket = self.udp_sockets.get_mut(&session.stream_id()).unwrap();
                    // TODO: effectively breaks backpressure.
                    udp_socket.send_buffer.push_back(datagram);
                }
                Http3ServerEvent::ConnectUdp(ConnectUdpServerEvent::SessionClosed {
                    session,
                    reason,
                    headers: _,
                }) => {
                    qdebug!(
                        "ConnectUdp session closed: {:?} reason: {:?}",
                        session,
                        reason
                    );
                    self.udp_sockets.remove(&session.stream_id());
                }
                Http3ServerEvent::StateChange { .. } | Http3ServerEvent::PriorityUpdate { .. } => {}
                Http3ServerEvent::StreamReset { stream, error } => {
                    qtrace!("Http3ServerEvent::StreamReset {:?} {:?}", stream, error);
                }
                Http3ServerEvent::StreamStopSending { stream, error } => {
                    qtrace!(
                        "Http3ServerEvent::StreamStopSending {:?} {:?}",
                        stream,
                        error
                    );
                }
                Http3ServerEvent::WebTransport(_) => {}
            }
        }
    }

    fn has_events(&self) -> bool {
        self.server.has_events()
    }

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut progressed = false;
        let mut failed_udp_sockets: Vec<StreamId> = Vec::new();

        for (_sessionid, stream) in &mut self.tcp_streams {
            if let Poll::Ready(Ok(())) = stream.stream.poll_read_ready(cx) {
                loop {
                    let mut buf = vec![0; 1024];
                    match stream.stream.try_read(&mut buf) {
                        Ok(0) => {
                            qdebug!("TCP: Received 0 bytes -FIN");
                            stream.received_fin = true;
                            // TODO: Reset CONNECT stream.
                            break;
                        }
                        Ok(n) => {
                            qdebug!("TCP: Received {} bytes from origin", n);
                            // TODO: extend() effectively breaks backpressure.
                            stream.recv_buffer.extend(&buf[0..n]);
                            while !stream.recv_buffer.is_empty() {
                                let sent = match stream.session.send_data(
                                    &stream.recv_buffer.make_contiguous(),
                                    Instant::now(),
                                ) {
                                    Ok(n) => n,
                                    Err(e) => {
                                        qdebug!("TCP: send_data failed: {}", e);
                                        break;
                                    }
                                };
                                qdebug!("TCP: stream send to client sent={}", sent);
                                if sent == 0 {
                                    break;
                                }
                                stream.recv_buffer.drain(0..sent);
                            }
                            progressed = true;
                        }
                        Err(e) => {
                            qdebug!("TCP read error: {e:?}");
                            stream.received_fin = true;
                            // TODO: Handle the error
                            break;
                        }
                    }
                }
            }

            if let Poll::Ready(Ok(())) = stream.stream.poll_write_ready(cx) {
                while !stream.send_buffer.is_empty() {
                    match stream
                        .stream
                        .try_write(&stream.send_buffer.make_contiguous())
                    {
                        Ok(0) => break,
                        Ok(n) => {
                            qdebug!("TCP: Sent {} bytes to origin", n);
                            stream.send_buffer.drain(0..n);
                            progressed = true;
                        }
                        Err(e) => {
                            qdebug!("TCP write error: {e:?}");
                            stream.received_fin = true;
                            // TODO: Handle the error
                            break;
                        }
                    }
                }
            }
            if stream.send_fin {
                let _ = stream.stream.shutdown();
            }
        }

        for (stream_id, socket) in &mut self.udp_sockets {
            loop {
                let mut buf = vec![0u8; u16::MAX as usize];
                let mut read_buf = ReadBuf::new(buf.as_mut());
                match socket.socket.poll_recv(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let len = read_buf.filled().len();
                        qinfo!("Received {} bytes from origin", len);
                        buf.resize(len, 0);
                        // TODO: Might overflow our current datagram buffer of 10
                        // https://github.com/mozilla/neqo/issues/2852
                        socket
                            .session
                            .send_datagram(buf.as_slice(), None, Instant::now())
                            .unwrap();
                        progressed = true;
                    }
                    Poll::Ready(Err(e)) => {
                        qerror!("Error receiving UDP datagram: {}, closing socket", e);
                        failed_udp_sockets.push(*stream_id);
                        break;
                    }
                    Poll::Pending => break,
                }
            }

            while let Some(datagram) = socket.send_buffer.pop_front() {
                match socket.socket.poll_send(cx, datagram.as_ref()) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        socket.send_buffer.push_front(datagram);
                        break;
                    }
                    Poll::Ready(Ok(n)) => {
                        assert_eq!(n, datagram.len());
                        qinfo!("Sent {}/{} bytes to origin", n, datagram.len());
                        progressed = true;
                    }
                    Poll::Ready(Err(e)) => {
                        qerror!(
                            "Error sending UDP datagram: {} {:?}, closing socket",
                            e,
                            socket.socket
                        );
                        failed_udp_sockets.push(*stream_id);
                        break;
                    }
                }
            }
        }

        // Remove failed UDP sockets from the list
        for stream_id in failed_udp_sockets {
            if let Some(socket) = self.udp_sockets.remove(&stream_id) {
                qdebug!("Removed failed UDP socket for stream {}", stream_id);
                // Close the session with an error code
                let _ = socket
                    .session
                    .close_session(0x0100, "UDP socket error", Instant::now());
            }
        }

        if progressed {
            return Poll::Ready(());
        }

        Poll::Pending
    }
}

struct TcpStream {
    send_buffer: VecDeque<u8>,
    recv_buffer: VecDeque<u8>,
    stream: tokio::net::TcpStream,
    send_fin: bool,
    received_fin: bool,
    session: Http3OrWebTransportStream,
}

struct UdpSocket {
    session: ConnectUdpRequest,
    send_buffer: VecDeque<Bytes>,
    socket: tokio::net::UdpSocket,
}
#[derive(Default)]
struct NonRespondingServer {}

impl ::std::fmt::Display for NonRespondingServer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "NonRespondingServer")
    }
}

impl HttpServer for NonRespondingServer {
    fn process_multiple<'a, D: IntoIterator<Item = Datagram<&'a mut [u8]>>>(
        &mut self,
        _dgrams: D,
        _now: Instant,
        _max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        OutputBatch::None
    }

    fn process_events(&mut self, _now: Instant) {}

    fn has_events(&self) -> bool {
        false
    }
}

fn spawn_server<S: HttpServer + Unpin + 'static>(
    server: S,
    port: u16,
    task_set: &LocalSet,
    hosts: &mut Vec<SocketAddr>,
) -> Result<(), io::Error> {
    let addr: SocketAddr = if cfg!(target_os = "windows") {
        format!("127.0.0.1:{}", port).parse().unwrap()
    } else {
        format!("[::]:{}", port).parse().unwrap()
    };

    let socket = match neqo_bin::udp::Socket::bind(&addr) {
        Err(err) => {
            eprintln!("Unable to bind UDP socket: {}", err);
            exit(1)
        }
        Ok(s) => s,
    };

    let local_addr = match socket.local_addr() {
        Err(err) => {
            eprintln!("Socket local address not bound: {}", err);
            exit(1)
        }
        Ok(s) => s,
    };

    task_set
        .spawn_local(Runner::new(server, Box::new(Instant::now), vec![(local_addr, socket)]).run());
    hosts.push(local_addr);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    neqo_common::log::init(None);

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Wrong arguments.");
        exit(1)
    }

    // Read data from stdin and terminate the server if EOF is detected, which
    // means that runxpcshelltests.py ended without shutting down the server.
    thread::spawn(|| {
        loop {
            let mut buffer = String::new();
            match io::stdin().read_line(&mut buffer) {
                Ok(n) => {
                    if n == 0 {
                        exit(0);
                    }
                }
                Err(_) => {
                    exit(0);
                }
            }
        }
    });

    init_db(PathBuf::from(args[1].clone())).unwrap();

    let local = LocalSet::new();
    let mut hosts = vec![];

    let proxy_port = match env::var("MOZ_HTTP3_PROXY_PORT") {
        Ok(val) => val.parse::<u16>().unwrap(),
        _ => 0,
    };

    let anti_replay = || {
        AntiReplay::new(Instant::now(), Duration::from_secs(10), 7, 14)
            .expect("unable to setup anti-replay")
    };
    let cid_mgr = Rc::new(RefCell::new(RandomConnectionIdGenerator::new(10)));

    spawn_server(
        Http3TestServer::new(
            Http3Server::new(
                Instant::now(),
                &[" HTTP2 Test Cert"],
                PROTOCOLS,
                anti_replay(),
                cid_mgr.clone(),
                Http3Parameters::default()
                    .max_table_size_encoder(MAX_TABLE_SIZE)
                    .max_table_size_decoder(MAX_TABLE_SIZE)
                    .max_blocked_streams(MAX_BLOCKED_STREAMS)
                    .webtransport(true)
                    .connection_parameters(
                        ConnectionParameters::default()
                            .datagram_size(1200)
                            .mcquic_server_support(true),
                    ),
                None,
            )
            .expect("We cannot make a server!"),
        ),
        0,
        &local,
        &mut hosts,
    )?;

    spawn_server(
        Server(
            neqo_transport::server::Server::new(
                Instant::now(),
                &[" HTTP2 Test Cert"],
                PROTOCOLS,
                anti_replay(),
                Box::new(AllowZeroRtt {}),
                cid_mgr.clone(),
                ConnectionParameters::default(),
            )
            .expect("We cannot make a server!"),
        ),
        0,
        &local,
        &mut hosts,
    )?;

    let ech_config = {
        let mut server = Http3TestServer::new(
            Http3Server::new(
                Instant::now(),
                &[" HTTP2 Test Cert"],
                PROTOCOLS,
                anti_replay(),
                cid_mgr.clone(),
                Http3Parameters::default()
                    .max_table_size_encoder(MAX_TABLE_SIZE)
                    .max_table_size_decoder(MAX_TABLE_SIZE)
                    .max_blocked_streams(MAX_BLOCKED_STREAMS)
                    .webtransport(true)
                    .connection_parameters(ConnectionParameters::default().datagram_size(1200)),
                None,
            )
            .expect("We cannot make a server!"),
        );
        let (sk, pk) = generate_ech_keys().unwrap();
        server
            .server
            .enable_ech(ECH_CONFIG_ID, ECH_PUBLIC_NAME, &sk, &pk)
            .expect("unable to enable ech");
        let ech_config = server.server.ech_config().to_vec();
        spawn_server(server, 0, &local, &mut hosts)?;
        ech_config
    };

    spawn_server(
        {
            let server_config = if env::var("MOZ_HTTP3_MOCHITEST").is_ok() {
                ("mochitest-cert", 8888)
            } else {
                (" HTTP2 Test Cert", -1)
            };
            let server = Http3ReverseProxyServer::new(
                Http3Server::new(
                    Instant::now(),
                    &[server_config.0],
                    PROTOCOLS,
                    anti_replay(),
                    cid_mgr.clone(),
                    Http3Parameters::default()
                        .max_table_size_encoder(MAX_TABLE_SIZE)
                        .max_table_size_decoder(MAX_TABLE_SIZE)
                        .max_blocked_streams(MAX_BLOCKED_STREAMS)
                        .webtransport(true)
                        .connection_parameters(ConnectionParameters::default().datagram_size(1200)),
                    None,
                )
                .expect("We cannot make a server!"),
                server_config.1,
            );
            server
        },
        proxy_port,
        &local,
        &mut hosts,
    )?;

    spawn_server(NonRespondingServer::default(), 0, &local, &mut hosts)?;

    spawn_server(
        Http3ConnectProxyServer::new(
            Http3Server::new(
                Instant::now(),
                &[" HTTP2 Test Cert"],
                PROTOCOLS,
                anti_replay(),
                cid_mgr,
                Http3Parameters::default()
                    .max_table_size_encoder(MAX_TABLE_SIZE)
                    .connection_parameters(
                        ConnectionParameters::default()
                            // TODO: Restrict in size.
                            .datagram_size(u16::MAX as u64)
                            .pmtud(true),
                    )
                    .max_table_size_decoder(MAX_TABLE_SIZE)
                    .max_blocked_streams(MAX_BLOCKED_STREAMS)
                    .connect(true)
                    .http3_datagram(true),
                None,
            )
            .expect("We cannot make a server!"),
        ),
        0,
        &local,
        &mut hosts,
    )?;

    // Note this is parsed by test runner.
    // https://searchfox.org/mozilla-central/rev/e69f323af80c357d287fb6314745e75c62eab92a/testing/mozbase/mozserve/mozserve/servers.py#116-121
    println!(
        "HTTP3 server listening on ports {}, {}, {}, {}, {} and {}. EchConfig is @{}@",
        hosts[0].port(),
        hosts[1].port(),
        hosts[2].port(),
        hosts[3].port(),
        hosts[4].port(),
        hosts[5].port(),
        BASE64_STANDARD.encode(ech_config)
    );

    local.await;

    Ok(())
}

#[no_mangle]
extern "C" fn __tsan_default_suppressions() -> *const std::os::raw::c_char {
    // https://github.com/rust-lang/rust/issues/128769
    concat!(
        "race:<tokio::runtime::io::registration_set::RegistrationSet>::allocate\n",
        "race:tokio::runtime::io::registration_set::RegistrationSet::allocate\0",
    )
    .as_ptr() as *const _
}

// Work around until we can use raw-dylibs.
#[cfg_attr(target_os = "windows", link(name = "runtimeobject"))]
extern "C" {}
#[cfg_attr(target_os = "windows", link(name = "propsys"))]
extern "C" {}
#[cfg_attr(target_os = "windows", link(name = "iphlpapi"))]
extern "C" {}
#[cfg_attr(target_os = "windows", link(name = "rpcrt4"))]
extern "C" {}
