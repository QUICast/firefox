// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// The class implementing a QUIC connection.

#[cfg(feature = "mcquic")]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{
    cell::RefCell,
    cmp::{max, min},
    fmt::{self, Debug, Display, Formatter, Write as _},
    iter, mem,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    ops::RangeInclusive,
    rc::{Rc, Weak},
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    time::{Duration, Instant},
};

use neqo_common::{
    Buffer, Datagram, Decoder, Ecn, Encoder, Role, Tos, datagram, event::Provider as EventProvider,
    hex, hex_snip_middle, hex_with_len, hrtime, qdebug, qerror, qinfo, qlog::Qlog, qtrace, qwarn,
};
use nss::{
    Agent, AntiReplay, AuthenticationStatus, Cipher, Client, Group, HandshakeState, PrivateKey,
    PublicKey, ResumptionToken, SecretAgentInfo, SecretAgentPreInfo, Server, ZeroRttChecker,
    agent::{CertificateCompressor, CertificateInfo},
};
use smallvec::SmallVec;
use strum::IntoEnumIterator as _;

#[cfg(feature = "mcquic")]
use crate::tparams::TransportParameterId::InitialMaxData;
use crate::{
    AppError, CloseReason, Error, Res, StreamId,
    addr_valid::{AddressValidation, NewTokenState},
    cc::Phase,
    cid::{
        ConnectionId, ConnectionIdEntry, ConnectionIdGenerator, ConnectionIdManager,
        ConnectionIdRef, ConnectionIdStore,
    },
    crypto::{Crypto, CryptoDxState, Epoch},
    ecn,
    events::{ConnectionEvent, ConnectionEvents, OutgoingDatagramOutcome},
    frame::{CloseError, Frame, FrameEncoder as _, FrameType},
    packet::{self},
    path::{Path, PathRef, Paths},
    qlog,
    quic_datagrams::{
        DATAGRAM_FRAME_TYPE_VARINT_LEN, DatagramTracking,
        OutputJournal as QuicDatagramOutputJournal, QuicDatagrams,
    },
    recovery::{self, SendProfile, sent},
    recv_stream,
    rtt::{GRANULARITY, RttEstimate},
    saved::SavedDatagrams,
    send_stream::{self, SendStream},
    stateless_reset::Token as Srt,
    stats::{OutputStatsCheckpoint, Stats, StatsCell},
    stream_id::StreamType,
    streams::{SendOrder, StreamOutputJournal, Streams},
    tparams::{
        self,
        TransportParameterId::{
            self, AckDelayExponent, ActiveConnectionIdLimit, DisableMigration, GreaseQuicBit,
            InitialSourceConnectionId, MaxAckDelay, MaxDatagramFrameSize, MaxUdpPayloadSize,
            MinAckDelay, OriginalDestinationConnectionId, RetrySourceConnectionId,
            StatelessResetToken,
        },
        TransportParameters, TransportParametersHandler,
    },
    tracking::{
        AckOutputCheckpoint, AckTracker, PacketNumberSpace, PacketNumberSpaceSet, RecvdPackets,
    },
    version::{self, Version},
};

mod idle;
pub mod params;
mod state;
#[cfg(any(test, feature = "build-fuzzing-corpus"))]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_internal;

use idle::IdleTimeout;
pub use params::ConnectionParameters;
use params::PreferredAddressConfig;
use state::StateSignaling;
pub use state::{ClosingFrame, State};

pub use crate::send_stream::{RetransmissionPriority, TransmissionPriority};

static NEXT_OUTPUT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_STREAM_FRAMES: usize = 64 * 1024;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_STREAM_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_STREAM_OWNERS: usize = 1024;
#[cfg(feature = "mcquic")]
const MAX_AUTHORIZED_MCQUIC_STREAMS: usize = 4096;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CHANNELS: usize = 32;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_OWNER_EXPIRIES_PER_TURN: usize = 64;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_OWNER_EXPIRIES: usize = MAX_PENDING_MCQUIC_STREAM_OWNERS;
#[cfg(feature = "mcquic")]
const MAX_AUTHORIZED_MCQUIC_OWNER_EXPIRIES: usize = MAX_AUTHORIZED_MCQUIC_STREAMS;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_PENDING_CHANNEL_OWNER_LINKS: usize =
    MAX_PENDING_MCQUIC_STREAM_OWNERS * MAX_MCQUIC_CHANNELS;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_SEND_FRAMES: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_SEND_BYTES: usize = 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_OPERATION_CONTROL_FRAMES: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_PENDING_MCQUIC_OPERATION_CONTROL_BYTES: usize = 64 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_RETIRED_CHANNELS: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_RETIRED_CHANNEL_BYTES: usize = 64 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_RETIRED_CHANNEL_AGE: Duration = Duration::from_secs(5 * 60);
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_RESOURCE_LIMIT_NOTICES: usize = 32;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL: usize = 32;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_UNKNOWN_CONTROL_FRAMES: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_UNKNOWN_CONTROL_BYTES: usize = 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_KEYS: usize = 64;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_KEY_BYTES: usize = 4 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_INTEGRITY_HASHES: usize = 32 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_INTEGRITY_BYTES: usize = 2 * 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_PENDING_PACKETS: usize = 4096;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_PENDING_PACKET_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_DATAGRAMS: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_CONNECTION_DATAGRAM_BYTES: usize = 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_PENDING_CONTROL_AGE: Duration = Duration::from_secs(5);
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_PENDING_OWNER_AGE: Duration = Duration::from_secs(5);
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_AUTHORIZED_OWNER_AGE: Duration = Duration::from_secs(5 * 60);
#[cfg(feature = "mcquic")]
const MCQUIC_AUTHORIZED_OWNER_REFRESH: Duration = Duration::from_secs(150);
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_ACTIVE_CONTROL_FRAMES: usize = 256;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_ACTIVE_CONTROL_BYTES: usize = 1024 * 1024;
#[cfg(feature = "mcquic")]
const MAX_MCQUIC_ACTIVE_CONTROL_AGE: Duration = Duration::from_secs(5);

#[cfg(feature = "mcquic")]
#[derive(Debug)]
struct PendingMcquicStreamFrame {
    channel_id: Option<Vec<u8>>,
    frame: crate::mcquic::ChannelFrame,
    inserted_at: Instant,
}
#[cfg(feature = "mcquic")]
#[derive(Debug)]
struct PendingMcquicControl {
    frame: crate::mcquic::Frame,
    encoded_len: usize,
    inserted_at: Instant,
}

#[cfg(feature = "mcquic")]
struct QueuedMcquicFrame {
    frame: crate::mcquic::Frame,
    encoded_len: usize,
}

#[cfg(feature = "mcquic")]
#[derive(Default)]
struct McquicSendQueue {
    frames: VecDeque<QueuedMcquicFrame>,
    encoded_bytes: usize,
}

#[cfg(feature = "mcquic")]
impl McquicSendQueue {
    fn push_back(&mut self, frame: crate::mcquic::Frame) -> Res<()> {
        self.push(frame, false)
    }

    fn push_front(&mut self, frame: crate::mcquic::Frame) -> Res<()> {
        self.push(frame, true)
    }

    fn push(&mut self, frame: crate::mcquic::Frame, front: bool) -> Res<()> {
        let encoded_len = frame.encoded_len_erasing()?;
        if let crate::mcquic::Frame::Ack(new_ack) = &frame
            && let Some(index) = self.frames.iter().position(|queued| {
                matches!(&queued.frame,
                    crate::mcquic::Frame::Ack(ack) if ack.channel_id == new_ack.channel_id)
            })
        {
            let old_len = self.frames[index].encoded_len;
            let encoded_bytes = self
                .encoded_bytes
                .checked_sub(old_len)
                .and_then(|bytes| bytes.checked_add(encoded_len))
                .ok_or(Error::McquicResourceLimit)?;
            if encoded_bytes > MAX_MCQUIC_SEND_BYTES {
                return Err(Error::McquicResourceLimit);
            }
            self.frames[index] = QueuedMcquicFrame { frame, encoded_len };
            self.encoded_bytes = encoded_bytes;
            return Ok(());
        }

        let encoded_bytes = self
            .encoded_bytes
            .checked_add(encoded_len)
            .ok_or(Error::McquicResourceLimit)?;
        if self.frames.len() >= MAX_MCQUIC_SEND_FRAMES || encoded_bytes > MAX_MCQUIC_SEND_BYTES {
            return Err(Error::McquicResourceLimit);
        }
        let queued = QueuedMcquicFrame { frame, encoded_len };
        if front {
            self.frames.push_front(queued);
        } else {
            self.frames.push_back(queued);
        }
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }

    fn pop_front(&mut self) -> Option<QueuedMcquicFrame> {
        let queued = self.frames.pop_front()?;
        let Some(encoded_bytes) = self.encoded_bytes.checked_sub(queued.encoded_len) else {
            panic!("MCQUIC send byte accounting");
        };
        self.encoded_bytes = encoded_bytes;
        Some(queued)
    }

    fn restore_front(&mut self, queued: QueuedMcquicFrame) {
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(queued.encoded_len)
            .expect("MCQUIC send byte accounting");
        debug_assert!(self.frames.len() < MAX_MCQUIC_SEND_FRAMES);
        debug_assert!(self.encoded_bytes <= MAX_MCQUIC_SEND_BYTES);
        self.frames.push_front(queued);
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.encoded_bytes = 0;
    }

    #[cfg(test)]
    fn retain(&mut self, mut keep: impl FnMut(&crate::mcquic::Frame) -> bool) {
        self.frames.retain(|queued| keep(&queued.frame));
        self.encoded_bytes = self.frames.iter().map(|queued| queued.encoded_len).sum();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.frames.len()
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = &crate::mcquic::Frame> {
        self.frames.iter().map(|queued| &queued.frame)
    }
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ZeroRttState {
    Init,
    Sending,
    AcceptedClient,
    AcceptedServer,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Type returned from `process()` and `process_output()`. Users are required to
/// call these repeatedly until `Callback` or `None` is returned.
pub enum Output {
    /// Connection requires no action.
    None,
    /// Connection requires the datagram be sent.
    Datagram(Datagram),
    /// Connection requires `process_input()` be called when the `Duration`
    /// elapses.
    Callback(Duration),
}

impl TryFrom<OutputBatch> for Output {
    type Error = ();

    fn try_from(value: OutputBatch) -> Result<Self, <Self as TryFrom<OutputBatch>>::Error> {
        match value {
            OutputBatch::None => Ok(Self::None),
            OutputBatch::DatagramBatch(dg) => Ok(Self::Datagram(dg.try_into()?)),
            OutputBatch::Callback(t) => Ok(Self::Callback(t)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputBatch {
    /// Connection requires no action.
    None,
    /// Connection requires the datagram batch be sent.
    DatagramBatch(datagram::Batch),
    /// Connection requires `process_input()` be called when the `Duration`
    /// elapses.
    Callback(Duration),
}

impl From<Output> for OutputBatch {
    fn from(value: Output) -> Self {
        match value {
            Output::None => Self::None,
            Output::Datagram(dg) => Self::DatagramBatch(datagram::Batch::from(dg)),
            Output::Callback(t) => Self::Callback(t),
        }
    }
}

impl OutputBatch {
    fn error(error: Error) -> Self {
        std::panic::panic_any(error)
    }

    /// Convert into an [`Option<datagram::Batch>`].
    #[must_use]
    pub fn dgram(self) -> Option<datagram::Batch> {
        match self {
            Self::DatagramBatch(dg) => Some(dg),
            _ => None,
        }
    }
}

impl Output {
    /// Convert into an [`Option<Datagram>`].
    #[must_use]
    pub fn dgram(self) -> Option<Datagram> {
        match self {
            Self::Datagram(dg) => Some(dg),
            _ => None,
        }
    }

    /// Get a reference to the Datagram, if any.
    #[must_use]
    pub const fn as_dgram_ref(&self) -> Option<&Datagram> {
        match self {
            Self::Datagram(dg) => Some(dg),
            _ => None,
        }
    }

    /// Ask how long the caller should wait before calling back.
    #[must_use]
    pub const fn callback(&self) -> Duration {
        match self {
            Self::Callback(t) => *t,
            _ => Duration::new(0, 0),
        }
    }
}

impl From<Option<Datagram>> for Output {
    fn from(value: Option<Datagram>) -> Self {
        value.map_or(Self::None, Self::Datagram)
    }
}

pub struct OutputToken {
    connection_id: u64,
    generation: u64,
    resolved: bool,
}

impl Debug for OutputToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("OutputToken(..)")
    }
}

pub struct TrackedOutputBatch {
    output: OutputBatch,
    token: Option<OutputToken>,
    segment_count: usize,
}

impl TrackedOutputBatch {
    #[must_use]
    pub const fn output(&self) -> &OutputBatch {
        &self.output
    }

    #[must_use]
    pub const fn segment_count(&self) -> usize {
        self.segment_count
    }

    #[must_use]
    pub fn into_parts(self) -> (OutputBatch, Option<OutputToken>) {
        (self.output, self.token)
    }
}

#[derive(Clone)]
struct SegmentFixedCheckpoint {
    path: PathRef,
    path_state: crate::path::OutputCheckpoint,
    loss: recovery::OutputCheckpoint,
    acks: AckOutputCheckpoint,
    idle_timeout: IdleTimeout,
    state_signaling: StateSignaling,
    stats: OutputStatsCheckpoint,
    received_untracked: bool,
    qlog_events: usize,
}

struct OutputSegment {
    fixed: SegmentFixedCheckpoint,
    streams: StreamOutputJournal,
    quic_datagrams: QuicDatagramOutputJournal,
    packets: Vec<recovery::SentPacketId>,
    /// Tokens selected for a packet that could not be registered in recovery.
    untracked_tokens: Vec<recovery::Tokens>,
    /// Packet-number spaces discarded only after this segment is accepted.
    discard_spaces: Vec<PacketNumberSpace>,
}

struct BuildingOutput {
    state_signaling: StateSignaling,
    segments: Vec<OutputSegment>,
    current: Option<OutputSegment>,
    discard_spaces: PacketNumberSpaceSet,
}

struct PendingOutput {
    generation: u64,
    state_signaling: StateSignaling,
    segments: Vec<OutputSegment>,
}

/// Used by inner functions like `Connection::output`.
enum SendOptionBatch {
    /// Yes, please send this datagram.
    Yes(datagram::Batch),
    /// Don't send.  If this was blocked on the pacer (the arg is true).
    No(bool),
}

impl Default for SendOptionBatch {
    fn default() -> Self {
        Self::No(false)
    }
}

/// Used by inner functions like `Connection::output`.
enum SendOption {
    /// Yes, please send this datagram.
    Yes,
    /// Don't send.
    No(
        /// Whether this was blocked on the pacer.
        bool,
    ),
}

struct OutputGenerationError {
    path: Option<PathRef>,
    error: Error,
}
/// Used by `Connection::preprocess` to determine what to do
/// with an packet before attempting to remove protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreprocessResult {
    /// End processing and return successfully.
    End,
    /// Stop processing this datagram and move on to the next.
    Next,
    /// Continue and process this packet.
    Continue,
}

/// `AddressValidationInfo` holds information relevant to either
/// responding to address validation (`NewToken`, `Retry`) or generating
/// tokens for address validation (`Server`).
enum AddressValidationInfo {
    None,
    // We are a client and have information from `NEW_TOKEN`.
    NewToken(Vec<u8>),
    // We are a client and have received a `Retry` packet.
    Retry {
        token: Vec<u8>,
        retry_source_cid: ConnectionId,
    },
    // We are a server and can generate tokens.
    Server(Weak<RefCell<AddressValidation>>),
}

impl AddressValidationInfo {
    pub fn token(&self) -> &[u8] {
        match self {
            Self::NewToken(token) | Self::Retry { token, .. } => token,
            _ => &[],
        }
    }

    pub fn generate_new_token(&self, peer_address: SocketAddr, now: Instant) -> Option<Vec<u8>> {
        match self {
            Self::Server(w) => w
                .upgrade()?
                .borrow()
                .generate_new_token(peer_address, now)
                .ok(),
            Self::None => None,
            _ => unreachable!("called a server function on a client"),
        }
    }
}

/// A QUIC Connection
///
/// First, create a new connection using `new_client()` or `new_server()`.
///
/// For the life of the connection, handle activity in the following manner:
/// 1. Perform operations using the `stream_*()` methods.
/// 1. Call `process_input()` when a datagram is received or the timer expires. Obtain information
///    on connection state changes by checking `events()`.
/// 1. Having completed handling current activity, repeatedly call `process_output()` for packets to
///    send, until it returns `Output::Callback` or `Output::None`.
///
/// After the connection is closed (either by calling `close()` or by the
/// remote) continue processing until `state()` returns `Closed`.
pub struct Connection {
    role: Role,
    version: Version,
    state: State,
    tps: Rc<RefCell<TransportParametersHandler>>,
    /// What we are doing with 0-RTT.
    zero_rtt_state: ZeroRttState,
    /// All of the network paths that we are aware of.
    paths: Paths,
    /// This object will generate connection IDs for the connection.
    cid_manager: ConnectionIdManager,
    address_validation: AddressValidationInfo,
    /// The connection IDs that were provided by the peer.
    cids: ConnectionIdStore<Srt>,

    /// The source connection ID that this endpoint uses for the handshake.
    /// Since we need to communicate this to our peer in tparams, setting
    /// this value is part of constructing the struct.
    local_initial_source_cid: ConnectionId,
    /// The source connection ID from the first packet from the other end.
    /// This is checked against the peer's transport parameters.
    remote_initial_source_cid: Option<ConnectionId>,
    /// The destination connection ID from the first packet from the client.
    /// This is checked by the client against the server's transport
    /// parameters.
    original_destination_cid: Option<ConnectionId>,

    /// We sometimes save a datagram against the possibility that keys will
    /// later become available.  This avoids reporting packets as dropped
    /// during the handshake when they are either just reordered or we
    /// haven't been able to install keys yet. In particular, this occurs
    /// when asynchronous certificate validation happens.
    saved_datagrams: SavedDatagrams,
    /// Some packets were received, but not tracked.
    received_untracked: bool,

    /// This is responsible for the `QuicDatagrams`'handling:
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-quic-datagram>
    quic_datagrams: QuicDatagrams,
    /// Experimental MCQUIC control frames received from the peer.
    #[cfg(feature = "mcquic")]
    mcquic_recv: VecDeque<PendingMcquicControl>,
    #[cfg(feature = "mcquic")]
    mcquic_recv_bytes: usize,
    /// Application authorization state for this connection's MCQUIC operation.
    #[cfg(feature = "mcquic")]
    mcquic_operation_state: crate::mcquic::OperationState,
    /// Bounded controls received after the request but before CONNECT accepts
    /// this operation. These are not applied to channel state until acceptance.
    #[cfg(feature = "mcquic")]
    mcquic_pending_operation_controls: VecDeque<crate::mcquic::Frame>,
    #[cfg(feature = "mcquic")]
    mcquic_pending_operation_control_bytes: usize,
    #[cfg(feature = "mcquic")]
    mcquic_pending_operation_control_started_at: Option<Instant>,
    /// Experimental MCQUIC control frames queued for unicast delivery.
    #[cfg(feature = "mcquic")]
    mcquic_send: McquicSendQueue,
    /// Integrity hash lengths learned from peer `MC_ANNOUNCE` frames.
    #[cfg(feature = "mcquic")]
    mcquic_integrity_hash_lens: BTreeMap<Vec<u8>, usize>,
    /// Authenticated receive state for each announced multicast channel.
    #[cfg(feature = "mcquic")]
    mcquic_channels: BTreeMap<Vec<u8>, crate::mcquic::ChannelReceiveState>,
    /// Channel IDs retired until the bounded operation is revoked.
    #[cfg(feature = "mcquic")]
    mcquic_retired_channels: BTreeMap<Vec<u8>, Instant>,
    /// Channels locally declined after bounded receiver state was exhausted.
    #[cfg(feature = "mcquic")]
    mcquic_resource_limited_channels: VecDeque<Vec<u8>>,
    /// An authenticated frame targeted a stream outside the permitted
    /// operation. HTTP/3 consumes this signal and revokes the optimization.
    #[cfg(feature = "mcquic")]
    mcquic_ownership_violation: bool,
    /// Channel controls that arrived before their matching `MC_ANNOUNCE`.
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_controls: BTreeMap<Vec<u8>, VecDeque<crate::mcquic::Frame>>,
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_control_bytes: usize,
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_control_count: usize,
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_control_started_at: BTreeMap<Vec<u8>, Instant>,
    /// Authenticated stream frames waiting for HTTP/3 to bind their stream to
    /// the permitted operation.
    #[cfg(feature = "mcquic")]
    mcquic_pending_stream_frames: BTreeMap<StreamId, VecDeque<PendingMcquicStreamFrame>>,
    /// Newly pending streams awaiting one incremental HTTP/3 owner check.
    #[cfg(feature = "mcquic")]
    mcquic_pending_owner_checks: BTreeSet<StreamId>,
    /// One live deadline for each pending owner binding.
    #[cfg(feature = "mcquic")]
    mcquic_pending_owner_expiries: BTreeSet<(Instant, StreamId)>,
    /// Reverse index used to retire one channel without scanning every owner.
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_streams: BTreeMap<Vec<u8>, BTreeSet<StreamId>>,
    #[cfg(feature = "mcquic")]
    mcquic_pending_channel_owner_links: usize,
    /// Streams whose ordinary prefix has been bound to the permitted operation.
    #[cfg(feature = "mcquic")]
    mcquic_authorized_streams: BTreeMap<StreamId, Instant>,
    /// One live deadline for each authorized owner binding.
    #[cfg(feature = "mcquic")]
    mcquic_authorized_stream_expiries: BTreeSet<(Instant, StreamId)>,
    /// Total payload bytes retained in `mcquic_pending_stream_frames`.
    #[cfg(feature = "mcquic")]
    mcquic_pending_stream_bytes: usize,
    /// Total frame count retained in `mcquic_pending_stream_frames`.
    #[cfg(feature = "mcquic")]
    mcquic_pending_stream_frame_count: usize,

    crypto: Crypto,
    acks: AckTracker,
    idle_timeout: IdleTimeout,
    streams: Streams,
    state_signaling: StateSignaling,
    loss_recovery: recovery::Loss,
    events: ConnectionEvents,
    new_token: NewTokenState,
    stats: StatsCell,
    qlog: Qlog,
    /// Identity and generation for connection-bound tracked output tokens.
    output_connection_id: u64,
    output_generation: u64,
    /// Output currently being assembled or awaiting socket disposition.
    output_building: Option<BuildingOutput>,
    output_pending: Option<PendingOutput>,
    /// A session ticket was received without `NEW_TOKEN`,
    /// this is when that turns into an event without `NEW_TOKEN`.
    release_resumption_token_timer: Option<Instant>,
    conn_params: ConnectionParameters,
    hrtime: hrtime::Handle,

    /// For testing purposes it is sometimes necessary to inject frames that
    /// wouldn't otherwise be sent, just to see how a connection handles them.
    /// Inserting them into packets proper mean that the frames follow the entire
    /// processing path.
    #[cfg(any(test, feature = "build-fuzzing-corpus"))]
    test_frame_writer: Option<Box<dyn test_internal::FrameWriter>>,
}

impl Debug for Connection {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} Connection: {:?} {:?}",
            self.role,
            self.state,
            self.paths.primary()
        )
    }
}

impl Connection {
    /// A long default for timer resolution, so that we don't tax the
    /// system too hard when we don't need to.
    const LOOSE_TIMER_RESOLUTION: Duration = Duration::from_millis(50);
    /// The SCONE indicator.
    const SCONE_INDICATION: &[u8] = &[0xc8, 0x13];

    /// Create a new QUIC connection with Client role.
    /// # Errors
    /// When NSS fails and an agent cannot be created.
    pub fn new_client<I: Into<String>, A: AsRef<str>>(
        server_name: I,
        protocols: &[A],
        cid_generator: Rc<RefCell<dyn ConnectionIdGenerator>>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        conn_params: ConnectionParameters,
        now: Instant,
    ) -> Res<Self> {
        let dcid = ConnectionId::generate_initial();
        let mut c = Self::new(
            Role::Client,
            Agent::from(Client::new(server_name.into(), conn_params.is_greasing())?),
            cid_generator,
            protocols,
            conn_params,
        )?;
        c.crypto.states_mut().init(
            c.conn_params.get_versions().compatible(),
            Role::Client,
            &dcid,
            c.conn_params.randomize_first_pn_enabled(),
        )?;
        c.original_destination_cid = Some(dcid);
        let path = Path::temporary(
            local_addr,
            remote_addr,
            &c.conn_params,
            Qlog::default(),
            now,
            &mut c.stats.borrow_mut(),
        );
        c.setup_handshake_path(&Rc::new(RefCell::new(path)), now);
        Ok(c)
    }

    /// Create a new QUIC connection with Server role.
    /// # Errors
    /// When NSS fails and an agent cannot be created.
    pub fn new_server<A1: AsRef<str>, A2: AsRef<str>>(
        certs: &[A1],
        protocols: &[A2],
        cid_generator: Rc<RefCell<dyn ConnectionIdGenerator>>,
        conn_params: ConnectionParameters,
    ) -> Res<Self> {
        Self::new(
            Role::Server,
            Agent::from(Server::new(certs)?),
            cid_generator,
            protocols,
            conn_params,
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "connection construction initializes protocol state in one auditable place"
    )]
    fn new<P: AsRef<str>>(
        role: Role,
        agent: Agent,
        cid_generator: Rc<RefCell<dyn ConnectionIdGenerator>>,
        protocols: &[P],
        conn_params: ConnectionParameters,
    ) -> Res<Self> {
        // Setup the local connection ID.
        let local_initial_source_cid = cid_generator
            .borrow_mut()
            .generate_cid()
            .ok_or(Error::ConnectionIdsExhausted)?;
        let mut cid_manager =
            ConnectionIdManager::new(cid_generator, local_initial_source_cid.clone());
        let mut tps = conn_params.create_transport_parameter(role, &mut cid_manager)?;
        tps.local_mut()
            .set_bytes(InitialSourceConnectionId, local_initial_source_cid.to_vec());

        let tphandler = Rc::new(RefCell::new(tps));
        let crypto = Crypto::new(
            conn_params.get_versions().initial(),
            &conn_params,
            agent,
            protocols.iter().map(P::as_ref).map(String::from).collect(),
            Rc::clone(&tphandler),
        )?;

        let stats = StatsCell::default();
        let events = ConnectionEvents::default();
        let quic_datagrams = QuicDatagrams::new(
            conn_params.get_datagram_size(),
            conn_params.get_outgoing_datagram_queue(),
            conn_params.get_incoming_datagram_queue(),
            events.clone(),
        );

        #[cfg(feature = "mcquic")]
        let mcquic_operation_state = match role {
            Role::Client => match conn_params.get_mcquic_operation_policy() {
                crate::mcquic::OperationPolicy::Prohibit => {
                    crate::mcquic::OperationState::Prohibited
                }
                crate::mcquic::OperationPolicy::Allow => crate::mcquic::OperationState::Pending,
            },
            Role::Server => crate::mcquic::OperationState::Active,
        };

        let c = Self {
            role,
            version: conn_params.get_versions().initial(),
            state: State::Init,
            paths: Paths::new(conn_params.pmtud_enabled()),
            cid_manager,
            tps: Rc::clone(&tphandler),
            zero_rtt_state: ZeroRttState::Init,
            address_validation: AddressValidationInfo::None,
            local_initial_source_cid,
            remote_initial_source_cid: None,
            original_destination_cid: None,
            saved_datagrams: SavedDatagrams::default(),
            received_untracked: false,
            crypto,
            acks: AckTracker::default(),
            idle_timeout: IdleTimeout::new(conn_params.get_idle_timeout()),
            streams: Streams::new(tphandler, role, events.clone()),
            cids: ConnectionIdStore::default(),
            state_signaling: StateSignaling::Idle,
            loss_recovery: recovery::Loss::new(stats.clone(), conn_params.get_fast_pto()),
            events,
            new_token: NewTokenState::new(role),
            stats,
            qlog: Qlog::disabled(),
            output_connection_id: NEXT_OUTPUT_CONNECTION_ID.fetch_add(1, AtomicOrdering::Relaxed),
            output_generation: 0,
            output_building: None,
            output_pending: None,
            release_resumption_token_timer: None,
            conn_params,
            hrtime: hrtime::Time::get(Self::LOOSE_TIMER_RESOLUTION),
            quic_datagrams,
            #[cfg(feature = "mcquic")]
            mcquic_recv: VecDeque::new(),
            #[cfg(feature = "mcquic")]
            mcquic_recv_bytes: 0,
            #[cfg(feature = "mcquic")]
            mcquic_operation_state,
            #[cfg(feature = "mcquic")]
            mcquic_pending_operation_controls: VecDeque::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_operation_control_bytes: 0,
            #[cfg(feature = "mcquic")]
            mcquic_pending_operation_control_started_at: None,
            #[cfg(feature = "mcquic")]
            mcquic_send: McquicSendQueue::default(),
            #[cfg(feature = "mcquic")]
            mcquic_integrity_hash_lens: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_channels: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_retired_channels: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_resource_limited_channels: VecDeque::new(),
            #[cfg(feature = "mcquic")]
            mcquic_ownership_violation: false,
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_controls: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_control_bytes: 0,
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_control_count: 0,
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_control_started_at: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_stream_frames: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_owner_checks: BTreeSet::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_owner_expiries: BTreeSet::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_streams: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_channel_owner_links: 0,
            #[cfg(feature = "mcquic")]
            mcquic_authorized_streams: BTreeMap::new(),
            #[cfg(feature = "mcquic")]
            mcquic_authorized_stream_expiries: BTreeSet::new(),
            #[cfg(feature = "mcquic")]
            mcquic_pending_stream_bytes: 0,
            #[cfg(feature = "mcquic")]
            mcquic_pending_stream_frame_count: 0,
            #[cfg(any(test, feature = "build-fuzzing-corpus"))]
            test_frame_writer: None,
        };
        c.stats.borrow_mut().init(format!("{c}"));
        Ok(c)
    }

    const fn ensure_output_resolved(&self) -> Res<()> {
        if self.output_pending.is_some() || self.output_building.is_some() {
            Err(Error::OutputPending)
        } else {
            Ok(())
        }
    }

    fn assert_output_resolved(&self) {
        if let Err(error) = self.ensure_output_resolved() {
            std::panic::panic_any(error);
        }
    }

    /// Whether tracked output is waiting for a socket acceptance decision.
    #[must_use]
    pub const fn output_pending(&self) -> bool {
        self.output_pending.is_some() || self.output_building.is_some()
    }

    fn begin_output_transaction(&mut self) -> Res<()> {
        self.ensure_output_resolved()?;
        self.qlog
            .begin_output_transaction()
            .map_err(|_| Error::Internal)?;
        self.output_building = Some(BuildingOutput {
            state_signaling: self.state_signaling.clone(),
            segments: Vec::new(),
            current: None,
            discard_spaces: PacketNumberSpaceSet::new(),
        });
        Ok(())
    }

    fn begin_output_segment(&mut self, path: &PathRef) -> Res<()> {
        let qlog_events = self
            .qlog
            .output_transaction_checkpoint()
            .map_err(|_| Error::Internal)?;
        let segment = OutputSegment {
            fixed: SegmentFixedCheckpoint {
                path: Rc::clone(path),
                path_state: path.borrow().output_checkpoint(),
                loss: self.loss_recovery.output_checkpoint(),
                acks: self.acks.output_checkpoint(),
                idle_timeout: self.idle_timeout.clone(),
                state_signaling: self.state_signaling.clone(),
                stats: self.stats.borrow().output_checkpoint(),
                received_untracked: self.received_untracked,
                qlog_events,
            },
            streams: StreamOutputJournal::default(),
            quic_datagrams: QuicDatagramOutputJournal::default(),
            packets: Vec::new(),
            untracked_tokens: Vec::new(),
            discard_spaces: Vec::new(),
        };
        let building = self.output_building.as_mut().ok_or(Error::Internal)?;
        if building.current.replace(segment).is_some() {
            return Err(Error::Internal);
        }
        Ok(())
    }

    fn finish_output_segment(&mut self) -> Res<()> {
        let building = self.output_building.as_mut().ok_or(Error::Internal)?;
        let segment = building.current.take().ok_or(Error::Internal)?;
        building.segments.push(segment);
        Ok(())
    }

    fn defer_discard_keys(&mut self, space: PacketNumberSpace) -> Res<()> {
        let building = self.output_building.as_mut().ok_or(Error::Internal)?;
        if building.discard_spaces.insert(space) {
            building
                .current
                .as_mut()
                .ok_or(Error::Internal)?
                .discard_spaces
                .push(space);
        }
        Ok(())
    }

    fn track_output_packet(
        &mut self,
        packet: sent::Packet,
        path: &PathRef,
        now: Instant,
    ) -> Res<()> {
        let space = PacketNumberSpace::from(packet.packet_type());
        if self
            .output_building
            .as_ref()
            .is_some_and(|building| building.discard_spaces.contains(space))
        {
            // The legacy output path discarded this recovery space before
            // registering the packet. Keep the packet out of recovery and
            // pacing while retaining its tokens until socket disposition.
            return self.track_unregistered_output_tokens(packet.into_tokens());
        }
        let segment = self
            .output_building
            .as_mut()
            .and_then(|building| building.current.as_mut())
            .ok_or(Error::Internal)?;
        match self.loss_recovery.on_packet_sent_tracked(path, packet, now) {
            Ok(packet_id) => segment.packets.push(packet_id),
            Err(packet) => segment.untracked_tokens.push(packet.into_tokens()),
        }
        Ok(())
    }

    fn track_unregistered_output_tokens(&mut self, tokens: recovery::Tokens) -> Res<()> {
        self.output_building
            .as_mut()
            .and_then(|building| building.current.as_mut())
            .ok_or(Error::Internal)?
            .untracked_tokens
            .push(tokens);
        Ok(())
    }

    fn restore_abandoned_output_tokens(
        &mut self,
        tokens: recovery::Tokens,
        abandoned_datagrams: &mut Vec<DatagramTracking>,
    ) {
        for token in tokens.into_iter().rev() {
            match token {
                recovery::Token::Ack(_)
                | recovery::Token::HandshakeDone
                | recovery::Token::KeepAlive
                | recovery::Token::Stream(_)
                | recovery::Token::EcnEct0
                | recovery::Token::PmtudProbe => (),
                recovery::Token::Crypto(token) => self.crypto.lost(&token),
                recovery::Token::NewToken(seqno) => self.new_token.lost(seqno),
                recovery::Token::NewConnectionId(entry) => self.cid_manager.lost(&entry),
                recovery::Token::RetireConnectionId(seqno) => {
                    self.paths.lost_retire_cid(seqno);
                }
                recovery::Token::AckFrequency(rate) => self.paths.lost_ack_frequency(&rate),
                recovery::Token::Datagram(tracker) => abandoned_datagrams.push(tracker),
                #[cfg(feature = "mcquic")]
                recovery::Token::Mcquic(frame) => self
                    .mcquic_send
                    .push_front(frame)
                    .expect("abandoned output restores its previously queued MCQUIC frame"),
            }
        }
    }

    fn rollback_output_segments(
        &mut self,
        segments: Vec<OutputSegment>,
        state_signaling: Option<StateSignaling>,
    ) -> Res<()> {
        let Some(qlog_events) = segments.first().map(|segment| segment.fixed.qlog_events) else {
            if let Some(state_signaling) = state_signaling {
                self.state_signaling = state_signaling;
            }
            return Ok(());
        };
        let mut abandoned_datagrams = Vec::new();

        for segment in segments.into_iter().rev() {
            self.quic_datagrams.restore_output(segment.quic_datagrams);
            for packet_id in segment.packets.into_iter().rev() {
                if let Some(packet) = self.loss_recovery.remove_output_packet(packet_id) {
                    self.restore_abandoned_output_tokens(
                        packet.into_tokens(),
                        &mut abandoned_datagrams,
                    );
                }
            }
            for tokens in segment.untracked_tokens.into_iter().rev() {
                self.restore_abandoned_output_tokens(tokens, &mut abandoned_datagrams);
            }

            self.streams.undo_output(segment.streams);
            segment
                .fixed
                .path
                .borrow_mut()
                .restore_output(segment.fixed.path_state);
            self.loss_recovery.restore_output(&segment.fixed.loss);
            self.acks.restore_output(&segment.fixed.acks);
            self.idle_timeout = segment.fixed.idle_timeout;
            self.state_signaling = segment.fixed.state_signaling;
            self.stats.borrow_mut().restore_output(&segment.fixed.stats);
            self.received_untracked = segment.fixed.received_untracked;
        }

        if let Some(state_signaling) = state_signaling {
            self.state_signaling = state_signaling;
        }
        self.qlog
            .truncate_output_transaction(qlog_events)
            .map_err(|_| Error::Internal)?;

        for tracker in abandoned_datagrams.into_iter().rev() {
            self.events
                .datagram_outcome(&tracker, OutgoingDatagramOutcome::Abandoned);
            self.stats.borrow_mut().datagram_tx.abandoned += 1;
        }
        Ok(())
    }

    fn rollback_current_output_segment(&mut self) -> Res<()> {
        let building = self.output_building.as_mut().ok_or(Error::Internal)?;
        let segment = building.current.take().ok_or(Error::Internal)?;
        for space in &segment.discard_spaces {
            building.discard_spaces.remove(*space);
        }
        self.rollback_output_segments(vec![segment], None)
    }

    fn take_current_quic_datagram_output(&mut self) -> Res<QuicDatagramOutputJournal> {
        Ok(mem::take(
            &mut self
                .output_building
                .as_mut()
                .and_then(|building| building.current.as_mut())
                .ok_or(Error::Internal)?
                .quic_datagrams,
        ))
    }

    fn commit_quic_datagram_output(&self, journal: QuicDatagramOutputJournal) {
        self.quic_datagrams
            .commit_output(journal, &mut self.stats.borrow_mut());
    }

    fn abandon_building_output(&mut self) -> Res<()> {
        let mut building = self.output_building.take().ok_or(Error::Internal)?;
        if let Some(current) = building.current.take() {
            building.segments.push(current);
        }
        self.rollback_output_segments(building.segments, Some(building.state_signaling))?;
        self.qlog
            .finish_output_transaction(false)
            .map_err(|_| Error::Internal)
    }

    /// # Errors
    /// When the operation fails.
    pub fn server_enable_0rtt<Z: ZeroRttChecker + 'static>(
        &mut self,
        anti_replay: &AntiReplay,
        zero_rtt_checker: Z,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        self.crypto
            .server_enable_0rtt(Rc::clone(&self.tps), anti_replay, zero_rtt_checker)
    }

    /// # Errors
    /// When the operation fails.
    pub fn set_certificate_compression<T: CertificateCompressor>(&mut self) -> Res<()> {
        self.ensure_output_resolved()?;
        self.crypto.tls_mut().set_certificate_compression::<T>()?;
        Ok(())
    }

    /// # Errors
    /// When the operation fails.
    pub fn server_enable_ech(
        &mut self,
        config: u8,
        public_name: &str,
        sk: &PrivateKey,
        pk: &PublicKey,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        self.crypto.server_enable_ech(config, public_name, sk, pk)
    }
    /// Get the active ECH configuration, which is empty if ECH is disabled.
    #[must_use]
    pub fn ech_config(&self) -> &[u8] {
        self.crypto.ech_config()
    }

    /// # Errors
    /// When the operation fails.
    pub fn client_enable_ech<A: AsRef<[u8]>>(&mut self, ech_config_list: A) -> Res<()> {
        self.ensure_output_resolved()?;
        self.crypto.client_enable_ech(ech_config_list)
    }

    /// Set or clear the qlog for this connection.
    pub fn set_qlog(&mut self, qlog: Qlog) {
        self.assert_output_resolved();
        self.loss_recovery.set_qlog(qlog.clone());
        self.paths.set_qlog(qlog.clone());
        self.qlog = qlog;
    }

    /// Get the qlog (if any) for this connection.
    pub fn qlog_mut(&mut self) -> &mut Qlog {
        self.assert_output_resolved();
        &mut self.qlog
    }
    /// Get the original destination connection id for this connection. This
    /// will always be present for `Role::Client` but not if `Role::Server` is in
    /// `State::Init`.
    #[must_use]
    pub const fn odcid(&self) -> Option<&ConnectionId> {
        self.original_destination_cid.as_ref()
    }

    /// Set a local transport parameter, possibly overriding a default value.
    /// This only sets transport parameters without dealing with other aspects of
    /// setting the value.
    ///
    /// # Errors
    /// When the transport parameter is invalid.
    /// # Panics
    /// This panics if the transport parameter is known to this crate.
    #[cfg(test)]
    pub fn set_local_tparam(
        &self,
        tp: TransportParameterId,
        value: tparams::TransportParameter,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        if *self.state() == State::Init {
            self.tps.borrow_mut().local_mut().set(tp, value);
            Ok(())
        } else {
            qerror!("Current state: {:?}", self.state());
            qerror!("Cannot set local tparam when not in an initial connection state");
            Err(Error::ConnectionState)
        }
    }

    /// `odcid` is their original choice for our CID, which we get from the Retry
    /// token. `remote_cid` is the value from the Source Connection ID field of an
    /// incoming packet: what the peer wants us to use now. `retry_cid` is what we
    /// asked them to use when we sent the Retry.
    pub(crate) fn set_retry_cids(
        &mut self,
        odcid: &ConnectionId,
        remote_cid: ConnectionId,
        retry_cid: &ConnectionId,
    ) {
        self.assert_output_resolved();
        debug_assert_eq!(self.role, Role::Server);
        qtrace!("[{self}] Retry CIDs: odcid={odcid} remote={remote_cid} retry={retry_cid}");
        // We advertise "our" choices in transport parameters.
        self.tps
            .borrow_mut()
            .local_mut()
            .set_bytes(OriginalDestinationConnectionId, odcid.to_vec());
        self.tps
            .borrow_mut()
            .local_mut()
            .set_bytes(RetrySourceConnectionId, retry_cid.to_vec());

        // ...and save their choices for later validation.
        self.remote_initial_source_cid = Some(remote_cid);
    }

    fn retry_sent(&self) -> bool {
        self.tps
            .borrow()
            .local()
            .get_bytes(RetrySourceConnectionId)
            .is_some()
    }

    /// Set ALPN preferences. Strings that appear earlier in the list are given
    /// higher preference.
    /// # Errors
    /// When the operation fails, which is usually due to bad inputs or bad
    /// connection state.
    pub fn set_alpn<A: AsRef<[u8]>>(&mut self, protocols: &[A]) -> Res<()> {
        self.ensure_output_resolved()?;
        self.crypto.tls_mut().set_alpn(protocols)?;
        Ok(())
    }

    /// Enable a set of ciphers.
    /// # Errors
    /// When the operation fails, which is usually due to
    /// bad inputs or bad connection state.
    pub fn set_ciphers(&mut self, ciphers: &[Cipher]) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.state != State::Init {
            qerror!("[{self}] Cannot enable ciphers in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        self.crypto.tls_mut().set_ciphers(ciphers)?;
        Ok(())
    }

    /// Enable a set of key exchange groups.
    /// # Errors
    /// When the operation fails, which is usually due to bad inputs or bad
    /// connection state.
    pub fn set_groups(&mut self, groups: &[Group]) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.state != State::Init {
            qerror!("[{self}] Cannot enable groups in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        self.crypto.tls_mut().set_groups(groups)?;
        Ok(())
    }

    /// Set the number of additional key shares to send in the client hello.
    /// # Errors
    /// When the operation fails, which is usually due to bad inputs or bad
    /// connection state.
    pub fn send_additional_key_shares(&mut self, count: usize) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.state != State::Init {
            qerror!("[{self}] Cannot enable groups in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        self.crypto.tls_mut().send_additional_key_shares(count)?;
        Ok(())
    }

    fn make_resumption_token(&mut self) -> ResumptionToken {
        debug_assert_eq!(self.role, Role::Client);
        debug_assert!(self.crypto.has_resumption_token());
        // Values less than GRANULARITY are ignored when using the token, so use 0
        // where needed.
        let rtt = self.paths.primary().map_or_else(
            // If we don't have a path, we don't have an RTT.
            || Duration::from_millis(0),
            |p| {
                let rtt = p.borrow().rtt().estimate();
                if p.borrow().rtt().is_guesstimate() {
                    // When we have no actual RTT sample, do not encode a
                    // guestimated RTT larger than the default initial RTT. (The
                    // guess can be very large under lossy conditions.)
                    if rtt < self.conn_params.get_initial_rtt() {
                        rtt
                    } else {
                        Duration::from_millis(0)
                    }
                } else {
                    rtt
                }
            },
        );

        self.crypto
            .create_resumption_token(
                self.new_token.take_token(),
                self.tps
                    .borrow()
                    .remote_handshake()
                    .as_ref()
                    .expect("should have transport parameters"),
                self.version,
                u64::try_from(rtt.as_millis()).unwrap_or(0),
            )
            .expect("caller checked if a resumption token existed")
    }

    fn confirmed(&self) -> bool {
        self.state == State::Confirmed
    }

    /// Get the simplest PTO calculation for all those cases where we need
    /// a value of this approximate order.  Don't use this for loss recovery,
    /// only use it where a more precise value is not important.
    fn pto(&self) -> Duration {
        self.paths.primary().map_or_else(
            || RttEstimate::new(self.conn_params.get_initial_rtt()).pto(self.confirmed()),
            |p| p.borrow().rtt().pto(self.confirmed()),
        )
    }

    fn create_resumption_token(&mut self, now: Instant) {
        if self.role == Role::Server || self.state < State::Connected {
            return;
        }

        qtrace!(
            "[{self}] Maybe create resumption token: {} {}",
            self.crypto.has_resumption_token(),
            self.new_token.has_token()
        );

        while self.crypto.has_resumption_token() && self.new_token.has_token() {
            let token = self.make_resumption_token();
            self.events.client_resumption_token(token);
        }

        // If we have a resumption ticket check or set a timer.
        if self.crypto.has_resumption_token() {
            let arm = if let Some(expiration_time) = self.release_resumption_token_timer {
                if expiration_time <= now {
                    let token = self.make_resumption_token();
                    self.events.client_resumption_token(token);
                    self.release_resumption_token_timer = None;

                    // This means that we release one session ticket every 3 PTOs
                    // if no NEW_TOKEN frame is received.
                    self.crypto.has_resumption_token()
                } else {
                    false
                }
            } else {
                true
            };

            if arm {
                self.release_resumption_token_timer = Some(now + 3 * self.pto());
            }
        }
    }

    /// The correct way to obtain a resumption token is to wait for the
    /// `ConnectionEvent::ResumptionToken` event. To emit the event we are waiting
    /// for a resumption token and a `NEW_TOKEN` frame to arrive. Some servers
    /// don't send `NEW_TOKEN` frames and in this case, we wait for 3xPTO before
    /// emitting an event. This is especially a problem for short-lived
    /// connections, where the connection is closed before any events are
    /// released. This function retrieves the token, without waiting for a
    /// `NEW_TOKEN` frame to arrive.
    ///
    /// # Panics
    ///
    /// If this is called on a server.
    pub fn take_resumption_token(&mut self, now: Instant) -> Option<ResumptionToken> {
        self.assert_output_resolved();
        assert_eq!(self.role, Role::Client);

        self.crypto.has_resumption_token().then(|| {
            let token = self.make_resumption_token();
            if self.crypto.has_resumption_token() {
                self.release_resumption_token_timer = Some(now + 3 * self.pto());
            }
            token
        })
    }

    /// Enable resumption, using a token previously provided.
    /// This can only be called once and only on the client.
    /// After calling the function, it should be possible to attempt 0-RTT
    /// if the token supports that.
    ///
    /// This function starts the TLS stack, which means that any configuration
    /// change to that stack needs to occur prior to calling this.
    ///
    /// # Errors
    /// When the operation fails, which is usually due to bad inputs or bad
    /// connection state.
    pub fn enable_resumption<A: AsRef<[u8]>>(&mut self, now: Instant, token: A) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.state != State::Init {
            qerror!("[{self}] set token in state {:?}", self.state);
            return Err(Error::ConnectionState);
        }
        if self.role == Role::Server {
            return Err(Error::ConnectionState);
        }

        qinfo!(
            "[{self}] resumption token {}",
            hex_snip_middle(token.as_ref())
        );
        let mut dec = Decoder::from(token.as_ref());

        let version = Version::try_from(
            dec.decode_uint::<version::Wire>()
                .ok_or(Error::InvalidResumptionToken)?,
        )?;
        qtrace!("[{self}]   version {version:?}");
        if !self.conn_params.get_versions().all().contains(&version) {
            return Err(Error::DisabledVersion);
        }

        let rtt = Duration::from_millis(dec.decode_varint().ok_or(Error::InvalidResumptionToken)?);
        qtrace!("[{self}]   RTT {rtt:?}");

        let tp_slice = dec.decode_vvec().ok_or(Error::InvalidResumptionToken)?;
        qtrace!("[{self}]   transport parameters {}", hex(tp_slice));
        let mut dec_tp = Decoder::from(tp_slice);
        let tp =
            TransportParameters::decode(&mut dec_tp).map_err(|_| Error::InvalidResumptionToken)?;

        let init_token = dec.decode_vvec().ok_or(Error::InvalidResumptionToken)?;
        qtrace!("[{self}]   Initial token {}", hex(init_token));

        let tok = dec.decode_remainder();
        qtrace!("[{self}]   TLS token {}", hex(tok));

        match self.crypto.tls_mut() {
            Agent::Client(c) => {
                let res = c.enable_resumption(tok);
                if let Err(e) = res {
                    self.absorb_error::<Error>(now, Err(Error::from(e)));
                    return Ok(());
                }
            }
            Agent::Server(_) => return Err(Error::WrongRole),
        }

        self.version = version;
        self.conn_params.get_versions_mut().set_initial(version);
        self.tps.borrow_mut().set_version(version);
        self.tps.borrow_mut().set_remote_0rtt(Some(tp));
        if !init_token.is_empty() {
            self.address_validation = AddressValidationInfo::NewToken(init_token.to_vec());
        }
        self.paths
            .primary()
            .ok_or(Error::Internal)?
            .borrow_mut()
            .rtt_mut()
            .set_initial(rtt);
        self.set_initial_limits();
        // Start up TLS, which has the effect of setting up all the necessary
        // state for 0-RTT.  This only stages the CRYPTO frames.
        let res = self.client_start(now);
        self.absorb_error(now, res);
        Ok(())
    }

    pub(crate) fn set_validation(&mut self, validation: &Rc<RefCell<AddressValidation>>) {
        self.assert_output_resolved();
        qtrace!("[{self}] Enabling NEW_TOKEN");
        assert_eq!(self.role, Role::Server);
        self.address_validation = AddressValidationInfo::Server(Rc::downgrade(validation));
    }

    /// Send a TLS session ticket AND a `NEW_TOKEN` frame (if possible).
    /// # Errors
    /// When the operation fails, which is usually due to bad inputs or bad
    /// connection state.
    pub fn send_ticket(&mut self, now: Instant, extra: &[u8]) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.role == Role::Client {
            return Err(Error::WrongRole);
        }

        let tps = &self.tps;
        if let Agent::Server(s) = self.crypto.tls_mut() {
            let mut enc = Encoder::default();
            enc.encode_vvec_with(|enc_inner| {
                tps.borrow().local().encode(enc_inner);
            });
            enc.encode(extra);
            let records = s.send_ticket(now, enc.as_ref())?;
            qdebug!("[{self}] send session ticket {}", hex(&enc));
            self.crypto.buffer_records(records)?;
        } else {
            unreachable!();
        }

        // If we are able, also send a NEW_TOKEN frame.
        // This should be recording all remote addresses that are valid,
        // but there are just 0 or 1 in the current implementation.
        match self.paths.primary() {
            Some(path) => {
                if let Some(token) = self
                    .address_validation
                    .generate_new_token(path.borrow().remote_address(), now)
                {
                    self.new_token.send_new_token(token);
                }
                Ok(())
            }
            None => Err(Error::NotConnected),
        }
    }

    #[must_use]
    pub fn tls_info(&self) -> Option<&SecretAgentInfo> {
        self.crypto.tls().info()
    }

    /// # Errors
    /// When there is no information to obtain.
    pub fn tls_preinfo(&self) -> Res<SecretAgentPreInfo> {
        Ok(self.crypto.tls().preinfo()?)
    }
    /// Get the peer's certificate chain and other info.
    #[must_use]
    pub fn peer_certificate(&self) -> Option<CertificateInfo> {
        self.crypto.tls().peer_certificate()
    }

    /// Call by application when the peer cert has been verified.
    ///
    /// This panics if there is no active peer.  It's OK to call this
    /// when authentication isn't needed, that will likely only cause
    /// the connection to fail.  However, if no packets have been
    /// exchanged, it's not OK.
    pub fn authenticated(&mut self, status: AuthenticationStatus, now: Instant) {
        self.assert_output_resolved();
        qdebug!("[{self}] Authenticated {status:?}");
        self.crypto.tls_mut().authenticated(status);
        let res = self.handshake(now, self.version, PacketNumberSpace::Handshake, None);
        self.absorb_error(now, res);
        self.process_saved(now);
    }

    /// Get the role of the connection.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }
    /// Get the state of the connection.
    #[must_use]
    pub const fn state(&self) -> &State {
        &self.state
    }

    /// The QUIC version in use.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Get the 0-RTT state of the connection.
    #[must_use]
    pub const fn zero_rtt_state(&self) -> ZeroRttState {
        self.zero_rtt_state
    }

    /// Get a snapshot of collected statistics.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.stats_with_output_checkpoint(None)
    }

    /// Get a snapshot that excludes output awaiting socket acceptance.
    #[must_use]
    pub fn committed_stats(&self) -> Stats {
        let checkpoint = self
            .output_pending
            .as_ref()
            .and_then(|pending| pending.segments.first())
            .map(|segment| &segment.fixed.stats);
        self.stats_with_output_checkpoint(checkpoint)
    }

    fn stats_with_output_checkpoint(&self, checkpoint: Option<&OutputStatsCheckpoint>) -> Stats {
        let mut v = self.stats.borrow().clone();
        if let Some(checkpoint) = checkpoint {
            v.restore_output(checkpoint);
        }
        v.version = self.version;
        if let Some(p) = self.paths.primary() {
            let p = p.borrow();
            v.rtt = p.rtt().estimate();
            v.rttvar = p.rtt().rttvar();
            v.min_rtt = p.rtt().minimum();
        }
        v
    }

    // This function wraps a call to another function and sets the connection
    // state properly if that call fails.
    fn capture_error<T>(
        &mut self,
        path: Option<PathRef>,
        now: Instant,
        frame_type: FrameType,
        res: Res<T>,
    ) -> Res<T> {
        if let Err(v) = &res {
            #[cfg(debug_assertions)]
            let msg = format!("{v:?}");
            #[cfg(not(debug_assertions))]
            let msg = "";
            let error = CloseReason::Transport(v.clone());
            match &self.state {
                State::Closing { error: err, .. }
                | State::Draining { error: err, .. }
                | State::Closed(err) => {
                    qwarn!("[{self}] Closing again after error {err:?}");
                }
                State::Init => {
                    // We have not even sent anything just close the connection
                    // without sending any error. This may happen when client_start
                    // fails.
                    self.set_state(State::Closed(error), now);
                }
                State::WaitInitial | State::WaitVersion => {
                    // We don't have any state yet, so don't bother with
                    // the closing state, just send one CONNECTION_CLOSE.
                    if let Some(path) = path.or_else(|| self.paths.primary()) {
                        self.state_signaling
                            .close(path, error.clone(), frame_type, msg);
                    }
                    self.set_state(State::Closed(error), now);
                }
                _ => match path.or_else(|| self.paths.primary()) {
                    Some(path) => {
                        self.state_signaling
                            .close(path, error.clone(), frame_type, msg);
                        if matches!(v, Error::KeysExhausted) {
                            self.set_state(State::Closed(error), now);
                        } else {
                            self.set_state(
                                State::Closing {
                                    error,
                                    timeout: self.get_closing_period_time(now),
                                },
                                now,
                            );
                        }
                    }
                    None => {
                        self.set_state(State::Closed(error), now);
                    }
                },
            }
        }
        res
    }

    /// For use with `process_input()`. Errors there can be ignored, but this
    /// needs to ensure that the state is updated.
    fn absorb_error<T>(&mut self, now: Instant, res: Res<T>) -> Option<T> {
        self.capture_error(None, now, FrameType::Padding, res).ok()
    }

    fn process_timer(&mut self, now: Instant) {
        match &self.state {
            // Only the client runs timers while waiting for Initial packets.
            State::WaitInitial => debug_assert_eq!(self.role, Role::Client),
            // If Closing or Draining, check if it is time to move to Closed.
            State::Closing { error, timeout } | State::Draining { error, timeout }
                if *timeout <= now =>
            {
                let st = State::Closed(error.clone());
                self.set_state(st, now);
                qinfo!("Closing timer expired");
                return;
            }
            State::Closed(_) => {
                qdebug!("Timer fired while closed");
                return;
            }
            _ => (),
        }

        let pto = self.pto();
        if self.idle_timeout.expired(now, pto) {
            qinfo!("[{self}] idle timeout expired");
            self.set_state(
                State::Closed(CloseReason::Transport(Error::IdleTimeout)),
                now,
            );
            return;
        }

        if self.state.closing() {
            qtrace!("[{self}] Closing, not processing other timers");
            return;
        }

        self.streams.cleanup_closed_streams();

        #[cfg(feature = "mcquic")]
        self.expire_mcquic_resources(now);

        let res = self.crypto.states_mut().check_key_update(now);
        self.absorb_error(now, res);

        if let Some(path) = self.paths.primary() {
            let lost = self
                .loss_recovery
                .timeout(&path, now, self.crypto.has_handshake_keys());
            self.handle_lost_packets(&lost);
            qlog::packets_lost(&mut self.qlog, &lost, now);
        }

        if self.release_resumption_token_timer.is_some() {
            self.create_resumption_token(now);
        }

        if !self
            .paths
            .process_timeout(now, pto, &mut self.stats.borrow_mut())
        {
            qinfo!("[{self}] last available path failed");
            self.absorb_error::<Error>(now, Err(Error::NoAvailablePath));
        }
    }

    /// Whether the given [`ConnectionIdRef`] is a valid local [`ConnectionId`].
    #[must_use]
    pub fn is_valid_local_cid(&self, cid: ConnectionIdRef) -> bool {
        self.cid_manager.is_valid(cid)
    }

    /// Process a new input datagram on the connection.
    pub fn process_input<A: AsRef<[u8]> + AsMut<[u8]>>(&mut self, d: Datagram<A>, now: Instant) {
        self.process_multiple_input(iter::once(d), now);
    }

    /// Process new input datagrams on the connection.
    pub fn process_multiple_input<
        A: AsRef<[u8]> + AsMut<[u8]>,
        I: IntoIterator<Item = Datagram<A>>,
    >(
        &mut self,
        dgrams: I,
        now: Instant,
    ) {
        self.assert_output_resolved();
        let mut dgrams = dgrams.into_iter().peekable();
        if dgrams.peek().is_none() {
            return;
        }

        // Snapshot timer type before ACKs can alter loss state.
        if let Some(path) = self.paths.primary() {
            self.loss_recovery.note_timeout_type(&path.borrow(), now);
        }
        for d in dgrams {
            self.input(d, now, now);
        }
        self.process_saved(now);
        self.streams.cleanup_closed_streams();
    }

    /// Get the time that we next need to be called back, relative to `now`.
    fn next_delay(&mut self, now: Instant, paced: bool) -> Duration {
        qtrace!("[{self}] Get callback delay {now:?}");

        // Only one timer matters when closing...
        if let State::Closing { timeout, .. } | State::Draining { timeout, .. } = self.state {
            self.hrtime.update(Self::LOOSE_TIMER_RESOLUTION);
            return timeout.duration_since(now);
        }

        let mut delays = SmallVec::<[_; 7]>::new();
        if let Some(ack_time) = self.acks.ack_time(now) {
            qtrace!("[{self}] Delayed ACK timer {ack_time:?}");
            delays.push(ack_time);
        }

        if let Some(p) = self.paths.primary() {
            let path = p.borrow();
            let rtt = path.rtt();
            let pto = rtt.pto(self.confirmed());

            let idle_time = self.idle_timeout.expiry(now, pto);
            qtrace!("[{self}] Idle timer {idle_time:?}");
            delays.push(idle_time);

            if self.streams.need_keep_alive()
                && let Some(keep_alive_time) = self.idle_timeout.next_keep_alive(now, pto)
            {
                qtrace!("[{self}] Keep alive timer {keep_alive_time:?}");
                delays.push(keep_alive_time);
            }

            if let Some(lr_time) = self.loss_recovery.next_timeout(&path) {
                qtrace!("[{self}] Loss recovery timer {lr_time:?}");
                delays.push(lr_time);
            }

            if paced && let Some(pace_time) = path.sender().next_paced(rtt.estimate()) {
                qtrace!("[{self}] Pacing timer {pace_time:?}");
                delays.push(pace_time);
            }

            if let Some(path_time) = self.paths.next_timeout(pto) {
                qtrace!("[{self}] Path probe timer {path_time:?}");
                delays.push(path_time);
            }
        }

        if let Some(key_update_time) = self.crypto.states().update_time() {
            qtrace!("[{self}] Key update timer {key_update_time:?}");
            delays.push(key_update_time);
        }

        #[cfg(feature = "mcquic")]
        if let Some(mcquic_expiry) = self.next_mcquic_resource_expiry() {
            delays.push(mcquic_expiry);
        }

        // `release_resumption_token_timer` is not considered here, because
        // it is not important enough to force the application to set a
        // timeout for it  It is expected that other activities will
        // drive it.

        let earliest = delays.into_iter().min().expect("at least one delay");
        // TODO(agrover, mt) - need to analyze and fix #47
        // rather than just clamping to zero here.
        debug_assert!(earliest > now);
        let delay = earliest.saturating_duration_since(now);
        qdebug!("[{self}] delay duration {delay:?}");
        self.hrtime.update(delay / 4);
        delay
    }

    /// Wrapper around [`Connection::process_multiple_output`] that processes a
    /// single output datagram only.
    #[expect(clippy::missing_panics_doc, reason = "see expect()")]
    #[must_use = "Output of the process_output function must be handled"]
    pub fn process_output(&mut self, now: Instant) -> Output {
        self.process_multiple_output(now, 1.try_into().expect(">0"))
            .try_into()
            .expect("max_datagrams is 1")
    }
    /// Get output packets, as a result of receiving packets, or actions taken
    /// by the application.
    /// Returns datagrams to send, and how long to wait before calling again
    /// even if no incoming packets.
    #[must_use = "OutputBatch of the process_multiple_output function must be handled"]
    pub fn process_multiple_output(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        let tracked = match self.process_multiple_output_tracked(now, max_datagrams) {
            Ok(tracked) => tracked,
            Err(error) => return OutputBatch::error(error),
        };
        let segment_count = tracked.segment_count();
        let (output, token) = tracked.into_parts();
        if let Some(mut token) = token
            && let Err(error) = self.resolve_output(&mut token, segment_count, now)
        {
            return OutputBatch::error(error);
        }
        output
    }

    /// Generate output whose send-side effects remain tentative until
    /// [`Self::resolve_output`] records how many UDP/GSO segments were accepted
    /// by the socket.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputPending`] while an earlier tracked batch remains
    /// unresolved.
    pub fn process_multiple_output_tracked(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> Res<TrackedOutputBatch> {
        self.ensure_output_resolved()?;
        qtrace!("[{self}] process_output {:?} {now:?}", self.state);

        match (&self.state, self.role) {
            (State::Init, Role::Client) => {
                let res = self.client_start(now);
                self.absorb_error(now, res);
            }
            (State::Init | State::WaitInitial, Role::Server) => {
                return Ok(TrackedOutputBatch {
                    output: OutputBatch::None,
                    token: None,
                    segment_count: 0,
                });
            }
            _ => {
                self.process_timer(now);
            }
        }

        self.begin_output_transaction()?;
        let generated = match self.output(now, max_datagrams) {
            Ok(generated) => generated,
            Err(OutputGenerationError { path, error }) => {
                self.abandon_building_output()?;
                let _: Option<()> = self
                    .capture_error::<()>(path, now, FrameType::Padding, Err(error))
                    .ok();
                let output = match self.state {
                    State::Init | State::Closed(_) => OutputBatch::None,
                    State::Closing { timeout, .. } | State::Draining { timeout, .. } => {
                        OutputBatch::Callback(timeout.duration_since(now))
                    }
                    _ => OutputBatch::Callback(self.next_delay(now, false)),
                };
                return Ok(TrackedOutputBatch {
                    output,
                    token: None,
                    segment_count: 0,
                });
            }
        };
        match generated {
            SendOptionBatch::Yes(dgram) => {
                let valid = self.output_building.as_ref().is_some_and(|building| {
                    building.current.is_none() && building.segments.len() == dgram.num_datagrams()
                });
                if !valid {
                    self.abandon_building_output()?;
                    return Err(Error::Internal);
                }
                let Some(generation) = self.output_generation.checked_add(1) else {
                    self.abandon_building_output()?;
                    return Err(Error::Internal);
                };
                let building = self.output_building.take().ok_or(Error::Internal)?;
                self.output_generation = generation;
                let segment_count = building.segments.len();
                self.output_pending = Some(PendingOutput {
                    generation,
                    state_signaling: building.state_signaling,
                    segments: building.segments,
                });
                Ok(TrackedOutputBatch {
                    output: OutputBatch::DatagramBatch(dgram),
                    token: Some(OutputToken {
                        connection_id: self.output_connection_id,
                        generation,
                        resolved: false,
                    }),
                    segment_count,
                })
            }
            SendOptionBatch::No(paced) => {
                self.abandon_building_output()?;
                let output = match self.state {
                    State::Init | State::Closed(_) => OutputBatch::None,
                    State::Closing { timeout, .. } | State::Draining { timeout, .. } => {
                        OutputBatch::Callback(timeout.duration_since(now))
                    }
                    _ => OutputBatch::Callback(self.next_delay(now, paced)),
                };
                Ok(TrackedOutputBatch {
                    output,
                    token: None,
                    segment_count: 0,
                })
            }
        }
    }

    /// Resolve a tracked output batch at UDP/GSO segment granularity.
    ///
    /// `accepted_gso_segments` accepts a prefix. Every packet in the remaining
    /// suffix is removed from recovery and its unsent obligations are restored
    /// without declaring network loss.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOutputToken`] for a foreign, stale, duplicate,
    /// or otherwise invalid token, and [`Error::InvalidInput`] for a prefix
    /// longer than the tracked batch.
    ///
    /// # Panics
    ///
    /// Panics only if the validated transaction's private rollback journal is
    /// internally inconsistent.
    #[expect(
        clippy::unwrap_in_result,
        reason = "post-validation transaction invariants must fail closed rather than leave partial state"
    )]
    pub fn resolve_output(
        &mut self,
        token: &mut OutputToken,
        accepted_gso_segments: usize,
        now: Instant,
    ) -> Res<()> {
        if token.resolved {
            return Err(Error::InvalidOutputToken);
        }
        let Some(pending) = self.output_pending.as_ref() else {
            return Err(Error::InvalidOutputToken);
        };
        let token_matches_connection = token.connection_id == self.output_connection_id;
        if !token_matches_connection || token.generation != pending.generation {
            return Err(Error::InvalidOutputToken);
        }
        if accepted_gso_segments > pending.segments.len() {
            return Err(Error::InvalidInput);
        }
        token.resolved = true;

        let qlog_events = self
            .qlog
            .output_transaction_checkpoint()
            .expect("tracked output owns the active qlog transaction");
        assert!(
            pending
                .segments
                .iter()
                .all(|segment| segment.fixed.qlog_events <= qlog_events),
            "tracked output qlog checkpoints remain valid until resolution"
        );

        let pending = self
            .output_pending
            .take()
            .expect("validated tracked output remains pending");
        if accepted_gso_segments == pending.segments.len() {
            let discard_spaces = pending
                .segments
                .iter()
                .flat_map(|segment| segment.discard_spaces.iter().copied())
                .collect::<Vec<_>>();
            let datagram_outputs = pending
                .segments
                .into_iter()
                .map(|segment| segment.quic_datagrams)
                .collect::<Vec<_>>();
            self.qlog
                .finish_output_transaction(true)
                .expect("validated tracked output owns the qlog transaction");
            for datagram_output in datagram_outputs {
                self.commit_quic_datagram_output(datagram_output);
            }
            for space in discard_spaces {
                self.discard_keys(space, now);
            }
            return Ok(());
        }

        let mut segments = pending.segments;
        let discard_spaces = segments[..accepted_gso_segments]
            .iter()
            .flat_map(|segment| segment.discard_spaces.iter().copied())
            .collect::<Vec<_>>();
        let abandoned = segments.split_off(accepted_gso_segments);
        let accepted_path = segments
            .last()
            .map(|segment| Rc::clone(&segment.fixed.path));
        self.rollback_output_segments(
            abandoned,
            (accepted_gso_segments == 0).then_some(pending.state_signaling),
        )
        .expect("validated tracked output can be rolled back");

        if let Some(path) = accepted_path {
            path.borrow_mut()
                .on_datagrams_sent(accepted_gso_segments, &mut self.stats.borrow_mut());
        }
        let datagram_outputs = segments
            .into_iter()
            .map(|segment| segment.quic_datagrams)
            .collect::<Vec<_>>();
        self.qlog
            .finish_output_transaction(true)
            .expect("validated tracked output owns the qlog transaction");
        for datagram_output in datagram_outputs {
            self.commit_quic_datagram_output(datagram_output);
        }
        for space in discard_spaces {
            self.discard_keys(space, now);
        }
        let generation = token.generation;
        qdebug!(
            "[{self}] resolved tracked output generation {generation} with \
             {accepted_gso_segments} accepted segments at {now:?}"
        );
        Ok(())
    }

    /// A test-only output function that uses the provided writer to
    /// pack something extra into the output.
    #[cfg(any(test, feature = "build-fuzzing-corpus"))]
    pub fn test_write_frames<W>(&mut self, writer: W, now: Instant) -> Output
    where
        W: test_internal::FrameWriter + 'static,
    {
        self.assert_output_resolved();
        self.test_frame_writer = Some(Box::new(writer));
        let res = self.process_output(now);
        self.test_frame_writer = None;
        res
    }

    /// Wrapper around [`Connection::process_multiple`], processing a single
    /// input and single output datagram only.
    #[expect(clippy::missing_panics_doc, reason = "see expect()")]
    #[must_use = "Output of the process function must be handled"]
    pub fn process<A: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        dgram: Option<Datagram<A>>,
        now: Instant,
    ) -> Output {
        self.process_multiple(dgram, now, 1.try_into().expect(">0"))
            .try_into()
            .expect("max_datagrams is 1")
    }
    /// Process input and generate output.
    #[must_use = "OutputBatch of the process_multiple function must be handled"]
    pub fn process_multiple<A: AsRef<[u8]> + AsMut<[u8]>>(
        &mut self,
        dgram: Option<Datagram<A>>,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> OutputBatch {
        if let Err(error) = self.ensure_output_resolved() {
            return OutputBatch::error(error);
        }
        if let Some(d) = dgram {
            // Snapshot timer type before ACKs can alter loss state.
            if let Some(path) = self.paths.primary() {
                self.loss_recovery.note_timeout_type(&path.borrow(), now);
            }
            self.input(d, now, now);
            self.process_saved(now);
        }
        let output = self.process_multiple_output(now, max_datagrams);
        #[cfg(feature = "build-fuzzing-corpus")]
        if self.test_frame_writer.is_none()
            && let OutputBatch::DatagramBatch(batch) = &output
        {
            for dgram in batch.iter() {
                neqo_common::write_item_to_fuzzing_corpus("packet", &dgram);
            }
        }
        output
    }

    fn handle_retry(&mut self, packet: &packet::Public, now: Instant) -> Res<()> {
        qinfo!("[{self}] received Retry");
        if matches!(self.address_validation, AddressValidationInfo::Retry { .. }) {
            self.stats.borrow_mut().pkt_dropped("Extra Retry");
            return Ok(());
        }
        if packet.token().is_empty() {
            self.stats.borrow_mut().pkt_dropped("Retry without a token");
            return Ok(());
        }
        if !packet.is_valid_retry(
            self.original_destination_cid
                .as_ref()
                .ok_or(Error::InvalidRetry)?,
        ) {
            self.stats
                .borrow_mut()
                .pkt_dropped("Retry with bad integrity tag");
            return Ok(());
        }
        // At this point, we should only have the connection ID that we generated.
        // Update to the one that the server prefers.
        let Some(path) = self.paths.primary() else {
            self.stats
                .borrow_mut()
                .pkt_dropped("Retry without an existing path");
            return Ok(());
        };

        path.borrow_mut().set_remote_cid(packet.scid());

        let retry_scid = ConnectionId::from(packet.scid());
        qinfo!(
            "[{self}] Valid Retry received, token={} scid={retry_scid}",
            hex(packet.token())
        );

        let lost_packets = self.loss_recovery.retry(&path, now);
        self.handle_lost_packets(&lost_packets);

        self.crypto.states_mut().init(
            self.conn_params.get_versions().compatible(),
            self.role,
            &retry_scid,
            false, // don't randomize on Retry
        )?;
        self.address_validation = AddressValidationInfo::Retry {
            token: packet.token().to_vec(),
            retry_source_cid: retry_scid,
        };
        Ok(())
    }

    fn discard_keys(&mut self, space: PacketNumberSpace, now: Instant) {
        if self.crypto.discard(space) {
            qdebug!("[{self}] Drop packet number space {space}");
            if let Some(path) = self.paths.primary() {
                self.loss_recovery.discard(&path, space, now);
            }
            self.acks.drop_space(space);
        }
    }

    fn is_stateless_reset(&self, path: &PathRef, d: &[u8]) -> bool {
        // If the datagram is too small, don't try.
        // If the connection is connected, then the reset token will be invalid.
        if d.len() < Srt::LEN || !self.state.connected() {
            return false;
        }
        Srt::try_from(&d[d.len() - Srt::LEN..])
            .is_ok_and(|token| path.borrow().is_stateless_reset(&token))
    }

    fn check_stateless_reset(
        &mut self,
        path: &PathRef,
        d: &[u8],
        first: bool,
        now: Instant,
    ) -> Res<()> {
        if first && self.is_stateless_reset(path, d) {
            // Failing to process a packet in a datagram might
            // indicate that there is a stateless reset present.
            qdebug!(
                "[{self}] Stateless reset: {}",
                hex(&d[d.len() - Srt::LEN..])
            );
            self.state_signaling.reset();
            self.set_state(
                State::Draining {
                    error: CloseReason::Transport(Error::StatelessReset),
                    timeout: self.get_closing_period_time(now),
                },
                now,
            );
            Err(Error::StatelessReset)
        } else {
            Ok(())
        }
    }

    /// Process any saved datagrams that might be available for processing.
    fn process_saved(&mut self, now: Instant) {
        while let Some(epoch) = self.saved_datagrams.available() {
            qdebug!("[{self}] process saved for epoch {epoch:?}");
            debug_assert!(
                self.crypto
                    .states_mut()
                    .rx_hp(self.version, epoch)
                    .is_some()
            );
            for saved in self.saved_datagrams.take_saved() {
                qtrace!("[{self}] input saved @{:?}: {:?}", saved.t, saved.d);
                self.input(saved.d, saved.t, now);
            }
        }
    }

    /// In case a datagram arrives that we can only partially process, save any
    /// part that we don't have keys for.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "To consume an owned datagram below."
    )]
    fn save_datagram(
        &mut self,
        epoch: Epoch,
        d: Datagram<impl AsRef<[u8]>>,
        remaining: usize,
        now: Instant,
    ) {
        let d = Datagram::new(
            d.source(),
            d.destination(),
            d.tos(),
            d[d.len() - remaining..].to_vec(),
        );
        self.saved_datagrams.save(epoch, d, now);
        self.stats.borrow_mut().saved_datagrams += 1;
        // We already counted the datagram as received in [`input_path`]. We
        // will do so again when we (re-)process it, so reduce the count now.
        self.stats.borrow_mut().packets_rx -= 1;
    }

    /// Perform version negotiation.
    fn version_negotiation(&mut self, supported: &[version::Wire], now: Instant) -> Res<()> {
        debug_assert_eq!(self.role, Role::Client);

        if let Some(version) = self.conn_params.get_versions().preferred(supported) {
            assert_ne!(self.version, version);

            qinfo!("[{self}] Version negotiation: trying {version:?}");
            let path = self.paths.primary().ok_or(Error::NoAvailablePath)?;
            let local_addr = path.borrow().local_address();
            let remote_addr = path.borrow().remote_address();
            let conn_params = self
                .conn_params
                .clone()
                .versions(version, self.conn_params.get_versions().all().to_vec());
            let mut c = Self::new_client(
                self.crypto.server_name().ok_or(Error::VersionNegotiation)?,
                self.crypto.protocols(),
                self.cid_manager.generator(),
                local_addr,
                remote_addr,
                conn_params,
                now,
            )?;
            c.conn_params
                .get_versions_mut()
                .set_initial(self.conn_params.get_versions().initial());
            mem::swap(self, &mut c);
            qlog::client_version_information_negotiated(
                &mut self.qlog,
                self.conn_params.get_versions().all(),
                supported,
                version,
                now,
            );
            Ok(())
        } else {
            qinfo!("[{self}] Version negotiation: failed with {supported:?}");
            // This error goes straight to closed.
            self.set_state(
                State::Closed(CloseReason::Transport(Error::VersionNegotiation)),
                now,
            );
            Err(Error::VersionNegotiation)
        }
    }

    /// Perform any processing that we might have to do on packets prior to
    /// attempting to remove protection.
    #[expect(clippy::too_many_lines, reason = "Yeah, it's a work in progress.")]
    fn preprocess_packet(
        &mut self,
        packet: &packet::Public,
        path: &PathRef,
        dcid: Option<&ConnectionId>,
        now: Instant,
    ) -> Res<PreprocessResult> {
        if dcid.is_some_and(|d| d != &packet.dcid()) {
            self.stats
                .borrow_mut()
                .pkt_dropped("Coalesced packet has different DCID");
            return Ok(PreprocessResult::Next);
        }

        if (packet.packet_type() == packet::Type::Initial
            || packet.packet_type() == packet::Type::Handshake)
            && self.role == Role::Client
            && !path.borrow().is_primary()
        {
            // If we have received a packet from a different address than we
            // have sent to we should ignore the packet. In such a case a path
            // will be a newly created temporary path, not the primary path.
            return Ok(PreprocessResult::Next);
        }

        match(packet.packet_type(), &self.state, &self.role) {
            (packet::Type::Initial, State::Init, Role::Server) => {
              let version = packet.version().ok_or(Error::ProtocolViolation) ? ;
              if !packet
                .is_valid_initial() ||
                    !self.conn_params.get_versions().all().contains(&version) {
                  self.stats.borrow_mut().pkt_dropped("Invalid Initial");
                  return Ok(PreprocessResult::Next);
                }
              qinfo !(
                  "[{self}] Received valid Initial packet with scid {:?} dcid {:?}",
                  packet.scid(), packet.dcid());
              // Record the client's selected CID so that it can be accepted
              // until the client starts using a real connection ID.
              let dcid = ConnectionId::from(packet.dcid());
              self.crypto.states_mut().init_server(
                  version, &dcid,
                  self.conn_params.randomize_first_pn_enabled(), )
                  ? ;
              self.original_destination_cid = Some(dcid);
              self.set_state(State::WaitInitial, now);

              // We need to make sure that we set this transport parameter.
              // This has to happen prior to processing the packet so that
              // the TLS handshake has all it needs.
              if !self
                .retry_sent() {
                  self.tps.borrow_mut().local_mut().set_bytes(
                      OriginalDestinationConnectionId, packet.dcid().to_vec());
                }
            }
            (packet::Type::VersionNegotiation, State::WaitInitial,
             Role::Client) => {
              if let
                Ok(versions) = packet.supported_versions() {
                  if versions
                    .is_empty() ||
                        versions.contains(&self.version().wire_version()) ||
                        versions.contains(&0) ||
                        &packet.scid() != self.odcid().ok_or(Error::Internal)
                        ? || matches !(self.address_validation,
                                       AddressValidationInfo::Retry{..}) {
                      // Ignore VersionNegotiation packets that contain the
                      // current version. Or don't have the right connection ID.
                      // Or are received after a Retry.
                      self.stats.borrow_mut().pkt_dropped("Invalid VN");
                    }
                  else {
                    self.version_negotiation(&versions, now) ? ;
                  }
                }
              else {
                self.stats.borrow_mut().pkt_dropped("VN with no versions");
              }
              return Ok(PreprocessResult::End);
            }
            (packet::Type::Retry, State::WaitInitial, Role::Client) => {
              self.handle_retry(packet, now) ? ;
              return Ok(PreprocessResult::Next);
            }
            (packet::Type::Handshake | packet::Type::Short, State::WaitInitial,
             Role::Client)
                // This packet can't be processed now, but it could be a sign
                // that Initial packets were lost.
                // Resend Initial CRYPTO frames immediately a few times just
                // in case.  As we don't have an RTT estimate yet, this helps
                // when there is a short RTT and losses. Also mark all 0-RTT
                // data as lost.
                if dcid.is_none() &&
                self.cid_manager.is_valid(packet.dcid()) &&
                !self.saved_datagrams.is_either_full() => {
              qtrace !(
                  "Resending Initial in response to an undecryptable packet");
              self.crypto.resend_unacked(PacketNumberSpace::Initial);
              self.resend_0rtt(now);
            }
            (packet::Type::VersionNegotiation | packet::Type::Retry |
                 packet::Type::OtherVersion,
             .., ) => {
              self.stats.borrow_mut().pkt_dropped(
                  format !("{:?}", packet.packet_type()));
              return Ok(PreprocessResult::Next);
            }
            _ => {}
          }

        let res = match self.state {
            State::Init => {
                self.stats
                    .borrow_mut()
                    .pkt_dropped("Received while in Init state");
                PreprocessResult::Next
            }
            State::WaitInitial => PreprocessResult::Continue,
            State::WaitVersion | State::Handshaking | State::Connected | State::Confirmed => {
                if self.cid_manager.is_valid(packet.dcid()) {
                    if self.role == Role::Server && packet.packet_type() == packet::Type::Handshake
                    {
                        // Server has received a Handshake packet -> discard Initial
                        // keys and states
                        self.discard_keys(PacketNumberSpace::Initial, now);
                    }
                    PreprocessResult::Continue
                } else {
                    self.stats
                        .borrow_mut()
                        .pkt_dropped(format!("Invalid DCID {:?}", packet.dcid()));
                    PreprocessResult::Next
                }
            }
            State::Closing { .. } => {
                // Don't bother processing the packet. Instead ask to get a
                // new close frame.
                //
                // > In the closing state, an endpoint retains only enough
                // > information to generate a packet containing a
                // > CONNECTION_CLOSE frame and to identify packets as belonging
                // > to the connection. An endpoint in the closing state sends a
                // > packet containing a CONNECTION_CLOSE frame in response to any
                // > incoming packet that it attributes to the connection.
                //
                // <https://www.rfc-editor.org/rfc/rfc9000.html#section-10.2.1-2>
                self.state_signaling.send_close();
                PreprocessResult::Next
            }
            State::Draining { .. } | State::Closed(..) => {
                // Do nothing.
                self.stats
                    .borrow_mut()
                    .pkt_dropped(format!("State {:?}", self.state));
                PreprocessResult::Next
            }
        };
        Ok(res)
    }

    /// After a Initial, Handshake, `ZeroRtt`, or Short packet is
    /// successfully processed.
    #[expect(clippy::too_many_arguments, reason = "Yes, but they're needed.")]
    fn postprocess_packet(
        &mut self,
        path: &PathRef,
        tos: Tos,
        remote: SocketAddr,
        packet: &packet::Decrypted,
        packet_number: packet::Number,
        migrate: bool,
        now: Instant,
    ) {
        let ecn_mark = Ecn::from(tos);
        let mut stats = self.stats.borrow_mut();
        stats.ecn_rx[packet.packet_type()] += ecn_mark;
        if let Some(last_ecn_mark) = stats.ecn_last_mark.filter(|&last_ecn_mark| {
            last_ecn_mark != ecn_mark && stats.ecn_rx_transition[last_ecn_mark][ecn_mark].is_none()
        }) {
            stats.ecn_rx_transition[last_ecn_mark][ecn_mark] =
                Some((packet.packet_type(), packet_number));
        }

        stats.ecn_last_mark = Some(ecn_mark);
        drop(stats);
        let space = PacketNumberSpace::from(packet.packet_type());
        if let Some(space) = self.acks.get_mut(space) {
            *space.ecn_marks() += ecn_mark;
        } else {
            qtrace!("Not tracking ECN for dropped packet number space");
        }

        if self.state == State::WaitInitial {
            self.start_handshake(path, packet, now);
        }

        if matches!(self.state, State::WaitInitial | State::WaitVersion) {
            let new_state = if self.has_version() {
                State::Handshaking
            } else {
                State::WaitVersion
            };
            self.set_state(new_state, now);
            if self.role == Role::Server && self.state == State::Handshaking {
                self.zero_rtt_state =
                    if self.crypto.enable_0rtt(self.version, self.role) == Ok(true) {
                        qdebug!("[{self}] Accepted 0-RTT");
                        ZeroRttState::AcceptedServer
                    } else {
                        ZeroRttState::Rejected
                    };
            }
        }

        if self.state.connected() {
            self.handle_migration(path, remote, migrate, now);
        } else if self.role != Role::Client
            && (packet.packet_type() == packet::Type::Handshake
                || (packet.dcid().len() >= 8 && packet.dcid() == self.local_initial_source_cid))
        {
            // We only allow one path during setup, so apply handshake
            // path validation to this path.
            path.borrow_mut().set_valid(now);
        }

        // Update SCONE signal.
        if let Some(rate) = path.borrow_mut().update_scone(now, packet.scone()) {
            qdebug!("[{self}] SCONE rate updated to {rate:x?}");
            self.events.scone_updated(rate);
        }
    }

    /// Take a datagram as input.  This reports an error if the packet was
    /// bad. This takes two times: when the datagram was received, and the
    /// current time.
    fn input(
        &mut self,
        d: Datagram<impl AsRef<[u8]> + AsMut<[u8]>>,
        received: Instant,
        now: Instant,
    ) {
        // First determine the path.
        let path = self.paths.find_path(
            d.destination(),
            d.source(),
            &self.conn_params,
            now,
            &mut self.stats.borrow_mut(),
        );
        path.borrow_mut().add_received(d.len());
        let res = self.input_path(&path, d, received);
        _ = self.capture_error(Some(path), now, FrameType::Padding, res);
    }

    fn input_path(
        &mut self,
        path: &PathRef,
        mut d: Datagram<impl AsRef<[u8]> + AsMut<[u8]>>,
        now: Instant,
    ) -> Res<()> {
        qtrace!("[{self}] {} input {}", path.borrow(), hex(&d));
        let tos = d.tos();
        let remote = d.source();
        let mut slc = d.as_mut();
        let mut dcid = None;
        let pto = path.borrow().rtt().pto(self.confirmed());

        // Handle each packet in the datagram.
        while !slc.is_empty() {
            self.stats.borrow_mut().packets_rx += 1;
            self.stats.borrow_mut().dscp_rx[tos.into()] += 1;
            let slc_len = slc.len();
            let (packet, remainder) =
                match packet::Public::decode(slc, self.cid_manager.decoder().as_ref()) {
                    Ok((packet, remainder)) => {
                        #[cfg(feature = "build-fuzzing-corpus")]
                        neqo_common::write_item_to_fuzzing_corpus("packet", packet.data());
                        (packet, remainder)
                    }
                    Err(e) => {
                        qinfo!("[{self}] Garbage packet: {e}");
                        self.stats.borrow_mut().pkt_dropped("Garbage packet");
                        break;
                    }
                };
            match self.preprocess_packet(&packet, path, dcid.as_ref(), now)? {
                PreprocessResult::Continue => (),
                PreprocessResult::Next => break,
                PreprocessResult::End => return Ok(()),
            }

            qtrace!("[{self}] Received unverified packet {packet:?}");

            let packet_len = packet.len();
            match packet.decrypt(self.crypto.states_mut(), now + pto) {
                Ok(payload) => {
                    // OK, we have a valid packet.
                    let pn = payload.pn();
                    self.idle_timeout.on_packet_received(now);
                    self.log_packet(
                        packet::MetaData::new_in(path, tos, packet_len, &payload, self.version),
                        now,
                    );

                    #[cfg(feature = "build-fuzzing-corpus")]
                    if payload.packet_type() == packet::Type::Initial {
                        let target = if self.role == Role::Client {
                            "server_initial"
                        } else {
                            "client_initial"
                        };
                        neqo_common::write_item_to_fuzzing_corpus(target, &payload[..]);
                    }

                    let space = PacketNumberSpace::from(payload.packet_type());
                    if let Some(space) = self.acks.get_mut(space) {
                        if space.is_duplicate(pn) {
                            qdebug!("Duplicate packet {space}-{pn}");
                            self.stats.borrow_mut().dups_rx += 1;
                        } else {
                            match self.process_packet(path, &payload, now) {
                                Ok(migrate) => {
                                    self.postprocess_packet(
                                        path, tos, remote, &payload, pn, migrate, now,
                                    );
                                }
                                Err(e) => {
                                    self.ensure_error_path(path, &payload, now);
                                    return Err(e);
                                }
                            }
                        }
                    } else {
                        qdebug!(
                            "[{self}] Received packet {space} for untracked space {}",
                            payload.pn()
                        );
                        return Err(Error::ProtocolViolation);
                    }
                    dcid = Some(ConnectionId::from(payload.dcid()));
                }
                Err(e) => {
                    match e.error {
                        Error::KeysPending(epoch) => {
                            // This packet can't be decrypted because we don't have the keys
                            // yet.
                            // Don't check this packet for a stateless reset, just return.
                            let remaining = slc_len;
                            self.save_datagram(epoch, d, remaining, now);
                            return Ok(());
                        }
                        Error::KeysExhausted => {
                            // Exhausting read keys is fatal.
                            return Err(e.error);
                        }
                        Error::KeysDiscarded(epoch) => self.handle_keys_discarded(epoch),
                        _ => (),
                    }
                    // Decryption failure, or not having keys is not fatal.
                    // If the state isn't available, or we can't decrypt the packet, drop
                    // the rest of the datagram on the floor, but don't generate an error.
                    self.check_stateless_reset(path, e.data, dcid.is_none(), now)?;
                    self.stats.borrow_mut().pkt_dropped("Decryption failure");
                    qlog::packet_dropped(&mut self.qlog, &e, now);
                    dcid = Some(e.dcid);
                }
            }
            slc = remainder;
        }
        self.check_stateless_reset(path, &d, dcid.is_none(), now)?;
        Ok(())
    }

    /// Handle receiving a packet for which keys have been discarded.
    fn handle_keys_discarded(&mut self, epoch: Epoch) {
        // Client: receiving undecryptable Initial packets while waiting
        // indicates server's Initial was lost. Probe with Handshake.
        self.received_untracked |= self.role == Role::Client && epoch == Epoch::Initial;

        // Server: receiving undecryptable Handshake packets while Confirmed
        // indicates the client hasn't received HANDSHAKE_DONE. Resend it.
        if self.role == Role::Server && epoch == Epoch::Handshake && self.state == State::Confirmed
        {
            self.state_signaling.handshake_done();
        }
    }

    /// Process a packet.  Returns true if the packet might initiate
    /// migration.
    fn process_packet(
        &mut self,
        path: &PathRef,
        packet: &packet::Decrypted,
        now: Instant,
    ) -> Res<bool> {
        (!packet.is_empty())
            .then_some(())
            .ok_or(Error::ProtocolViolation)?;

        // TODO(ekr@rtfm.com): Have the server blow away the initial
        // crypto state if this fails? Otherwise, we will get a panic
        // on the assert for doesn't exist.
        // OK, we have a valid packet.

        // Get the next packet number we'll send, for ACK verification.
        // This is used by `input_frame` to verify that ACKs don't acknowledge
        // unsent packets.
        let next_pn = self
            .crypto
            .states()
            .select_tx(self.version, PacketNumberSpace::from(packet.packet_type()))
            .map_or(0, |(_, tx)| tx.next_pn());

        let mut ack_eliciting = false;
        let mut probing = true;
        let mut d = Decoder::from(&packet[..]);
        while d.remaining() > 0 {
            #[cfg(feature = "build-fuzzing-corpus")]
            let pos = d.offset();
            #[cfg(feature = "mcquic")]
            let inactive_mcquic = self.role == Role::Client
                && self.mcquic_operation_state != crate::mcquic::OperationState::Active
                && Self::next_frame_is_mcquic(&d);
            let f = match self.decode_frame(&mut d) {
                Ok(frame) => frame,
                #[cfg(feature = "mcquic")]
                Err(error) if inactive_mcquic => {
                    qdebug!("[{self}] ignoring malformed inactive MCQUIC control: {error}");
                    self.decline_pending_mcquic_operation();
                    // The malformed frame has no trustworthy boundary. Do not
                    // ACK this packet and thereby discard any ordinary QUIC
                    // frames that might follow it.
                    return Ok(false);
                }
                Err(error) => return Err(error),
            };
            #[cfg(feature = "build-fuzzing-corpus")]
            neqo_common::write_item_to_fuzzing_corpus("frame", &packet[pos..d.offset()]);
            ack_eliciting |= f.ack_eliciting();
            probing &= f.path_probing();
            let t = f.get_type();
            if let Err(e) = self.input_frame(
                path,
                packet.version(),
                packet.packet_type(),
                f,
                next_pn,
                now,
            ) {
                self.capture_error(Some(Rc::clone(path)), now, t, Err(e))?;
            }
        }

        let largest_received = if let Some(space) = self
            .acks
            .get_mut(PacketNumberSpace::from(packet.packet_type()))
        {
            space.set_received(
                now,
                packet.pn(),
                ack_eliciting,
                &mut self.stats.borrow_mut(),
            )?
        } else {
            qdebug!(
                "[{self}] processed a {:?} packet without tracking it",
                packet.packet_type(),
            );
            // This was a valid packet that caused the same packet number to be
            // discarded.  This happens when the client discards the Initial
            // packet number space after receiving the ServerHello.  Remember
            // this so that we guarantee that we send a Handshake packet.
            self.received_untracked = true;
            // We don't migrate during the handshake, so return false.
            false
        };

        Ok(largest_received && !probing)
    }

    #[cfg(not(feature = "mcquic"))]
    fn decode_frame<'a>(&self, dec: &mut Decoder<'a>) -> Res<Frame<'a>> {
        Frame::decode(dec)
    }

    #[cfg(feature = "mcquic")]
    fn next_frame_is_mcquic(dec: &Decoder) -> bool {
        let mut peek = Decoder::from(dec.as_ref());
        peek.decode_varint()
            .is_some_and(crate::mcquic::is_frame_type)
    }

    #[cfg(feature = "mcquic")]
    fn decode_frame<'a>(&self, dec: &mut Decoder<'a>) -> Res<Frame<'a>> {
        let mut peek = Decoder::from(dec.as_ref());
        let frame_type_start = peek.offset();
        let frame_type = peek.decode_varint().ok_or(Error::NoMoreData)?;

        if Encoder::varint_len(frame_type) != peek.offset() - frame_type_start {
            return Err(Error::ProtocolViolation);
        }

        if !crate::mcquic::is_frame_type(frame_type) {
            return Frame::decode(dec);
        }

        let frame_type_start = dec.offset();
        let decoded_frame_type = dec.decode_varint().ok_or(Error::NoMoreData)?;
        debug_assert_eq!(decoded_frame_type, frame_type);
        if Encoder::varint_len(decoded_frame_type) != dec.offset() - frame_type_start {
            return Err(Error::ProtocolViolation);
        }

        let integrity_hash_len = self.mcquic_integrity_hash_len_for_frame(frame_type, dec)?;
        crate::mcquic::Frame::decode_payload(frame_type, dec, integrity_hash_len).map(Frame::Mcquic)
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_integrity_hash_len_for_frame(
        &self,
        frame_type: u64,
        dec: &Decoder,
    ) -> Res<Option<usize>> {
        if frame_type != crate::mcquic::FRAME_TYPE_INTEGRITY_WITH_LENGTH {
            return Ok(None);
        }

        let mut peek = Decoder::from(dec.as_ref());
        let channel_id_len = peek.decode_uint::<u8>().ok_or(Error::NoMoreData)?;
        let channel_id = peek
            .decode(usize::from(channel_id_len))
            .ok_or(Error::NoMoreData)?;

        if let Some(hash_len) = self.mcquic_integrity_hash_lens.get(channel_id) {
            return Ok(Some(*hash_len));
        }

        self.mcquic_pending_operation_controls
            .iter()
            .rev()
            .find_map(|frame| match frame {
                crate::mcquic::Frame::Announce(announce) if announce.channel_id == channel_id => {
                    Some(crate::mcquic::integrity_hash_len_from_id(
                        announce.integrity_hash_algorithm,
                    ))
                }
                _ => None,
            })
            .transpose()
    }

    /// During connection setup, the first path needs to be setup.
    /// This uses the connection IDs that were provided during the handshake
    /// to setup that path.
    fn setup_handshake_path(&mut self, path: &PathRef, now: Instant) {
        self.paths.make_permanent(
            path,
            Some(self.local_initial_source_cid.clone()),
            // Ideally we know what the peer wants us to use for the remote CID.
            // But we will use our own guess if necessary.
            ConnectionIdEntry::initial_remote(
                self.remote_initial_source_cid
                    .as_ref()
                    .or(self.original_destination_cid.as_ref())
                    .expect("have either remote_initial_source_cid or original_destination_cid")
                    .clone(),
            ),
            now,
        );
        if self.role == Role::Client {
            path.borrow_mut().set_valid(now);
        }
    }

    /// If the path isn't permanent, assign it a connection ID to make it so.
    fn ensure_permanent(&mut self, path: &PathRef, now: Instant) -> Res<()> {
        if self.paths.is_temporary(path) {
            // If there isn't a connection ID to use for this path, the packet
            // will be processed, but it won't be attributed to a path.  That
            // means no path probes or PATH_RESPONSE.  But it's not fatal.
            match self.cids.next() {
                Some(cid) => {
                    self.paths.make_permanent(path, None, cid, now);
                    Ok(())
                }
                None => {
                    if let Some(primary) = self.paths.primary() {
                        if primary.borrow().remote_cid().is_none_or(|id| id.is_empty()) {
                            self.paths.make_permanent(
                                path,
                                None,
                                ConnectionIdEntry::empty_remote(),
                                now,
                            );
                            Ok(())
                        } else {
                            qtrace!("[{self}] Unable to make path permanent: {}", path.borrow());
                            Err(Error::InvalidMigration)
                        }
                    } else {
                        qtrace!("[{self}] Unable to make path permanent: {}", path.borrow());
                        Err(Error::InvalidMigration)
                    }
                }
            }
        } else {
            Ok(())
        }
    }

    /// After an error, a permanent path is needed to send the
    /// `CONNECTION_CLOSE`. This attempts to ensure that this exists.  As the
    /// connection is now temporary, there is no reason to do anything special
    /// here.
    fn ensure_error_path(&mut self, path: &PathRef, packet: &packet::Decrypted, now: Instant) {
        path.borrow_mut().set_valid(now);
        if self.paths.is_temporary(path) {
            // First try to fill in handshake details.
            if packet.packet_type() == packet::Type::Initial {
                self.remote_initial_source_cid = Some(ConnectionId::from(packet.scid()));
                self.setup_handshake_path(path, now);
            } else {
                // Otherwise try to get a usable connection ID.
                drop(self.ensure_permanent(path, now));
            }
        }
    }

    fn start_handshake(&mut self, path: &PathRef, packet: &packet::Decrypted, now: Instant) {
        qtrace!("[{self}] starting handshake");
        debug_assert_eq!(packet.packet_type(), packet::Type::Initial);
        self.remote_initial_source_cid = Some(ConnectionId::from(packet.scid()));

        if self.role == Role::Server {
            let Some(original_destination_cid) = self.original_destination_cid.as_ref() else {
                qdebug!("[{self}] No original destination DCID");
                return;
            };
            self.cid_manager.add_odcid(original_destination_cid.clone());
            // Make a path on which to run the handshake.
            self.setup_handshake_path(path, now);
        } else {
            qdebug!("[{self}] Changing to use Server CID={}", packet.scid());
            debug_assert!(path.borrow().is_primary());
            path.borrow_mut().set_remote_cid(packet.scid());
        }
    }

    /// Migrate to the provided path.
    /// Either local or remote address (but not both) may be provided as `None`
    /// to have the address from the current primary path used. If `force` is
    /// true, then migration is immediate. Otherwise, migration occurs after the
    /// path is probed successfully. Either way, the path is probed and will be
    /// abandoned if the probe fails.
    ///
    /// # Errors
    ///
    /// Fails if this is not a client, not confirmed, the peer disabled
    /// connection migration, or there are not enough connection IDs available
    /// to use.
    pub fn migrate(
        &mut self,
        local: Option<SocketAddr>,
        remote: Option<SocketAddr>,
        force: bool,
        now: Instant,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.role != Role::Client {
            return Err(Error::InvalidMigration);
        }
        if !matches!(self.state(), State::Confirmed) {
            return Err(Error::InvalidMigration);
        }
        if self.tps.borrow().remote().get_empty(DisableMigration) {
            return Err(Error::InvalidMigration);
        }

        // Fill in the blanks, using the current primary path.
        if local.is_none() && remote.is_none() {
            // Pointless migration is pointless.
            return Err(Error::InvalidMigration);
        }

        let path = self.paths.primary().ok_or(Error::InvalidMigration)?;
        let local = local.unwrap_or_else(|| path.borrow().local_address());
        let remote = remote.unwrap_or_else(|| path.borrow().remote_address());

        if mem::discriminant(&local.ip()) != mem::discriminant(&remote.ip()) {
            // Can't mix address families.
            return Err(Error::InvalidMigration);
        }
        if local.port() == 0 || remote.ip().is_unspecified() || remote.port() == 0 {
            // All but the local address need to be specified.
            return Err(Error::InvalidMigration);
        }
        if (local.ip().is_loopback() ^ remote.ip().is_loopback()) && !local.ip().is_unspecified() {
            // Block attempts to migrate to a path with loopback on only one end,
            // unless the local address is unspecified.
            return Err(Error::InvalidMigration);
        }

        let path = self.paths.find_path(
            local,
            remote,
            &self.conn_params,
            now,
            &mut self.stats.borrow_mut(),
        );
        self.ensure_permanent(&path, now)?;
        qinfo!(
            "[{self}] Migrate to {} probe {}",
            path.borrow(),
            if force { "now" } else { "after" }
        );
        if self.paths.migrate(
            &path,
            force,
            self.conn_params.ecn_enabled(),
            now,
            &mut self.stats.borrow_mut(),
        ) {
            self.loss_recovery.migrate();
            self.path_migrated(&path);
        }
        Ok(())
    }

    fn path_migrated(&self, path: &PathRef) {
        let p = path.borrow();
        self.events
            .path_migrated(p.local_address(), p.remote_address());
    }

    fn migrate_to_preferred_address(&mut self, now: Instant) -> Res<()> {
        let spa: Option<(tparams::PreferredAddress, ConnectionIdEntry<Srt>)> = if matches!(
            self.conn_params.get_preferred_address(),
            PreferredAddressConfig::Disabled
        ) {
            qdebug!("[{self}] Preferred address is disabled");
            None
        } else {
            self.tps.borrow_mut().remote().get_preferred_address()
        };
        if let Some((addr, cid)) = spa {
            // The connection ID isn't special, so just save it.
            self.cids.add_remote(cid)?;

            // The preferred address doesn't dictate what the local address is, so
            // this has to use the existing address.  So only pay attention to a
            // preferred address from the same family as is currently in use. More
            // thought will be needed to work out how to get addresses from a
            // different family.
            let prev = self
                .paths
                .primary()
                .ok_or(Error::NoAvailablePath)?
                .borrow()
                .remote_address();
            let remote = match prev.ip() {
                IpAddr::V4(_) => addr.ipv4().map(SocketAddr::V4),
                IpAddr::V6(_) => addr.ipv6().map(SocketAddr::V6),
            };

            if let Some(remote) = remote {
                // Ignore preferred address that move to loopback from
                // non-loopback. `migrate` doesn't enforce this rule.
                if !prev.ip().is_loopback() && remote.ip().is_loopback() {
                    qwarn!("[{self}] Ignoring a move to a loopback address: {remote}");
                    return Ok(());
                }

                if self.migrate(None, Some(remote), false, now).is_err() {
                    qwarn!("[{self}] Ignoring bad preferred address: {remote}");
                }
            } else {
                qwarn!("[{self}] Unable to migrate to a different address family");
            }
        } else {
            qdebug!("[{self}] No preferred address to migrate to");
        }
        Ok(())
    }

    fn handle_migration(
        &mut self,
        path: &PathRef,
        remote: SocketAddr,
        migrate: bool,
        now: Instant,
    ) {
        if !migrate {
            return;
        }
        if self.role == Role::Client {
            return;
        }

        if self.ensure_permanent(path, now).is_ok() {
            let was_primary = path.borrow().is_primary();
            self.paths
                .handle_migration(path, remote, now, &mut self.stats.borrow_mut());
            if !was_primary {
                self.path_migrated(path);
            }
        } else {
            qinfo!(
                "[{self}] {} Peer migrated, but no connection ID available",
                path.borrow()
            );
        }
    }

    fn output(
        &mut self,
        now: Instant,
        max_datagrams: NonZeroUsize,
    ) -> Result<SendOptionBatch, OutputGenerationError> {
        qtrace!("[{self}] output {now:?}");
        match &self.state {
            State::Init
            | State::WaitInitial
            | State::WaitVersion
            | State::Handshaking
            | State::Connected
            | State::Confirmed => self.paths.select_path().map_or_else(
                || Ok(SendOptionBatch::default()),
                |path| {
                    self.output_dgram_batch_on_path(&path, now, None, max_datagrams)
                        .map_err(|error| OutputGenerationError {
                            path: Some(path),
                            error,
                        })
                },
            ),
            State::Closing { .. } | State::Draining { .. } | State::Closed(_) => {
                self.state_signaling.close_frame().map_or_else(
                    || Ok(SendOptionBatch::default()),
                    |details| {
                        let path = Rc::clone(details.path());
                        // In some error cases, we will not be able to make a
                        // new, permanent path. For example, if we run out of
                        // connection IDs and the error results from a packet
                        // on a new path, we avoid sending (and the privacy
                        // risk) rather than reuse a connection ID.
                        if path.borrow().is_temporary() {
                            qerror!("[{self}] Attempting to close with a temporary path");
                            Err(OutputGenerationError {
                                path: Some(path),
                                error: Error::Internal,
                            })
                        } else {
                            self.output_dgram_batch_on_path(
                                &path,
                                now,
                                Some(&details),
                                max_datagrams,
                            )
                            .map_err(|error| OutputGenerationError {
                                path: Some(path),
                                error,
                            })
                        }
                    },
                )
            }
        }
    }

    #[expect(clippy::too_many_arguments, reason = "no easy way to simplify")]
    fn build_packet_header<'a>(
        path: &Path,
        epoch: Epoch,
        encoder: Encoder<&'a mut Vec<u8>>,
        tx: &CryptoDxState,
        address_validation: &AddressValidationInfo,
        version: Version,
        grease_quic_bit: bool,
        limit: usize,
        largest_acknowledged: Option<packet::Number>,
    ) -> (
        packet::Type,
        packet::Builder<&'a mut Vec<u8>>,
        packet::Number,
    ) {
        let pt = packet::Type::from(epoch);
        let mut builder = if pt == packet::Type::Short {
            qdebug!("Building Short dcid {:?}", path.remote_cid());
            packet::Builder::short(encoder, tx.key_phase(), path.remote_cid(), limit)
        } else {
            qdebug!(
                "Building {pt:?} dcid {:?} scid {:?}",
                path.remote_cid(),
                path.local_cid(),
            );
            packet::Builder::long(
                encoder,
                pt,
                version,
                path.remote_cid(),
                path.local_cid(),
                limit,
            )
        };
        if builder.remaining() > 0 {
            builder.scramble(grease_quic_bit);
            if pt == packet::Type::Initial {
                builder.initial_token(address_validation.token());
            }
        }

        let pn = tx.next_pn();
        let unacked_range = largest_acknowledged.map_or_else(|| pn + 1, |la| (pn - la) << 1);
        // Count how many bytes in this range are non-zero.
        let pn_len = size_of::<packet::Number>()
            - usize::try_from(unacked_range.leading_zeros() / 8).expect("u32 fits in usize");
        assert!(
            pn_len > 0,
            "pn_len can't be zero as unacked_range should be > 0, pn {pn}, largest_acknowledged {largest_acknowledged:?}, tx {tx}"
        );
        // TODO(mt) also use `4*path CWND/path MTU` to set a minimum length.
        builder.pn(pn, pn_len);

        (pt, builder, pn)
    }

    fn can_grease_quic_bit(&self) -> bool {
        let tph = self.tps.borrow();
        tph.remote_handshake()
            .as_ref()
            .is_some_and(|r| r.get_empty(GreaseQuicBit))
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_negotiated(&self) -> bool {
        let tph = self.tps.borrow();
        let Some(remote) = tph.remote_handshake() else {
            return false;
        };
        match self.role {
            Role::Client => {
                tph.local().get_mcquic_client_params().is_some()
                    && remote.get_mcquic_server_support()
            }
            Role::Server => {
                tph.local().get_mcquic_server_support()
                    && remote.get_mcquic_client_params().is_some()
            }
        }
    }

    /// Write the frames that are exchanged in the application data space.
    /// The order of calls here determines the relative priority of frames.
    #[expect(
        clippy::too_many_lines,
        reason = "frame priority is expressed by one ordered application-space dispatcher"
    )]
    fn write_appdata_frames(
        &mut self,
        builder: &mut packet::Builder<&mut Vec<u8>>,
        tokens: &mut recovery::Tokens,
        now: Instant,
    ) {
        let rtt = self.paths.primary().map_or_else(
            || RttEstimate::new(self.conn_params.get_initial_rtt()).estimate(),
            |p| p.borrow().rtt().estimate(),
        );

        {
            let stats = &mut self.stats.borrow_mut();
            let frame_stats = &mut stats.frame_tx;
            if self.role == Role::Server
                && let Some(t) = self.state_signaling.write_done(builder)
            {
                tokens.push(t);
                frame_stats.handshake_done += 1;
            }

            self.streams.write_frames_tracked(
                TransmissionPriority::Critical,
                builder,
                tokens,
                frame_stats,
                &mut self
                    .output_building
                    .as_mut()
                    .expect("output transaction active")
                    .current
                    .as_mut()
                    .expect("output segment active")
                    .streams,
            );
            if builder.is_full() {
                return;
            }

            self.streams.write_maintenance_frames_tracked(
                builder,
                tokens,
                frame_stats,
                now,
                rtt,
                &mut self
                    .output_building
                    .as_mut()
                    .expect("output transaction active")
                    .current
                    .as_mut()
                    .expect("output segment active")
                    .streams,
            );
            if builder.is_full() {
                return;
            }

            self.streams.write_frames_tracked(
                TransmissionPriority::Important,
                builder,
                tokens,
                frame_stats,
                &mut self
                    .output_building
                    .as_mut()
                    .expect("output transaction active")
                    .current
                    .as_mut()
                    .expect("output segment active")
                    .streams,
            );
            if builder.is_full() {
                return;
            }

            // NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, and ACK_FREQUENCY.
            self.cid_manager.write_frames(builder, tokens, frame_stats);
            if builder.is_full() {
                return;
            }

            self.paths.write_frames(builder, tokens, frame_stats);
            if builder.is_full() {
                return;
            }

            for prio in [TransmissionPriority::High, TransmissionPriority::Normal] {
                self.streams.write_frames_tracked(
                    prio,
                    builder,
                    tokens,
                    &mut stats.frame_tx,
                    &mut self
                        .output_building
                        .as_mut()
                        .expect("output transaction active")
                        .current
                        .as_mut()
                        .expect("output segment active")
                        .streams,
                );
                if builder.is_full() {
                    return;
                }
            }

            // Datagrams are best-effort and unreliable.  Let streams starve
            // them for now.
            self.quic_datagrams.write_frames(
                builder,
                tokens,
                stats,
                &mut self
                    .output_building
                    .as_mut()
                    .expect("output transaction active")
                    .current
                    .as_mut()
                    .expect("output segment active")
                    .quic_datagrams,
            );
            if builder.is_full() {
                return;
            }
        }

        #[cfg(feature = "mcquic")]
        {
            if self.write_mcquic_frames(builder, tokens) || builder.is_full() {
                return;
            }
        }

        // CRYPTO here only includes NewSessionTicket, plus NEW_TOKEN.
        // Both of these are only used for resumption and so can be relatively low
        // priority.
        let stats = &mut self.stats.borrow_mut();
        let frame_stats = &mut stats.frame_tx;
        self.crypto.write_frame(
            PacketNumberSpace::ApplicationData,
            self.conn_params.sni_slicing_enabled(),
            builder,
            tokens,
            frame_stats,
        );
        if builder.is_full() {
            return;
        }

        self.new_token.write_frames(builder, tokens, frame_stats);
        if builder.is_full() {
            return;
        }

        self.streams.write_frames_tracked(
            TransmissionPriority::Low,
            builder,
            tokens,
            frame_stats,
            &mut self
                .output_building
                .as_mut()
                .expect("output transaction active")
                .current
                .as_mut()
                .expect("output segment active")
                .streams,
        );
    }

    #[cfg(feature = "mcquic")]
    fn write_mcquic_frames(
        &mut self,
        builder: &mut packet::Builder<&mut Vec<u8>>,
        tokens: &mut recovery::Tokens,
    ) -> bool {
        while let Some(queued) = self.mcquic_send.pop_front() {
            let encoded = queued
                .frame
                .to_vec()
                .expect("MCQUIC frames are validated when queued");
            if encoded.len() > builder.remaining() {
                self.mcquic_send.restore_front(queued);
                return false;
            }

            debug_assert_eq!(encoded.len(), queued.encoded_len);
            let requires_packet_end = queued.frame.requires_packet_end();
            builder.encode(&encoded);
            tokens.push(recovery::Token::Mcquic(queued.frame));
            if requires_packet_end {
                return true;
            }
        }
        false
    }

    // Maybe send a probe.  Return true if the packet was ack-eliciting.
    fn maybe_probe<B: Buffer>(
        &mut self,
        path: &PathRef,
        force_probe: bool,
        builder: &mut packet::Builder<B>,
        ack_end: usize,
        tokens: &mut recovery::Tokens,
        now: Instant,
    ) -> bool {
        let untracked = self.received_untracked && !self.state.connected();
        self.received_untracked = false;

        // Anything written after an ACK already elicits acknowledgment.
        // If we need to probe and nothing has been written, send a PING.
        if builder.len() > ack_end {
            return true;
        }

        let pto = path.borrow().rtt().pto(self.confirmed());
        let mut probe = if untracked && builder.packet_empty() || force_probe {
            // If we received an untracked packet and we aren't probing already
            // or the PTO timer fired: probe.
            true
        } else if !builder.packet_empty() {
            // The packet only contains an ACK.  Check whether we want to
            // force an ACK with a PING so we can stop tracking packets.
            self.loss_recovery.should_probe(pto, now)
        } else {
            false
        };

        if self.streams.need_keep_alive() {
            // We need to keep the connection alive, including sending a PING
            // again. If a PING is already scheduled (i.e. `probe` is `true`)
            // piggy back on it. If not, schedule one.
            probe |= self.idle_timeout.send_keep_alive(now, pto, tokens);
        }

        if probe {
            // Nothing ack-eliciting and we need to probe; send PING.
            debug_assert_ne!(builder.remaining(), 0);
            builder.encode_frame(FrameType::Ping, |_| {});
            let stats = &mut self.stats.borrow_mut().frame_tx;
            stats.ping += 1;
        }
        probe
    }

    /// Write frames to the provided builder.  Returns a list of tokens used for
    /// tracking loss or acknowledgment, whether any frame was ACK eliciting,
    /// and whether the packet was padded.
    fn write_frames(
        &mut self,
        path: &PathRef,
        space: PacketNumberSpace,
        profile: &SendProfile,
        builder: &mut packet::Builder<&mut Vec<u8>>,
        coalesced: bool, // Whether this packet is coalesced
        // behind another one.
        now: Instant,
    ) -> (recovery::Tokens, bool, bool) {
        let mut tokens = recovery::Tokens::new();
        let primary = path.borrow().is_primary();
        let mut ack_eliciting = false;

        if primary {
            let stats = &mut self.stats.borrow_mut().frame_tx;
            self.acks.write_frame(
                space,
                now,
                path.borrow().rtt().estimate(),
                builder,
                &mut tokens,
                stats,
            );
        }
        let ack_end = builder.len();

        // Avoid sending path validation probes until the handshake completes,
        // but send them even when we don't have space.
        let full_mtu = profile.limit() == path.borrow().plpmtu();
        if space == PacketNumberSpace::ApplicationData && self.state.connected() {
            // Path validation probes should only be padded if the full MTU is
            // available. The probing code needs to know so it can track that.
            if path.borrow_mut().write_frames(
                builder,
                &mut self.stats.borrow_mut().frame_tx,
                full_mtu,
                now,
            ) {
                builder.enable_padding(true);
            }
        }

        if profile.ack_only() {
            // If we are CC limited we can only send ACKs!
            return (tokens, false, false);
        }

        if primary {
            if space == PacketNumberSpace::ApplicationData {
                if self
              .state.connected() && path.borrow().pmtud().needs_probe() &&
                  !coalesced  // Only send PMTUD probes using non-coalesced
                              // packets.
                  && full_mtu
                {
                    path.borrow_mut().pmtud_mut().send_probe(
                        builder,
                        &mut tokens,
                        &mut self.stats.borrow_mut(),
                    );
                    ack_eliciting = true;
                }
                self.write_appdata_frames(builder, &mut tokens, now);
            } else {
                let stats = &mut self.stats.borrow_mut().frame_tx;
                self.crypto.write_frame(
                    space,
                    self.conn_params.sni_slicing_enabled(),
                    builder,
                    &mut tokens,
                    stats,
                );
            }

            #[cfg(test)]
            if let Some(w) = &mut self.test_frame_writer {
                assert!(!builder.is_full(), "test_frame_writer set on full packet");
                w.write_frames(builder);
            }
        }

        // Maybe send a probe now, either to probe for losses or to keep the
        // connection live.
        let force_probe = profile.should_probe(space);
        ack_eliciting |= self.maybe_probe(path, force_probe, builder, ack_end, &mut tokens, now);
        // If this is not the primary path, this should be ack-eliciting.
        debug_assert!(primary || ack_eliciting);

        // Add padding.  Only pad 1-RTT packets so that we don't prevent
        // coalescing. And avoid padding packets that otherwise only contain ACK
        // because adding PADDING causes those packets to consume congestion
        // window, which is not tracked (yet). And avoid padding if we don't have
        // a full MTU available.
        let stats = &mut self.stats.borrow_mut().frame_tx;
        let padded = if ack_eliciting && full_mtu && builder.pad() {
            stats.padding += 1;
            true
        } else {
            false
        };

        (tokens, ack_eliciting, padded)
    }

    fn write_closing_frames<B: Buffer>(
        &mut self,
        close: &ClosingFrame,
        builder: &mut packet::Builder<B>,
        space: PacketNumberSpace,
        now: Instant,
        path: &PathRef,
        tokens: &mut recovery::Tokens,
    ) {
        if builder.remaining() > ClosingFrame::MIN_LENGTH + RecvdPackets::USEFUL_ACK_LEN {
            // Include an ACK frame with the CONNECTION_CLOSE.
            let limit = builder.limit();
            builder.set_limit(limit - ClosingFrame::MIN_LENGTH);
            self.acks.immediate_ack(space, now);
            self.acks.write_frame(
                space,
                now,
                path.borrow().rtt().estimate(),
                builder,
                tokens,
                &mut self.stats.borrow_mut().frame_tx,
            );
            builder.set_limit(limit);
        }
        // CloseReason::Application is only allowed at 1RTT.
        let sanitized = if space == PacketNumberSpace::ApplicationData {
            None
        } else {
            close.sanitize()
        };
        sanitized.as_ref().unwrap_or(close).write_frame(builder);
        self.stats.borrow_mut().frame_tx.connection_close += 1;
    }

    /// Build batch of datagrams to be sent on the provided path.
    fn output_dgram_batch_on_path(
        &mut self,
        path: &PathRef,
        now: Instant,
        mut closing_frame: Option<&ClosingFrame>,
        max_datagrams: NonZeroUsize,
    ) -> Res<SendOptionBatch> {
        let packet_tos = path.borrow().tos();
        let mut send_buffer = Vec::new();
        let mut max_datagram_size = None;
        let mut num_datagrams = 0;
        let mtu = path.borrow().plpmtu();
        let address_family_max_mtu = path.borrow().pmtud().address_family_max_mtu();

        loop {
            if max_datagrams.get() <= num_datagrams {
                break;
            }
            if path.borrow().pmtud().needs_probe() && num_datagrams != 0 {
                // Next datagram will be larger due to PMTUD probing.  GSO
                // requires that all datagrams in a batch are of equal size.
                // Only the last datagram can be smaller. Given that this would
                // not be the first datagram, close the batch early to uphold
                // the above GSO requirement.
                break;
            }

            let send_buffer_len_before = send_buffer.len();

            // Check if we can fit another PMTUD sized datagram into the batch.
            if max_datagram_size.is_some_and(|datagram_size| {
                // GSO requires that all datagrams in a batch are of equal size.
                // The last datagram can be smaller. The datagrams already in
                // the batch are each `datagram_size` large. The next datagram
                // can be up to `mtu` large. Break in case the next could be
                // larger than the ones already in the batch.
                datagram_size < mtu
               // GSO allows total datagram batch size up to the address family
               // max MTU. If the next datagram could exceed that limit, break.
               //
               // See for example Linux kernel:
               // https://github.com/torvalds/linux/blob/fb4d33ab452ea254e2c319bac5703d1b56d895bf/include/linux/netdevice.h#L2402
               || address_family_max_mtu - send_buffer.len() < mtu
            }) {
                break;
            }

            self.begin_output_segment(path)?;

            let output = self.output_dgram_on_path(
                path,
                now,
                closing_frame.take(),
                Encoder::new_borrowed_vec(&mut send_buffer),
                packet_tos,
            );
            match output {
                Err(error) => {
                    self.rollback_current_output_segment()?;
                    return Err(error);
                }
                Ok(SendOption::Yes) => {
                    self.finish_output_segment()?;
                    debug_assert_eq!(
                        mtu,
                        path.borrow().plpmtu(),
                        "MTU does not change within batch"
                    );
                    num_datagrams += 1;
                    let datagram_size = send_buffer.len() - send_buffer_len_before;
                    let max_datagram_size = *max_datagram_size.get_or_insert(datagram_size);

                    // GSO requires that all datagrams in a batch are of equal
                    // size. Only the last datagram can be smaller.
                    debug_assert!(datagram_size <= max_datagram_size);
                    if datagram_size < max_datagram_size {
                        // This packet was smaller. Make sure it is the last by
                        // breaking the loop.
                        break;
                    }
                }
                Ok(SendOption::No(paced)) => {
                    let datagram_output = self.take_current_quic_datagram_output()?;
                    self.rollback_current_output_segment()?;
                    if num_datagrams == 0 {
                        debug_assert!(send_buffer.is_empty());
                        self.commit_quic_datagram_output(datagram_output);
                        return Ok(SendOptionBatch::No(paced));
                    }
                    self.output_building
                        .as_mut()
                        .and_then(|building| building.segments.last_mut())
                        .ok_or(Error::Internal)?
                        .quic_datagrams
                        .append(datagram_output);
                    break;
                }
            }
        }

        debug_assert!(!send_buffer.is_empty());
        let batch = path.borrow_mut().datagram_batch(
            send_buffer,
            packet_tos,
            num_datagrams,
            max_datagram_size.ok_or(Error::Internal)?,
            &mut self.stats.borrow_mut(),
        );

        Ok(SendOptionBatch::Yes(batch))
    }

    /// Build a datagram, possibly from multiple packets (for different PN
    /// spaces) and each containing 1+ frames.
    #[expect(clippy::too_many_lines, reason = "Yeah, that's just the way it is.")]
    fn output_dgram_on_path(
        &mut self,
        path: &PathRef,
        now: Instant,
        closing_frame: Option<&ClosingFrame>,
        mut encoder: Encoder<&mut Vec<u8>>,
        packet_tos: Tos,
    ) -> Res<SendOption> {
        let mut initial_sent: Option<sent::Packet> = None;
        let mut needs_padding = false;
        let grease_quic_bit = self.can_grease_quic_bit();
        let version = self.version();

        // Determine how we are sending packets (PTO, etc..).
        let profile = self.loss_recovery.send_profile(&path.borrow(), now);
        qdebug!("[{self}] output_dgram_on_path send_profile {profile:?}");

        // Frames for different epochs must go in different packets, but then
        // these packets can go in a single datagram
        for space in PacketNumberSpace::iter() {
            if self
                .output_building
                .as_ref()
                .is_some_and(|building| building.discard_spaces.contains(space))
            {
                continue;
            }
            // Ensure we have tx crypto state for this epoch, or skip it.
            let Some((epoch, tx)) = self.crypto.states_mut().select_tx_mut(self.version, space)
            else {
                continue;
            };
            let aead_expansion = tx.expansion();

            let header_start = encoder.len();

            // Configure the limits and padding for this packet.
            let limit = if path.borrow().pmtud().needs_probe() {
                needs_padding = true;
                debug_assert!(path.borrow().pmtud().probe_size() >= profile.limit());
                path.borrow().pmtud().probe_size()
            } else {
                profile.limit()
                    - if space == PacketNumberSpace::Initial && self.conn_params.scone_enabled() {
                        // Reserve some space for the SCONE indication in an Initial.
                        // This reduces the amount available for building the packet,
                        // but we'll pad to `profile.limit()` when padding.
                        // This will not reserve space for the indication if packets
                        // are coalesced (with Handshake or 0-RTT). That's too bad.
                        Self::SCONE_INDICATION.len()
                    } else {
                        0
                    }
            } - aead_expansion;

            let (pt, mut builder, pn) = Self::build_packet_header(
                &path.borrow(),
                epoch,
                encoder,
                tx,
                &self.address_validation,
                version,
                grease_quic_bit,
                limit,
                self.loss_recovery.largest_acknowledged_pn(space),
            );
            // The builder will set the limit to 0 if there isn't enough space
            // for the header.
            if builder.is_full() {
                encoder = builder.abort();
                break;
            }

            builder.enable_padding(needs_padding);
            if builder.is_full() {
                encoder = builder.abort();
                break;
            }

            // Add frames to the packet.
            let payload_start = builder.len();
            let (mut tokens, mut ack_eliciting, mut padded) =
                (recovery::Tokens::new(), false, false);
            if let Some(close) = closing_frame {
                self.write_closing_frames(close, &mut builder, space, now, path, &mut tokens);
            } else {
                (tokens, ack_eliciting, padded) =
                    self.write_frames(path, space, &profile, &mut builder, header_start != 0, now);
            }
            if builder.packet_empty() {
                // Nothing to include in this packet.
                encoder = builder.abort();

                continue;
            }

            if packet_tos.is_ecn_marked() {
                tokens.push(recovery::Token::EcnEct0);
            }

            self.log_packet(
                packet::MetaData::new_out(
                    path,
                    pt,
                    pn,
                    builder.len() + aead_expansion,
                    &builder.as_ref()[payload_start..],
                    packet_tos,
                    self.version,
                ),
                now,
            );

            self.stats.borrow_mut().packets_tx += 1;
            // Track which packet types are sent with which ECN codepoints. For
            // coalesced packets, this increases the counts for each packet type
            // contained in the coalesced packet. This is per Section 13.4.1 of
            // RFC 9000.
            self.stats.borrow_mut().ecn_tx[pt] += Ecn::from(packet_tos);
            let tx = self
                .crypto
                .states_mut()
                .tx_mut(self.version, epoch)
                .ok_or(Error::Internal)?;
            encoder = match builder.build(tx) {
                Ok(encoder) => encoder,
                Err(error) => {
                    self.track_unregistered_output_tokens(tokens)?;
                    if let Some(initial) = initial_sent.take() {
                        self.track_unregistered_output_tokens(initial.into_tokens())?;
                    }
                    return Err(error);
                }
            };
            if let Err(error) = self.crypto.states_mut().auto_update() {
                self.track_unregistered_output_tokens(tokens)?;
                if let Some(initial) = initial_sent.take() {
                    self.track_unregistered_output_tokens(initial.into_tokens())?;
                }
                return Err(error);
            }

            if ack_eliciting {
                self.idle_timeout.on_packet_sent(now);
            }
            let sent = sent::Packet::new(
                pt,
                pn,
                now,
                ack_eliciting,
                tokens,
                encoder.len() - header_start,
            );
            if padded {
                needs_padding = false;
                self.track_output_packet(sent, path, now)?;
            } else if pt == packet::Type::Initial && (self.role == Role::Client || ack_eliciting) {
                // Packets containing Initial packets might need padding, and we
                // want to track that padding along with the Initial packet.  So
                // defer tracking.
                initial_sent = Some(sent);
                needs_padding = true;
            } else {
                if pt.is_long() && self.role == Role::Client && initial_sent.is_none() {
                    // Disable padding for any long header packet if the UDP
                    // packet doesn't include an Initial packet.
                    needs_padding = false;
                }
                self.track_output_packet(sent, path, now)?;
            }

            if space == PacketNumberSpace::Handshake {
                if self.role == Role::Client {
                    // We're sending a Handshake packet, so we can discard
                    // Initial keys after the containing UDP segment is accepted.
                    self.defer_discard_keys(PacketNumberSpace::Initial)?;
                } else if self.role == Role::Server && self.state == State::Confirmed {
                    // We could discard handshake keys in set_state,
                    // but wait until after sending an ACK.
                    self.defer_discard_keys(PacketNumberSpace::Handshake)?;
                }
            }

            // If the client has more CRYPTO data queued up, do not coalesce if
            // this packet is an Initial. Without this, 0-RTT packets could be
            // coalesced with the first Initial, which some server (e.g., ours)
            // do not support, because they may not save packets they can't
            // decrypt yet.
            if self.role == Role::Client
                && space == PacketNumberSpace::Initial
                && !self.crypto.streams_mut().is_empty(space)
            {
                break;
            }
        }

        if encoder.is_empty() {
            qdebug!("TX blocked, profile={profile:?}");
            Ok(SendOption::No(profile.paced()))
        } else {
            // Perform additional padding for Initial packets as necessary.
            if let Some(mut initial) = initial_sent.take() {
                if needs_padding {
                    self.pad_initial(&mut encoder, &mut initial, &profile);
                }
                self.track_output_packet(initial, path, now)?;
            }
            path.borrow_mut().add_sent(encoder.len());
            Ok(SendOption::Yes)
        }
    }

    fn pad_initial(
        &self,
        encoder: &mut Encoder<&mut Vec<u8>>,
        initial: &mut sent::Packet,
        profile: &SendProfile,
    ) {
        if encoder.len() >= profile.limit() {
            return;
        }

        qdebug!(
            "[{self}] pad Initial from {} to {}",
            encoder.len(),
            profile.limit()
        );
        let pad_amount = profile.limit() - encoder.len();
        initial.track_padding(pad_amount);
        if self.conn_params.scone_enabled() {
            // This ensures that the last bytes are a SCONE indication, if there
            // is enough space. This is not tracked, other than for congestion
            // control (above)
            if pad_amount >= Self::SCONE_INDICATION.len() {
                encoder.pad_to(
                    profile.limit() - Self::SCONE_INDICATION.len() + 1,
                    Self::SCONE_INDICATION[0],
                );
                encoder.encode(&Self::SCONE_INDICATION[1..]);
            } else {
                encoder.pad_to(profile.limit(), Self::SCONE_INDICATION[0]);
            }
        } else {
            encoder.pad_to(profile.limit(), 0);
        }
    }

    /// # Errors
    /// When connection state is not valid.
    pub fn initiate_key_update(&mut self) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.state == State::Confirmed {
            let la = self
                .loss_recovery
                .largest_acknowledged_pn(PacketNumberSpace::ApplicationData);
            qinfo!("[{self}] Initiating key update");
            self.crypto.states_mut().initiate_key_update(la)
        } else {
            Err(Error::KeyUpdateBlocked)
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn get_epochs(&self) -> (Option<usize>, Option<usize>) {
        self.crypto.states().get_epochs()
    }

    fn client_start(&mut self, now: Instant) -> Res<()> {
        qdebug!("[{self}] client_start");
        debug_assert_eq!(self.role, Role::Client);
        if let Some(path) = self.paths.primary() {
            qlog::client_connection_started(&mut self.qlog, &path, now);
            qlog::recovery_parameters_set(
                &mut self.qlog,
                path.borrow().plpmtu(),
                self.conn_params.get_congestion_control(),
                now,
            );
            qlog::congestion_state_updated(
                &mut self.qlog,
                None,
                Phase::SlowStart.into(),
                None,
                now,
            );
        }
        qlog::client_version_information_initiated(
            &mut self.qlog,
            self.conn_params.get_versions(),
            now,
        );

        self.handshake(now, self.version, PacketNumberSpace::Initial, None)?;
        self.set_state(State::WaitInitial, now);
        self.zero_rtt_state = if self.crypto.enable_0rtt(self.version, self.role)? {
            qdebug!("[{self}] Enabled 0-RTT");
            ZeroRttState::Sending
        } else {
            ZeroRttState::Init
        };
        Ok(())
    }

    fn get_closing_period_time(&self, now: Instant) -> Instant {
        // Spec says close time should be at least PTO times 3.
        now + (self.pto() * 3)
    }

    /// Close the connection.
    pub fn close<A: AsRef<str>>(&mut self, now: Instant, app_error: AppError, msg: A) {
        self.assert_output_resolved();
        let error = CloseReason::Application(app_error);
        let timeout = self.get_closing_period_time(now);
        match self.paths.primary() {
            Some(path) => {
                self.state_signaling
                    .close(path, error.clone(), FrameType::Padding, msg);
                self.set_state(State::Closing { error, timeout }, now);
            }
            None => {
                self.set_state(State::Closed(error), now);
            }
        }
    }

    fn set_initial_limits(&mut self) {
        self.streams.set_initial_limits();
        let peer_timeout = self
            .tps
            .borrow()
            .remote()
            .get_integer(TransportParameterId::IdleTimeout);
        if peer_timeout > 0 {
            self.idle_timeout
                .set_peer_timeout(Duration::from_millis(peer_timeout));
        }

        self.quic_datagrams
            .set_remote_datagram_size(self.tps.borrow().remote().get_integer(MaxDatagramFrameSize));
    }

    #[must_use]
    pub fn is_stream_id_allowed(&self, stream_id: StreamId) -> bool {
        self.streams.is_stream_id_allowed(stream_id)
    }

    /// Process the final set of transport parameters.
    fn process_tps(&mut self, now: Instant) -> Res<()> {
        self.validate_cids()?;
        self.validate_versions()?;
        {
            let tps = self.tps.borrow();
            let remote = tps.remote_handshake().ok_or(Error::TransportParameter)?;

            // If the peer provided a preferred address, then we have to be a client
            // and they have to be using a non-empty connection ID.
            if remote.get_preferred_address().is_some()
                && (self.role == Role::Server
                    || self
                        .remote_initial_source_cid
                        .as_ref()
                        .ok_or(Error::UnknownConnectionId)?
                        .is_empty())
            {
                return Err(Error::TransportParameter);
            }

            let reset_token = remote.get_bytes(StatelessResetToken).map_or_else(
                || Ok(Srt::random()),
                |token| Srt::try_from(token).map_err(|_| Error::TransportParameter),
            )?;
            let path = self.paths.primary().ok_or(Error::NoAvailablePath)?;
            path.borrow_mut().set_reset_token(reset_token);

            if let Ok(max_udp_payload) = usize::try_from(remote.get_integer(MaxUdpPayloadSize)) {
                path.borrow_mut()
                    .pmtud_mut()
                    .set_peer_max_udp_payload(max_udp_payload);
                self.stats.borrow_mut().pmtud_peer_max_udp_payload = Some(max_udp_payload);
            }

            let max_ad = Duration::from_millis(remote.get_integer(MaxAckDelay));
            let min_ad = if remote.has_value(MinAckDelay) {
                let min_ad = Duration::from_micros(remote.get_integer(MinAckDelay));
                if min_ad > max_ad {
                    return Err(Error::TransportParameter);
                }
                Some(min_ad)
            } else {
                None
            };
            path.borrow_mut()
                .set_ack_delay(max_ad, min_ad, self.conn_params.get_ack_ratio());

            let max_active_cids = remote.get_integer(ActiveConnectionIdLimit);
            self.cid_manager.set_limit(max_active_cids);
        }
        self.set_initial_limits();
        qlog::connection_tparams_set(&mut self.qlog, &self.tps.borrow(), now);
        Ok(())
    }

    fn validate_cids(&self) -> Res<()> {
        let tph = self.tps.borrow();
        let remote_tps = tph.remote_handshake().ok_or(Error::TransportParameter)?;

        let tp = remote_tps.get_bytes(InitialSourceConnectionId);
        if self
            .remote_initial_source_cid
            .as_ref()
            .map(ConnectionId::as_cid_ref)
            != tp.map(ConnectionIdRef::from)
        {
            qwarn!(
                "[{self}] ISCID test failed: self cid {:?} != tp cid {:?}",
                self.remote_initial_source_cid,
                tp.map(hex),
            );
            return Err(Error::ProtocolViolation);
        }

        if self.role == Role::Client {
            let tp = remote_tps.get_bytes(OriginalDestinationConnectionId);
            if self
                .original_destination_cid
                .as_ref()
                .map(ConnectionId::as_cid_ref)
                != tp.map(ConnectionIdRef::from)
            {
                qwarn!(
                    "[{self}] ODCID test failed: self cid {:?} != tp cid {:?}",
                    self.original_destination_cid,
                    tp.map(hex),
                );
                return Err(Error::ProtocolViolation);
            }

            let tp = remote_tps.get_bytes(RetrySourceConnectionId);
            let expected = if let AddressValidationInfo::Retry {
                retry_source_cid, ..
            } = &self.address_validation
            {
                Some(retry_source_cid.as_cid_ref())
            } else {
                None
            };
            if expected != tp.map(ConnectionIdRef::from) {
                qwarn!(
                    "[{self}] RSCID test failed. self cid {expected:?} != tp cid {:?}",
                    tp.map(hex),
                );
                return Err(Error::ProtocolViolation);
            }
        }

        Ok(())
    }

    /// Validate the `version_negotiation` transport parameter from the peer.
    fn validate_versions(&self) -> Res<()> {
        let tph = self.tps.borrow();
        let remote_tps = tph.remote_handshake().ok_or(Error::TransportParameter)?;
        // `current` and `other` are the value from the peer's transport
        // parameters. We're checking that these match our expectations.
        if let Some((current, other)) = remote_tps.get_versions() {
            qtrace!(
                "[{self}] validate_versions: current={:x} chosen={current:x} other={other:x?}",
                self.version.wire_version(),
            );
            if self.role == Role::Server {
                // 1. A server acts on transport parameters, with validation
                // of `current` happening in the transport parameter handler.
                // All we need to do is confirm that the transport parameter
                // was provided.
                Ok(())
            } else if self.version().wire_version() != current {
                qinfo!("[{self}] validate_versions: current version mismatch");
                Err(Error::VersionNegotiation)
            } else if self
                .conn_params
                .get_versions()
                .initial()
                .is_compatible(self.version)
            {
                // 2. The current version is compatible with what we attempted.
                // That's a compatible upgrade and that's OK.
                Ok(())
            } else {
                // 3. The initial version we attempted isn't compatible.  Check that
                // the one we would have chosen is compatible with this one.
                let mut all_versions = other.to_owned();
                all_versions.push(current);
                if self
                    .conn_params
                    .get_versions()
                    .preferred(&all_versions)
                    .ok_or(Error::VersionNegotiation)?
                    .is_compatible(self.version)
                {
                    Ok(())
                } else {
                    qinfo!("[{self}] validate_versions: failed");
                    Err(Error::VersionNegotiation)
                }
            }
        } else if self.version != Version::Version1 && !self.version.is_draft() {
            qinfo!("[{self}] validate_versions: missing extension");
            Err(Error::VersionNegotiation)
        } else {
            Ok(())
        }
    }

    const fn has_version(&self) -> bool {
        self.crypto.has_handshake_keys()
    }

    /// Commit to a particular version.
    fn compatible_upgrade(&mut self, packet_version: Version) -> Res<()> {
        if !matches!(self.state, State::WaitInitial | State::WaitVersion) {
            return Ok(());
        }

        let v = if self.role == Role::Client {
            packet_version
        } else {
            let version = self.tps.borrow().version();
            let dcid = self
                .original_destination_cid
                .as_ref()
                .ok_or(Error::ProtocolViolation)?;
            // No need to randomize the starting packet number; that's already taken
            // care of.
            self.crypto.states_mut().init_server(version, dcid, false)?;
            version
        };

        // OK, it's all confirmed.
        if self.version != v {
            qdebug!("[{self}] Compatible upgrade {:?} ==> {v:?}", self.version);
            self.version = v;
        }
        self.crypto.confirm_version(v)?;
        Ok(())
    }

    fn handshake(
        &mut self,
        now: Instant,
        packet_version: Version,
        space: PacketNumberSpace,
        data: Option<&[u8]>,
    ) -> Res<()> {
        qtrace!(
            "[{self}] Handshake space={space} data: {:?}",
            data.as_ref().map(hex_with_len),
        );

        let was_authentication_pending =
            *self.crypto.tls().state() == HandshakeState::AuthenticationPending;
        let try_update = data.is_some();
        match self.crypto.handshake(now, space, data)? {
            HandshakeState::Authenticated(_) | HandshakeState::InProgress => (),
            HandshakeState::AuthenticationPending => {
                if !was_authentication_pending {
                    self.events.authentication_needed();
                }
            }
            HandshakeState::EchFallbackAuthenticationPending(public_name) => self
                .events
                .ech_fallback_authentication_needed(public_name.clone()),
            HandshakeState::Complete(_) => {
                if !self.state.connected() {
                    self.set_connected(now)?;
                }
            }
            _ => {
                qerror!("Crypto state should not be new or failed after successful handshake");
                return Err(Error::Crypto(nss::Error::Internal));
            }
        }

        // There is a chance that this could be called less often, but getting the
        // conditions right is a little tricky, so call whenever CRYPTO data is
        // used.
        if try_update {
            // We have transport parameters, it's go time.
            if self.tps.borrow().remote_handshake().is_some() {
                self.set_initial_limits();
            }
            if self.crypto.tls().has_secret(Epoch::Handshake) {
                self.compatible_upgrade(packet_version)?;
            }
            if self.crypto.install_keys(self.role)? {
                self.saved_datagrams.make_available(Epoch::Handshake);
            }
        }

        Ok(())
    }

    fn set_confirmed(&mut self, now: Instant) -> Res<()> {
        self.set_state(State::Confirmed, now);
        if self.conn_params.pmtud_enabled() {
            self.paths
                .primary()
                .ok_or(Error::Internal)?
                .borrow_mut()
                .pmtud_mut()
                .start(now, &mut self.stats.borrow_mut());
        }
        if self.conn_params.ecn_enabled() {
            self.paths.start_ecn(&mut self.stats.borrow_mut());
        }
        Ok(())
    }

    #[expect(clippy::too_many_lines, reason = "Yep, but it's a nice big match.")]
    fn input_frame(
        &mut self,
        path: &PathRef,
        packet_version: Version,
        packet_type: packet::Type,
        frame: Frame,
        next_pn: packet::Number,
        now: Instant,
    ) -> Res<()> {
        if !frame.is_allowed(packet_type) {
            qinfo!("frame not allowed: {frame:?} {packet_type:?}");
            return Err(Error::ProtocolViolation);
        }
        let space = PacketNumberSpace::from(packet_type);
        if frame.is_stream() {
            return self
                .streams
                .input_frame(&frame, &mut self.stats.borrow_mut().frame_rx);
        }
        match frame {
            Frame::Padding(length) => {
                self.stats.borrow_mut().frame_rx.padding += usize::from(length);
            }
            Frame::Ping => {
                // If we get a PING and there are outstanding CRYPTO frames,
                // prepare to resend them.
                self.stats.borrow_mut().frame_rx.ping += 1;
                self.crypto.resend_unacked(space);
                // Send an ACK immediately if we might not otherwise do so.
                self.acks.immediate_ack(space, now);
            }
            Frame::Ack {
                largest_acknowledged,
                ack_delay,
                first_ack_range,
                ack_ranges,
                ecn_count,
            } => {
                // Ensure that the largest acknowledged packet number was actually sent.
                // (If we ever start using non-contiguous packet numbers, we need to check
                // all the packet numbers in the ACKed ranges.)
                if largest_acknowledged >= next_pn {
                    qwarn!("Largest ACKed {largest_acknowledged} was never sent");
                    return Err(Error::AckedUnsentPacket);
                }

                let ranges =
                    Frame::decode_ack_frame(largest_acknowledged, first_ack_range, &ack_ranges)?;
                self.handle_ack(space, ranges, ecn_count.as_ref(), ack_delay, now)?;
            }
            Frame::Crypto { offset, data } => {
                qtrace!(
                    "[{self}] Crypto frame on space={space} offset={offset}: {d}",
                    d = hex_snip_middle(data),
                );
                self.stats.borrow_mut().frame_rx.crypto += 1;
                self.crypto
                    .streams_mut()
                    .inbound_frame(space, offset, data)?;

                if self.role == Role::Client
                    && space == PacketNumberSpace::Initial
                    && packet_version != self.version
                {
                    // If the server has switched versions, switch to that version.
                    // This is an assumption, but very often a good one.
                    // This function does nothing if we already have a version.
                    self.compatible_upgrade(packet_version)?;
                }

                let mut buf = Vec::new();
                if self.crypto.streams().data_ready(space)
                    && self.crypto.streams_mut().read_to_end(space, &mut buf)? > 0
                {
                    self.handshake(now, packet_version, space, Some(&buf))?;
                    self.create_resumption_token(now);
                } else {
                    // If we get a useless CRYPTO frame send outstanding CRYPTO frames and
                    // 0-RTT data again.
                    self.crypto.resend_unacked(space);
                    if space == PacketNumberSpace::Initial {
                        self.crypto.resend_unacked(PacketNumberSpace::Handshake);
                        self.resend_0rtt(now);
                    }
                }
            }
            Frame::NewToken { token } => {
                if self.role == Role::Server || !self.state.connected() {
                    // > Clients MUST NOT send NEW_TOKEN frames. A server MUST
                    // > treat receipt of a NEW_TOKEN frame as a connection error of
                    // > type PROTOCOL_VIOLATION.
                    //
                    // <https://www.rfc-editor.org/rfc/rfc9000.html#name-new_token-frames>
                    return Err(Error::ProtocolViolation);
                }
                self.stats.borrow_mut().frame_rx.new_token += 1;
                self.new_token.save_token(token.to_vec());
                self.create_resumption_token(now);
            }
            Frame::NewConnectionId {
                sequence_number,
                connection_id,
                stateless_reset_token,
                retire_prior,
            } => {
                self.stats.borrow_mut().frame_rx.new_connection_id += 1;
                self.cids.add_remote(ConnectionIdEntry::new(
                    sequence_number,
                    ConnectionId::from(connection_id),
                    stateless_reset_token,
                ))?;
                self.paths.retire_cids(retire_prior, &mut self.cids);
                if self.cids.len() >= ConnectionIdManager::ACTIVE_LIMIT {
                    qinfo!("[{self}] received too many connection IDs");
                    return Err(Error::ConnectionIdLimitExceeded);
                }
            }
            Frame::RetireConnectionId { sequence_number } => {
                self.stats.borrow_mut().frame_rx.retire_connection_id += 1;
                self.cid_manager.retire(sequence_number);
            }
            Frame::PathChallenge { data } => {
                self.stats.borrow_mut().frame_rx.path_challenge += 1;
                // If we were challenged, try to make the path permanent.
                // Report an error if we don't have enough connection IDs.
                self.ensure_permanent(path, now)?;
                path.borrow_mut().challenged(data);
                // A PATH_CHALLENGE indicates the peer sees a different path,
                // so start PMTUD to discover any MTU changes.
                if self.conn_params.pmtud_enabled() {
                    path.borrow_mut()
                        .pmtud_mut()
                        .start(now, &mut self.stats.borrow_mut());
                }
            }
            Frame::PathResponse { data } => {
                self.stats.borrow_mut().frame_rx.path_response += 1;
                if let Some(primary) =
                    self.paths
                        .path_response(data, now, &mut self.stats.borrow_mut())
                {
                    self.path_migrated(&primary);
                    self.loss_recovery.migrate();
                }
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason_phrase,
            } => {
                self.stats.borrow_mut().frame_rx.connection_close += 1;
                qinfo!(
                    "[{self}] ConnectionClose received. Error code: {error_code:?} frame type {frame_type:x} reason {reason_phrase}"
                );
                let (detail, frame_type) = if let CloseError::Application(_) = error_code {
                    // Use a transport error here because we want to send
                    // NO_ERROR in this case.
                    (
                        Error::PeerApplication(error_code.code()),
                        FrameType::ConnectionCloseApplication,
                    )
                } else {
                    (
                        Error::Peer(error_code.code()),
                        FrameType::ConnectionCloseTransport,
                    )
                };
                let error = CloseReason::Transport(detail);
                self.state_signaling
                    .drain(Rc::clone(path), error.clone(), frame_type, "");
                self.set_state(
                    State::Draining {
                        error,
                        timeout: self.get_closing_period_time(now),
                    },
                    now,
                );
            }
            Frame::HandshakeDone => {
                self.stats.borrow_mut().frame_rx.handshake_done += 1;
                if self.role == Role::Server || !self.state.connected() {
                    return Err(Error::ProtocolViolation);
                }
                self.set_confirmed(now)?;
                self.discard_keys(PacketNumberSpace::Handshake, now);
                self.migrate_to_preferred_address(now)?;
            }
            Frame::AckFrequency {
                seqno,
                tolerance,
                delay,
                ignore_order,
            } => {
                self.stats.borrow_mut().frame_rx.ack_frequency += 1;
                let delay = Duration::from_micros(delay);
                if delay < GRANULARITY {
                    return Err(Error::ProtocolViolation);
                }
                self.acks
                    .ack_freq(seqno, tolerance - 1, delay, ignore_order);
            }
            Frame::Datagram { data, .. } => {
                self.stats.borrow_mut().frame_rx.datagram += 1;
                self.quic_datagrams
                    .handle_datagram(data, &mut self.stats.borrow_mut())?;
            }
            #[cfg(feature = "mcquic")]
            Frame::Mcquic(frame) => {
                self.input_mcquic_frame(frame, now)?;
            }
            _ => unreachable!("All other frames are for streams"),
        }

        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn input_mcquic_frame(&mut self, frame: crate::mcquic::Frame, now: Instant) -> Res<()> {
        if self.role == Role::Client {
            match self.mcquic_operation_state {
                crate::mcquic::OperationState::Pending => {
                    return self.queue_pending_mcquic_operation_control(frame, now);
                }
                crate::mcquic::OperationState::Prohibited
                | crate::mcquic::OperationState::Revoked => return Ok(()),
                crate::mcquic::OperationState::Active => {}
            }
        }

        if !self.mcquic_negotiated() {
            return Err(Error::ProtocolViolation);
        }

        let expected_sender = match self.role {
            Role::Client => crate::mcquic::Sender::Server,
            Role::Server => crate::mcquic::Sender::Client,
        };
        if frame.sender() != expected_sender {
            return Err(Error::ProtocolViolation);
        }

        if Self::mcquic_control_channel_id(&frame)
            .is_some_and(|channel_id| self.mcquic_retired_channels.contains_key(channel_id))
        {
            return Ok(());
        }

        let encoded_len = frame.encoded_len_erasing()?;
        let recv_bytes = self
            .mcquic_recv_bytes
            .checked_add(encoded_len)
            .ok_or(Error::McquicResourceLimit)?;
        if self.mcquic_recv.len() >= MAX_MCQUIC_ACTIVE_CONTROL_FRAMES
            || recv_bytes > MAX_MCQUIC_ACTIVE_CONTROL_BYTES
        {
            if let Some(channel_id) = Self::mcquic_control_channel_id(&frame) {
                let channel_id = channel_id.to_vec();
                self.limit_mcquic_channel(&channel_id, now);
            } else {
                self.mcquic_revoke_operation();
                self.mcquic_resource_limited_channels.push_back(Vec::new());
            }
            return Ok(());
        }

        let released = match self.apply_mcquic_channel_control(&frame, now) {
            Ok(released) => released,
            Err(Error::McquicResourceLimit) => {
                if let Some(channel_id) = Self::mcquic_control_channel_id(&frame) {
                    self.limit_mcquic_channel(channel_id, now);
                } else {
                    self.mcquic_revoke_operation();
                }
                return Ok(());
            }
            Err(Error::McquicOwnershipViolation) => {
                self.note_mcquic_ownership_violation();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        self.mcquic_recv.push_back(PendingMcquicControl {
            frame,
            encoded_len,
            inserted_at: now,
        });
        self.mcquic_recv_bytes = recv_bytes;
        let released_channel = released.first().map(|packet| packet.channel_id.clone());
        match self.process_mcquic_released_packets_with_ownership(released, now) {
            Ok(()) => Ok(()),
            Err((_, Error::McquicResourceLimit)) => {
                if let Some(channel_id) = released_channel {
                    self.limit_mcquic_channel(&channel_id, now);
                } else {
                    self.mcquic_revoke_operation();
                }
                Ok(())
            }
            Err((_, error)) => Err(error),
        }
    }

    #[cfg(feature = "mcquic")]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the fallible shape is retained for direct cap tests and control-path symmetry"
    )]
    fn queue_pending_mcquic_operation_control(
        &mut self,
        frame: crate::mcquic::Frame,
        now: Instant,
    ) -> Res<()> {
        let Ok(encoded_len) = frame.encoded_len_erasing() else {
            self.decline_pending_mcquic_operation();
            return Ok(());
        };
        let Some(pending_bytes) = self
            .mcquic_pending_operation_control_bytes
            .checked_add(encoded_len)
        else {
            self.decline_pending_mcquic_operation();
            return Ok(());
        };
        if pending_bytes > MAX_PENDING_MCQUIC_OPERATION_CONTROL_BYTES
            || self.mcquic_pending_operation_controls.len()
                >= MAX_PENDING_MCQUIC_OPERATION_CONTROL_FRAMES
        {
            self.decline_pending_mcquic_operation();
            return Ok(());
        }

        self.mcquic_pending_operation_controls.push_back(frame);
        self.mcquic_pending_operation_control_bytes = pending_bytes;
        self.mcquic_pending_operation_control_started_at
            .get_or_insert(now);
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn decline_pending_mcquic_operation(&mut self) {
        if self.role == Role::Client
            && self.mcquic_operation_state == crate::mcquic::OperationState::Pending
        {
            self.mcquic_operation_state = crate::mcquic::OperationState::Prohibited;
        }
        self.mcquic_pending_operation_controls.clear();
        self.mcquic_pending_operation_control_bytes = 0;
        self.mcquic_pending_operation_control_started_at = None;
    }

    #[cfg(feature = "mcquic")]
    #[expect(
        clippy::too_many_lines,
        reason = "all draft -08 channel-control transitions are kept in one exhaustive match"
    )]
    fn apply_mcquic_channel_control(
        &mut self,
        frame: &crate::mcquic::Frame,
        now: Instant,
    ) -> Res<Vec<crate::mcquic::ChannelPacket>> {
        let released = match frame {
            crate::mcquic::Frame::Announce(announce) => {
                if !self.mcquic_channels.contains_key(&announce.channel_id) {
                    let params = self
                        .tps
                        .borrow()
                        .local()
                        .get_mcquic_client_params()
                        .cloned()
                        .ok_or(Error::NotAvailable)?;
                    let tracked_ids = self
                        .mcquic_channels
                        .len()
                        .checked_add(
                            self.mcquic_pending_channel_controls.len()
                                - usize::from(
                                    self.mcquic_pending_channel_controls
                                        .contains_key(&announce.channel_id),
                                ),
                        )
                        .ok_or(Error::McquicResourceLimit)?;
                    let aggregate_rate_kibps = self
                        .mcquic_channels
                        .iter()
                        .filter(|(channel_id, _)| {
                            channel_id.as_slice() != announce.channel_id.as_slice()
                        })
                        .try_fold(announce.max_rate_kibps, |total, (_, channel)| {
                            total
                                .checked_add(channel.announce().max_rate_kibps)
                                .ok_or(Error::McquicResourceLimit)
                        })?;
                    if tracked_ids >= MAX_MCQUIC_CHANNELS
                        || u64::try_from(tracked_ids)? >= params.limits.max_channel_ids
                        || (announce.source.is_ipv4() && !params.limits.ipv4_channels_allowed)
                        || (announce.source.is_ipv6() && !params.limits.ipv6_channels_allowed)
                        || announce.source.is_ipv4() != announce.group.is_ipv4()
                        || aggregate_rate_kibps > params.limits.max_aggregate_rate_kibps
                    {
                        return Err(Error::McquicResourceLimit);
                    }
                }
                let hash_len =
                    crate::mcquic::integrity_hash_len_from_id(announce.integrity_hash_algorithm)?;
                if let Some(existing) = self.mcquic_channels.get(&announce.channel_id) {
                    if existing.announce() != announce {
                        return Err(Error::ProtocolViolation);
                    }
                } else {
                    let state = crate::mcquic::ChannelReceiveState::new(announce.clone())?;
                    self.mcquic_channels
                        .insert(announce.channel_id.clone(), state);
                }
                self.mcquic_integrity_hash_lens
                    .insert(announce.channel_id.clone(), hash_len);

                let pending = self
                    .mcquic_pending_channel_controls
                    .remove(&announce.channel_id)
                    .unwrap_or_default();
                self.mcquic_pending_channel_control_started_at
                    .remove(&announce.channel_id);
                let pending_bytes = pending
                    .iter()
                    .filter_map(|frame| frame.encoded_len_erasing().ok())
                    .sum::<usize>();
                self.mcquic_pending_channel_control_bytes = self
                    .mcquic_pending_channel_control_bytes
                    .saturating_sub(pending_bytes);
                self.mcquic_pending_channel_control_count = self
                    .mcquic_pending_channel_control_count
                    .saturating_sub(pending.len());
                let state = self
                    .mcquic_channels
                    .get_mut(&announce.channel_id)
                    .ok_or(Error::Internal)?;
                let mut released = Vec::new();
                for pending_frame in pending {
                    released.extend(Self::apply_known_mcquic_channel_control(
                        state,
                        &pending_frame,
                        now,
                    )?);
                }
                Ok(released)
            }
            crate::mcquic::Frame::Key(key) => {
                let Some(state) = self.mcquic_channels.get_mut(&key.channel_id) else {
                    self.queue_unknown_mcquic_control(&key.channel_id, frame.clone(), now)?;
                    return Ok(Vec::new());
                };
                Self::apply_known_mcquic_channel_control(state, frame, now)
            }
            crate::mcquic::Frame::Integrity(integrity) => {
                let Some(state) = self.mcquic_channels.get_mut(&integrity.channel_id) else {
                    self.queue_unknown_mcquic_control(&integrity.channel_id, frame.clone(), now)?;
                    return Ok(Vec::new());
                };
                Self::apply_known_mcquic_channel_control(state, frame, now)
            }
            crate::mcquic::Frame::Retire(retire) => {
                self.retire_mcquic_channel_state(&retire.channel_id, now);
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }?;
        if !self.mcquic_channel_resources_within_limits() {
            return Err(Error::McquicResourceLimit);
        }
        Ok(released)
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_channel_resources_within_limits(&self) -> bool {
        let usage = self.mcquic_channels.values().fold(
            crate::mcquic::ChannelResourceUsage::default(),
            |mut total, channel| {
                let channel = channel.resource_usage();
                total.keys = total.keys.saturating_add(channel.keys);
                total.key_bytes = total.key_bytes.saturating_add(channel.key_bytes);
                total.integrity_hashes = total
                    .integrity_hashes
                    .saturating_add(channel.integrity_hashes);
                total.integrity_bytes = total
                    .integrity_bytes
                    .saturating_add(channel.integrity_bytes);
                total.pending_packets = total
                    .pending_packets
                    .saturating_add(channel.pending_packets);
                total.pending_packet_bytes = total
                    .pending_packet_bytes
                    .saturating_add(channel.pending_packet_bytes);
                total.datagrams = total.datagrams.saturating_add(channel.datagrams);
                total.datagram_bytes = total.datagram_bytes.saturating_add(channel.datagram_bytes);
                total
            },
        );
        usage.keys <= MAX_MCQUIC_CONNECTION_KEYS
            && usage.key_bytes <= MAX_MCQUIC_CONNECTION_KEY_BYTES
            && usage.integrity_hashes <= MAX_MCQUIC_CONNECTION_INTEGRITY_HASHES
            && usage.integrity_bytes <= MAX_MCQUIC_CONNECTION_INTEGRITY_BYTES
            && usage.pending_packets <= MAX_MCQUIC_CONNECTION_PENDING_PACKETS
            && usage.pending_packet_bytes <= MAX_MCQUIC_CONNECTION_PENDING_PACKET_BYTES
            && usage.datagrams <= MAX_MCQUIC_CONNECTION_DATAGRAMS
            && usage.datagram_bytes <= MAX_MCQUIC_CONNECTION_DATAGRAM_BYTES
    }

    #[cfg(feature = "mcquic")]
    #[expect(
        clippy::too_many_lines,
        reason = "bounded expiry coordinates all related MCQUIC resource indexes"
    )]
    fn expire_mcquic_resources(&mut self, now: Instant) {
        while self
            .mcquic_recv
            .front()
            .is_some_and(|pending| pending.inserted_at + MAX_MCQUIC_ACTIVE_CONTROL_AGE <= now)
        {
            let pending = self.mcquic_recv.pop_front().expect("front exists");
            self.mcquic_recv_bytes = self.mcquic_recv_bytes.saturating_sub(pending.encoded_len);
            if let Some(channel_id) = Self::mcquic_control_channel_id(&pending.frame) {
                let channel_id = channel_id.to_vec();
                self.limit_mcquic_channel(&channel_id, now);
            } else {
                self.mcquic_revoke_operation();
                self.mcquic_resource_limited_channels.push_back(Vec::new());
                return;
            }
        }

        if self
            .mcquic_pending_operation_control_started_at
            .is_some_and(|started| started + MAX_MCQUIC_PENDING_CONTROL_AGE <= now)
        {
            self.decline_pending_mcquic_operation();
        }

        let expired_unknown = self
            .mcquic_pending_channel_control_started_at
            .iter()
            .filter(|(_, started)| **started + MAX_MCQUIC_PENDING_CONTROL_AGE <= now)
            .map(|(channel_id, _)| channel_id.clone())
            .collect::<Vec<_>>();
        for channel_id in expired_unknown {
            self.limit_mcquic_channel(&channel_id, now);
        }

        for _ in 0..MAX_MCQUIC_OWNER_EXPIRIES_PER_TURN {
            let Some((deadline, stream_id)) = self.mcquic_pending_owner_expiries.first().copied()
            else {
                break;
            };
            if deadline > now {
                break;
            }
            self.mcquic_pending_owner_expiries
                .remove(&(deadline, stream_id));
            let Some(frames) = self.mcquic_pending_stream_frames.get(&stream_id) else {
                continue;
            };
            if frames
                .front()
                .is_some_and(|frame| frame.inserted_at + MAX_MCQUIC_PENDING_OWNER_AGE > now)
            {
                continue;
            }
            let channels = frames
                .iter()
                .filter_map(|frame| frame.channel_id.clone())
                .collect::<BTreeSet<_>>();
            self.mcquic_retire_stream(stream_id);
            if channels.is_empty() {
                self.mcquic_revoke_operation();
                self.mcquic_resource_limited_channels.push_back(Vec::new());
                return;
            }
            for channel_id in channels {
                self.limit_mcquic_channel(&channel_id, now);
            }
        }

        for _ in 0..MAX_MCQUIC_OWNER_EXPIRIES_PER_TURN {
            let Some((deadline, stream_id)) =
                self.mcquic_authorized_stream_expiries.first().copied()
            else {
                break;
            };
            if deadline > now {
                break;
            }
            self.mcquic_authorized_stream_expiries
                .remove(&(deadline, stream_id));
            if self
                .mcquic_authorized_streams
                .get(&stream_id)
                .is_some_and(|last_seen| *last_seen + MAX_MCQUIC_AUTHORIZED_OWNER_AGE <= now)
            {
                // An idle authorized stream no longer has a prefix event with
                // which to re-establish ownership. Revoke the optimization
                // instead of silently stranding later unicast recovery.
                self.mcquic_revoke_operation();
                self.mcquic_resource_limited_channels.push_back(Vec::new());
                return;
            }
        }

        if self
            .mcquic_retired_channels
            .values()
            .any(|retired_at| *retired_at + MAX_MCQUIC_RETIRED_CHANNEL_AGE <= now)
        {
            // Retired channel IDs cannot be safely reused within an operation.
            // End the optimization when its bounded tombstone lifetime ends.
            self.mcquic_revoke_operation();
            self.mcquic_resource_limited_channels.push_back(Vec::new());
            return;
        }

        let limited = self
            .mcquic_channels
            .iter_mut()
            .filter_map(|(channel_id, channel)| {
                channel.prune_expired(now).err().map(|_| channel_id.clone())
            })
            .collect::<Vec<_>>();
        for channel_id in limited {
            self.limit_mcquic_channel(&channel_id, now);
        }
    }

    #[cfg(feature = "mcquic")]
    fn next_mcquic_resource_expiry(&self) -> Option<Instant> {
        self.mcquic_channels
            .values()
            .filter_map(crate::mcquic::ChannelReceiveState::next_expiry)
            .chain(
                self.mcquic_pending_operation_control_started_at
                    .map(|started| started + MAX_MCQUIC_PENDING_CONTROL_AGE),
            )
            .chain(
                self.mcquic_pending_channel_control_started_at
                    .values()
                    .map(|started| *started + MAX_MCQUIC_PENDING_CONTROL_AGE),
            )
            .chain(
                self.mcquic_pending_owner_expiries
                    .first()
                    .map(|(deadline, _)| *deadline),
            )
            .chain(
                self.mcquic_authorized_stream_expiries
                    .first()
                    .map(|(deadline, _)| *deadline),
            )
            .chain(
                self.mcquic_retired_channels
                    .values()
                    .map(|retired_at| *retired_at + MAX_MCQUIC_RETIRED_CHANNEL_AGE),
            )
            .chain(
                self.mcquic_recv
                    .front()
                    .map(|pending| pending.inserted_at + MAX_MCQUIC_ACTIVE_CONTROL_AGE),
            )
            .min()
    }
    #[cfg(feature = "mcquic")]
    fn mcquic_control_channel_id(frame: &crate::mcquic::Frame) -> Option<&[u8]> {
        match frame {
            crate::mcquic::Frame::Announce(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Key(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Join(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Leave(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Integrity(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Ack(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Retire(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::State(frame) => Some(&frame.channel_id),
            crate::mcquic::Frame::Limits(_) => None,
        }
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_pending_owner_deadline(
        frames: &VecDeque<PendingMcquicStreamFrame>,
    ) -> Option<Instant> {
        frames
            .front()
            .map(|frame| frame.inserted_at + MAX_MCQUIC_PENDING_OWNER_AGE)
    }

    #[cfg(feature = "mcquic")]
    #[expect(
        clippy::unwrap_in_result,
        reason = "exact owner accounting is an internal invariant after the owner entry is removed"
    )]
    fn take_pending_mcquic_stream_frames(
        &mut self,
        stream_id: StreamId,
    ) -> Option<VecDeque<PendingMcquicStreamFrame>> {
        let frames = self.mcquic_pending_stream_frames.remove(&stream_id)?;
        self.mcquic_pending_owner_checks.remove(&stream_id);
        if let Some(deadline) = Self::mcquic_pending_owner_deadline(&frames) {
            self.mcquic_pending_owner_expiries
                .remove(&(deadline, stream_id));
        }

        let bytes = frames
            .iter()
            .map(|pending| Self::mcquic_stream_frame_bytes(&pending.frame))
            .sum::<usize>();
        self.mcquic_pending_stream_bytes = self
            .mcquic_pending_stream_bytes
            .checked_sub(bytes)
            .expect("MCQUIC pending stream byte accounting");
        self.mcquic_pending_stream_frame_count = self
            .mcquic_pending_stream_frame_count
            .checked_sub(frames.len())
            .expect("MCQUIC pending stream frame accounting");

        let channels = frames
            .iter()
            .filter_map(|pending| pending.channel_id.as_ref())
            .collect::<BTreeSet<_>>();
        for channel_id in channels {
            let remove_channel = {
                let streams = self
                    .mcquic_pending_channel_streams
                    .get_mut(channel_id)
                    .expect("MCQUIC pending channel reverse index");
                assert!(streams.remove(&stream_id));
                streams.is_empty()
            };
            self.mcquic_pending_channel_owner_links = self
                .mcquic_pending_channel_owner_links
                .checked_sub(1)
                .expect("MCQUIC pending owner link accounting");
            if remove_channel {
                self.mcquic_pending_channel_streams.remove(channel_id);
            }
        }
        Some(frames)
    }

    #[cfg(feature = "mcquic")]
    fn set_mcquic_authorized_stream(&mut self, stream_id: StreamId, now: Instant) -> Res<()> {
        if let Some(previous) = self.mcquic_authorized_streams.get(&stream_id).copied() {
            assert!(
                self.mcquic_authorized_stream_expiries
                    .remove(&(previous + MAX_MCQUIC_AUTHORIZED_OWNER_AGE, stream_id))
            );
        } else if self.mcquic_authorized_streams.len() >= MAX_AUTHORIZED_MCQUIC_STREAMS
            || self.mcquic_authorized_stream_expiries.len() >= MAX_AUTHORIZED_MCQUIC_OWNER_EXPIRIES
        {
            return Err(Error::McquicResourceLimit);
        }

        self.mcquic_authorized_streams.insert(stream_id, now);
        assert!(
            self.mcquic_authorized_stream_expiries
                .insert((now + MAX_MCQUIC_AUTHORIZED_OWNER_AGE, stream_id))
        );
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn remove_mcquic_authorized_stream(&mut self, stream_id: StreamId) {
        if let Some(last_seen) = self.mcquic_authorized_streams.remove(&stream_id) {
            assert!(
                self.mcquic_authorized_stream_expiries
                    .remove(&(last_seen + MAX_MCQUIC_AUTHORIZED_OWNER_AGE, stream_id))
            );
        }
    }

    #[cfg(feature = "mcquic")]
    fn retire_mcquic_channel_state(&mut self, channel_id: &[u8], now: Instant) {
        if !self.mcquic_retired_channels.contains_key(channel_id)
            && (self.mcquic_retired_channels.len() >= MAX_MCQUIC_RETIRED_CHANNELS
                || self
                    .mcquic_retired_channels
                    .keys()
                    .map(Vec::len)
                    .sum::<usize>()
                    .saturating_add(channel_id.len())
                    > MAX_MCQUIC_RETIRED_CHANNEL_BYTES)
        {
            self.mcquic_revoke_operation();
            self.mcquic_resource_limited_channels.push_back(Vec::new());
            return;
        }
        self.mcquic_retired_channels
            .insert(channel_id.to_vec(), now);
        self.mcquic_channels.remove(channel_id);
        self.mcquic_integrity_hash_lens.remove(channel_id);
        if let Some(pending) = self.mcquic_pending_channel_controls.remove(channel_id) {
            self.mcquic_pending_channel_control_started_at
                .remove(channel_id);
            let bytes = pending
                .iter()
                .filter_map(|frame| frame.encoded_len_erasing().ok())
                .sum::<usize>();
            self.mcquic_pending_channel_control_bytes = self
                .mcquic_pending_channel_control_bytes
                .saturating_sub(bytes);
            self.mcquic_pending_channel_control_count = self
                .mcquic_pending_channel_control_count
                .saturating_sub(pending.len());
        }

        let affected_streams = self
            .mcquic_pending_channel_streams
            .remove(channel_id)
            .unwrap_or_default();
        self.mcquic_pending_channel_owner_links = self
            .mcquic_pending_channel_owner_links
            .checked_sub(affected_streams.len())
            .expect("MCQUIC pending owner link accounting");

        for stream_id in affected_streams {
            let frames = self
                .mcquic_pending_stream_frames
                .get_mut(&stream_id)
                .expect("MCQUIC pending channel reverse index");
            let old_deadline = Self::mcquic_pending_owner_deadline(frames)
                .expect("pending stream has at least one frame");
            assert!(
                self.mcquic_pending_owner_expiries
                    .remove(&(old_deadline, stream_id))
            );
            let old_len = frames.len();
            let removed_bytes = frames
                .iter()
                .filter(|pending| pending.channel_id.as_deref() == Some(channel_id))
                .map(|pending| Self::mcquic_stream_frame_bytes(&pending.frame))
                .sum::<usize>();
            frames.retain(|pending| pending.channel_id.as_deref() != Some(channel_id));
            let removed_frames = old_len - frames.len();
            assert!(removed_frames > 0);
            self.mcquic_pending_stream_bytes = self
                .mcquic_pending_stream_bytes
                .checked_sub(removed_bytes)
                .expect("MCQUIC pending stream byte accounting");
            self.mcquic_pending_stream_frame_count = self
                .mcquic_pending_stream_frame_count
                .checked_sub(removed_frames)
                .expect("MCQUIC pending stream frame accounting");

            if let Some(deadline) = Self::mcquic_pending_owner_deadline(frames) {
                assert!(
                    self.mcquic_pending_owner_expiries
                        .insert((deadline, stream_id))
                );
            } else {
                self.mcquic_pending_stream_frames.remove(&stream_id);
                self.mcquic_pending_owner_checks.remove(&stream_id);
            }
        }
    }

    #[cfg(feature = "mcquic")]
    fn queue_unknown_mcquic_control(
        &mut self,
        channel_id: &[u8],
        frame: crate::mcquic::Frame,
        now: Instant,
    ) -> Res<()> {
        let encoded_len = frame.encoded_len_erasing()?;
        let params = self
            .tps
            .borrow()
            .local()
            .get_mcquic_client_params()
            .cloned()
            .ok_or(Error::NotAvailable)?;
        let is_new_channel = !self
            .mcquic_pending_channel_controls
            .contains_key(channel_id);
        let tracked_ids = self
            .mcquic_channels
            .len()
            .checked_add(self.mcquic_pending_channel_controls.len())
            .ok_or(Error::McquicResourceLimit)?;
        let pending_bytes = self
            .mcquic_pending_channel_control_bytes
            .checked_add(encoded_len)
            .ok_or(Error::McquicResourceLimit)?;
        let per_channel = self
            .mcquic_pending_channel_controls
            .get(channel_id)
            .map_or(0, VecDeque::len);
        if (is_new_channel
            && (tracked_ids >= MAX_MCQUIC_CHANNELS
                || u64::try_from(tracked_ids)? >= params.limits.max_channel_ids))
            || per_channel >= MAX_MCQUIC_UNKNOWN_CONTROLS_PER_CHANNEL
            || self.mcquic_pending_channel_control_count >= MAX_MCQUIC_UNKNOWN_CONTROL_FRAMES
            || pending_bytes > MAX_MCQUIC_UNKNOWN_CONTROL_BYTES
        {
            return Err(Error::McquicResourceLimit);
        }

        self.mcquic_pending_channel_controls
            .entry(channel_id.to_vec())
            .or_default()
            .push_back(frame);
        self.mcquic_pending_channel_control_bytes = pending_bytes;
        self.mcquic_pending_channel_control_count += 1;
        self.mcquic_pending_channel_control_started_at
            .entry(channel_id.to_vec())
            .or_insert(now);
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn limit_mcquic_channel(&mut self, channel_id: &[u8], now: Instant) {
        self.retire_mcquic_channel_state(channel_id, now);
        if self.mcquic_operation_state == crate::mcquic::OperationState::Revoked {
            return;
        }
        self.mcquic_recv
            .retain(|pending| Self::mcquic_control_channel_id(&pending.frame) != Some(channel_id));
        self.mcquic_recv_bytes = self
            .mcquic_recv
            .iter()
            .map(|pending| pending.encoded_len)
            .sum();
        if self.mcquic_resource_limited_channels.len() < MAX_MCQUIC_RESOURCE_LIMIT_NOTICES
            && !self
                .mcquic_resource_limited_channels
                .iter()
                .any(|pending| pending == channel_id)
        {
            self.mcquic_resource_limited_channels
                .push_back(channel_id.to_vec());
        }
    }

    #[cfg(feature = "mcquic")]
    fn apply_known_mcquic_channel_control(
        state: &mut crate::mcquic::ChannelReceiveState,
        frame: &crate::mcquic::Frame,
        now: Instant,
    ) -> Res<Vec<crate::mcquic::ChannelPacket>> {
        match frame {
            crate::mcquic::Frame::Key(key) => state.insert_key_for_connection(key.clone(), now),
            crate::mcquic::Frame::Integrity(integrity) => {
                state.insert_integrity_for_connection(integrity, now)
            }
            _ => Err(Error::Internal),
        }
    }

    #[cfg(feature = "mcquic")]
    fn process_mcquic_released_packets(
        &mut self,
        packets: Vec<crate::mcquic::ChannelPacket>,
        now: Instant,
    ) -> Result<(), (FrameType, Error)> {
        for packet in packets {
            if self.role == Role::Client
                && packet.frames.iter().any(|frame| {
                    matches!(
                        frame,
                        crate::mcquic::ChannelFrame::Stream { stream_id, .. }
                            | crate::mcquic::ChannelFrame::ResetStream { stream_id, .. }
                            if {
                                let stream_id = StreamId::from(*stream_id);
                                !stream_id.is_remote_initiated(self.role) || !stream_id.is_uni()
                            }
                    )
                })
            {
                return Err((FrameType::Stream, Error::McquicOwnershipViolation));
            }
            let channel_id = packet.channel_id;
            let packet_number = packet.packet_number;
            for frame in packet.frames {
                let frame_type = Self::mcquic_channel_frame_type(&frame)
                    .map_err(|error| (FrameType::Padding, error))?;
                if let Err(error) =
                    self.input_mcquic_channel_frame_from_packet(frame, now, Some(&channel_id))
                {
                    return Err((frame_type, error));
                }
            }
            let state = self
                .mcquic_channels
                .get_mut(&channel_id)
                .ok_or((FrameType::Padding, Error::Internal))?;
            state.mark_packet_released(packet_number);
            state.note_released_at(now);
        }
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn process_mcquic_released_packets_with_ownership(
        &mut self,
        packets: Vec<crate::mcquic::ChannelPacket>,
        now: Instant,
    ) -> Result<(), (FrameType, Error)> {
        match self.process_mcquic_released_packets(packets, now) {
            Err((_, Error::McquicOwnershipViolation)) => {
                self.note_mcquic_ownership_violation();
                Ok(())
            }
            result => result,
        }
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_channel_frame_type(frame: &crate::mcquic::ChannelFrame) -> Res<FrameType> {
        Ok(match frame {
            crate::mcquic::ChannelFrame::Padding { .. } => FrameType::Padding,
            crate::mcquic::ChannelFrame::Ping => FrameType::Ping,
            crate::mcquic::ChannelFrame::ResetStream { .. } => FrameType::ResetStream,
            crate::mcquic::ChannelFrame::Stream { .. } => FrameType::Stream,
            crate::mcquic::ChannelFrame::Datagram { .. } => FrameType::Datagram,
            crate::mcquic::ChannelFrame::Multicast(frame) => {
                FrameType::try_from(frame.frame_type()?)?
            }
        })
    }
    #[cfg(all(feature = "mcquic", test))]
    fn input_mcquic_channel_frame(
        &mut self,
        frame: crate::mcquic::ChannelFrame,
        now: Instant,
    ) -> Res<()> {
        self.input_mcquic_channel_frame_from_packet(frame, now, None)
    }

    #[cfg(feature = "mcquic")]
    fn input_mcquic_channel_frame_from_packet(
        &mut self,
        frame: crate::mcquic::ChannelFrame,
        now: Instant,
        channel_id: Option<&[u8]>,
    ) -> Res<()> {
        if channel_id.is_some_and(|id| self.mcquic_retired_channels.contains_key(id)) {
            return Ok(());
        }

        match frame {
            crate::mcquic::ChannelFrame::Padding { len } => {
                self.stats.borrow_mut().frame_rx.padding += len;
            }
            crate::mcquic::ChannelFrame::Ping => {
                self.stats.borrow_mut().frame_rx.ping += 1;
            }
            frame @ (crate::mcquic::ChannelFrame::ResetStream { .. }
            | crate::mcquic::ChannelFrame::Stream { .. }) => {
                self.queue_or_input_mcquic_stream_frame(frame, channel_id, now)?;
            }
            crate::mcquic::ChannelFrame::Datagram { data } => {
                self.stats.borrow_mut().frame_rx.datagram += 1;
                self.quic_datagrams
                    .handle_datagram(&data, &mut self.stats.borrow_mut())?;
            }
            crate::mcquic::ChannelFrame::Multicast(frame) => {
                self.input_mcquic_frame(frame, now)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_stream_frame_id(frame: &crate::mcquic::ChannelFrame) -> StreamId {
        match frame {
            crate::mcquic::ChannelFrame::ResetStream { stream_id, .. }
            | crate::mcquic::ChannelFrame::Stream { stream_id, .. } => StreamId::from(*stream_id),
            _ => unreachable!("only STREAM and RESET_STREAM frames are queued"),
        }
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_stream_frame_bytes(frame: &crate::mcquic::ChannelFrame) -> usize {
        match frame {
            crate::mcquic::ChannelFrame::Stream { data, .. } => data.len(),
            crate::mcquic::ChannelFrame::ResetStream { .. } => 0,
            _ => unreachable!("only STREAM and RESET_STREAM frames are queued"),
        }
    }

    #[cfg(feature = "mcquic")]
    fn queue_or_input_mcquic_stream_frame(
        &mut self,
        frame: crate::mcquic::ChannelFrame,
        channel_id: Option<&[u8]>,
        now: Instant,
    ) -> Res<()> {
        if self.role != Role::Client {
            return self.input_authorized_mcquic_stream_frame(frame);
        }

        let stream_id = Self::mcquic_stream_frame_id(&frame);
        if !stream_id.is_remote_initiated(self.role) || !stream_id.is_uni() {
            return Err(Error::McquicOwnershipViolation);
        }
        if !self.streams.is_stream_id_allowed(stream_id) {
            return Err(Error::StreamLimit);
        }
        if self.mcquic_authorized_streams.contains_key(&stream_id) {
            let refresh = self
                .mcquic_authorized_streams
                .get(&stream_id)
                .is_some_and(|last_seen| *last_seen + MCQUIC_AUTHORIZED_OWNER_REFRESH <= now);
            if refresh && self.set_mcquic_authorized_stream(stream_id, now).is_err() {
                self.mcquic_revoke_operation();
                self.mcquic_resource_limited_channels.push_back(Vec::new());
                return Ok(());
            }
            return self.input_authorized_mcquic_stream_frame(frame);
        }

        let frame_bytes = Self::mcquic_stream_frame_bytes(&frame);
        let channel_id = channel_id.map(<[u8]>::to_vec);
        let new_owner = !self.mcquic_pending_stream_frames.contains_key(&stream_id);
        let new_channel_link = channel_id.as_ref().is_some_and(|channel_id| {
            !self
                .mcquic_pending_channel_streams
                .get(channel_id)
                .is_some_and(|streams| streams.contains(&stream_id))
        });
        if new_owner
            && (self.mcquic_pending_stream_frames.len() >= MAX_PENDING_MCQUIC_STREAM_OWNERS
                || self.mcquic_pending_owner_checks.len() >= MAX_PENDING_MCQUIC_OWNER_EXPIRIES
                || self.mcquic_pending_owner_expiries.len() >= MAX_PENDING_MCQUIC_OWNER_EXPIRIES)
        {
            return Err(Error::McquicResourceLimit);
        }
        if new_channel_link
            && self.mcquic_pending_channel_owner_links >= MAX_MCQUIC_PENDING_CHANNEL_OWNER_LINKS
        {
            return Err(Error::McquicResourceLimit);
        }
        let pending_bytes = self
            .mcquic_pending_stream_bytes
            .checked_add(frame_bytes)
            .ok_or(Error::McquicResourceLimit)?;
        let transport_limit =
            usize::try_from(self.tps.borrow().local().get_integer(InitialMaxData))
                .unwrap_or(usize::MAX);
        if pending_bytes > transport_limit {
            return Err(Error::FlowControl);
        }
        if pending_bytes > MAX_PENDING_MCQUIC_STREAM_BYTES
            || self.mcquic_pending_stream_frame_count >= MAX_PENDING_MCQUIC_STREAM_FRAMES
            || self
                .mcquic_pending_stream_frames
                .get(&stream_id)
                .map_or(0, VecDeque::len)
                >= MAX_PENDING_MCQUIC_STREAM_FRAMES_PER_OWNER
        {
            return Err(Error::McquicResourceLimit);
        }

        self.mcquic_pending_stream_frames
            .entry(stream_id)
            .or_default()
            .push_back(PendingMcquicStreamFrame {
                channel_id: channel_id.clone(),
                frame,
                inserted_at: now,
            });
        self.mcquic_pending_stream_bytes = pending_bytes;
        self.mcquic_pending_stream_frame_count += 1;
        if new_owner {
            assert!(self.mcquic_pending_owner_checks.insert(stream_id));
            assert!(
                self.mcquic_pending_owner_expiries
                    .insert((now + MAX_MCQUIC_PENDING_OWNER_AGE, stream_id))
            );
        }
        if new_channel_link {
            assert!(
                self.mcquic_pending_channel_streams
                    .entry(channel_id.expect("new channel link has a channel"))
                    .or_default()
                    .insert(stream_id)
            );
            self.mcquic_pending_channel_owner_links += 1;
        }
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn input_authorized_mcquic_stream_frame(
        &mut self,
        frame: crate::mcquic::ChannelFrame,
    ) -> Res<()> {
        match frame {
            crate::mcquic::ChannelFrame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                let frame = Frame::ResetStream {
                    stream_id: StreamId::from(stream_id),
                    application_error_code: error_code,
                    final_size,
                };
                self.streams
                    .input_frame(&frame, &mut self.stats.borrow_mut().frame_rx)
            }
            crate::mcquic::ChannelFrame::Stream {
                stream_id,
                offset,
                fin,
                data,
            } => {
                let frame = Frame::Stream {
                    stream_id: StreamId::from(stream_id),
                    offset,
                    data: &data,
                    fin,
                    fill: false,
                };
                self.streams
                    .input_frame(&frame, &mut self.stats.borrow_mut().frame_rx)
            }
            _ => Err(Error::Internal),
        }
    }

    /// Given a set of `sent::Packet` instances, ensure that the source of the
    /// packet is told that they are lost.  This gives the frame generation code
    /// a chance to retransmit the frame as needed.
    fn handle_lost_packets(&mut self, lost_packets: &[sent::Packet]) {
        for lost in lost_packets {
            for token in lost.tokens() {
                qdebug!("[{self}] Lost: {token:?}");
                match token {
                    recovery::Token::Ack(ack_token) => {
                        // If we lost an ACK frame during the handshake, send
                        // another one.
                        if ack_token.space() != PacketNumberSpace::ApplicationData {
                            self.acks.immediate_ack(ack_token.space(), lost.time_sent());
                        }
                    }
                    recovery::Token::Crypto(ct) => self.crypto.lost(ct),
                    recovery::Token::HandshakeDone => self.state_signaling.handshake_done(),
                    recovery::Token::NewToken(seqno) => self.new_token.lost(*seqno),
                    recovery::Token::NewConnectionId(ncid) => self.cid_manager.lost(ncid),
                    recovery::Token::RetireConnectionId(seqno) => {
                        self.paths.lost_retire_cid(*seqno);
                    }
                    recovery::Token::AckFrequency(rate) => self.paths.lost_ack_frequency(rate),
                    recovery::Token::KeepAlive => self.idle_timeout.lost_keep_alive(),
                    recovery::Token::Stream(stream_token) => self.streams.lost(stream_token),
                    recovery::Token::Datagram(dgram_tracker) => {
                        self.events
                            .datagram_outcome(dgram_tracker, OutgoingDatagramOutcome::Lost);
                        self.stats.borrow_mut().datagram_tx.lost += 1;
                    }
                    #[cfg(feature = "mcquic")]
                    recovery::Token::Mcquic(frame) => {
                        if frame.retransmit_on_loss()
                            && (self.role == Role::Server
                                || self.mcquic_operation_state
                                    == crate::mcquic::OperationState::Active
                                || Self::mcquic_terminal_frame(frame))
                            && self.mcquic_send.push_back(frame.clone()).is_err()
                            && self.role == Role::Client
                        {
                            self.mcquic_revoke_operation();
                            if self.mcquic_resource_limited_channels.len()
                                < MAX_MCQUIC_RESOURCE_LIMIT_NOTICES
                            {
                                self.mcquic_resource_limited_channels.push_back(Vec::new());
                            }
                        }
                    }
                    recovery::Token::EcnEct0 => self.paths.lost_ecn(&mut self.stats.borrow_mut()),
                    // PMTUD probe loss is handled by the PMTUD state machine.
                    recovery::Token::PmtudProbe => (),
                }
            }
        }
    }

    fn decode_ack_delay(&self, v: u64) -> Res<Duration> {
        // If we have remote transport parameters, use them.
        // Otherwise, ack delay should be zero (because it's the handshake).
        self.tps.borrow().remote_handshake().map_or_else(
            || Ok(Duration::default()),
            |r| {
                let exponent = u32::try_from(r.get_integer(AckDelayExponent))?;
                // ACK_DELAY_EXPONENT > 20 is invalid per RFC9000. We already
                // checked that in TransportParameter::decode.
                let corrected = if v.leading_zeros() >= exponent {
                    v << exponent
                } else {
                    u64::MAX
                };
                Ok(Duration::from_micros(corrected))
            },
        )
    }

    fn handle_ack<R>(
        &mut self,
        space: PacketNumberSpace,
        ack_ranges: R,
        ack_ecn: Option<&ecn::Count>,
        ack_delay: u64,
        now: Instant,
    ) -> Res<()>
    where
        R: IntoIterator<Item = RangeInclusive<packet::Number>> + Debug,
        R::IntoIter: ExactSizeIterator,
    {
        qdebug!("[{self}] Rx ACK space={space}, ranges={ack_ranges:?}");

        let Some(path) = self.paths.primary() else {
            return Ok(());
        };
        let (acked_packets, lost_packets) = self.loss_recovery.on_ack_received(
            &path,
            space,
            ack_ranges,
            ack_ecn,
            self.decode_ack_delay(ack_delay)?,
            now,
        );
        let largest_acknowledged = acked_packets.first().map(sent::Packet::pn);
        qlog::packets_acked(&mut self.qlog, space, &acked_packets, now);
        for acked in acked_packets {
            for token in acked.tokens() {
                match token {
                    recovery::Token::Stream(stream_token) => self.streams.acked(stream_token),
                    recovery::Token::Ack(at) => self.acks.acked(at),
                    recovery::Token::Crypto(ct) => self.crypto.acked(ct),
                    recovery::Token::NewToken(seqno) => self.new_token.acked(*seqno),
                    recovery::Token::NewConnectionId(entry) => self.cid_manager.acked(entry),
                    recovery::Token::RetireConnectionId(seqno) => {
                        self.paths.acked_retire_cid(*seqno);
                    }
                    recovery::Token::AckFrequency(rate) => self.paths.acked_ack_frequency(rate),
                    recovery::Token::KeepAlive => self.idle_timeout.ack_keep_alive(),
                    recovery::Token::Datagram(dgram_tracker) => self
                        .events
                        .datagram_outcome(dgram_tracker, OutgoingDatagramOutcome::Acked),
                    #[cfg(feature = "mcquic")]
                    recovery::Token::Mcquic(_) => (),
                    recovery::Token::EcnEct0 => self.paths.acked_ecn(),
                    // We don't care about these being ACK'ed
                    recovery::Token::HandshakeDone | recovery::Token::PmtudProbe => (),
                }
            }
        }
        self.handle_lost_packets(&lost_packets);
        qlog::packets_lost(&mut self.qlog, &lost_packets, now);
        let stats = &mut self.stats.borrow_mut().frame_rx;
        stats.ack += 1;
        if let Some(largest_acknowledged) = largest_acknowledged {
            stats.largest_acknowledged = max(stats.largest_acknowledged, largest_acknowledged);
        }
        Ok(())
    }

    /// Tell 0-RTT packets that they were "lost".
    fn resend_0rtt(&mut self, now: Instant) {
        if let Some(path) = self.paths.primary() {
            let dropped = self.loss_recovery.drop_0rtt(&path, now);
            self.handle_lost_packets(&dropped);
        }
    }

    /// When the server rejects 0-RTT we need to drop a bunch of stuff.
    fn client_0rtt_rejected(&mut self, now: Instant) {
        if !matches!(self.zero_rtt_state, ZeroRttState::Sending) {
            return;
        }
        qdebug!("[{self}] 0-RTT rejected");
        self.resend_0rtt(now);
        self.streams.zero_rtt_rejected();
        self.crypto.states_mut().discard_0rtt_keys();
        self.events.client_0rtt_rejected();
    }

    fn set_connected(&mut self, now: Instant) -> Res<()> {
        qdebug!("[{self}] TLS connection complete");
        if self
            .crypto
            .tls()
            .info()
            .map(SecretAgentInfo::alpn)
            .is_none()
        {
            qwarn!("[{self}] No ALPN, closing connection");
            // 120 = no_application_protocol
            return Err(Error::CryptoAlert(120));
        }
        if self.role == Role::Server {
            // Remove the randomized client CID from the list of acceptable CIDs.
            self.cid_manager.remove_odcid();
            // Mark the path as validated, if it isn't already.
            let path = self.paths.primary().ok_or(Error::NoAvailablePath)?;
            path.borrow_mut().set_valid(now);
            // Generate a qlog event that the server connection started.
            qlog::server_connection_started(&mut self.qlog, &path, now);
            qlog::recovery_parameters_set(
                &mut self.qlog,
                path.borrow().plpmtu(),
                self.conn_params.get_congestion_control(),
                now,
            );
            qlog::congestion_state_updated(
                &mut self.qlog,
                None,
                Phase::SlowStart.into(),
                None,
                now,
            );
        } else {
            self.zero_rtt_state = if self
                .crypto
                .tls()
                .info()
                .ok_or(Error::Internal)?
                .early_data_accepted()
            {
                ZeroRttState::AcceptedClient
            } else {
                self.client_0rtt_rejected(now);
                ZeroRttState::Rejected
            };
        }

        // Setting application keys has to occur after 0-RTT rejection.
        let pto = self.pto();
        self.crypto
            .install_application_keys(self.version, now + pto)?;
        self.process_tps(now)?;
        self.set_state(State::Connected, now);
        self.create_resumption_token(now);
        self.saved_datagrams.make_available(Epoch::ApplicationData);
        self.stats.borrow_mut().resumed =
            self.crypto.tls().info().ok_or(Error::Internal)?.resumed();
        if self.role == Role::Server {
            self.state_signaling.handshake_done();
            self.set_confirmed(now)?;
        }
        qinfo!("[{self}] Connection established");
        Ok(())
    }

    fn set_state(&mut self, state: State, now: Instant) {
        if state > self.state {
            qdebug!("[{self}] State change from {:?} -> {state:?}", self.state);
            let old_state = self.state.clone();
            self.state = state.clone();
            if self.state.closed() {
                self.streams.clear_streams();
            }
            self.events.connection_state_change(state);
            qlog::connection_state_updated(&mut self.qlog, &old_state, &self.state, now);
            if let State::Closed(reason) = &self.state {
                qlog::connection_closed(&mut self.qlog, reason, now);
            }
        } else if mem::discriminant(&state) != mem::discriminant(&self.state) {
            // Only tolerate a regression in state if the new state is closing
            // and the connection is already closed.
            debug_assert!(matches!(
                state,
                State::Closing { .. } | State::Draining { .. }
            ));
            debug_assert!(self.state.closed());
        }
    }

    /// Create a stream.
    /// Returns new stream id
    ///
    /// # Errors
    ///
    /// `ConnectionState` if the connection stat does not allow to create
    /// streams. `StreamLimitError` if we are limited by server's stream
    /// concurrence.
    pub fn stream_create(&mut self, st: StreamType) -> Res<StreamId> {
        self.ensure_output_resolved()?;
        // Can't make streams while closing, otherwise rely on the stream
        // limits.
        match self.state {
            State::Closing { .. } | State::Draining { .. } | State::Closed { .. } => {
                return Err(Error::ConnectionState);
            }
            State::WaitInitial | State::Handshaking
                if self.role == Role::Client && self.zero_rtt_state != ZeroRttState::Sending =>
            {
                return Err(Error::ConnectionState);
            }
            // In all other states, trust that the stream limits are correct.
            _ => (),
        }

        self.streams.stream_create(st)
    }

    /// Set the priority of a stream.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` the stream does not exist.
    pub fn stream_priority(
        &mut self,
        stream_id: StreamId,
        transmission: TransmissionPriority,
        retransmission: RetransmissionPriority,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams
            .get_send_stream_mut(stream_id)?
            .set_priority(transmission, retransmission);
        Ok(())
    }

    /// Set the `SendOrder` of a stream.  Re-enqueues to keep the ordering
    /// correct
    ///
    /// # Errors
    /// When the stream does not exist.
    pub fn stream_sendorder(
        &mut self,
        stream_id: StreamId,
        sendorder: Option<SendOrder>,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.set_sendorder(stream_id, sendorder)
    }

    /// Set the Fairness of a stream
    ///
    /// # Errors
    /// When the stream does not exist.
    pub fn stream_fairness(&mut self, stream_id: StreamId, fairness: bool) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.set_fairness(stream_id, fairness)
    }

    /// # Errors
    /// When the stream does not exist.
    pub fn send_stream_stats(&self, stream_id: StreamId) -> Res<send_stream::Stats> {
        self.streams
            .get_send_stream(stream_id)
            .map(SendStream::stats)
    }

    /// # Errors
    /// When the stream does not exist.
    pub fn recv_stream_stats(&mut self, stream_id: StreamId) -> Res<recv_stream::Stats> {
        let stream = self.streams.get_recv_stream_mut(stream_id)?;

        Ok(stream.stats())
    }

    /// Send data on a stream.
    /// Returns how many bytes were successfully sent. Could be less
    /// than total, based on receiver credit space available, etc.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` the stream does not exist,
    /// `InvalidInput` if length of `data` is zero,
    /// `FinalSizeError` if the stream has already been closed.
    pub fn stream_send(&mut self, stream_id: StreamId, data: &[u8]) -> Res<usize> {
        self.ensure_output_resolved()?;
        self.streams.get_send_stream_mut(stream_id)?.send(data)
    }

    /// Send all data or nothing on a stream. May cause `DATA_BLOCKED` or
    /// `STREAM_DATA_BLOCKED` frames to be sent.
    /// Returns true if data was successfully sent, otherwise false.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` the stream does not exist,
    /// `InvalidInput` if length of `data` is zero,
    /// `FinalSizeError` if the stream has already been closed.
    pub fn stream_send_atomic(&mut self, stream_id: StreamId, data: &[u8]) -> Res<bool> {
        self.ensure_output_resolved()?;
        let val = self
            .streams
            .get_send_stream_mut(stream_id)?
            .send_atomic(data);
        if let Ok(val) = val {
            debug_assert!(
                val == 0 || val == data.len(),
                "Unexpected value {val} when trying to send {} bytes atomically",
                data.len()
            );
        }
        val.map(|v| v == data.len())
    }

    /// Bytes that `stream_send()` is guaranteed to accept for sending.
    /// i.e. that will not be blocked by flow credits or send buffer max
    /// capacity.
    /// # Errors
    /// When the stream ID is invalid.
    pub fn stream_avail_send_space(&self, stream_id: StreamId) -> Res<usize> {
        Ok(self.streams.get_send_stream(stream_id)?.avail())
    }

    /// Set low watermark for [`ConnectionEvent::SendStreamWritable`] event.
    ///
    /// Stream emits a [`crate::ConnectionEvent::SendStreamWritable`] event
    /// when:
    /// - the available sendable bytes increased to or above the watermark
    /// - and was previously below the watermark.
    ///
    /// Default value is `1`. In other words
    /// [`crate::ConnectionEvent::SendStreamWritable`] is emitted whenever the
    /// available sendable bytes was previously at `0` and now increased to `1`
    /// or more.
    ///
    /// Use this when your protocol needs at least `watermark` amount of available
    /// sendable bytes to make progress.
    ///
    /// # Errors
    /// When the stream ID is invalid.
    pub fn stream_set_writable_event_low_watermark(
        &mut self,
        stream_id: StreamId,
        watermark: NonZeroUsize,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams
            .get_send_stream_mut(stream_id)?
            .set_writable_event_low_watermark(watermark);
        Ok(())
    }

    /// Close the stream. Enqueued data will be sent.
    /// # Errors
    /// When the stream ID is invalid.
    pub fn stream_close_send(&mut self, stream_id: StreamId) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.get_send_stream_mut(stream_id)?.close();
        Ok(())
    }

    /// Abandon transmission of in-flight and future stream data.
    /// # Errors
    /// When the stream ID is invalid.
    pub fn stream_reset_send(&mut self, stream_id: StreamId, err: AppError) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.get_send_stream_mut(stream_id)?.reset(err);
        Ok(())
    }

    /// Read buffered data from stream. bool says whether read bytes includes
    /// the final data on stream.
    ///
    /// # Errors
    ///
    /// `InvalidStreamId` if the stream does not exist.
    /// `NoMoreData` if data and fin bit were previously read by the
    /// application.
    pub fn stream_recv(&mut self, stream_id: StreamId, data: &mut [u8]) -> Res<(usize, bool)> {
        self.ensure_output_resolved()?;
        self.streams.recv(stream_id, data)
    }

    /// Application is no longer interested in this stream.
    /// # Errors
    /// When the stream ID is invalid.
    pub fn stream_stop_sending(&mut self, stream_id: StreamId, err: AppError) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.stop_sending(stream_id, err)
    }

    /// Increases `max_stream_data` for a `stream_id`.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStreamId` if a stream does not exist or the receiving
    /// side is closed.
    pub fn set_stream_max_data(&mut self, stream_id: StreamId, max_data: u64) -> Res<()> {
        self.ensure_output_resolved()?;
        let stream = self.streams.get_recv_stream_mut(stream_id)?;

        stream.set_stream_max_data(max_data);
        Ok(())
    }

    /// Mark a receive stream as being important enough to keep the connection
    /// alive (if `keep` is `true`) or no longer important (if `keep` is
    /// `false`).  If any stream is marked this way, PING frames will be used to
    /// keep the connection alive, even when there is no activity.
    ///
    /// # Errors
    ///
    /// Returns `InvalidStreamId` if a stream does not exist or the receiving
    /// side is closed.
    pub fn stream_keep_alive(&mut self, stream_id: StreamId, keep: bool) -> Res<()> {
        self.ensure_output_resolved()?;
        self.streams.keep_alive(stream_id, keep)
    }
    #[must_use]
    pub const fn remote_datagram_size(&self) -> u64 {
        self.quic_datagrams.remote_datagram_size()
    }

    /// Returns the current max size of a datagram that can fit into a packet.
    /// The value will change over time depending on the encoded size of the
    /// packet number, ack frames, etc.
    ///
    /// # Errors
    /// The function returns `NotAvailable` if datagrams are not enabled.
    /// # Panics
    /// Basically never, because that unwrap won't fail.
    pub fn max_datagram_size(&self) -> Res<u64> {
        let max_dgram_size = self.quic_datagrams.remote_datagram_size();
        if max_dgram_size == 0 {
            return Err(Error::NotAvailable);
        }
        let version = self.version();
        let Some((epoch, tx)) = self
            .crypto
            .states()
            .select_tx(self.version, PacketNumberSpace::ApplicationData)
        else {
            return Err(Error::NotAvailable);
        };
        let path = self.paths.primary().ok_or(Error::NotAvailable)?;
        let mtu = path.borrow().plpmtu();
        let mut buffer = Vec::new();
        let encoder = Encoder::new_borrowed_vec(&mut buffer);

        let (_, builder, _) = Self::build_packet_header(
            &path.borrow(),
            epoch,
            encoder,
            tx,
            &self.address_validation,
            version,
            false,
            usize::MAX,
            self.loss_recovery
                .largest_acknowledged_pn(PacketNumberSpace::ApplicationData),
        );

        let data_len_possible = u64::try_from(
            mtu.saturating_sub(tx.expansion() + builder.len() + DATAGRAM_FRAME_TYPE_VARINT_LEN),
        )?;
        Ok(min(data_len_possible, max_dgram_size))
    }

    /// Queue a datagram for sending.
    ///
    /// # Errors
    ///
    /// The function returns `TooMuchData` if the supply buffer is bigger than
    /// the allowed remote datagram size. The function does not check if the
    /// datagram can fit into a packet (i.e. MTU limit). This is checked during
    /// creation of an actual packet and the datagram will be dropped if it does
    /// not fit into the packet. The app is encourage to use `max_datagram_size`
    /// to check the estimated max datagram size and to use smaller datagrams.
    /// `max_datagram_size` is just a current estimate and will change over
    /// time depending on the encoded size of the packet number, ack frames,
    /// etc.
    pub fn send_datagram<I: Into<DatagramTracking>>(&mut self, buf: Vec<u8>, id: I) -> Res<()> {
        self.ensure_output_resolved()?;
        self.quic_datagrams
            .add_datagram(buf, id.into(), &mut self.stats.borrow_mut())
    }
    /// Process one protected multicast UDP payload for an announced channel.
    ///
    /// Authenticated `STREAM` and `RESET_STREAM` frames enter the ordinary QUIC
    /// receive-stream machinery. Authenticated `DATAGRAM` frames also retain
    /// the legacy channel `DATAGRAM` queue while entering ordinary QUIC
    /// `DATAGRAM` delivery.
    ///
    /// # Errors
    ///
    /// Returns `NotAvailable` for an unknown channel, an authentication error
    /// for an invalid channel packet, or the QUIC stream error raised while
    /// applying an authenticated frame. Stream errors also close the
    /// connection in the same way as errors from unicast packets.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_process_channel_packet(
        &mut self,
        channel_id: &[u8],
        protected_packet: &[u8],
        now: Instant,
    ) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.mcquic_operation_state != crate::mcquic::OperationState::Active
            || !self.mcquic_negotiated()
        {
            return Err(Error::NotAvailable);
        }
        let released = match self
            .mcquic_channels
            .get_mut(channel_id)
            .ok_or(Error::NotAvailable)?
            .process_protected_packet_for_connection(protected_packet, now)
        {
            Ok(released) => released,
            Err(Error::McquicResourceLimit) => {
                self.limit_mcquic_channel(channel_id, now);
                return Err(Error::McquicResourceLimit);
            }
            Err(Error::McquicOwnershipViolation) => {
                self.note_mcquic_ownership_violation();
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !self.mcquic_channel_resources_within_limits() {
            self.limit_mcquic_channel(channel_id, now);
            return Err(Error::McquicResourceLimit);
        }

        match self.process_mcquic_released_packets_with_ownership(released, now) {
            Ok(()) => Ok(()),
            Err((_, Error::McquicResourceLimit)) => {
                self.limit_mcquic_channel(channel_id, now);
                Err(Error::McquicResourceLimit)
            }
            Err((frame_type, error)) => self.capture_error(None, now, frame_type, Err(error)),
        }
    }

    #[cfg(feature = "mcquic")]
    fn note_mcquic_ownership_violation(&mut self) {
        self.revoke_mcquic_operation_inner();
        self.mcquic_ownership_violation = true;
    }

    /// Pop a legacy DATAGRAM released from an authenticated channel packet.
    ///
    /// New stream-based integrations do not need this compatibility API.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_pop_channel_datagram(&mut self) -> Option<crate::mcquic::ChannelDatagram> {
        self.assert_output_resolved();
        self.mcquic_channels
            .values_mut()
            .find_map(crate::mcquic::ChannelReceiveState::pop_datagram)
    }
    /// Queue all pending channel acknowledgements for unicast delivery.
    ///
    /// # Errors
    ///
    /// Returns an error if MCQUIC is unavailable or an ACK cannot be queued.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_send_pending_acks(&mut self) -> Res<bool> {
        self.ensure_output_resolved()?;
        self.mcquic_send_acks(None)
    }

    /// Queue channel acknowledgements whose advertised delay has elapsed.
    ///
    /// # Errors
    ///
    /// Returns an error if MCQUIC is unavailable or an ACK cannot be queued.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_send_due_acks(&mut self, now: Instant) -> Res<bool> {
        self.ensure_output_resolved()?;
        self.mcquic_send_acks(Some(now))
    }

    #[cfg(feature = "mcquic")]
    fn mcquic_send_acks(&mut self, now: Option<Instant>) -> Res<bool> {
        if self.mcquic_operation_state != crate::mcquic::OperationState::Active {
            return Err(Error::NotAvailable);
        }

        let pending = self
            .mcquic_channels
            .iter()
            .filter_map(|(channel_id, channel)| {
                let ack = now.map_or_else(
                    || channel.pending_ack(),
                    |now| channel.pending_ack_if_due(now),
                );
                ack.map(|ack| (channel_id.clone(), ack))
            })
            .collect::<Vec<_>>();

        for (_, ack) in &pending {
            self.mcquic_send(crate::mcquic::Frame::Ack(ack.clone()))?;
        }
        for (channel_id, _) in &pending {
            self.mcquic_channels
                .get_mut(channel_id)
                .ok_or(Error::Internal)?
                .mark_ack_sent();
        }
        Ok(!pending.is_empty())
    }

    /// Queue an experimental MCQUIC control frame for unicast delivery.
    ///
    /// # Errors
    ///
    /// Returns `NotAvailable` if MCQUIC was not negotiated, or an encoding
    /// error if the frame is malformed.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_send(&mut self, frame: crate::mcquic::Frame) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.mcquic_operation_state != crate::mcquic::OperationState::Active
            || !self.mcquic_negotiated()
        {
            return Err(Error::NotAvailable);
        }

        let expected_sender = match self.role {
            Role::Client => crate::mcquic::Sender::Client,
            Role::Server => crate::mcquic::Sender::Server,
        };
        if frame.sender() != expected_sender {
            return Err(Error::ProtocolViolation);
        }

        self.mcquic_send.push_back(frame)
    }

    /// Queue terminal MCQUIC state after this operation has been revoked.
    ///
    /// Only zero limits and `LEFT`/`RETIRED` state generated after revocation
    /// are accepted. This keeps stale pre-revocation output from escaping.
    ///
    /// # Errors
    ///
    /// Returns an error for non-client connections, active operations,
    /// nonterminal frames, wrong-sender frames, or bounded queue exhaustion.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_send_terminal(&mut self, frame: crate::mcquic::Frame) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.role != Role::Client
            || self.mcquic_operation_state != crate::mcquic::OperationState::Revoked
            || !Self::mcquic_terminal_frame(&frame)
            || frame.sender() != crate::mcquic::Sender::Client
        {
            return Err(Error::NotAvailable);
        }
        self.mcquic_send.push_back(frame)
    }

    /// Pop the next received experimental MCQUIC control frame.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_recv(&mut self) -> Option<crate::mcquic::Frame> {
        self.assert_output_resolved();
        let pending = self.mcquic_recv.pop_front()?;
        self.mcquic_recv_bytes = self.mcquic_recv_bytes.saturating_sub(pending.encoded_len);
        Some(pending.frame)
    }

    /// Pop a channel that was locally declined due to a receiver bound.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_take_resource_limited_channel(&mut self) -> Option<Vec<u8>> {
        self.assert_output_resolved();
        self.mcquic_resource_limited_channels.pop_front()
    }
    /// Return and clear a transport-level multicast stream ownership
    /// violation.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_take_ownership_violation(&mut self) -> bool {
        self.assert_output_resolved();
        mem::take(&mut self.mcquic_ownership_violation)
    }
    /// Return whether an experimental MCQUIC control frame is ready.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub fn mcquic_readable(&self) -> bool {
        !self.mcquic_recv.is_empty()
    }

    /// Accept CONNECT negotiation for this connection-isolated operation.
    ///
    /// # Errors
    ///
    /// Returns `NotAvailable` unless a permitted client operation is pending
    /// and both peers advertised MCQUIC transport capability.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_accept_operation(&mut self, now: Instant) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.role != Role::Client
            || self.mcquic_operation_state != crate::mcquic::OperationState::Pending
            || !self.mcquic_negotiated()
        {
            return Err(Error::NotAvailable);
        }
        self.mcquic_ownership_violation = false;
        self.mcquic_operation_state = crate::mcquic::OperationState::Active;
        let pending = mem::take(&mut self.mcquic_pending_operation_controls);
        self.mcquic_pending_operation_control_bytes = 0;
        self.mcquic_pending_operation_control_started_at = None;
        for frame in pending {
            if let Err(error) = self.input_mcquic_frame(frame, now) {
                self.mcquic_revoke_operation();
                return Err(error);
            }
        }
        Ok(())
    }

    /// Bind a receive stream's ordinary application prefix to the permitted
    /// operation and release authenticated frames queued for that stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is inactive or if ordinary QUIC
    /// stream validation rejects any queued frame.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_authorize_stream(&mut self, stream_id: StreamId, now: Instant) -> Res<()> {
        self.ensure_output_resolved()?;
        if self.role != Role::Client
            || self.mcquic_operation_state != crate::mcquic::OperationState::Active
            || !stream_id.is_remote_initiated(self.role)
            || !stream_id.is_uni()
        {
            return Err(Error::NotAvailable);
        }

        if self.set_mcquic_authorized_stream(stream_id, now).is_err() {
            self.mcquic_revoke_operation();
            self.mcquic_resource_limited_channels.push_back(Vec::new());
            return Ok(());
        }
        let Some(mut frames) = self.take_pending_mcquic_stream_frames(stream_id) else {
            return Ok(());
        };
        while let Some(pending) = frames.pop_front() {
            self.input_authorized_mcquic_stream_frame(pending.frame)?;
        }
        Ok(())
    }

    /// Return whether authenticated frames are waiting for a stream's ordinary
    /// application prefix to establish ownership.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub fn mcquic_has_pending_stream(&self, stream_id: StreamId) -> bool {
        self.mcquic_pending_stream_frames.contains_key(&stream_id)
    }
    /// Return stream IDs with authenticated data waiting for HTTP/3 ownership
    /// validation.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub fn mcquic_pending_stream_ids(&self) -> Vec<StreamId> {
        self.mcquic_pending_stream_frames.keys().copied().collect()
    }

    /// Pop one newly pending stream for incremental HTTP/3 ownership checking.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_take_pending_stream_owner(&mut self) -> Option<StreamId> {
        self.assert_output_resolved();
        while let Some(stream_id) = self.mcquic_pending_owner_checks.pop_first() {
            if self.mcquic_pending_stream_frames.contains_key(&stream_id) {
                return Some(stream_id);
            }
        }
        None
    }

    /// Retire all operation ownership state associated with a closed stream.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_retire_stream(&mut self, stream_id: StreamId) {
        self.assert_output_resolved();
        self.take_pending_mcquic_stream_frames(stream_id);
        self.remove_mcquic_authorized_stream(stream_id);
    }

    /// Revoke or decline this connection-isolated operation permanently.
    #[cfg(feature = "mcquic")]
    pub fn mcquic_revoke_operation(&mut self) {
        self.assert_output_resolved();
        self.revoke_mcquic_operation_inner();
    }

    /// Fallible revocation entry point for embedders that cannot unwind across
    /// an FFI boundary.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutputPending`] while tracked socket output is
    /// unresolved.
    #[cfg(feature = "mcquic")]
    pub fn try_mcquic_revoke_operation(&mut self) -> Res<()> {
        self.ensure_output_resolved()?;
        self.revoke_mcquic_operation_inner();
        Ok(())
    }

    #[cfg(feature = "mcquic")]
    fn revoke_mcquic_operation_inner(&mut self) {
        if self.role != Role::Client {
            return;
        }
        self.mcquic_operation_state = crate::mcquic::OperationState::Revoked;
        self.mcquic_send.clear();
        self.mcquic_pending_operation_controls.clear();
        self.mcquic_pending_operation_control_bytes = 0;
        self.mcquic_pending_operation_control_started_at = None;
        self.mcquic_recv.clear();
        self.mcquic_recv_bytes = 0;
        self.mcquic_integrity_hash_lens.clear();
        self.mcquic_channels.clear();
        self.mcquic_retired_channels.clear();
        self.mcquic_resource_limited_channels.clear();
        self.mcquic_pending_channel_controls.clear();
        self.mcquic_pending_channel_control_bytes = 0;
        self.mcquic_pending_channel_control_count = 0;
        self.mcquic_pending_channel_control_started_at.clear();
        self.mcquic_pending_stream_frames.clear();
        self.mcquic_pending_owner_checks.clear();
        self.mcquic_pending_owner_expiries.clear();
        self.mcquic_pending_channel_streams.clear();
        self.mcquic_pending_channel_owner_links = 0;
        self.mcquic_authorized_streams.clear();
        self.mcquic_authorized_stream_expiries.clear();
        self.mcquic_pending_stream_bytes = 0;
        self.mcquic_pending_stream_frame_count = 0;
    }

    #[cfg(feature = "mcquic")]
    const fn mcquic_terminal_frame(frame: &crate::mcquic::Frame) -> bool {
        match frame {
            crate::mcquic::Frame::Limits(limits) => {
                !limits.limits.ipv4_channels_allowed
                    && !limits.limits.ipv6_channels_allowed
                    && limits.limits.max_aggregate_rate_kibps == 0
                    && limits.limits.max_channel_ids == 0
                    && limits.max_joined_count == 0
            }
            crate::mcquic::Frame::State(state) => matches!(
                state.state,
                crate::mcquic::ChannelState::Left | crate::mcquic::ChannelState::Retired
            ),
            _ => false,
        }
    }

    /// Return this connection's MCQUIC application authorization state.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub const fn mcquic_operation_state(&self) -> crate::mcquic::OperationState {
        self.mcquic_operation_state
    }
    /// Return whether the peer advertised MCQUIC server support.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub fn peer_mcquic_server_support(&self) -> bool {
        self.tps
            .borrow()
            .remote_handshake()
            .is_some_and(TransportParameters::get_mcquic_server_support)
    }

    /// Return the peer's MCQUIC client transport parameters, if present.
    #[cfg(feature = "mcquic")]
    #[must_use]
    pub fn peer_mcquic_client_params(&self) -> Option<crate::mcquic::ClientTransportParams> {
        self.tps
            .borrow()
            .remote_handshake()
            .and_then(TransportParameters::get_mcquic_client_params)
            .cloned()
    }

    /// Return the PLMTU of the primary path.
    ///
    /// # Panics
    ///
    /// The function panics if there is no primary path. (Should be fine for
    /// test usage.)
    #[cfg(test)]
    #[must_use]
    pub fn plpmtu(&self) -> usize {
        self.paths.primary().unwrap().borrow().plpmtu()
    }

    fn log_packet(&mut self, meta: packet::MetaData, now: Instant) {
        if log::log_enabled!(log::Level::Debug) {
            let mut s = String::new();
            let mut d = Decoder::from(meta.payload());
            while d.remaining() > 0 {
                let Ok(f) = Frame::decode(&mut d) else {
                    s.push_str(" [broken]...");
                    break;
                };
                let x = f.dump();
                if !x.is_empty() {
                    _ = write!(&mut s, "\n  {} {x}", meta.direction());
                }
            }
            qdebug!("[{self}] {meta}{s}");
        }

        qlog::packet_io(&mut self.qlog, meta, now);
    }
}

impl EventProvider for Connection {
    type Event = ConnectionEvent;

    /// Return true if there are outstanding events.
    fn has_events(&self) -> bool {
        self.events.has_events()
    }

    /// Get events that indicate state changes on the connection. This method
    /// correctly handles cases where handling one event can obsolete
    /// previously-queued events, or cause new events to be generated.
    fn next_event(&mut self) -> Option<Self::Event> {
        self.assert_output_resolved();
        self.events.next_event()
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?} ", self.role)?;
        if let Some(cid) = self.odcid() {
            Display::fmt(&cid, f)
        } else {
            write!(f, "...")
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
