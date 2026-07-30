/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#![expect(clippy::missing_panics_doc, reason = "OK here")]

#[cfg(feature = "fuzzing")]
use std::time::Duration;
use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    cmp::min,
    ffi::c_void,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
    ptr,
    rc::Rc,
    slice, str,
    time::{Duration, Instant},
};
use std::sync::{
    Mutex,
    atomic::{AtomicU8, Ordering as AtomicOrdering},
};

use firefox_on_glean::{
    metrics::networking,
    private::{LocalCustomDistribution, LocalMemoryDistribution},
};
#[cfg(not(windows))]
use libc::{c_int, AF_INET, AF_INET6};
use libc::{c_uchar, size_t};
use log::debug;
use mcrx_core::{Context as McrxContext, McrxError, SourceFilter, SubscriptionConfig};
use neqo_common::{
    datagram, event::Provider as _, qdebug, qerror, qlog::Qlog, qwarn, Datagram, Decoder, Encoder,
    Header, Role, Tos,
};
use neqo_http3::{
    features::extended_connect::session, ConnectUdpEvent, Error as Http3Error, Http3Client,
    Http3ClientEvent, Http3Parameters, Http3State, Priority, WebTransportEvent,
};
use neqo_transport::{
    stream_id::StreamType, CongestionControl, Connection, ConnectionParameters,
    Error as TransportError, HyStartCssBaseline, OutputBatch, OutputToken,
    RandomConnectionIdGenerator, SlowStart, StreamId, Version,
};
use nserror::{
    nsresult, NS_BASE_STREAM_WOULD_BLOCK, NS_ERROR_CONNECTION_REFUSED,
    NS_ERROR_DOM_INVALID_HEADER_NAME, NS_ERROR_FILE_ALREADY_EXISTS, NS_ERROR_FILE_TOO_BIG,
    NS_ERROR_ILLEGAL_VALUE, NS_ERROR_INVALID_ARG, NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    NS_ERROR_NET_INTERRUPT, NS_ERROR_NET_RESET, NS_ERROR_NET_TIMEOUT, NS_ERROR_NOT_AVAILABLE,
    NS_ERROR_NOT_CONNECTED, NS_ERROR_OUT_OF_MEMORY, NS_ERROR_SOCKET_ADDRESS_IN_USE,
    NS_ERROR_UNEXPECTED, NS_OK,
};
use nss_rs::{agent::CertificateCompressor, init, PRErrorCode};
use nsstring::{nsACString, nsCString};
use thin_vec::ThinVec;
use uuid::Uuid;
#[cfg(windows)]
use winapi::{
    ctypes::c_int,
    shared::ws2def::{AF_INET, AF_INET6},
};
use xpcom::{AtomicRefcnt, RefCounted, RefPtr};
use zlib_rs::{decompress_slice, InflateConfig, ReturnCode};

std::thread_local! {
  static RECV_BUF : RefCell<neqo_udp::RecvBuf> =
                        RefCell::new (neqo_udp::RecvBuf::default());
}

#[cfg(target_vendor = "apple")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(target_vendor = "apple")]
static APPLE_FAST_PATH: AtomicBool = AtomicBool::new(false);

#[allow(clippy::cast_possible_truncation, reason = "see check below")]
const AF_INET_U16: u16 = AF_INET as u16;
static_assertions::const_assert_eq!(AF_INET_U16 as c_int, AF_INET);

#[allow(clippy::cast_possible_truncation, reason = "see check below")]
const AF_INET6_U16: u16 = AF_INET6 as u16;
static_assertions::const_assert_eq!(AF_INET6_U16 as c_int, AF_INET6);

#[repr(C)]
pub struct WouldBlockCounter {
    rx: usize,
    tx: usize,
}

impl WouldBlockCounter {
    pub fn new() -> Self {
        Self { rx: 0, tx: 0 }
    }

    pub fn increment_rx(&mut self) {
        self.rx += 1;
    }

    pub fn increment_tx(&mut self) {
        self.tx += 1;
    }

    pub fn rx_count(&self) -> usize {
        self.rx
    }

    pub fn tx_count(&self) -> usize {
        self.tx
    }
}

#[repr(C)]
pub struct NeqoHttp3Conn {
    conn: Http3Client,
    local_addr: SocketAddr,
    refcnt: AtomicRefcnt,
    /// Socket to use for IO.
    ///
    /// When [`None`], NSPR is used for IO.
    //
    // Use a `BorrowedSocket` instead of e.g. `std::net::UdpSocket`. The
    // latter would close the file descriptor on `Drop`. The lifetime of the
    // underlying OS socket is managed not by `neqo_glue` but `NSPR`.
    socket: Option<neqo_udp::Socket<BorrowedSocket>>,
    /// Tentative output retained after a socket `WouldBlock` result.
    buffered_outbound_datagram: Option<BufferedTrackedOutput>,

    #[cfg(feature = "mcquic")]
    mcquic_client_limits: Option<neqo_transport::mcquic::ClientLimits>,

    datagram_segment_size_sent: LocalMemoryDistribution<'static>,
    datagram_segment_size_received: LocalMemoryDistribution<'static>,
    datagram_size_sent: LocalMemoryDistribution<'static>,
    datagram_size_received: LocalMemoryDistribution<'static>,
    datagram_segments_sent: LocalCustomDistribution<'static>,
    datagram_segments_received: LocalCustomDistribution<'static>,
    would_block_counter: WouldBlockCounter,
    test_drop_abandon_observer: bool,
}

struct BufferedTrackedOutput {
    batch: datagram::Batch,
    token: OutputToken,
    segment_count: usize,
    generated_at: Instant,
}

impl Drop for NeqoHttp3Conn {
    fn drop(&mut self) {
        let abandoned = self.abandon_buffered_output(Instant::now());
        if let Err(err) = &abandoned {
            qerror!("failed to abandon tracked output during connection drop: {err}");
        }
        self.record_test_drop_abandon_result(&abandoned);
        self.record_stats_in_glean();
    }
}

static TEST_DROP_ABANDON_RESULT: AtomicU8 = AtomicU8::new(0);
static TEST_DROP_GLEAN_STATS: Mutex<Option<NeqoGlueTestCommittedStats>> = Mutex::new(None);

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NeqoGlueTestCommittedStats {
    pub available: bool,
    pub packets_tx: usize,
    pub pmtud_tx: usize,
    pub frames_tx: usize,
    pub ecn_tx: u64,
    pub ecn_path_validation: u64,
}

// Opaque interface to mozilla::net::NetAddr defined in DNS.h
#[repr(C)]
pub union NetAddr {
    private: [u8; 0],
}
#[repr(C)]
pub struct McquicMcrxReceiver {
    context: McrxContext,
}
#[repr(C)]
pub struct McquicMcrxPacket {
    pub subscription_id: u64,
    pub source_ip: nsCString,
    pub source_port: u16,
    pub group_ip: nsCString,
    pub dst_port: u16,
    pub socket_local_ip: nsCString,
    pub socket_local_port: u16,
    pub configured_interface_ip: nsCString,
    pub has_configured_interface_index: bool,
    pub configured_interface_index: u32,
    pub destination_local_ip: nsCString,
    pub has_ingress_interface_index: bool,
    pub ingress_interface_index: u32,
    pub payload: ThinVec<u8>,
}

impl Default for McquicMcrxPacket {
    fn default() -> Self {
        Self {
            subscription_id: 0,
            source_ip: nsCString::new(),
            source_port: 0,
            group_ip: nsCString::new(),
            dst_port: 0,
            socket_local_ip: nsCString::new(),
            socket_local_port: 0,
            configured_interface_ip: nsCString::new(),
            has_configured_interface_index: false,
            configured_interface_index: 0,
            destination_local_ip: nsCString::new(),
            has_ingress_interface_index: false,
            ingress_interface_index: 0,
            payload: ThinVec::new(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McquicControlFrameTag {
    NoFrame,
    Announce,
    Key,
    Integrity,
    Join,
    Leave,
    Retire,
    State,
    Ack,
    Limits,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McquicChannelStateExternal {
    Left,
    DeclinedJoin,
    Joined,
    Retired,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McquicOperationPolicyExternal {
    Prohibit,
    Allow,
}

#[repr(C)]
pub struct McquicControlFrameExternal {
    pub tag: McquicControlFrameTag,
    pub channel_id: ThinVec<u8>,
    pub source_ip: nsCString,
    pub group_ip: nsCString,
    pub udp_port: u16,
    pub address_family: u8,
    pub max_rate_kibps: u64,
    pub key_sequence: u64,
    pub packet_number_start: u64,
    pub packet_hash_count: u64,
    pub largest_acknowledged: u64,
    pub state_sequence: u64,
    pub limits_sequence: u64,
    pub channel_state: u8,
}

impl Default for McquicControlFrameExternal {
    fn default() -> Self {
        Self {
            tag: McquicControlFrameTag::NoFrame,
            channel_id: ThinVec::new(),
            source_ip: nsCString::new(),
            group_ip: nsCString::new(),
            udp_port: 0,
            address_family: 0,
            max_rate_kibps: 0,
            key_sequence: 0,
            packet_number_start: 0,
            packet_hash_count: 0,
            largest_acknowledged: 0,
            state_sequence: 0,
            limits_sequence: 0,
            channel_state: 0,
        }
    }
}

#[repr(C)]
pub struct McquicChannelDatagram {
    pub channel_id: ThinVec<u8>,
    pub packet_number: u64,
    pub payload: ThinVec<u8>,
}

impl Default for McquicChannelDatagram {
    fn default() -> Self {
        Self {
            channel_id: ThinVec::new(),
            packet_number: 0,
            payload: ThinVec::new(),
        }
    }
}

#[repr(C)]
pub struct McquicSendPendingAcksResult {
    pub result: nsresult,
    pub sent: bool,
}

fn parse_mcquic_mcrx_ip(value: &nsACString) -> Result<IpAddr, nsresult> {
    str::from_utf8(value)
        .map_err(|_| NS_ERROR_INVALID_ARG)?
        .parse()
        .map_err(|_| NS_ERROR_INVALID_ARG)
}

fn parse_optional_mcquic_mcrx_ip(value: &nsACString) -> Result<Option<IpAddr>, nsresult> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_mcquic_mcrx_ip(value).map(Some)
    }
}

fn mcquic_mcrx_error_to_nsresult(err: &McrxError) -> nsresult {
    match err {
        McrxError::InvalidDestinationPort
        | McrxError::InvalidMulticastGroup
        | McrxError::InvalidSourceAddress
        | McrxError::InvalidIpv4SsmGroup
        | McrxError::InvalidIpv6SsmGroup
        | McrxError::SourceAddressFamilyMismatch
        | McrxError::InterfaceAddressFamilyMismatch
        | McrxError::InvalidInterfaceIndex
        | McrxError::InterfaceIndexRequiresIpv6
        | McrxError::ExistingSocketAddressFamilyMismatch
        | McrxError::ExistingSocketPortMismatch { .. } => NS_ERROR_INVALID_ARG,
        McrxError::DuplicateSubscription | McrxError::SubscriptionAlreadyJoined => {
            NS_ERROR_FILE_ALREADY_EXISTS
        }
        McrxError::SubscriptionNotFound | McrxError::SubscriptionNotJoined => {
            NS_ERROR_NOT_AVAILABLE
        }
        McrxError::SocketBindFailed(_) => NS_ERROR_SOCKET_ADDRESS_IN_USE,
        _ => NS_ERROR_UNEXPECTED,
    }
}

fn socket_addr_ip_string(addr: Option<SocketAddr>) -> nsCString {
    addr.map_or_else(nsCString::new, |addr| {
        nsCString::from(addr.ip().to_string())
    })
}

fn ip_string(addr: Option<IpAddr>) -> nsCString {
    addr.map_or_else(nsCString::new, |addr| nsCString::from(addr.to_string()))
}

fn fill_mcquic_mcrx_packet(out: &mut McquicMcrxPacket, packet: mcrx_core::PacketWithMetadata) {
    let source = packet.packet.source;
    let socket_local_addr = packet.metadata.socket_local_addr;

    out.subscription_id = packet.packet.subscription_id.0;
    out.source_ip = nsCString::from(source.ip().to_string());
    out.source_port = source.port();
    out.group_ip = nsCString::from(packet.packet.group.to_string());
    out.dst_port = packet.packet.dst_port;
    out.socket_local_ip = socket_addr_ip_string(socket_local_addr);
    out.socket_local_port = socket_local_addr.map_or(0, |addr| addr.port());
    out.configured_interface_ip = ip_string(packet.metadata.configured_interface);
    out.has_configured_interface_index = packet.metadata.configured_interface_index.is_some();
    out.configured_interface_index = packet.metadata.configured_interface_index.unwrap_or(0);
    out.destination_local_ip = ip_string(packet.metadata.destination_local_ip);
    out.has_ingress_interface_index = packet.metadata.ingress_interface_index.is_some();
    out.ingress_interface_index = packet.metadata.ingress_interface_index.unwrap_or(0);
    out.payload = packet.packet.payload.as_ref().into();
}

#[cfg(feature = "mcquic")]
fn default_mcquic_client_limits() -> neqo_transport::mcquic::ClientLimits {
    neqo_transport::mcquic::ClientLimits {
        ipv4_channels_allowed: true,
        ipv6_channels_allowed: true,
        max_aggregate_rate_kibps: 100_000,
        max_channel_ids: 32,
    }
}

#[cfg(feature = "mcquic")]
fn mcquic_transport_error_to_nsresult(err: neqo_transport::Error) -> nsresult {
    match err {
        neqo_transport::Error::NotAvailable => NS_ERROR_NOT_AVAILABLE,
        neqo_transport::Error::McquicResourceLimit => NS_ERROR_FILE_TOO_BIG,
        neqo_transport::Error::FrameEncoding
        | neqo_transport::Error::InvalidInput
        | neqo_transport::Error::ProtocolViolation
        | neqo_transport::Error::UnknownFrameType => NS_ERROR_INVALID_ARG,
        neqo_transport::Error::Decrypt | neqo_transport::Error::InvalidPacket => {
            NS_ERROR_NET_HTTP3_PROTOCOL_ERROR
        }
        _ => NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    }
}

#[cfg(feature = "mcquic")]
fn mcquic_http3_error_to_nsresult(err: Http3Error) -> nsresult {
    match err {
        Http3Error::Transport(err) => mcquic_transport_error_to_nsresult(err),
        Http3Error::InvalidInput => NS_ERROR_INVALID_ARG,
        Http3Error::Unavailable => NS_ERROR_NOT_AVAILABLE,
        _ => NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    }
}

#[cfg(feature = "mcquic")]
fn set_mcquic_control_channel_id(out: &mut McquicControlFrameExternal, channel_id: &[u8]) {
    out.channel_id = channel_id.into();
}

#[cfg(feature = "mcquic")]
fn fill_mcquic_control_frame(
    out: &mut McquicControlFrameExternal,
    frame: &neqo_transport::mcquic::Frame,
) {
    *out = McquicControlFrameExternal::default();
    match frame {
        neqo_transport::mcquic::Frame::Announce(announce) => {
            out.tag = McquicControlFrameTag::Announce;
            set_mcquic_control_channel_id(out, &announce.channel_id);
            out.source_ip = nsCString::from(announce.source.to_string());
            out.group_ip = nsCString::from(announce.group.to_string());
            out.udp_port = announce.udp_port;
            out.address_family = if announce.source.is_ipv4() { 4 } else { 6 };
            out.max_rate_kibps = announce.max_rate_kibps;
        }
        neqo_transport::mcquic::Frame::Key(key) => {
            out.tag = McquicControlFrameTag::Key;
            set_mcquic_control_channel_id(out, &key.channel_id);
            out.key_sequence = key.key_sequence;
            out.packet_number_start = key.from_packet_number;
        }
        neqo_transport::mcquic::Frame::Integrity(integrity) => {
            out.tag = McquicControlFrameTag::Integrity;
            set_mcquic_control_channel_id(out, &integrity.channel_id);
            out.packet_number_start = integrity.packet_number_start;
            out.packet_hash_count = integrity.packet_hash_count.unwrap_or(0);
        }
        neqo_transport::mcquic::Frame::Join(join) => {
            out.tag = McquicControlFrameTag::Join;
            set_mcquic_control_channel_id(out, &join.channel_id);
            out.key_sequence = join.mc_key_sequence;
            out.state_sequence = join.mc_state_sequence;
            out.limits_sequence = join.mc_limits_sequence;
        }
        neqo_transport::mcquic::Frame::Leave(leave) => {
            out.tag = McquicControlFrameTag::Leave;
            set_mcquic_control_channel_id(out, &leave.channel_id);
            out.state_sequence = leave.mc_state_sequence;
            out.packet_number_start = leave.after_packet_number;
        }
        neqo_transport::mcquic::Frame::Retire(retire) => {
            out.tag = McquicControlFrameTag::Retire;
            set_mcquic_control_channel_id(out, &retire.channel_id);
            out.packet_number_start = retire.after_packet_number;
        }
        neqo_transport::mcquic::Frame::State(state) => {
            out.tag = McquicControlFrameTag::State;
            set_mcquic_control_channel_id(out, &state.channel_id);
            out.state_sequence = state.sequence;
            out.channel_state = state.state.into();
        }
        neqo_transport::mcquic::Frame::Ack(ack) => {
            out.tag = McquicControlFrameTag::Ack;
            set_mcquic_control_channel_id(out, &ack.channel_id);
            out.largest_acknowledged = ack.largest_acknowledged;
        }
        neqo_transport::mcquic::Frame::Limits(limits) => {
            out.tag = McquicControlFrameTag::Limits;
            out.state_sequence = limits.sequence;
        }
    }
}

extern "C" {
    pub fn moz_netaddr_get_family(arg: *const NetAddr) -> u16;
    pub fn moz_netaddr_get_network_order_ip(arg: *const NetAddr) -> u32;
    pub fn moz_netaddr_get_ipv6(arg: *const NetAddr) -> *const u8;
    pub fn moz_netaddr_get_network_order_port(arg: *const NetAddr) -> u16;
}

fn netaddr_to_socket_addr(arg: *const NetAddr) -> Result<SocketAddr, nsresult> {
    if arg.is_null() {
        return Err(NS_ERROR_INVALID_ARG);
    }

    unsafe {
        let family = i32::from(moz_netaddr_get_family(arg));
        if family == AF_INET {
            let port = u16::from_be(moz_netaddr_get_network_order_port(arg));
            let ipv4 = Ipv4Addr::from(u32::from_be(moz_netaddr_get_network_order_ip(arg)));
            return Ok(SocketAddr::new(IpAddr::V4(ipv4), port));
        }

        if family == AF_INET6 {
            let port = u16::from_be(moz_netaddr_get_network_order_port(arg));
            let ipv6_slice: [u8; 16] = slice::from_raw_parts(moz_netaddr_get_ipv6(arg), 16)
                .try_into()
                .expect("slice with incorrect length");
            let ipv6 = Ipv6Addr::from(ipv6_slice);
            return Ok(SocketAddr::new(IpAddr::V6(ipv6), port));
        }
    }

    Err(NS_ERROR_UNEXPECTED)
}

fn enable_zlib_decoder(c: &mut Connection) -> neqo_transport::Res<()> {
    struct ZlibCertDecoder {}

    impl CertificateCompressor for ZlibCertDecoder {
        // RFC 8879
        const ID: u16 = 0x1;
        const NAME: &std::ffi::CStr = c"zlib";

        fn decode(input: &[u8], output: &mut [u8]) -> nss_rs::Res<()> {
            let (output_slice, error) = decompress_slice(output, &input, InflateConfig::default());
            if error != ReturnCode::Ok {
                return Err(nss_rs::Error::CertificateDecoding);
            }
            if output_slice.len() != output.len() {
                return Err(nss_rs::Error::CertificateDecoding);
            }

            Ok(())
        }
    }

    c.set_certificate_compression::<ZlibCertDecoder>()
}

extern "C" {
    pub fn ZSTD_decompress(
        dst: *mut ::core::ffi::c_void,
        dstCapacity: usize,
        src: *const ::core::ffi::c_void,
        compressedSize: usize,
    ) -> usize;
}

extern "C" {
    pub fn ZSTD_isError(result: usize) -> ::core::ffi::c_uint;
}

fn enable_zstd_decoder(c: &mut Connection) -> neqo_transport::Res<()> {
    struct ZstdCertDecoder {}

    impl CertificateCompressor for ZstdCertDecoder {
        // RFC 8879
        const ID: u16 = 0x3;
        const NAME: &std::ffi::CStr = c"zstd";

        fn decode(input: &[u8], output: &mut [u8]) -> nss_rs::Res<()> {
            if input.is_empty() {
                return Err(nss_rs::Error::CertificateDecoding);
            }
            if output.is_empty() {
                return Err(nss_rs::Error::CertificateDecoding);
            }

            let output_len = unsafe {
                ZSTD_decompress(
                    output.as_mut_ptr() as *mut c_void,
                    output.len(),
                    input.as_ptr() as *const c_void,
                    input.len(),
                )
            };

            // ZSTD_isError return 1 if error, 0 otherwise
            if unsafe { ZSTD_isError(output_len) != 0 } {
                qdebug!("zstd compression failed with {output_len}");
                return Err(nss_rs::Error::CertificateDecoding);
            }

            if output.len() != output_len {
                qdebug!(
                    "zstd compression `output_len` {output_len} doesn't match expected `output.len()` {}",
                    output.len()
                );
                return Err(nss_rs::Error::CertificateDecoding);
            }

            Ok(())
        }
    }

    c.set_certificate_compression::<ZstdCertDecoder>()
}

#[repr(C)]
#[derive(Debug, PartialEq)]
pub enum BrotliDecoderResult {
    Error = 0,
    Success = 1,
    NeedsMoreInput = 2,
    NeedsMoreOutput = 3,
}

extern "C" {
    pub fn BrotliDecoderDecompress(
        encoded_size: size_t,
        encoded_buffer: *const c_uchar,
        decoded_size: *mut size_t,
        decoded_buffer: *mut c_uchar,
    ) -> BrotliDecoderResult;
}

fn enable_brotli_decoder(c: &mut Connection) -> neqo_transport::Res<()> {
    struct BrotliCertDecoder {}

    impl CertificateCompressor for BrotliCertDecoder {
        // RFC 8879
        const ID: u16 = 0x2;
        const NAME: &std::ffi::CStr = c"brotli";

        fn decode(input: &[u8], output: &mut [u8]) -> nss_rs::Res<()> {
            if input.is_empty() {
                return Err(nss_rs::Error::CertificateDecoding);
            }
            if output.is_empty() {
                return Err(nss_rs::Error::CertificateDecoding);
            }

            let mut uncompressed_size = output.len();
            let result = unsafe {
                BrotliDecoderDecompress(
                    input.len(),
                    input.as_ptr(),
                    &mut uncompressed_size as *mut usize,
                    output.as_mut_ptr(),
                )
            };

            if result != BrotliDecoderResult::Success {
                return Err(nss_rs::Error::CertificateDecoding);
            }

            if uncompressed_size != output.len() {
                return Err(nss_rs::Error::CertificateDecoding);
            }

            Ok(())
        }
    }

    c.set_certificate_compression::<BrotliCertDecoder>()
}

#[repr(C)]
pub struct SendResult {
    pub result: nsresult,
    pub bytes_written: u32,
}

type SendFunc = extern "C" fn(
    context: *mut c_void,
    addr_family: u16,
    addr: *const u8,
    port: u16,
    data: *const u8,
    size: u32,
) -> SendResult;

type SetTimerFunc = extern "C" fn(context: *mut c_void, timeout: u64);

#[cfg(feature = "mcquic")]
const MCQUIC_INITIAL_MAX_STREAMS_UNI: u64 = 1 << 30;

#[cfg(unix)]
type BorrowedSocket = std::os::fd::BorrowedFd<'static>;
#[cfg(windows)]
type BorrowedSocket = std::os::windows::io::BorrowedSocket<'static>;

impl NeqoHttp3Conn {
    /// Create a new [`NeqoHttp3Conn`].
    ///
    /// Note that [`NeqoHttp3Conn`] works under the assumption that the UDP
    /// socket of the connection, i.e. the one provided to
    /// [`NeqoHttp3Conn::new`], does not change throughout the lifetime of
    /// [`NeqoHttp3Conn`].
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "Nothing to be done about it."
    )]
    fn new(
        origin: &nsACString,
        alpn: &nsACString,
        local_addr: *const NetAddr,
        remote_addr: *const NetAddr,
        max_table_size: u64,
        max_blocked_streams: u16,
        max_data: u64,
        max_stream_data: u64,
        version_negotiation: bool,
        webtransport: bool,
        mcquic_policy: McquicOperationPolicyExternal,
        qlog_dir: &nsACString,
        idle_timeout: u32,
        fast_pto: u32,
        pmtud_enabled: bool,
        socket: Option<i64>,
    ) -> Result<RefPtr<Self>, nsresult> {
        // Nss init.
        init().map_err(|_| NS_ERROR_UNEXPECTED)?;
        #[cfg(not(feature = "mcquic"))]
        let _ = mcquic_policy;

        let socket = socket
            .map(|socket| {
                #[cfg(unix)]
                let borrowed = {
                    use std::os::fd::{BorrowedFd, RawFd};
                    if socket == -1 {
                        qerror!("got invalid socked {}", socket);
                        return Err(NS_ERROR_INVALID_ARG);
                    }
                    let raw: RawFd = socket.try_into().map_err(|e| {
                        qerror!("got invalid socked {}: {}", socket, e);
                        NS_ERROR_INVALID_ARG
                    })?;
                    unsafe { BorrowedFd::borrow_raw(raw) }
                };
                #[cfg(windows)]
                let borrowed = {
                    use std::os::windows::io::{BorrowedSocket, RawSocket};
                    if socket as usize == winapi::um::winsock2::INVALID_SOCKET {
                        qerror!("got invalid socked {}", socket);
                        return Err(NS_ERROR_INVALID_ARG);
                    }
                    let raw: RawSocket = socket.try_into().map_err(|e| {
                        qerror!("got invalid socked {}: {}", socket, e);
                        NS_ERROR_INVALID_ARG
                    })?;
                    unsafe { BorrowedSocket::borrow_raw(raw) }
                };
                let s = neqo_udp::Socket::new(borrowed).map_err(|e| {
                    qerror!("failed to initialize socket {}: {}", socket, e);
                    into_nsresult(&e)
                })?;
                // Called after Socket::new (which sets up IP_RECVTOS etc.) since
                // enable_apple_fast_path only sets the fast-path flag on the
                // already-constructed UdpSocketState.
                #[cfg(target_vendor = "apple")]
                if APPLE_FAST_PATH.load(Ordering::Relaxed)
                    && static_prefs::pref!("network.http.http3.apple_fast_datapath")
                {
                    // SAFETY: The probe has verified the APIs work on this OS version.
                    unsafe { s.enable_apple_fast_path() }
                }
                Ok(s)
            })
            .transpose()?;

        let origin_conv = str::from_utf8(origin).map_err(|_| NS_ERROR_INVALID_ARG)?;

        let alpn_conv = str::from_utf8(alpn).map_err(|_| NS_ERROR_INVALID_ARG)?;

        let local: SocketAddr = netaddr_to_socket_addr(local_addr)?;

        let remote: SocketAddr = netaddr_to_socket_addr(remote_addr)?;

        let quic_version = match alpn_conv {
            "h3" => Version::Version1,
            _ => return Err(NS_ERROR_INVALID_ARG),
        };

        let version_list = if version_negotiation {
            Version::all()
        } else {
            vec![quic_version]
        };

        let cc_algorithm = match static_prefs::pref!("network.http.http3.cc_algorithm") {
            0 => CongestionControl::NewReno,
            1 => CongestionControl::Cubic,
            _ => {
                // Unknown preferences; default to Cubic
                CongestionControl::Cubic
            }
        };

        let slow_start = match static_prefs::pref!("network.http.http3.slow_start_algorithm") {
            0 => SlowStart::Classic,
            1 => SlowStart::HyStart,
            2 => SlowStart::Search,
            _ => {
                // Unknown preferences; default to Classic
                debug!("Unknown http3.slow_start_algorithm pref, defaulting to SlowStart::Classic");
                SlowStart::Classic
            }
        };

        let pmtud_enabled =
    // Check if PMTUD is explicitly enabled,
    pmtud_enabled
    // or enabled via pref,
    || static_prefs::pref !("network.http.http3.pmtud")
           // but disable PMTUD if NSPR is used (socket == None) or
           // transmitted UDP datagrams might get fragmented by the IP layer.
           && socket.as_ref().map_or(false, | s | !s.may_fragment());

        let spurious_recovery = static_prefs::pref!("network.http.http3.spurious_recovery");
        let ecn_enabled = socket.is_some() && static_prefs::pref!("network.http.http3.ecn_mark");

        let css_baseline =
            if static_prefs::pref!("network.http.http3.hystart_alternative_css_baseline") {
                HyStartCssBaseline::EntryThreshold
            } else {
                HyStartCssBaseline::CurrentRoundMinRtt
            };

        let mut params = ConnectionParameters::default()
            .versions(quic_version, version_list)
            .congestion_control(cc_algorithm)
            .slow_start(slow_start)
            .max_data(max_data)
            .max_stream_data(StreamType::BiDi, false, max_stream_data)
            .grease(static_prefs::pref!("security.tls.grease_http3_enable"))
            .sni_slicing(static_prefs::pref!("network.http.http3.sni-slicing"))
            .idle_timeout(Duration::from_secs(idle_timeout.into()))
            // Disabled on OpenBSD. See
            // <https://bugzilla.mozilla.org/show_bug.cgi?id=1952304>.
            .pmtud_iface_mtu(cfg!(not(target_os = "openbsd")))
            // MLKEM support is configured further below. By default, disable it.
            .mlkem(false)
            .ecn(ecn_enabled)
            .pmtud(pmtud_enabled)
            .spurious_recovery(spurious_recovery)
            .hystart_css_baseline(css_baseline);

        // 0 means "use neqo's spec-compliant default PTO scaling".
        if fast_pto > 0 {
            if let Ok(v) = u8::try_from(fast_pto) {
                params = params.fast_pto(v);
            } else {
                debug_assert!(false, "fast_pto value {fast_pto} exceeds u8::MAX");
            }
        }

        // Set a short timeout when fuzzing.
        #[cfg(feature = "fuzzing")]
        if static_prefs::pref!("fuzzing.necko.http3") {
            params = params.idle_timeout(Duration::from_millis(10));
        }

        #[cfg(feature = "mcquic")]
        let mcquic_client_limits = (mcquic_policy == McquicOperationPolicyExternal::Allow)
            .then(default_mcquic_client_limits);

        #[cfg(feature = "mcquic")]
        if mcquic_policy == McquicOperationPolicyExternal::Allow {
            params = params
                .max_streams(StreamType::UniDi, MCQUIC_INITIAL_MAX_STREAMS_UNI)
                .mcquic_operation_policy(neqo_transport::mcquic::OperationPolicy::Allow);
            if let Some(limits) = mcquic_client_limits.clone() {
                params = params.mcquic_client_params(Some(
                    neqo_transport::mcquic::ClientTransportParams {
                        limits,
                        hash_algorithms: vec![1],
                        encryption_algorithms: vec![0x1301],
                    },
                ));
            }
        }

        let http3_settings = Http3Parameters::default()
            .max_table_size_encoder(max_table_size)
            .max_table_size_decoder(max_table_size)
            .max_blocked_streams(max_blocked_streams)
            .max_concurrent_push_streams(0)
            .connection_parameters(params)
            .webtransport(webtransport)
            .connect(true)
            .http3_datagram(true);

        let Ok(mut conn) = Connection::new_client(
            origin_conv,
            &[alpn_conv],
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(3))),
            local,
            remote,
            http3_settings.get_connection_parameters().clone(),
            Instant::now(),
        ) else {
            return Err(NS_ERROR_INVALID_ARG);
        };

        let mut additional_shares = usize::from(static_prefs::pref!(
            "security.tls.client_hello.send_p256_keyshare"
        ));
        if static_prefs::pref!("security.tls.enable_kyber")
            && static_prefs::pref!("network.http.http3.enable_kyber")
        {
            // These operations are infallible when conn.state == State::Init.
            conn.set_groups(&[
                nss_rs::TLS_GRP_KEM_MLKEM768X25519,
                nss_rs::TLS_GRP_EC_X25519,
                nss_rs::TLS_GRP_EC_SECP256R1,
                nss_rs::TLS_GRP_EC_SECP384R1,
                nss_rs::TLS_GRP_EC_SECP521R1,
            ])
            .map_err(|_| NS_ERROR_UNEXPECTED)?;
            additional_shares += 1;
        }
        // If additional_shares == 2, send mlkem768x25519, x25519, and p256.
        // If additional_shares == 1, send {mlkem768x25519, x25519} or {x25519, p256}.
        // If additional_shares == 0, send x25519.
        conn.send_additional_key_shares(additional_shares)
            .map_err(|_| NS_ERROR_UNEXPECTED)?;

        if static_prefs::pref!("security.tls.enable_certificate_compression_zlib")
            && static_prefs::pref!("network.http.http3.enable_certificate_compression_zlib")
        {
            enable_zlib_decoder(&mut conn).map_err(|_| NS_ERROR_UNEXPECTED)?;
        }

        if static_prefs::pref!("security.tls.enable_certificate_compression_zstd")
            && static_prefs::pref!("network.http.http3.enable_certificate_compression_zstd")
        {
            enable_zstd_decoder(&mut conn).map_err(|_| NS_ERROR_UNEXPECTED)?;
        }

        if static_prefs::pref!("security.tls.enable_certificate_compression_brotli")
            && static_prefs::pref!("network.http.http3.enable_certificate_compression_brotli")
        {
            enable_brotli_decoder(&mut conn).map_err(|_| NS_ERROR_UNEXPECTED)?;
        }

        let mut conn = Http3Client::new_with_conn(conn, http3_settings);

        if !qlog_dir.is_empty() {
            let qlog_dir_conv = str::from_utf8(qlog_dir).map_err(|_| NS_ERROR_INVALID_ARG)?;
            let qlog_path = PathBuf::from(qlog_dir_conv);

            match Qlog::enabled_with_file(
                qlog_path.clone(),
                Role::Client,
                Some("Firefox Client qlog".to_string()),
                Some("Firefox Client qlog".to_string()),
                format!("{}_{}.qlog", origin, Uuid::new_v4()),
                Instant::now(),
            ) {
                Ok(qlog) => conn.set_qlog(qlog),
                Err(e) => {
                    // Emit warnings but to not return an error if qlog initialization
                    // fails.
                    qwarn!("failed to create Qlog at {}: {}", qlog_path.display(), e);
                }
            }
        }

        let conn = Box::into_raw(Box::new(Self {
            conn,
            local_addr: local,
            refcnt: unsafe { AtomicRefcnt::new() },
            socket,
            datagram_segment_size_sent: networking::http_3_udp_datagram_segment_size_sent
                .start_buffer(),
            datagram_segment_size_received: networking::http_3_udp_datagram_segment_size_received
                .start_buffer(),
            datagram_size_sent: networking::http_3_udp_datagram_size_sent.start_buffer(),
            datagram_size_received: networking::http_3_udp_datagram_size_received.start_buffer(),
            datagram_segments_sent: networking::http_3_udp_datagram_segments_sent.start_buffer(),
            datagram_segments_received: networking::http_3_udp_datagram_segments_received
                .start_buffer(),
            buffered_outbound_datagram: None,
            #[cfg(feature = "mcquic")]
            mcquic_client_limits,
            would_block_counter: WouldBlockCounter::new(),
            test_drop_abandon_observer: false,
        }));
        unsafe { RefPtr::from_raw(conn).ok_or(NS_ERROR_NOT_CONNECTED) }
    }

    fn record_stats_in_glean(&self) {
        use firefox_on_glean::metrics::networking as glean;
        use neqo_common::Ecn;
        use neqo_transport::{ecn, SlowStartExitReason};
        use std::cmp::Ordering;

        /// The biggest initial congestion window that can be set in neqo. Needs to be
        /// kept in sync with neqo.
        const MAX_INITIAL_CWND: usize = 12520;
        // Metric values must be recorded as integers. Glean does not support
        // floating point distributions. In order to represent values <1, they
        // are multiplied by `PRECISION_FACTOR`. A `PRECISION_FACTOR` of
        // `10_000` allows one to represent fractions down to 0.0001.
        const PRECISION_FACTOR: u64 = 10_000;
        #[allow(clippy::cast_possible_truncation, reason = "see check below")]
        const PRECISION_FACTOR_USIZE: usize = PRECISION_FACTOR as usize;
        static_assertions::const_assert_eq!(PRECISION_FACTOR_USIZE as u64, PRECISION_FACTOR);

        let stats = self.conn.committed_transport_stats();
        if self.test_drop_abandon_observer {
            let mut observed = TEST_DROP_GLEAN_STATS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *observed = Some(NeqoGlueTestCommittedStats::from_stats(&stats));
        }

        if stats.packets_tx == 0 {
            return;
        }

        for (s, postfix) in [(&stats.frame_tx, "_tx"), (&stats.frame_rx, "_rx")] {
            let add = |label: &str, value: usize| {
                glean::http_3_quic_frame_count
                    .get(&(label.to_string() + postfix))
                    .add(value.try_into().unwrap_or(i32::MAX));
            };

            add("ack", s.ack);
            add("crypto", s.crypto);
            add("stream", s.stream);
            add("reset_stream", s.reset_stream);
            add("stop_sending", s.stop_sending);
            add("ping", s.ping);
            add("padding", s.padding);
            add("max_streams", s.max_streams);
            add("streams_blocked", s.streams_blocked);
            add("max_data", s.max_data);
            add("data_blocked", s.data_blocked);
            add("max_stream_data", s.max_stream_data);
            add("stream_data_blocked", s.stream_data_blocked);
            add("new_connection_id", s.new_connection_id);
            add("retire_connection_id", s.retire_connection_id);
            add("path_challenge", s.path_challenge);
            add("path_response", s.path_response);
            add("connection_close", s.connection_close);
            add("handshake_done", s.handshake_done);
            add("new_token", s.new_token);
            add("ack_frequency", s.ack_frequency);
            add("datagram", s.datagram);
        }

        // Only record the metrics below for connections that established. Not
        // gating on `stats.packets_rx` as it counts garbage too, so it would
        // still admit a network that replies to every UDP packet with junk
        // without ever speaking QUIC.
        if stats.frame_rx.handshake_done == 0 {
            return;
        }

        let version_label = match stats.version {
            Version::Version1 => "v1",
            Version::Version2 => "v2",
        };
        glean::http_3_quic_version.get(version_label).add(1);

        if !static_prefs::pref!("network.http.http3.use_nspr_for_io")
            && static_prefs::pref!("network.http.http3.ecn_report")
        {
            let rx_ect0_sum: u64 = stats.ecn_rx.into_values().map(|v| v[Ecn::Ect0]).sum();
            let rx_ce_sum: u64 = stats.ecn_rx.into_values().map(|v| v[Ecn::Ce]).sum();
            if rx_ect0_sum > 0 {
                if let Ok(ratio) = i64::try_from((rx_ce_sum * PRECISION_FACTOR) / rx_ect0_sum) {
                    glean::http_3_ecn_ce_ect0_ratio_received.accumulate_single_sample_signed(ratio);
                } else {
                    let msg = "Failed to convert ratio to i64 for use with glean";
                    qwarn!("{msg}");
                    debug_assert!(false, "{msg}");
                }
            }
        }

        if !static_prefs::pref!("network.http.http3.use_nspr_for_io")
            && static_prefs::pref!("network.http.http3.ecn_mark")
        {
            let tx_ect0_sum: u64 = stats.ecn_tx_acked.into_values().map(|v| v[Ecn::Ect0]).sum();
            let tx_ce_sum: u64 = stats.ecn_tx_acked.into_values().map(|v| v[Ecn::Ce]).sum();
            if tx_ect0_sum > 0 {
                if let Ok(ratio) = i64::try_from((tx_ce_sum * PRECISION_FACTOR) / tx_ect0_sum) {
                    glean::http_3_ecn_ce_ect0_ratio_sent.accumulate_single_sample_signed(ratio);
                } else {
                    let msg = "Failed to convert ratio to i64 for use with glean";
                    qwarn!("{msg}");
                    debug_assert!(false, "{msg}");
                }
            }
            for (outcome, value) in stats.ecn_path_validation.into_iter() {
                let Ok(value) = i32::try_from(value) else {
                    let msg = format!("Failed to convert {value} to i32 for use with glean");
                    qwarn!("{msg}");
                    debug_assert!(false, "{msg}");
                    continue;
                };
                match outcome {
                    ecn::ValidationOutcome::Capable => {
                        glean::http_3_ecn_path_capability.get("capable").add(value);
                    }
                    ecn::ValidationOutcome::NotCapable(ecn::ValidationError::BlackHole) => {
                        glean::http_3_ecn_path_capability
                            .get("black-hole")
                            .add(value);
                    }
                    ecn::ValidationOutcome::NotCapable(ecn::ValidationError::Bleaching) => {
                        glean::http_3_ecn_path_capability
                            .get("bleaching")
                            .add(value);
                    }
                    ecn::ValidationOutcome::NotCapable(
                        ecn::ValidationError::ReceivedUnsentECT1,
                    ) => {
                        glean::http_3_ecn_path_capability
                            .get("received-unsent-ect-1")
                            .add(value);
                    }
                }
            }
        }

        // Calculate and collect packet loss ratio. The value is used later to also
        // record the filtered loss ratio for connections that used the congestion
        // controller.
        let loss_ratio =
            match i64::try_from((stats.lost * PRECISION_FACTOR_USIZE) / stats.packets_tx) {
                Ok(v) => {
                    glean::http_3_loss_ratio.accumulate_single_sample_signed(v);
                    Some(v)
                }
                Err(e) => {
                    qwarn!("Failed to convert ratio to i64 for use with glean: {e}");
                    debug_assert!(
                        false,
                        "Failed to convert ratio to i64 for use with glean: {e}"
                    );
                    None
                }
            };
        // Records the unfiltered (old) slow start exit ratio
        if stats.cc.slow_start_exit_cwnd.is_some() {
            glean::http_3_slow_start_exited.get("exited").add(1);
        } else {
            glean::http_3_slow_start_exited.get("not_exited").add(1);
        }

        let cwnd_that_grew = stats.cc.cwnd.filter(|&c| c > MAX_INITIAL_CWND);
        let growth_label = match (cwnd_that_grew, stats.cc.slow_start_exit_cwnd) {
            (Some(_), Some(exit_cwnd)) if exit_cwnd < MAX_INITIAL_CWND => {
                "no_growth_then_exit_then_growth"
            }
            (Some(_), _) => "had_growth",
            (None, Some(_)) => "no_growth_but_exit",
            (None, None) => "no_growth",
        };
        glean::http_3_congestion_window_growth
            .get(growth_label)
            .add(1);
        // Filtered: only record CC metrics for connections that grew past the initial
        // window.
        if let Some(final_cwnd) = cwnd_that_grew {
            glean::http_3_final_cwnd.accumulate(final_cwnd as u64);
            if let Some(loss) = loss_ratio {
                glean::http_3_loss_ratio_filtered.accumulate_single_sample_signed(loss);
            }
            // Record metrics concerning the slow start exit point below this filter.
            debug_assert_eq!(
                stats.cc.slow_start_exit_cwnd.is_some(),
                stats.cc.slow_start_exit_reason.is_some(),
                "slow_start_exit_cwnd and slow_start_exit_reason must always be set together"
            );
            let mut hystart_label = "not_exited";
            let mut search_label = "not_exited";
            if let (Some(exit_cwnd), Some(reason)) = (
                stats.cc.slow_start_exit_cwnd,
                stats.cc.slow_start_exit_reason,
            ) {
                glean::http_3_slow_start_exit_cwnd.accumulate(exit_cwnd as u64);
                glean::http_3_slow_start_exited_filtered
                    .get("exited")
                    .add(1);
                let accuracy_cwnd =
                    ((exit_cwnd.abs_diff(final_cwnd) as f64) / final_cwnd as f64) * 100.0;
                let accuracy_w_max = if let Some(final_w_max) = stats.cc.w_max {
                    assert!(final_w_max > 0.0, "w_max can never be non-positive");
                    glean::http_3_final_w_max.accumulate(final_w_max as u64);
                    Some(((exit_cwnd as f64 - final_w_max).abs() / final_w_max) * 100.0)
                } else {
                    None
                };
                let direction_label = match exit_cwnd.cmp(&final_cwnd) {
                    Ordering::Greater => "overshoot",
                    Ordering::Less => "undershoot",
                    Ordering::Equal => "exact",
                };
                let (reason_label, accuracy_label) = match reason {
                    SlowStartExitReason::CongestionEvent => {
                        glean::http_3_slow_start_exit_direction_loss
                            .get(direction_label)
                            .add(1);
                        hystart_label = "exited_ce";
                        search_label = "exited_ce";
                        ("ce", "ce_exit")
                    }
                    SlowStartExitReason::Heuristic => {
                        glean::http_3_slow_start_exit_direction_heuristic
                            .get(direction_label)
                            .add(1);
                        hystart_label = "exited_hystart";
                        search_label = "exited_search";
                        ("heuristic", "heuristic_exit")
                    }
                };
                glean::http_3_slow_start_exit_reason
                    .get(reason_label)
                    .add(1);
                glean::http_3_slow_start_exit_accuracy
                    .get(accuracy_label)
                    .accumulate_single_sample_signed(accuracy_cwnd as i64);
                if let Some(accuracy_w_max) = accuracy_w_max {
                    glean::http_3_slow_start_exit_accuracy_w_max
                        .get(accuracy_label)
                        .accumulate_single_sample_signed(accuracy_w_max as i64);
                }
            } else {
                glean::http_3_slow_start_exited_filtered
                    .get("not_exited")
                    .add(1);
            }
            // Only record HyStart metrics when HyStart is enabled (1 == HyStart, see
            // constructor).
            if static_prefs::pref!("network.http.http3.slow_start_algorithm") == 1 {
                glean::http_3_hystart_css_rounds_finished
                    .get(hystart_label)
                    .accumulate_single_sample_signed(stats.cc.hystart_css_rounds_finished as i64);
                glean::http_3_hystart_css_entries
                    .get(hystart_label)
                    .accumulate_single_sample_signed(stats.cc.hystart_css_entries as i64);
            }

            // Only record SEARCH metrics when SEARCH is enabled (2 == SEARCH, see
            // constructor).
            if static_prefs::pref!("network.http.http3.slow_start_algorithm") == 2 {
                // Metrics for drain phase evaluation
                if let Some(empty_buffer_bdp) = stats.cc.search_empty_buffer_target {
                    glean::http_3_search_empty_buffer_bdp_estimate.accumulate(empty_buffer_bdp);
                }
                if let Some(full_buffer_bdp) = stats.cc.search_full_buffer_target {
                    glean::http_3_search_full_buffer_bdp_estimate.accumulate(full_buffer_bdp);
                }
                // Metrics to tune EXTRA_BINS
                if let Some(lookback_bins) = stats.cc.search_lookback_bins_needed {
                    glean::http_3_search_lookback_bins
                        .accumulate_single_sample_signed(lookback_bins as i64);
                    glean::http_3_search_rtt_inflated.get("inflated").add(1);
                } else {
                    glean::http_3_search_rtt_inflated
                        .get("never_inflated")
                        .add(1);
                }
                // Metrics to tune THRESH
                if let Some(max_norm_diff) = stats.cc.search_max_norm_diff {
                    glean::http_3_search_max_norm_diff
                        .get(search_label)
                        .accumulate_single_sample_signed(max_norm_diff as i64);
                }
                // Metrics to calibrate reset mechanism
                glean::http_3_search_reset_count
                    .get(search_label)
                    .accumulate_single_sample_signed(stats.cc.search_reset.count as i64);
                if let Some(max_passed_bins) = stats.cc.search_reset.max_passed_bins {
                    glean::http_3_search_max_passed_bins
                        .accumulate_single_sample_signed(max_passed_bins as i64);
                }
                // Metrics to gain insights into app-limited behavior during SEARCH slow
                // start
                glean::http_3_search_zero_bytes_sent
                    .get(search_label)
                    .accumulate_single_sample_signed(stats.cc.search_zero_sent_bytes as i64);

                // Metrics to evaluate whether the first RTT used to initialize SEARCH is
                // inflated
                if let Some(first_rtt) = stats.cc.search_first_rtt {
                    let first_us = u64::try_from(first_rtt.as_micros()).unwrap_or(u64::MAX);
                    let min_us = u64::try_from(stats.min_rtt.as_micros()).unwrap_or(u64::MAX);
                    if min_us > 0 {
                        glean::http_3_search_first_rtt_vs_min_rtt
                            .accumulate_single_sample_signed((first_us * 100 / min_us) as i64);
                    }
                    // And whether using `min(first, second)` would be a viable fix
                    if let Some(second_rtt) = stats.cc.search_second_rtt {
                        let second_us = u64::try_from(second_rtt.as_micros()).unwrap_or(u64::MAX);
                        if second_us > 0 {
                            glean::http_3_search_first_rtt_vs_second_rtt
                                .accumulate_single_sample_signed(
                                    (first_us * 100 / second_us) as i64,
                                );
                        }
                    }
                }
            }
        }

        glean::http_3_congestion_event_count.accumulate_single_sample_signed(
            (stats.cc.congestion_events.ecn + stats.cc.congestion_events.loss)
                .saturating_sub(stats.cc.congestion_events.spurious) as i64,
        );

        if let Some(peer_max) = stats.pmtud_peer_max_udp_payload {
            if let Ok(v) = i64::try_from(peer_max) {
                glean::http_3_peer_max_udp_payload.accumulate_single_sample_signed(v);
            }
        }

        let rtt_ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        glean::http_3_rtt.accumulate_single_sample_signed(rtt_ms(stats.rtt));
        glean::http_3_rtt_var.accumulate_single_sample_signed(rtt_ms(stats.rttvar));
        glean::http_3_min_rtt.accumulate_single_sample_signed(rtt_ms(stats.min_rtt));

        // Ignore connections that never had loss induced congestion events (and prevent
        // dividing by zero).
        if stats.cc.congestion_events.loss != 0 {
            if let Ok(spurious) = i64::try_from(
                (stats.cc.congestion_events.spurious * PRECISION_FACTOR_USIZE)
                    / stats.cc.congestion_events.loss,
            ) {
                glean::http_3_spurious_congestion_event_ratio
                    .accumulate_single_sample_signed(spurious);
            } else {
                let msg = "Failed to convert ratio to i64 for use with glean";
                qwarn!("{msg}");
                debug_assert!(false, "{msg}");
            }
        }

        // Collect congestion event reason metric
        if let Ok(ce_loss) = i32::try_from(stats.cc.congestion_events.loss) {
            glean::http_3_congestion_event_reason
                .get("loss")
                .add(ce_loss);
        } else {
            let msg = "Failed to convert to i32 for use with glean";
            qwarn!("{msg}");
            debug_assert!(false, "{msg}");
        }
        if let Ok(ce_ecn) = i32::try_from(stats.cc.congestion_events.ecn) {
            glean::http_3_congestion_event_reason
                .get("ecn-ce")
                .add(ce_ecn);
        } else {
            let msg = "Failed to convert to i32 for use with glean";
            qwarn!("{msg}");
            debug_assert!(false, "{msg}");
        }
    }

    fn increment_would_block_rx(&mut self) {
        self.would_block_counter.increment_rx();
    }

    fn would_block_rx_count(&self) -> usize {
        self.would_block_counter.rx_count()
    }

    fn increment_would_block_tx(&mut self) {
        self.would_block_counter.increment_tx();
    }

    fn would_block_tx_count(&self) -> usize {
        self.would_block_counter.tx_count()
    }

    fn abandon_buffered_output(&mut self, now: Instant) -> Result<bool, Http3Error> {
        let Some(mut buffered) = self.buffered_outbound_datagram.take() else {
            return Ok(false);
        };
        self.conn.resolve_output(&mut buffered.token, 0, now)?;
        Ok(true)
    }

    fn record_test_drop_abandon_result(&self, result: &Result<bool, Http3Error>) {
        if !self.test_drop_abandon_observer {
            return;
        }
        match result {
            Ok(true) => TEST_DROP_ABANDON_RESULT.store(2, AtomicOrdering::SeqCst),
            Err(_) => TEST_DROP_ABANDON_RESULT.store(3, AtomicOrdering::SeqCst),
            Ok(false) => {
                // Preserve an abandonment already performed by the normal FFI
                // release helper. Drop repeats the operation so bypassing that
                // helper remains safe.
                let _ = TEST_DROP_ABANDON_RESULT.compare_exchange(
                    0,
                    1,
                    AtomicOrdering::SeqCst,
                    AtomicOrdering::SeqCst,
                );
            }
        }
    }
}

/// # Safety
///
/// See [`AtomicRefcnt::inc`].
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_addref(conn: &NeqoHttp3Conn) {
    conn.refcnt.inc();
}

/// # Safety
///
/// Manually drops a pointer without consuming pointee. The caller needs to
/// ensure no other referenecs remain. In addition safety conditions of
/// [`AtomicRefcnt::dec`] apply.
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_release(conn: &NeqoHttp3Conn) {
    let rc = conn.refcnt.dec();
    if rc == 0 {
        let mut conn = Box::from_raw(ptr::from_ref(conn).cast_mut());
        let abandoned = conn.abandon_buffered_output(Instant::now());
        if let Err(err) = &abandoned {
            qerror!("failed to abandon tracked output during connection destruction: {err}");
        }
        conn.record_test_drop_abandon_result(&abandoned);
        drop(conn);
    }
}

// xpcom::RefPtr support
unsafe impl RefCounted for NeqoHttp3Conn {
    unsafe fn addref(&self) {
        neqo_http3conn_addref(self);
    }
    unsafe fn release(&self) {
        neqo_http3conn_release(self);
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_new(result: &mut *mut McquicMcrxReceiver) -> nsresult {
    *result = ptr::null_mut();

    let receiver = Box::new(McquicMcrxReceiver {
        context: McrxContext::new(),
    });
    *result = Box::into_raw(receiver);
    NS_OK
}

#[no_mangle]
pub unsafe extern "C" fn neqo_mcquic_mcrx_receiver_free(receiver: *mut McquicMcrxReceiver) {
    if !receiver.is_null() {
        drop(Box::from_raw(receiver));
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_add_ssm_subscription(
    receiver: &mut McquicMcrxReceiver,
    source: &nsACString,
    group: &nsACString,
    dst_port: u16,
    interface_addr: &nsACString,
    has_interface_index: bool,
    interface_index: u32,
    subscription_id: &mut u64,
) -> nsresult {
    *subscription_id = 0;

    let source = match parse_mcquic_mcrx_ip(source) {
        Ok(source) => source,
        Err(result) => return result,
    };
    let group = match parse_mcquic_mcrx_ip(group) {
        Ok(group) => group,
        Err(result) => return result,
    };
    let interface = match parse_optional_mcquic_mcrx_ip(interface_addr) {
        Ok(interface) => interface,
        Err(result) => return result,
    };

    let config = SubscriptionConfig {
        group,
        source: SourceFilter::Source(source),
        dst_port,
        interface,
        interface_index: has_interface_index.then_some(interface_index),
    };

    match receiver.context.add_subscription(config) {
        Ok(id) => {
            *subscription_id = id.0;
            qdebug!("MCQUIC mcrx added SSM subscription {}", *subscription_id);
            NS_OK
        }
        Err(err) => {
            qwarn!("MCQUIC mcrx add SSM subscription failed: {err}");
            mcquic_mcrx_error_to_nsresult(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_join(
    receiver: &mut McquicMcrxReceiver,
    subscription_id: u64,
) -> nsresult {
    match receiver
        .context
        .join_subscription(mcrx_core::SubscriptionId(subscription_id))
    {
        Ok(()) => {
            qdebug!("MCQUIC mcrx joined subscription {subscription_id}");
            NS_OK
        }
        Err(err) => {
            qwarn!("MCQUIC mcrx join failed for subscription {subscription_id}: {err}");
            mcquic_mcrx_error_to_nsresult(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_leave(
    receiver: &mut McquicMcrxReceiver,
    subscription_id: u64,
) -> nsresult {
    match receiver
        .context
        .leave_subscription(mcrx_core::SubscriptionId(subscription_id))
    {
        Ok(()) => NS_OK,
        Err(err) => mcquic_mcrx_error_to_nsresult(&err),
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_remove(
    receiver: &mut McquicMcrxReceiver,
    subscription_id: u64,
) -> nsresult {
    if receiver
        .context
        .remove_subscription(mcrx_core::SubscriptionId(subscription_id))
    {
        NS_OK
    } else {
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_mcquic_mcrx_receiver_poll(
    receiver: &mut McquicMcrxReceiver,
    packet: &mut McquicMcrxPacket,
) -> nsresult {
    match receiver.context.try_recv_any_with_metadata() {
        Ok(Some(received)) => {
            fill_mcquic_mcrx_packet(packet, received);
            qdebug!(
                "MCQUIC mcrx received {} bytes from {}:{}",
                packet.payload.len(),
                packet.source_ip,
                packet.source_port
            );
            NS_OK
        }
        Ok(None) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(err) => {
            qwarn!("MCQUIC mcrx poll failed: {err}");
            mcquic_mcrx_error_to_nsresult(&err)
        }
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_recv_control_frame(
    conn: &mut NeqoHttp3Conn,
    frame: &mut McquicControlFrameExternal,
) -> nsresult {
    *frame = McquicControlFrameExternal::default();
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }

    #[cfg(feature = "mcquic")]
    {
        let Some(mcquic_frame) = conn.conn.mcquic_recv() else {
            return NS_OK;
        };
        fill_mcquic_control_frame(frame, &mcquic_frame);
        return NS_OK;
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_take_resource_limited_channel(
    conn: &mut NeqoHttp3Conn,
    channel_id: &mut ThinVec<u8>,
) -> bool {
    channel_id.clear();
    if abandon_output_before_mutation(conn, Instant::now()).is_err() {
        return false;
    }

    #[cfg(feature = "mcquic")]
    {
        if let Some(limited) = conn.conn.mcquic_take_resource_limited_channel() {
            channel_id.extend_from_slice(&limited);
            return true;
        }
    }

    #[cfg(not(feature = "mcquic"))]
    let _ = conn;
    false
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_process_channel_packet(
    conn: &mut NeqoHttp3Conn,
    channel_id: &nsACString,
    packet: &ThinVec<u8>,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        let channel_id = channel_id.to_vec();
        match conn.conn.mcquic_process_channel_packet(
            &channel_id,
            packet.as_slice(),
            Instant::now(),
        ) {
            Ok(()) => {
                qdebug!("MCQUIC processed protected channel packet");
                NS_OK
            }
            Err(err) => {
                qwarn!("MCQUIC failed to process protected channel packet: {err}");
                mcquic_http3_error_to_nsresult(err)
            }
        }
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, channel_id, packet);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_pop_channel_datagram(
    conn: &mut NeqoHttp3Conn,
    datagram: &mut McquicChannelDatagram,
) -> bool {
    *datagram = McquicChannelDatagram::default();
    if abandon_output_before_mutation(conn, Instant::now()).is_err() {
        return false;
    }

    #[cfg(feature = "mcquic")]
    {
        if let Some(released) = conn.conn.mcquic_pop_channel_datagram() {
            datagram.channel_id = released.channel_id.into();
            datagram.packet_number = released.packet_number;
            datagram.payload = released.data.into();
            return true;
        }
        false
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        false
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_send_limits(
    conn: &mut NeqoHttp3Conn,
    sequence: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        let Some(limits) = conn.mcquic_client_limits.clone() else {
            return NS_ERROR_NOT_AVAILABLE;
        };
        let max_joined_count = limits.max_channel_ids;
        let frame = neqo_transport::mcquic::Frame::Limits(neqo_transport::mcquic::Limits {
            sequence,
            limits,
            max_joined_count,
        });
        match conn.conn.mcquic_send(frame) {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        }
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, sequence);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_send_zero_limits(
    conn: &mut NeqoHttp3Conn,
    sequence: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        let limits = neqo_transport::mcquic::ClientLimits {
            ipv4_channels_allowed: false,
            ipv6_channels_allowed: false,
            max_aggregate_rate_kibps: 0,
            max_channel_ids: 0,
        };
        let frame = neqo_transport::mcquic::Frame::Limits(neqo_transport::mcquic::Limits {
            sequence,
            limits,
            max_joined_count: 0,
        });
        return match if conn.conn.mcquic_operation_state()
            == neqo_transport::mcquic::OperationState::Revoked
        {
            conn.conn.mcquic_send_terminal(frame)
        } else {
            conn.conn.mcquic_send(frame)
        } {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        };
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, sequence);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_accept_operation(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
) -> nsresult {
    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        return match conn
            .conn
            .mcquic_accept_operation(StreamId::from(session_id), now)
        {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        };
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, session_id);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_authorize_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    session_id: u64,
) -> nsresult {
    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        return match conn
            .conn
            .mcquic_authorize_stream(
                StreamId::from(stream_id),
                StreamId::from(session_id),
                now,
            )
        {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        };
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, stream_id, session_id);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_take_ownership_violation(conn: &mut NeqoHttp3Conn) -> bool {
    if abandon_output_before_mutation(conn, Instant::now()).is_err() {
        return false;
    }
    #[cfg(feature = "mcquic")]
    return conn.conn.mcquic_take_ownership_violation();

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        false
    }
}

fn tracked_output_error_to_nsresult(err: &Http3Error) -> nsresult {
    qerror!("tracked output transaction failed: {err}");
    match err {
        Http3Error::Transport(
            TransportError::OutputPending
            | TransportError::InvalidOutputToken
            | TransportError::InvalidInput,
        ) => NS_ERROR_UNEXPECTED,
        _ => NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    }
}

fn abandon_output_before_mutation(conn: &mut NeqoHttp3Conn, now: Instant) -> Result<(), nsresult> {
    conn.abandon_buffered_output(now)
        .map(|_| ())
        .map_err(|err| tracked_output_error_to_nsresult(&err))
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_abandon_output(conn: &mut NeqoHttp3Conn) -> nsresult {
    abandon_output_before_mutation(conn, Instant::now()).map_or_else(|err| err, |()| NS_OK)
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_revoke_operation(conn: &mut NeqoHttp3Conn) -> nsresult {
    #[cfg(feature = "mcquic")]
    {
        if let Err(err) = conn.abandon_buffered_output(Instant::now()) {
            qerror!("failed to abandon tracked output before MCQUIC revocation: {err}");
            return tracked_output_error_to_nsresult(&err);
        }
        return match conn.conn.try_mcquic_revoke_operation() {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        };
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_send_joined_state(
    conn: &mut NeqoHttp3Conn,
    channel_id: &nsACString,
    sequence: u64,
) -> nsresult {
    neqo_http3conn_mcquic_send_state(
        conn,
        channel_id,
        sequence,
        McquicChannelStateExternal::Joined,
        0x1,
    )
}
#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_send_state(
    conn: &mut NeqoHttp3Conn,
    channel_id: &nsACString,
    sequence: u64,
    state: McquicChannelStateExternal,
    reason_code: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    #[cfg(feature = "mcquic")]
    {
        let (state, reason_phrase) = match state {
            McquicChannelStateExternal::Left => (
                neqo_transport::mcquic::ChannelState::Left,
                b"left".as_slice(),
            ),
            McquicChannelStateExternal::DeclinedJoin => (
                neqo_transport::mcquic::ChannelState::DeclinedJoin,
                b"join declined".as_slice(),
            ),
            McquicChannelStateExternal::Joined => (
                neqo_transport::mcquic::ChannelState::Joined,
                b"joined".as_slice(),
            ),
            McquicChannelStateExternal::Retired => (
                neqo_transport::mcquic::ChannelState::Retired,
                b"retired".as_slice(),
            ),
        };
        let frame = neqo_transport::mcquic::Frame::State(neqo_transport::mcquic::State {
            channel_id: channel_id.to_vec(),
            sequence,
            state,
            reason_scope: neqo_transport::mcquic::StateReasonScope::Transport,
            reason_code,
            reason_phrase: reason_phrase.to_vec(),
        });
        match if conn.conn.mcquic_operation_state()
            == neqo_transport::mcquic::OperationState::Revoked
        {
            conn.conn.mcquic_send_terminal(frame)
        } else {
            conn.conn.mcquic_send(frame)
        } {
            Ok(()) => NS_OK,
            Err(err) => mcquic_http3_error_to_nsresult(err),
        }
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = (conn, channel_id, sequence, state, reason_code);
        NS_ERROR_NOT_AVAILABLE
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_mcquic_send_pending_acks(
    conn: &mut NeqoHttp3Conn,
) -> McquicSendPendingAcksResult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return McquicSendPendingAcksResult {
            result,
            sent: false,
        };
    }
    #[cfg(feature = "mcquic")]
    {
        match conn.conn.mcquic_send_due_acks(Instant::now()) {
            Ok(sent) => McquicSendPendingAcksResult {
                result: NS_OK,
                sent,
            },
            Err(err) => McquicSendPendingAcksResult {
                result: mcquic_http3_error_to_nsresult(err),
                sent: false,
            },
        }
    }

    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        McquicSendPendingAcksResult {
            result: NS_ERROR_NOT_AVAILABLE,
            sent: false,
        }
    }
}

// Allocate a new NeqoHttp3Conn object.
#[no_mangle]
pub extern "C" fn neqo_http3conn_new(
    origin: &nsACString,
    alpn: &nsACString,
    local_addr: *const NetAddr,
    remote_addr: *const NetAddr,
    max_table_size: u64,
    max_blocked_streams: u16,
    max_data: u64,
    max_stream_data: u64,
    version_negotiation: bool,
    webtransport: bool,
    mcquic_policy: McquicOperationPolicyExternal,
    qlog_dir: &nsACString,
    idle_timeout: u32,
    fast_pto: u32,
    socket: i64,
    pmtud_enabled: bool,
    result: &mut *const NeqoHttp3Conn,
) -> nsresult {
    *result = ptr::null_mut();

    match NeqoHttp3Conn::new(
        origin,
        alpn,
        local_addr,
        remote_addr,
        max_table_size,
        max_blocked_streams,
        max_data,
        max_stream_data,
        version_negotiation,
        webtransport,
        mcquic_policy,
        qlog_dir,
        idle_timeout,
        fast_pto,
        pmtud_enabled,
        Some(socket),
    ) {
        Ok(http3_conn) => {
            http3_conn.forget(result);
            NS_OK
        }
        Err(e) => e,
    }
}

// Allocate a new NeqoHttp3Conn object using NSPR for IO.
#[no_mangle]
pub extern "C" fn neqo_http3conn_new_use_nspr_for_io(
    origin: &nsACString,
    alpn: &nsACString,
    local_addr: *const NetAddr,
    remote_addr: *const NetAddr,
    max_table_size: u64,
    max_blocked_streams: u16,
    max_data: u64,
    max_stream_data: u64,
    version_negotiation: bool,
    webtransport: bool,
    mcquic_policy: McquicOperationPolicyExternal,
    qlog_dir: &nsACString,
    idle_timeout: u32,
    fast_pto: u32,
    result: &mut *const NeqoHttp3Conn,
) -> nsresult {
    *result = ptr::null_mut();

    match NeqoHttp3Conn::new(
        origin,
        alpn,
        local_addr,
        remote_addr,
        max_table_size,
        max_blocked_streams,
        max_data,
        max_stream_data,
        version_negotiation,
        webtransport,
        mcquic_policy,
        qlog_dir,
        idle_timeout,
        fast_pto,
        false,
        None,
    ) {
        Ok(http3_conn) => {
            http3_conn.forget(result);
            NS_OK
        }
        Err(e) => e,
    }
}

/// Process a packet.
/// packet holds packet data.
///
/// # Safety
///
/// Use of raw (i.e. unsafe) pointers as arguments.
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_process_input_use_nspr_for_io(
    conn: &mut NeqoHttp3Conn,
    remote_addr: *const NetAddr,
    packet: *const ThinVec<u8>,
) -> nsresult {
    assert!(conn.socket.is_none(), "NSPR IO path");

    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }

    let remote = match netaddr_to_socket_addr(remote_addr) {
        Ok(addr) => addr,
        Err(result) => return result,
    };
    let d = Datagram::new(
        remote,
        conn.local_addr,
        Tos::default(),
        (*packet).as_slice(),
    );
    conn.conn.process_input(d, now);
    NS_OK
}

#[repr(C)]
pub struct ProcessInputResult {
    pub result: nsresult,
    pub bytes_read: u32,
}
/// Process input, reading incoming datagrams from the socket and passing them
/// to the Neqo state machine.
///
/// # Safety
///
/// Marked as unsafe given exposition via FFI i.e. `extern "C"`.
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_process_input(
    conn: &mut NeqoHttp3Conn,
) -> ProcessInputResult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return ProcessInputResult {
            result,
            bytes_read: 0,
        };
    }
    let mut bytes_read = 0;

    RECV_BUF.with_borrow_mut(|recv_buf| {
        loop {
            let dgrams = match conn
                .socket
                .as_mut()
                .expect("non NSPR IO")
                .recv(conn.local_addr, recv_buf)
            {
                Ok(dgrams) => dgrams,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    conn.increment_would_block_rx();
                    break;
                }
                Err(e) => {
                    qwarn!("failed to receive datagrams: {}", e);
                    return ProcessInputResult {
                        result: into_nsresult(&e),
                        bytes_read: 0,
                    };
                }
            };

            // Attach metric instrumentation to `dgrams` iterator.
            let mut sum = 0;
            let mut segment_count = 0;
            let datagram_segment_size_received = &mut conn.datagram_segment_size_received;
            let dgrams = dgrams.inspect(|d| {
                datagram_segment_size_received.accumulate(d.len() as u64);
                sum += d.len();
                segment_count += 1;
            });

            // Override `dgrams` ECN marks according to prefs.
            let ecn_enabled = static_prefs::pref!("network.http.http3.ecn_report");
            let dgrams = dgrams.map(|mut d| {
                if !ecn_enabled {
                    d.set_tos(Tos::default());
                }
                d
            });

            conn.conn.process_multiple_input(dgrams, Instant::now());

            conn.datagram_size_received.accumulate(sum as u64);
            conn.datagram_segments_received.accumulate(segment_count);
            bytes_read += sum;
        }

        ProcessInputResult {
            result: NS_OK,
            bytes_read: bytes_read.try_into().unwrap_or(u32::MAX),
        }
    })
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_process_output_and_send_use_nspr_for_io(
    conn: &mut NeqoHttp3Conn,
    context: *mut c_void,
    send_func: SendFunc,
    set_timer_func: SetTimerFunc,
) -> nsresult {
    assert!(conn.socket.is_none(), "NSPR IO path");

    loop {
        let now = Instant::now();
        if let Some(mut buffered) = conn.buffered_outbound_datagram.take() {
            drop(buffered.batch);
            if let Err(result) = resolve_tracked_output(conn, &mut buffered.token, 0, now) {
                return result;
            }
        }

        let tracked = match conn
            .conn
            .process_multiple_output_tracked(now, NonZeroUsize::MIN)
        {
            Ok(tracked) => tracked,
            Err(err) => return tracked_output_error_to_nsresult(&err),
        };
        let segment_count = tracked.segment_count();
        let (output, token) = tracked.into_parts();

        match output {
            OutputBatch::DatagramBatch(dg) => {
                let Some(mut token) = token else {
                    return NS_ERROR_UNEXPECTED;
                };
                if segment_count != 1 || dg.num_datagrams() != 1 {
                    let _ = resolve_tracked_output(conn, &mut token, 0, now);
                    return NS_ERROR_UNEXPECTED;
                }
                let Ok(len) = u32::try_from(dg.data().len()) else {
                    let _ = resolve_tracked_output(conn, &mut token, 0, now);
                    return NS_ERROR_UNEXPECTED;
                };
                let sent = match dg.destination().ip() {
                    IpAddr::V4(v4) => send_func(
                        context,
                        AF_INET_U16,
                        v4.octets().as_ptr(),
                        dg.destination().port(),
                        dg.data().as_ptr(),
                        len,
                    ),
                    IpAddr::V6(v6) => send_func(
                        context,
                        AF_INET6_U16,
                        v6.octets().as_ptr(),
                        dg.destination().port(),
                        dg.data().as_ptr(),
                        len,
                    ),
                };

                if sent.result == NS_OK && sent.bytes_written == len {
                    if let Err(result) = resolve_tracked_output(conn, &mut token, 1, now) {
                        return result;
                    }
                    continue;
                }

                if sent.result == NS_BASE_STREAM_WOULD_BLOCK
                    && static_prefs::pref!("network.http.http3.pr_poll_write")
                {
                    conn.increment_would_block_tx();
                    conn.buffered_outbound_datagram = Some(BufferedTrackedOutput {
                        batch: dg,
                        token,
                        segment_count,
                        generated_at: now,
                    });
                    return NS_BASE_STREAM_WOULD_BLOCK;
                }

                if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                    return result;
                }
                if sent.result == NS_OK {
                    qerror!(
                        "NSPR UDP send reported a short write: {}/{} bytes",
                        sent.bytes_written,
                        len
                    );
                    return NS_ERROR_UNEXPECTED;
                }
                if sent.result == NS_ERROR_OUT_OF_MEMORY {
                    set_timer_func(context, 1);
                    break;
                }
                return sent.result;
            }
            OutputBatch::Callback(to) => {
                debug_assert!(token.is_none());
                let timeout = if to.is_zero() {
                    Duration::from_millis(1)
                } else {
                    to
                };
                let Ok(timeout) = u64::try_from(timeout.as_millis()) else {
                    return NS_ERROR_UNEXPECTED;
                };
                set_timer_func(context, timeout);
                break;
            }
            OutputBatch::None => {
                debug_assert!(token.is_none());
                set_timer_func(context, u64::MAX);
                break;
            }
        }
    }
    NS_OK
}

#[repr(C)]
pub struct ProcessOutputAndSendResult {
    pub result: nsresult,
    pub bytes_written: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum NeqoGlueTestSendOutcome {
    Full,
    Prefix,
    WouldBlock,
    UnsupportedGso,
    Transient,
    Fatal,
    Overlong,
}

#[repr(C)]
pub struct NeqoGlueTestSendResult {
    pub result: nsresult,
    pub bytes_written: u32,
    pub send_calls: u32,
    pub first_segment_count: u32,
    pub timer: u64,
    pub output_pending: bool,
}

#[repr(C)]
pub struct NeqoGlueTestTokenResult {
    pub overlong_rejected: bool,
    pub foreign_rejected: bool,
    pub duplicate_rejected: bool,
}

impl NeqoGlueTestCommittedStats {
    fn from_stats(stats: &neqo_transport::Stats) -> Self {
        let frames = &stats.frame_tx;
        let frames_tx = frames.ack
            + frames.crypto
            + frames.stream
            + frames.reset_stream
            + frames.stop_sending
            + frames.ping
            + frames.padding
            + frames.max_streams
            + frames.streams_blocked
            + frames.max_data
            + frames.data_blocked
            + frames.max_stream_data
            + frames.stream_data_blocked
            + frames.new_connection_id
            + frames.retire_connection_id
            + frames.path_challenge
            + frames.path_response
            + frames.connection_close
            + frames.handshake_done
            + frames.new_token
            + frames.ack_frequency
            + frames.datagram;
        let ecn_tx = stats
            .ecn_tx
            .values()
            .flat_map(|counts| counts.values())
            .copied()
            .sum();
        let ecn_path_validation = stats.ecn_path_validation.values().copied().sum();
        Self {
            available: true,
            packets_tx: stats.packets_tx,
            pmtud_tx: stats.pmtud_tx,
            frames_tx,
            ecn_tx,
            ecn_path_validation,
        }
    }
}

#[derive(Debug)]
enum SegmentSendOutcome {
    Accepted(usize),
    WouldBlock,
    RetryWithoutGso(io::Error),
    RetryLater(io::Error),
    Fatal(io::Error),
}

fn record_accepted_output(
    conn: &mut NeqoHttp3Conn,
    dg: &datagram::Batch,
    accepted: usize,
) -> usize {
    let segment_sizes = dg
        .iter()
        .take(accepted)
        .map(|segment| segment.len())
        .collect::<Vec<_>>();
    let accepted_bytes = segment_sizes.iter().sum::<usize>();
    if accepted_bytes == 0 {
        return 0;
    }

    conn.datagram_size_sent.accumulate(accepted_bytes as u64);
    conn.datagram_segments_sent.accumulate(accepted as u64);
    for segment_size in segment_sizes {
        conn.datagram_segment_size_sent
            .accumulate(segment_size as u64);
    }
    accepted_bytes
}

fn resolve_tracked_output(
    conn: &mut NeqoHttp3Conn,
    token: &mut OutputToken,
    accepted: usize,
    now: Instant,
) -> Result<(), nsresult> {
    conn.conn
        .resolve_output(token, accepted, now)
        .map_err(|err| tracked_output_error_to_nsresult(&err))
}

fn process_output_and_send_with<MaxSegments, SendSegments>(
    conn: &mut NeqoHttp3Conn,
    context: *mut c_void,
    set_timer_func: SetTimerFunc,
    buffer_would_block: bool,
    mut max_segments: MaxSegments,
    mut send_segments: SendSegments,
) -> ProcessOutputAndSendResult
where
    MaxSegments: FnMut(&mut NeqoHttp3Conn) -> Result<NonZeroUsize, nsresult>,
    SendSegments:
        FnMut(&mut NeqoHttp3Conn, &datagram::Batch, usize) -> SegmentSendOutcome,
{
    let mut bytes_written: usize = 0;
    loop {
        let max_gso_segments = match max_segments(conn) {
            Ok(max_gso_segments) => max_gso_segments,
            Err(result) => {
                return ProcessOutputAndSendResult {
                    result,
                    bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                };
            }
        };

        let now = Instant::now();
        if let Some(mut buffered) = conn.buffered_outbound_datagram.take() {
            qdebug!(
                "abandoning {}-segment tracked output retained for {:?} before regenerating",
                buffered.segment_count,
                buffered.generated_at.elapsed()
            );
            drop(buffered.batch);
            if let Err(result) = resolve_tracked_output(conn, &mut buffered.token, 0, now) {
                return ProcessOutputAndSendResult {
                    result,
                    bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                };
            }
        }

        let tracked = match conn
            .conn
            .process_multiple_output_tracked(now, max_gso_segments)
        {
            Ok(tracked) => tracked,
            Err(err) => {
                return ProcessOutputAndSendResult {
                    result: tracked_output_error_to_nsresult(&err),
                    bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                };
            }
        };
        let segment_count = tracked.segment_count();
        let (output, token) = tracked.into_parts();

        match output {
            OutputBatch::DatagramBatch(dg) => {
                let Some(mut token) = token else {
                    qerror!("tracked datagram output is missing its token");
                    return ProcessOutputAndSendResult {
                        result: NS_ERROR_UNEXPECTED,
                        bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                    };
                };
                if segment_count != dg.num_datagrams() {
                    let _ = resolve_tracked_output(conn, &mut token, 0, now);
                    return ProcessOutputAndSendResult {
                        result: NS_ERROR_UNEXPECTED,
                        bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                    };
                }

                if static_prefs::pref!("network.http.http3.block_loopback_ipv6_addr")
                    && matches!(dg.destination(), SocketAddr::V6(addr) if addr.ip().is_loopback())
                {
                    let result = resolve_tracked_output(conn, &mut token, 0, now)
                        .err()
                        .unwrap_or(NS_ERROR_CONNECTION_REFUSED);
                    return ProcessOutputAndSendResult {
                        result,
                        bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                    };
                }

                match send_segments(conn, &dg, segment_count) {
                    SegmentSendOutcome::Accepted(accepted) if accepted <= segment_count => {
                        if let Err(result) = resolve_tracked_output(conn, &mut token, accepted, now)
                        {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        bytes_written += record_accepted_output(conn, &dg, accepted);
                        if accepted == 0 {
                            set_timer_func(context, 1);
                            break;
                        }
                        if accepted < segment_count {
                            qdebug!(
                                "socket accepted {accepted}/{segment_count} tracked UDP segments; regenerating the abandoned suffix"
                            );
                        }
                    }
                    SegmentSendOutcome::Accepted(accepted) => {
                        qerror!(
                            "socket reported invalid accepted segment count {accepted} for batch of {segment_count}"
                        );
                        if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        return ProcessOutputAndSendResult {
                            result: NS_ERROR_UNEXPECTED,
                            bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                        };
                    }
                    SegmentSendOutcome::WouldBlock => {
                        conn.increment_would_block_tx();
                        if buffer_would_block {
                            qdebug!(
                                "buffering unresolved tracked output after socket WouldBlock (age {:?})",
                                now.elapsed()
                            );
                            conn.buffered_outbound_datagram = Some(BufferedTrackedOutput {
                                batch: dg,
                                token,
                                segment_count,
                                generated_at: now,
                            });
                            return ProcessOutputAndSendResult {
                                result: NS_BASE_STREAM_WOULD_BLOCK,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        qwarn!("abandoned tracked output after socket WouldBlock");
                        break;
                    }
                    SegmentSendOutcome::RetryWithoutGso(e) => {
                        if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        qdebug!(
                            "GSO send failed with {e}; abandoned the batch and regenerating without segmentation"
                        );
                    }
                    SegmentSendOutcome::RetryLater(e) => {
                        if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        qdebug!(
                            "socket rejected tracked output locally ({e}); retrying without reporting network loss"
                        );
                        set_timer_func(context, 1);
                        break;
                    }
                    SegmentSendOutcome::Fatal(e) => {
                        if let Err(result) = resolve_tracked_output(conn, &mut token, 0, now) {
                            return ProcessOutputAndSendResult {
                                result,
                                bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                            };
                        }
                        qwarn!("failed to send tracked datagram: {e}");
                        return ProcessOutputAndSendResult {
                            result: into_nsresult(&e),
                            bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                        };
                    }
                }
            }
            OutputBatch::Callback(to) => {
                debug_assert!(token.is_none());
                let timeout = if to.is_zero() {
                    Duration::from_millis(1)
                } else {
                    to
                };
                let Ok(timeout) = u64::try_from(timeout.as_millis()) else {
                    return ProcessOutputAndSendResult {
                        result: NS_ERROR_UNEXPECTED,
                        bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
                    };
                };
                set_timer_func(context, timeout);
                break;
            }
            OutputBatch::None => {
                debug_assert!(token.is_none());
                set_timer_func(context, u64::MAX);
                break;
            }
        }
    }

    ProcessOutputAndSendResult {
        result: NS_OK,
        bytes_written: bytes_written.try_into().unwrap_or(u32::MAX),
    }
}

fn socket_max_gso_segments(conn: &mut NeqoHttp3Conn) -> Result<NonZeroUsize, nsresult> {
    min(
        static_prefs::pref!("network.http.http3.max_gso_segments")
            .try_into()
            .expect("u32 fit usize"),
        conn.socket
            .as_mut()
            .expect("non NSPR IO")
            .max_gso_segments(),
    )
    .try_into()
    .map_err(|_| {
        qerror!("Socket returned a GSO size of 0");
        NS_ERROR_UNEXPECTED
    })
}

fn socket_send_segments(
    conn: &mut NeqoHttp3Conn,
    dg: &datagram::Batch,
    segment_count: usize,
) -> SegmentSendOutcome {
    let result = conn
        .socket
        .as_mut()
        .expect("non NSPR IO")
        .send_segments(dg);
    match result {
        Ok(accepted) => SegmentSendOutcome::Accepted(accepted),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            SegmentSendOutcome::WouldBlock
        }
        Err(error) => {
            let action = conn
                .socket
                .as_ref()
                .expect("non NSPR IO")
                .handle_send_error(&error, segment_count);
            match action {
                Some(neqo_udp::SendErrorAction::RetryWithoutGso) => {
                    SegmentSendOutcome::RetryWithoutGso(error)
                }
                Some(neqo_udp::SendErrorAction::RetryLater) => {
                    SegmentSendOutcome::RetryLater(error)
                }
                None => SegmentSendOutcome::Fatal(error),
            }
        }
    }
}

/// Process output, retrieving outgoing datagrams from the Neqo state machine
/// and writing them to the socket.
#[no_mangle]
pub extern "C" fn neqo_http3conn_process_output_and_send(
    conn: &mut NeqoHttp3Conn,
    context: *mut c_void,
    set_timer_func: SetTimerFunc,
) -> ProcessOutputAndSendResult {
    process_output_and_send_with(
        conn,
        context,
        set_timer_func,
        static_prefs::pref!("network.http.http3.pr_poll_write"),
        socket_max_gso_segments,
        socket_send_segments,
    )
}

extern "C" fn neqo_glue_test_set_timer(context: *mut c_void, timeout: u64) {
    assert!(!context.is_null());
    // SAFETY: `neqo_glue_test_process_output_and_send` supplies a live `u64`.
    unsafe {
        context.cast::<u64>().write(timeout);
    }
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_process_output_and_send(
    conn: &mut NeqoHttp3Conn,
    outcome: NeqoGlueTestSendOutcome,
    accepted_prefix: u32,
    max_segments: u32,
    buffer_would_block: bool,
) -> NeqoGlueTestSendResult {
    let force_single_segment = Cell::new(false);
    let first_segment_count = Cell::new(0);
    let send_calls = Cell::new(0_u32);
    let mut first_send = true;
    let mut timer = u64::MAX;
    let timer_context = ptr::from_mut(&mut timer).cast::<c_void>();
    let result = process_output_and_send_with(
        conn,
        timer_context,
        neqo_glue_test_set_timer,
        buffer_would_block,
        |_| {
            let requested = if force_single_segment.get() {
                1
            } else {
                usize::try_from(max_segments).map_err(|_| NS_ERROR_UNEXPECTED)?
            };
            NonZeroUsize::new(requested).ok_or(NS_ERROR_UNEXPECTED)
        },
        |_, _, segment_count| {
            send_calls.set(send_calls.get().saturating_add(1));
            if first_segment_count.get() == 0 {
                first_segment_count.set(u32::try_from(segment_count).unwrap_or(u32::MAX));
            }
            if !first_send {
                return if matches!(outcome, NeqoGlueTestSendOutcome::Prefix) {
                    SegmentSendOutcome::RetryLater(io::Error::from(io::ErrorKind::Interrupted))
                } else {
                    SegmentSendOutcome::Accepted(segment_count)
                };
            }
            first_send = false;
            match outcome {
                NeqoGlueTestSendOutcome::Full => SegmentSendOutcome::Accepted(segment_count),
                NeqoGlueTestSendOutcome::Prefix => SegmentSendOutcome::Accepted(
                    usize::try_from(accepted_prefix).unwrap_or(usize::MAX),
                ),
                NeqoGlueTestSendOutcome::WouldBlock => SegmentSendOutcome::WouldBlock,
                NeqoGlueTestSendOutcome::UnsupportedGso => {
                    force_single_segment.set(true);
                    SegmentSendOutcome::RetryWithoutGso(io::Error::from(
                        io::ErrorKind::Unsupported,
                    ))
                }
                NeqoGlueTestSendOutcome::Transient => {
                    SegmentSendOutcome::RetryLater(io::Error::from(io::ErrorKind::Interrupted))
                }
                NeqoGlueTestSendOutcome::Fatal => SegmentSendOutcome::Fatal(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                )),
                NeqoGlueTestSendOutcome::Overlong => {
                    SegmentSendOutcome::Accepted(segment_count.saturating_add(1))
                }
            }
        },
    );

    NeqoGlueTestSendResult {
        result: result.result,
        bytes_written: result.bytes_written,
        send_calls: send_calls.get(),
        first_segment_count: first_segment_count.get(),
        timer,
        output_pending: conn.buffered_outbound_datagram.is_some(),
    }
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_output_token_rejections(
    first: &mut NeqoHttp3Conn,
    second: &mut NeqoHttp3Conn,
) -> NeqoGlueTestTokenResult {
    let first_now = Instant::now();
    let Ok(first_tracked) = first
        .conn
        .process_multiple_output_tracked(first_now, NonZeroUsize::MIN)
    else {
        return NeqoGlueTestTokenResult {
            overlong_rejected: false,
            foreign_rejected: false,
            duplicate_rejected: false,
        };
    };
    let first_segments = first_tracked.segment_count();
    let (first_output, Some(mut first_token)) = first_tracked.into_parts() else {
        return NeqoGlueTestTokenResult {
            overlong_rejected: false,
            foreign_rejected: false,
            duplicate_rejected: false,
        };
    };

    let second_now = Instant::now();
    let Ok(second_tracked) = second
        .conn
        .process_multiple_output_tracked(second_now, NonZeroUsize::MIN)
    else {
        let _ = first
            .conn
            .resolve_output(&mut first_token, 0, first_now);
        return NeqoGlueTestTokenResult {
            overlong_rejected: false,
            foreign_rejected: false,
            duplicate_rejected: false,
        };
    };
    let (second_output, Some(mut second_token)) = second_tracked.into_parts() else {
        let _ = first
            .conn
            .resolve_output(&mut first_token, 0, first_now);
        return NeqoGlueTestTokenResult {
            overlong_rejected: false,
            foreign_rejected: false,
            duplicate_rejected: false,
        };
    };

    let overlong_rejected = matches!(
        first
            .conn
            .resolve_output(&mut first_token, first_segments.saturating_add(1), first_now),
        Err(Http3Error::Transport(TransportError::InvalidInput))
    );
    let foreign_rejected = matches!(
        second
            .conn
            .resolve_output(&mut first_token, 0, second_now),
        Err(Http3Error::Transport(TransportError::InvalidOutputToken))
    );
    let first_resolved = first
        .conn
        .resolve_output(&mut first_token, 0, first_now)
        .is_ok();
    let duplicate_rejected = first_resolved
        && matches!(
            first
                .conn
                .resolve_output(&mut first_token, first_segments, first_now),
            Err(Http3Error::Transport(TransportError::InvalidOutputToken))
        );
    let _ = second
        .conn
        .resolve_output(&mut second_token, 0, second_now);
    drop((first_output, second_output));

    NeqoGlueTestTokenResult {
        overlong_rejected,
        foreign_rejected,
        duplicate_rejected,
    }
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_tentative_packets_tx(conn: &NeqoHttp3Conn) -> usize {
    conn.conn.transport_stats().packets_tx
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_committed_stats(
    conn: &NeqoHttp3Conn,
) -> NeqoGlueTestCommittedStats {
    NeqoGlueTestCommittedStats::from_stats(&conn.conn.committed_transport_stats())
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_has_pending_output(conn: &NeqoHttp3Conn) -> bool {
    conn.buffered_outbound_datagram.is_some()
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_mcquic_revoked_clean(conn: &NeqoHttp3Conn) -> bool {
    #[cfg(feature = "mcquic")]
    {
        conn.conn.mcquic_operation_state()
            == neqo_transport::mcquic::OperationState::Revoked
            && !conn.conn.mcquic_readable()
    }
    #[cfg(not(feature = "mcquic"))]
    {
        let _ = conn;
        false
    }
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_arm_drop_abandon_observer(conn: &mut NeqoHttp3Conn) {
    TEST_DROP_ABANDON_RESULT.store(0, AtomicOrdering::SeqCst);
    *TEST_DROP_GLEAN_STATS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    conn.test_drop_abandon_observer = true;
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_take_drop_abandon_result() -> u8 {
    TEST_DROP_ABANDON_RESULT.swap(0, AtomicOrdering::SeqCst)
}

#[no_mangle]
pub extern "C" fn neqo_glue_test_take_drop_glean_stats() -> NeqoGlueTestCommittedStats {
    TEST_DROP_GLEAN_STATS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .unwrap_or_default()
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_close(conn: &mut NeqoHttp3Conn, error: u64) {
    let now = Instant::now();
    if abandon_output_before_mutation(conn, now).is_ok() {
        conn.conn.close(now, error, "");
    }
}

fn is_excluded_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "transfer-encoding"
            | "upgrade"
            | "sec-websocket-key"
    )
}

fn parse_headers(headers: &nsACString) -> Result<Vec<Header>, nsresult> {
    let mut hdrs = Vec::new();
    // this is only used for headers built by Firefox.
    // Firefox supplies all headers already prepared for sending over http1.
    // They need to be split into (name, value) pairs where name is a String
    // and value is a Vec<u8>.

    let headers_bytes: &[u8] = headers;

    // Split on either \r or \n. When splitting "\r\n" sequences, this produces
    // an empty element between them which is filtered out by the is_empty check.
    // This also handles malformed inputs with bare \r or \n.
    for elem in headers_bytes.split(|&b| b == b'\r' || b == b'\n').skip(1) {
        if elem.is_empty() {
            continue;
        }
        if elem.starts_with(b":") {
            // colon headers are for http/2 and 3 and this is http/1
            // input, so that is probably a smuggling attack of some
            // kind.
            continue;
        }

        let colon_pos = match elem.iter().position(|&b| b == b':') {
            Some(pos) => pos,
            None => continue, // No colon, skip this line
        };

        let name_bytes = &elem[..colon_pos];
        // Safe: if colon is at the end, this yields an empty slice
        let value_bytes = &elem[colon_pos + 1..];

        // Header names must be valid UTF-8
        let name = match str::from_utf8(name_bytes) {
            Ok(n) => n.trim().to_lowercase(),
            Err(_) => return Err(NS_ERROR_DOM_INVALID_HEADER_NAME),
        };

        if is_excluded_header(&name) {
            continue;
        }

        // Trim leading and trailing optional whitespace (OWS) from value.
        // Per RFC 9110, OWS is defined as *( SP / HTAB ), i.e., space and tab
        // only.
        let value = value_bytes
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .map_or(&value_bytes[0..0], |start| {
                let end = value_bytes
                    .iter()
                    .rposition(|&b| b != b' ' && b != b'\t')
                    .map_or(value_bytes.len(), |pos| pos + 1);
                &value_bytes[start..end]
            })
            .to_vec();

        hdrs.push(Header::new(name, value));
    }
    Ok(hdrs)
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_fetch(
    conn: &mut NeqoHttp3Conn,
    method: &nsACString,
    scheme: &nsACString,
    host: &nsACString,
    path: &nsACString,
    headers: &nsACString,
    stream_id: &mut u64,
    urgency: u8,
    incremental: bool,
) -> nsresult {
    let hdrs = match parse_headers(headers) {
        Err(e) => {
            return e;
        }
        Ok(h) => h,
    };
    let Ok(method_tmp) = str::from_utf8(method) else {
        return NS_ERROR_INVALID_ARG;
    };
    let Ok(scheme_tmp) = str::from_utf8(scheme) else {
        return NS_ERROR_INVALID_ARG;
    };
    let Ok(host_tmp) = str::from_utf8(host) else {
        return NS_ERROR_INVALID_ARG;
    };
    let Ok(path_tmp) = str::from_utf8(path) else {
        return NS_ERROR_INVALID_ARG;
    };
    if urgency >= 8 {
        return NS_ERROR_INVALID_ARG;
    }
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let priority = Priority::new(urgency, incremental);
    match conn.conn.fetch(
        Instant::now(),
        method_tmp,
        (scheme_tmp, host_tmp, path_tmp),
        &hdrs,
        priority,
    ) {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_connect(
    conn: &mut NeqoHttp3Conn,
    host: &nsACString,
    headers: &nsACString,
    stream_id: &mut u64,
    urgency: u8,
    incremental: bool,
) -> nsresult {
    let hdrs = match parse_headers(headers) {
        Err(e) => {
            return e;
        }
        Ok(h) => h,
    };
    let Ok(host_tmp) = str::from_utf8(host) else {
        return NS_ERROR_INVALID_ARG;
    };
    if urgency >= 8 {
        return NS_ERROR_INVALID_ARG;
    }
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let priority = Priority::new(urgency, incremental);
    match conn.conn.connect(Instant::now(), host_tmp, &hdrs, priority) {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_priority_update(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    urgency: u8,
    incremental: bool,
) -> nsresult {
    if urgency >= 8 {
        return NS_ERROR_INVALID_ARG;
    }
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let priority = Priority::new(urgency, incremental);
    match conn
        .conn
        .priority_update(StreamId::from(stream_id), priority)
    {
        Ok(_) => NS_OK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

/// # Safety
///
/// Use of raw (i.e. unsafe) pointers as arguments.
#[no_mangle]
pub unsafe extern "C" fn neqo_htttp3conn_send_request_body(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    buf: *const u8,
    len: u32,
    read: &mut u32,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let array = slice::from_raw_parts(buf, len as usize);
    conn.conn
        .send_data(StreamId::from(stream_id), array, Instant::now())
        .map_or(NS_ERROR_UNEXPECTED, |amount| {
            let Ok(amount) = u32::try_from(amount) else {
                return NS_ERROR_UNEXPECTED;
            };
            *read = amount;
            if amount == 0 {
                NS_BASE_STREAM_WOULD_BLOCK
            } else {
                NS_OK
            }
        })
}

const fn crypto_error_code(err: &nss_rs::Error) -> u64 {
    match err {
        nss_rs::Error::Aead => 1,
        nss_rs::Error::CertificateLoading => 2,
        nss_rs::Error::CreateSslSocket => 3,
        nss_rs::Error::Hkdf => 4,
        nss_rs::Error::Internal => 5,
        nss_rs::Error::IntegerOverflow => 6,
        nss_rs::Error::InvalidEpoch => 7,
        nss_rs::Error::MixedHandshakeMethod => 8,
        nss_rs::Error::NoDataAvailable => 9,
        nss_rs::Error::Nss { .. } => 10,
        nss_rs::Error::SelfEncrypt => 12,
        nss_rs::Error::TimeTravel => 13,
        nss_rs::Error::UnsupportedCipher => 14,
        nss_rs::Error::UnsupportedVersion => 15,
        nss_rs::Error::String => 16,
        nss_rs::Error::EchRetry(_) => 17,
        nss_rs::Error::CipherInit => 18,
        nss_rs::Error::CertificateDecoding => 19,
        nss_rs::Error::CertificateEncoding => 20,
        nss_rs::Error::InvalidCertificateCompressionID => 21,
        nss_rs::Error::InvalidAlpn => 22,
        nss_rs::Error::AeadTruncated => 23,
        nss_rs::Error::InvalidInput => 24,
        nss_rs::Error::UnsupportedCurve => 25,
        nss_rs::Error::UnsupportedHash => 26,
        nss_rs::Error::InvalidState => 27,
    }
}

// This is only used for telemetry. Therefore we only return error code
// numbers and do not label them. Recording telemetry is easier with a
// number.
#[repr(C)]
pub enum CloseError {
    TransportInternalError,
    TransportInternalErrorOther(u16),
    TransportError(u64),
    CryptoError(u64),
    CryptoAlert(u8),
    PeerAppError(u64),
    PeerError(u64),
    AppError(u64),
    EchRetry,
}

impl From<TransportError> for CloseError {
    fn from(error: TransportError) -> Self {
        #[expect(clippy::match_same_arms, reason = "It's cleaner this way.")]
        match error {
            TransportError::Internal => Self::TransportInternalError,
            TransportError::Crypto(nss_rs::Error::EchRetry(_)) => Self::EchRetry,
            TransportError::Crypto(c) => Self::CryptoError(crypto_error_code(&c)),
            TransportError::CryptoAlert(c) => Self::CryptoAlert(c),
            TransportError::PeerApplication(c) => Self::PeerAppError(c),
            TransportError::Peer(c) => Self::PeerError(c),
            TransportError::None
            | TransportError::IdleTimeout
            | TransportError::ConnectionRefused
            | TransportError::FlowControl
            | TransportError::StreamLimit
            | TransportError::StreamState
            | TransportError::FinalSize
            | TransportError::FrameEncoding
            | TransportError::TransportParameter
            | TransportError::ProtocolViolation
            | TransportError::InvalidToken
            | TransportError::KeysExhausted
            | TransportError::Application
            | TransportError::NoAvailablePath
            | TransportError::CryptoBufferExceeded => Self::TransportError(error.code()),
            TransportError::EchRetry(_) => Self::EchRetry,
            TransportError::AckedUnsentPacket => Self::TransportInternalErrorOther(0),
            TransportError::ConnectionIdLimitExceeded => Self::TransportInternalErrorOther(1),
            TransportError::ConnectionIdsExhausted => Self::TransportInternalErrorOther(2),
            TransportError::ConnectionState => Self::TransportInternalErrorOther(3),
            TransportError::Decrypt => Self::TransportInternalErrorOther(5),
            TransportError::IntegerOverflow => Self::TransportInternalErrorOther(7),
            TransportError::InvalidInput => Self::TransportInternalErrorOther(8),
            TransportError::InvalidMigration => Self::TransportInternalErrorOther(9),
            TransportError::InvalidPacket => Self::TransportInternalErrorOther(10),
            TransportError::InvalidResumptionToken => Self::TransportInternalErrorOther(11),
            TransportError::InvalidRetry => Self::TransportInternalErrorOther(12),
            TransportError::InvalidStreamId => Self::TransportInternalErrorOther(13),
            TransportError::KeysDiscarded(_) => Self::TransportInternalErrorOther(14),
            TransportError::KeysPending(_) => Self::TransportInternalErrorOther(15),
            TransportError::KeyUpdateBlocked => Self::TransportInternalErrorOther(16),
            TransportError::NoMoreData => Self::TransportInternalErrorOther(17),
            TransportError::NotConnected => Self::TransportInternalErrorOther(18),
            TransportError::PacketNumberOverlap => Self::TransportInternalErrorOther(19),
            TransportError::StatelessReset => Self::TransportInternalErrorOther(20),
            TransportError::TooMuchData => Self::TransportInternalErrorOther(21),
            TransportError::UnexpectedMessage => Self::TransportInternalErrorOther(22),
            TransportError::UnknownConnectionId => Self::TransportInternalErrorOther(23),
            TransportError::UnknownFrameType => Self::TransportInternalErrorOther(24),
            TransportError::VersionNegotiation => Self::TransportInternalErrorOther(25),
            TransportError::WrongRole => Self::TransportInternalErrorOther(26),
            TransportError::Qlog => Self::TransportInternalErrorOther(27),
            TransportError::NotAvailable => Self::TransportInternalErrorOther(28),
            TransportError::DisabledVersion => Self::TransportInternalErrorOther(29),
            TransportError::UnknownTransportParameter => Self::TransportInternalErrorOther(30),
            TransportError::McquicResourceLimit => Self::TransportInternalErrorOther(31),
            TransportError::OutputPending => Self::TransportInternalErrorOther(32),
            TransportError::InvalidOutputToken => Self::TransportInternalErrorOther(33),
            TransportError::McquicOwnershipViolation => Self::TransportInternalErrorOther(34),
        }
    }
}

// Keep in sync with `netwerk/metrics.yaml` `http_3_connection_close_reason`
// metric labels.
#[cfg(not(target_os = "android"))]
const fn transport_error_to_glean_label(error: &TransportError) -> &'static str {
    match error {
        TransportError::None => "NoError",
        TransportError::Internal => "InternalError",
        TransportError::ConnectionRefused => "ConnectionRefused",
        TransportError::FlowControl => "FlowControlError",
        TransportError::StreamLimit => "StreamLimitError",
        TransportError::StreamState => "StreamStateError",
        TransportError::FinalSize => "FinalSizeError",
        TransportError::FrameEncoding => "FrameEncodingError",
        TransportError::TransportParameter => "TransportParameterError",
        TransportError::ProtocolViolation => "ProtocolViolation",
        TransportError::InvalidToken => "InvalidToken",
        TransportError::Application => "ApplicationError",
        TransportError::CryptoBufferExceeded => "CryptoBufferExceeded",
        TransportError::Crypto(_) => "CryptoError",
        TransportError::Qlog => "QlogError",
        TransportError::CryptoAlert(_) => "CryptoAlert",
        TransportError::EchRetry(_) => "EchRetry",
        TransportError::AckedUnsentPacket => "AckedUnsentPacket",
        TransportError::ConnectionIdLimitExceeded => "ConnectionIdLimitExceeded",
        TransportError::ConnectionIdsExhausted => "ConnectionIdsExhausted",
        TransportError::ConnectionState => "ConnectionState",
        TransportError::Decrypt => "DecryptError",
        TransportError::DisabledVersion => "DisabledVersion",
        TransportError::IdleTimeout => "IdleTimeout",
        TransportError::IntegerOverflow => "IntegerOverflow",
        TransportError::InvalidInput => "InvalidInput",
        TransportError::InvalidMigration => "InvalidMigration",
        TransportError::InvalidPacket => "InvalidPacket",
        TransportError::InvalidResumptionToken => "InvalidResumptionToken",
        TransportError::InvalidRetry => "InvalidRetry",
        TransportError::InvalidStreamId => "InvalidStreamId",
        TransportError::KeysDiscarded(_) => "KeysDiscarded",
        TransportError::KeysExhausted => "KeysExhausted",
        TransportError::KeysPending(_) => "KeysPending",
        TransportError::KeyUpdateBlocked => "KeyUpdateBlocked",
        TransportError::NoAvailablePath => "NoAvailablePath",
        TransportError::NoMoreData => "NoMoreData",
        TransportError::NotAvailable => "NotAvailable",
        TransportError::NotConnected => "NotConnected",
        TransportError::PacketNumberOverlap => "PacketNumberOverlap",
        TransportError::PeerApplication(_) => "PeerApplicationError",
        TransportError::Peer(_) => "PeerError",
        TransportError::StatelessReset => "StatelessReset",
        TransportError::TooMuchData => "TooMuchData",
        TransportError::UnexpectedMessage => "UnexpectedMessage",
        TransportError::UnknownConnectionId => "UnknownConnectionId",
        TransportError::UnknownFrameType => "UnknownFrameType",
        TransportError::VersionNegotiation => "VersionNegotiation",
        TransportError::WrongRole => "WrongRole",
        TransportError::UnknownTransportParameter => "UnknownTransportParameter",
        TransportError::McquicResourceLimit => "McquicResourceLimit",
        TransportError::OutputPending => "OutputPending",
        TransportError::InvalidOutputToken => "InvalidOutputToken",
        // Ownership violations are consumed by the MCQUIC revocation path and
        // should never close the QUIC connection.
        TransportError::McquicOwnershipViolation => "InternalError",
    }
}

impl From<neqo_transport::CloseReason> for CloseError {
    fn from(error: neqo_transport::CloseReason) -> Self {
        match error {
            neqo_transport::CloseReason::Transport(c) => c.into(),
            neqo_transport::CloseReason::Application(c) => Self::AppError(c),
        }
    }
}

// Reset a stream with streamId.
#[no_mangle]
pub extern "C" fn neqo_http3conn_cancel_fetch(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    error: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn.conn.cancel_fetch(StreamId::from(stream_id), error) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// Reset a stream with streamId.
#[no_mangle]
pub extern "C" fn neqo_http3conn_reset_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    error: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn
        .conn
        .stream_reset_send(StreamId::from(stream_id), error)
    {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_stream_stop_sending(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    error: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn
        .conn
        .stream_stop_sending(StreamId::from(stream_id), error)
    {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// Close sending side of a stream with stream_id
#[no_mangle]
pub extern "C" fn neqo_http3conn_close_stream(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
) -> nsresult {
    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }
    match conn.conn.stream_close_send(StreamId::from(stream_id), now) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

// WebTransport streams can be unidirectional and bidirectional.
// It is mapped to and from neqo's StreamType enum.
#[repr(C)]
pub enum WebTransportStreamType {
    BiDi,
    UniDi,
}

impl From<StreamType> for WebTransportStreamType {
    fn from(t: StreamType) -> Self {
        match t {
            StreamType::BiDi => Self::BiDi,
            StreamType::UniDi => Self::UniDi,
        }
    }
}

impl From<WebTransportStreamType> for StreamType {
    fn from(t: WebTransportStreamType) -> Self {
        match t {
            WebTransportStreamType::BiDi => Self::BiDi,
            WebTransportStreamType::UniDi => Self::UniDi,
        }
    }
}

#[repr(C)]
pub enum SessionCloseReasonExternal {
    Error(u64),
    Status(u16),
    Clean(u32),
}

impl SessionCloseReasonExternal {
    fn new(reason: session::CloseReason, data: &mut ThinVec<u8>) -> Self {
        match reason {
            session::CloseReason::Error(e) => Self::Error(e),
            session::CloseReason::Status(s) => Self::Status(s),
            session::CloseReason::Clean { error, message } => {
                data.extend_from_slice(message.as_ref());
                Self::Clean(error)
            }
        }
    }
}

#[repr(C)]
pub enum WebTransportEventExternal {
    Negotiated(bool),
    Session(u64),
    SessionClosed {
        stream_id: u64,
        reason: SessionCloseReasonExternal,
    },
    NewStream {
        stream_id: u64,
        stream_type: WebTransportStreamType,
        session_id: u64,
    },
    Datagram {
        session_id: u64,
    },
}
#[repr(C)]
pub enum ConnectUdpEventExternal {
    Negotiated(bool),
    Session(u64),
    SessionClosed {
        stream_id: u64,
        reason: SessionCloseReasonExternal,
    },
    Datagram {
        session_id: u64,
    },
}

impl WebTransportEventExternal {
    fn new(event: WebTransportEvent, data: &mut ThinVec<u8>) -> Result<Self, nsresult> {
        match event {
            WebTransportEvent::Negotiated(n) => Ok(Self::Negotiated(n)),
            WebTransportEvent::NewSession {
                stream_id, headers, ..
            } => {
                let result = convert_webtransport_response_headers(&headers, data);
                if result != NS_OK {
                    return Err(result);
                }
                Ok(Self::Session(stream_id.as_u64()))
            }
            WebTransportEvent::SessionClosed {
                stream_id,
                reason,
                headers,
            } => match reason {
                session::CloseReason::Status(status) => {
                    if let Some(headers) = headers {
                        let result = convert_webtransport_response_headers(&headers, data);
                        if result != NS_OK {
                            return Err(result);
                        }
                    } else {
                        data.extend_from_slice(b"HTTP/3 ");
                        data.extend_from_slice(status.to_string().as_bytes());
                        data.extend_from_slice(b"\r\n\r\n");
                    }
                    Ok(Self::Session(stream_id.as_u64()))
                }
                _ => Ok(Self::SessionClosed {
                    stream_id: stream_id.as_u64(),
                    reason: SessionCloseReasonExternal::new(reason, data),
                }),
            },
            WebTransportEvent::NewStream {
                stream_id,
                session_id,
            } => Ok(Self::NewStream {
                stream_id: stream_id.as_u64(),
                stream_type: stream_id.stream_type().into(),
                session_id: session_id.as_u64(),
            }),
            WebTransportEvent::Datagram {
                session_id,
                datagram,
            } => {
                data.extend_from_slice(datagram.as_ref());
                Ok(Self::Datagram {
                    session_id: session_id.as_u64(),
                })
            }
        }
    }
}
impl ConnectUdpEventExternal {
    fn new(event: ConnectUdpEvent, data: &mut ThinVec<u8>) -> Self {
        match event {
            ConnectUdpEvent::Negotiated(n) => Self::Negotiated(n),
            ConnectUdpEvent::NewSession {
                stream_id, status, ..
            } => {
                data.extend_from_slice(b"HTTP/3 ");
                data.extend_from_slice(status.to_string().as_bytes());
                data.extend_from_slice(b"\r\n\r\n");
                Self::Session(stream_id.as_u64())
            }
            ConnectUdpEvent::SessionClosed {
                stream_id, reason, ..
            } => match reason {
                session::CloseReason::Status(status) => {
                    data.extend_from_slice(b"HTTP/3 ");
                    data.extend_from_slice(status.to_string().as_bytes());
                    data.extend_from_slice(b"\r\n\r\n");
                    Self::Session(stream_id.as_u64())
                }
                _ => Self::SessionClosed {
                    stream_id: stream_id.as_u64(),
                    reason: SessionCloseReasonExternal::new(reason, data),
                },
            },
            ConnectUdpEvent::Datagram {
                session_id,
                datagram,
            } => {
                data.extend_from_slice(datagram.as_ref());
                Self::Datagram {
                    session_id: session_id.as_u64(),
                }
            }
        }
    }
}

#[repr(C)]
pub enum Http3Event {
    /// A request stream has space for more data to be sent.
    DataWritable {
        stream_id: u64,
    },
    /// A server has sent a `STOP_SENDING` frame.
    StopSending {
        stream_id: u64,
        error: u64,
    },
    HeaderReady {
        stream_id: u64,
        fin: bool,
        interim: bool,
    },
    /// New bytes available for reading.
    DataReadable {
        stream_id: u64,
    },
    /// Peer reset the stream.
    Reset {
        stream_id: u64,
        error: u64,
        local: bool,
    },
    /// A `PushPromise`
    PushPromise {
        push_id: u64,
        request_stream_id: u64,
    },
    /// A push response headers are ready.
    PushHeaderReady {
        push_id: u64,
        fin: bool,
    },
    /// New bytes are available on a push stream for reading.
    PushDataReadable {
        push_id: u64,
    },
    /// A push has been canceled.
    PushCanceled {
        push_id: u64,
    },
    PushReset {
        push_id: u64,
        error: u64,
    },
    RequestsCreatable,
    AuthenticationNeeded,
    ZeroRttRejected,
    ConnectionConnected,
    GoawayReceived,
    PathMigrated,
    ConnectionClosing {
        error: CloseError,
    },
    ConnectionClosed {
        error: CloseError,
    },
    ResumptionToken {
        expire_in: u64, // microseconds
    },
    EchFallbackAuthenticationNeeded,
    WebTransport(WebTransportEventExternal),
    ConnectUdp(ConnectUdpEventExternal),
    NoEvent,
}

fn sanitize_header(mut y: Cow<[u8]>) -> Cow<[u8]> {
    for i in 0..y.len() {
        if matches!(y[i], b'\n' | b'\r' | b'\0') {
            y.to_mut()[i] = b' ';
        }
    }
    y
}

fn convert_h3_to_h1_headers(headers: &[Header], ret_headers: &mut ThinVec<u8>) -> nsresult {
    if headers.iter().filter(|&h| h.name() == ":status").count() != 1 {
        return NS_ERROR_ILLEGAL_VALUE;
    }

    let status_val = headers
        .iter()
        .find(|&h| h.name() == ":status")
        .expect("must be one")
        .value();

    ret_headers.extend_from_slice(b"HTTP/3 ");
    ret_headers.extend_from_slice(status_val);
    ret_headers.extend_from_slice(b"\r\n");

    for hdr in headers.iter().filter(|&h| h.name() != ":status") {
        ret_headers.extend_from_slice(&sanitize_header(Cow::from(hdr.name().as_bytes())));
        ret_headers.extend_from_slice(b": ");
        ret_headers.extend_from_slice(&sanitize_header(Cow::from(hdr.value())));
        ret_headers.extend_from_slice(b"\r\n");
    }
    ret_headers.extend_from_slice(b"\r\n");
    NS_OK
}

fn convert_webtransport_response_headers(
    headers: &[Header],
    ret_headers: &mut ThinVec<u8>,
) -> nsresult {
    if headers
        .iter()
        .filter(|header| header.name() == ":status")
        .count()
        != 1
    {
        return NS_ERROR_ILLEGAL_VALUE;
    }

    let status = headers
        .iter()
        .find(|header| header.name() == ":status")
        .expect("exactly one status header")
        .value();
    ret_headers.extend_from_slice(b"HTTP/3 ");
    ret_headers.extend_from_slice(status);
    ret_headers.extend_from_slice(b"\r\n");

    // The generic HTTP channel only needs the UA-controlled negotiation field.
    // In particular, WWW-Authenticate and Location must not trigger an HTTP
    // authentication retry or redirect for a WebTransport CONNECT response.
    for header in headers
        .iter()
        .filter(|header| header.name().eq_ignore_ascii_case("wt-multicast"))
    {
        ret_headers.extend_from_slice(b"wt-multicast: ");
        ret_headers.extend_from_slice(&sanitize_header(Cow::from(header.value())));
        ret_headers.extend_from_slice(b"\r\n");
    }
    ret_headers.extend_from_slice(b"\r\n");
    NS_OK
}

#[expect(clippy::too_many_lines, reason = "Nothing to be done about it.")]
#[no_mangle]
pub extern "C" fn neqo_http3conn_event(
    conn: &mut NeqoHttp3Conn,
    ret_event: &mut Http3Event,
    data: &mut ThinVec<u8>,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    while let Some(evt) = conn.conn.next_event() {
        let fe = match evt {
            Http3ClientEvent::DataWritable { stream_id } => Http3Event::DataWritable {
                stream_id: stream_id.as_u64(),
            },
            Http3ClientEvent::StopSending { stream_id, error } => Http3Event::StopSending {
                stream_id: stream_id.as_u64(),
                error,
            },
            Http3ClientEvent::HeaderReady {
                stream_id,
                headers,
                fin,
                interim,
            } => {
                let res = convert_h3_to_h1_headers(&headers, data);
                if res != NS_OK {
                    return res;
                }
                Http3Event::HeaderReady {
                    stream_id: stream_id.as_u64(),
                    fin,
                    interim,
                }
            }
            Http3ClientEvent::DataReadable { stream_id } => Http3Event::DataReadable {
                stream_id: stream_id.as_u64(),
            },
            Http3ClientEvent::Reset {
                stream_id,
                error,
                local,
            } => Http3Event::Reset {
                stream_id: stream_id.as_u64(),
                error,
                local,
            },
            Http3ClientEvent::PushPromise {
                push_id,
                request_stream_id,
                headers,
            } => {
                let res = convert_h3_to_h1_headers(&headers, data);
                if res != NS_OK {
                    return res;
                }
                Http3Event::PushPromise {
                    push_id: push_id.into(),
                    request_stream_id: request_stream_id.as_u64(),
                }
            }
            Http3ClientEvent::PushHeaderReady {
                push_id,
                headers,
                fin,
                interim,
            } => {
                if interim {
                    Http3Event::NoEvent
                } else {
                    let res = convert_h3_to_h1_headers(&headers, data);
                    if res != NS_OK {
                        return res;
                    }
                    Http3Event::PushHeaderReady {
                        push_id: push_id.into(),
                        fin,
                    }
                }
            }
            Http3ClientEvent::PushDataReadable { push_id } => Http3Event::PushDataReadable {
                push_id: push_id.into(),
            },
            Http3ClientEvent::PushCanceled { push_id } => Http3Event::PushCanceled {
                push_id: push_id.into(),
            },
            Http3ClientEvent::PushReset { push_id, error } => Http3Event::PushReset {
                push_id: push_id.into(),
                error,
            },
            Http3ClientEvent::RequestsCreatable => Http3Event::RequestsCreatable,
            Http3ClientEvent::AuthenticationNeeded => Http3Event::AuthenticationNeeded,
            Http3ClientEvent::ZeroRttRejected => Http3Event::ZeroRttRejected,
            Http3ClientEvent::ResumptionToken(token) => {
                // expiration_time time is Instant, transform it into microseconds it will
                // be valid for. Necko code will add the value to PR_Now() to get the
                // expiration time in PRTime.
                if token.expiration_time() > Instant::now() {
                    let e = (token.expiration_time() - Instant::now()).as_micros();
                    u64::try_from(e).map_or(Http3Event::NoEvent, |expire_in| {
                        data.extend_from_slice(token.as_ref());
                        Http3Event::ResumptionToken { expire_in }
                    })
                } else {
                    Http3Event::NoEvent
                }
            }
            Http3ClientEvent::GoawayReceived => Http3Event::GoawayReceived,
            Http3ClientEvent::PathMigrated => Http3Event::PathMigrated,
            Http3ClientEvent::StateChange(state) => match state {
                Http3State::Connected => Http3Event::ConnectionConnected,
                Http3State::Closing(reason) => {
                    if let neqo_transport::CloseReason::Transport(
                        TransportError::Crypto(nss_rs::Error::EchRetry(c))
                        | TransportError::EchRetry(c),
                    ) = &reason
                    {
                        data.extend_from_slice(c.as_ref());
                    }

                    #[cfg(not(target_os = "android"))]
                    {
                        let glean_label = match &reason {
                            neqo_transport::CloseReason::Application(_) => "Application",
                            neqo_transport::CloseReason::Transport(r) => {
                                transport_error_to_glean_label(r)
                            }
                        };
                        networking::http_3_connection_close_reason
                            .get(glean_label)
                            .add(1);
                    }

                    Http3Event::ConnectionClosing {
                        error: reason.into(),
                    }
                }
                Http3State::Closed(error_code) => {
                    if let neqo_transport::CloseReason::Transport(
                        TransportError::Crypto(nss_rs::Error::EchRetry(c))
                        | TransportError::EchRetry(c),
                    ) = &error_code
                    {
                        data.extend_from_slice(c.as_ref());
                    }
                    Http3Event::ConnectionClosed {
                        error: error_code.into(),
                    }
                }
                _ => Http3Event::NoEvent,
            },
            Http3ClientEvent::EchFallbackAuthenticationNeeded { public_name } => {
                data.extend_from_slice(public_name.as_ref());
                Http3Event::EchFallbackAuthenticationNeeded
            }
            Http3ClientEvent::WebTransport(e) => match WebTransportEventExternal::new(e, data) {
                Ok(event) => Http3Event::WebTransport(event),
                Err(error) => return error,
            },
            Http3ClientEvent::ConnectUdp(e) => {
                Http3Event::ConnectUdp(ConnectUdpEventExternal::new(e, data))
            }
        };

        if !matches!(fe, Http3Event::NoEvent) {
            *ret_event = fe;
            return NS_OK;
        }
    }

    *ret_event = Http3Event::NoEvent;
    NS_OK
}

// Read response data into buf.
///
/// # Safety
///
/// Marked as unsafe given exposition via FFI i.e. `extern "C"`.
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_read_response_data(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    buf: *mut u8,
    len: u32,
    read: &mut u32,
    fin: &mut bool,
) -> nsresult {
    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }
    let array = slice::from_raw_parts_mut(buf, len as usize);
    match conn
        .conn
        .read_data(now, StreamId::from(stream_id), &mut array[..])
    {
        Ok((amount, fin_recvd)) => {
            let Ok(amount) = u32::try_from(amount) else {
                return NS_ERROR_NET_HTTP3_PROTOCOL_ERROR;
            };
            *read = amount;
            *fin = fin_recvd;
            if (amount == 0) && !fin_recvd {
                NS_BASE_STREAM_WOULD_BLOCK
            } else {
                NS_OK
            }
        }
        Err(Http3Error::InvalidStreamId | Http3Error::Transport(TransportError::NoMoreData)) => {
            NS_ERROR_INVALID_ARG
        }
        Err(_) => NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    }
}

#[repr(C)]
pub struct NeqoSecretInfo {
    set: bool,
    version: u16,
    cipher: u16,
    group: u16,
    resumed: bool,
    early_data: bool,
    alpn: nsCString,
    signature_scheme: u16,
    ech_accepted: bool,
}
#[no_mangle]
pub extern "C" fn neqo_http3conn_tls_info(
    conn: &mut NeqoHttp3Conn,
    sec_info: &mut NeqoSecretInfo,
) -> nsresult {
    match conn.conn.tls_info() {
        Some(info) => {
            sec_info.set = true;
            sec_info.version = info.version();
            sec_info.cipher = info.cipher_suite();
            sec_info.group = info.key_exchange();
            sec_info.resumed = info.resumed();
            sec_info.early_data = info.early_data_accepted();
            sec_info.alpn = info.alpn().map_or_else(nsCString::new, nsCString::from);
            sec_info.signature_scheme = info.signature_scheme();
            sec_info.ech_accepted = info.ech_accepted();
            NS_OK
        }
        None => NS_ERROR_NOT_AVAILABLE,
    }
}

#[repr(C)]
pub struct NeqoCertificateInfo {
    certs: ThinVec<ThinVec<u8>>,
    stapled_ocsp_responses_present: bool,
    stapled_ocsp_responses: ThinVec<ThinVec<u8>>,
    signed_cert_timestamp_present: bool,
    signed_cert_timestamp: ThinVec<u8>,
}
#[no_mangle]
pub extern "C" fn neqo_http3conn_peer_certificate_info(
    conn: &mut NeqoHttp3Conn,
    neqo_certs_info: &mut NeqoCertificateInfo,
) -> nsresult {
    let Some(certs_info) = conn.conn.peer_certificate() else {
        return NS_ERROR_NOT_AVAILABLE;
    };

    neqo_certs_info.certs = certs_info.iter().map(ThinVec::from).collect();

    match &mut certs_info.stapled_ocsp_responses() {
        Some(ocsp_val) => {
            neqo_certs_info.stapled_ocsp_responses_present = true;
            neqo_certs_info.stapled_ocsp_responses = ocsp_val
                .iter()
                .map(|ocsp| ocsp.iter().copied().collect())
                .collect();
        }
        None => {
            neqo_certs_info.stapled_ocsp_responses_present = false;
        }
    };

    match certs_info.signed_cert_timestamp() {
        Some(sct_val) => {
            neqo_certs_info.signed_cert_timestamp_present = true;
            neqo_certs_info
                .signed_cert_timestamp
                .extend_from_slice(sct_val);
        }
        None => {
            neqo_certs_info.signed_cert_timestamp_present = false;
        }
    };

    NS_OK
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_authenticated(conn: &mut NeqoHttp3Conn, error: PRErrorCode) {
    let now = Instant::now();
    if abandon_output_before_mutation(conn, now).is_ok() {
        conn.conn.authenticated(error.into(), now);
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_set_resumption_token(
    conn: &mut NeqoHttp3Conn,
    token: &mut ThinVec<u8>,
) -> nsresult {
    let now = Instant::now();
    if let Err(result) = abandon_output_before_mutation(conn, now) {
        return result;
    }
    match conn.conn.enable_resumption(now, token) {
        Ok(_) => NS_OK,
        Err(_) => NS_ERROR_NET_HTTP3_PROTOCOL_ERROR,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_set_ech_config(
    conn: &mut NeqoHttp3Conn,
    ech_config: &mut ThinVec<u8>,
) {
    if abandon_output_before_mutation(conn, Instant::now()).is_ok() {
        _ = conn.conn.enable_ech(ech_config);
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_is_zero_rtt(conn: &mut NeqoHttp3Conn) -> bool {
    conn.conn.state() == Http3State::ZeroRtt
}
#[repr(C)]
#[derive(Default)]
pub struct Http3Stats {
    /// Total packets received, including all the bad ones.
    pub packets_rx: usize,
    /// Duplicate packets received.
    pub dups_rx: usize,
    /// Dropped packets or dropped garbage.
    pub dropped_rx: usize,
    /// The number of packet that were saved for later processing.
    pub saved_datagrams: usize,
    /// Total packets sent.
    pub packets_tx: usize,
    /// Total number of packets that are declared lost.
    pub lost: usize,
    /// Late acknowledgments, for packets that were declared lost already.
    pub late_ack: usize,
    /// Acknowledgments for packets that contained data that was marked
    /// for retransmission when the PTO timer popped.
    pub pto_ack: usize,
    /// Count PTOs. Single PTOs, 2 PTOs in a row, 3 PTOs in row, etc. are
    /// counted separately.
    pub pto_counts: [usize; 16],
    /// The count of WouldBlock errors encountered during receive operations
    /// on the UDP socket.
    pub would_block_rx: usize,
    /// The count of WouldBlock errors encountered during transmit operations
    /// on the UDP socket.
    pub would_block_tx: usize,
}
#[no_mangle]
pub extern "C" fn neqo_http3conn_get_stats(conn: &mut NeqoHttp3Conn, stats: &mut Http3Stats) {
    let t_stats = conn.conn.committed_transport_stats();
    stats.packets_rx = t_stats.packets_rx;
    stats.dups_rx = t_stats.dups_rx;
    stats.dropped_rx = t_stats.dropped_rx;
    stats.saved_datagrams = t_stats.saved_datagrams;
    stats.packets_tx = t_stats.packets_tx;
    stats.lost = t_stats.lost;
    stats.late_ack = t_stats.late_ack;
    stats.pto_ack = t_stats.pto_ack;
    stats.pto_counts = t_stats.pto_counts;
    stats.would_block_rx = conn.would_block_rx_count();
    stats.would_block_tx = conn.would_block_tx_count();
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_create_session(
    conn: &mut NeqoHttp3Conn,
    host: &nsACString,
    path: &nsACString,
    headers: &nsACString,
    stream_id: &mut u64,
) -> nsresult {
    let mut hdrs = match parse_headers(headers) {
        Err(e) => {
            return e;
        }
        Ok(h) => h,
    };
    let multicast_header_valid = {
        #[cfg(feature = "mcquic")]
        {
            conn.conn.mcquic_operation_state() == neqo_transport::mcquic::OperationState::Pending
                && hdrs
                    .iter()
                    .filter(|header| header.name() == "wt-multicast")
                    .count()
                    == 1
                && hdrs
                    .iter()
                    .any(|header| header.name() == "wt-multicast" && header.value() == b"?1")
        }
        #[cfg(not(feature = "mcquic"))]
        {
            false
        }
    };
    if !multicast_header_valid {
        hdrs.retain(|header| header.name() != "wt-multicast");
    }
    let Ok(host_tmp) = str::from_utf8(host) else {
        return NS_ERROR_INVALID_ARG;
    };
    let Ok(path_tmp) = str::from_utf8(path) else {
        return NS_ERROR_INVALID_ARG;
    };

    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }

    match conn.conn.webtransport_create_session(
        Instant::now(),
        ("https", host_tmp, path_tmp),
        &hdrs,
    ) {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_connect_udp_create_session(
    conn: &mut NeqoHttp3Conn,
    host: &nsACString,
    path: &nsACString,
    headers: &nsACString,
    stream_id: &mut u64,
) -> nsresult {
    let hdrs = match parse_headers(headers) {
        Err(e) => {
            return e;
        }
        Ok(h) => h,
    };
    let Ok(host_tmp) = str::from_utf8(host) else {
        return NS_ERROR_INVALID_ARG;
    };
    let Ok(path_tmp) = str::from_utf8(path) else {
        return NS_ERROR_INVALID_ARG;
    };

    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }

    match conn
        .conn
        .connect_udp_create_session(Instant::now(), ("https", host_tmp, path_tmp), &hdrs)
    {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_close_session(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    error: u32,
    message: &nsACString,
) -> nsresult {
    let Ok(message_tmp) = str::from_utf8(message) else {
        return NS_ERROR_INVALID_ARG;
    };
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn.conn.webtransport_close_session(
        StreamId::from(session_id),
        error,
        message_tmp,
        Instant::now(),
    ) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_connect_udp_close_session(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    error: u32,
    message: &nsACString,
) -> nsresult {
    let Ok(message_tmp) = str::from_utf8(message) else {
        return NS_ERROR_INVALID_ARG;
    };
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn.conn.connect_udp_close_session(
        StreamId::from(session_id),
        error,
        message_tmp,
        Instant::now(),
    ) {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_INVALID_ARG,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_create_stream(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    stream_type: WebTransportStreamType,
    stream_id: &mut u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn
        .conn
        .webtransport_create_stream(StreamId::from(session_id), stream_type.into())
    {
        Ok(id) => {
            *stream_id = id.as_u64();
            NS_OK
        }
        Err(Http3Error::StreamLimit) => NS_BASE_STREAM_WOULD_BLOCK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_send_datagram(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    data: &mut ThinVec<u8>,
    tracking_id: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let id = if tracking_id == 0 {
        None
    } else {
        Some(tracking_id)
    };
    match conn
        .conn
        .webtransport_send_datagram(StreamId::from(session_id), data, id, Instant::now())
    {
        Ok(()) => NS_OK,
        Err(Http3Error::Transport(TransportError::TooMuchData)) => NS_ERROR_NOT_AVAILABLE,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}
#[no_mangle]
pub extern "C" fn neqo_http3conn_connect_udp_send_datagram(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    data: &mut ThinVec<u8>,
    tracking_id: u64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    let id = if tracking_id == 0 {
        None
    } else {
        Some(tracking_id)
    };
    match conn
        .conn
        .connect_udp_send_datagram(StreamId::from(session_id), data, id, Instant::now())
    {
        Ok(()) => NS_OK,
        Err(Http3Error::Transport(TransportError::TooMuchData)) => NS_ERROR_NOT_AVAILABLE,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn neqo_http3conn_webtransport_max_datagram_size(
    conn: &mut NeqoHttp3Conn,
    session_id: u64,
    result: &mut u64,
) -> nsresult {
    conn.conn
        .webtransport_max_datagram_size(StreamId::from(session_id))
        .map_or(NS_ERROR_UNEXPECTED, |size| {
            *result = size;
            NS_OK
        })
}
/// # Safety
///
/// Use of raw (i.e. unsafe) pointers as arguments.
#[no_mangle]
pub unsafe extern "C" fn neqo_http3conn_webtransport_set_sendorder(
    conn: &mut NeqoHttp3Conn,
    stream_id: u64,
    sendorder: *const i64,
) -> nsresult {
    if let Err(result) = abandon_output_before_mutation(conn, Instant::now()) {
        return result;
    }
    match conn
        .conn
        .webtransport_set_sendorder(StreamId::from(stream_id), sendorder.as_ref().copied())
    {
        Ok(()) => NS_OK,
        Err(_) => NS_ERROR_UNEXPECTED,
    }
}

/// Convert a [`std::io::Error`] into a [`nsresult`].
///
/// Note that this conversion is specific to `neqo_glue`, i.e. does not aim to
/// implement a general-purpose conversion.
/// Treat NS_ERROR_NET_RESET as a generic retryable error for the upper layer.
///
/// Modeled after
/// [`ErrorAccordingToNSPR`](https://searchfox.org/mozilla-central/rev/a965e3c683ecc035dee1de72bd33a8d91b1203ed/netwerk/base/nsSocketTransport2.cpp#164-168).
//
// TODO: Use `non_exhaustive_omitted_patterns_lint` [once
// stablized](https://github.com/rust-lang/rust/issues/89554).
fn into_nsresult(e: &io::Error) -> nsresult {
    #[expect(clippy::match_same_arms, reason = "It's cleaner this way.")]
    match e.kind() {
        io::ErrorKind::ConnectionRefused => NS_ERROR_CONNECTION_REFUSED,
        io::ErrorKind::ConnectionReset => NS_ERROR_NET_RESET,

        // > We lump the following NSPR codes in with PR_CONNECT_REFUSED_ERROR. We
        // > could get better diagnostics by adding distinct XPCOM error codes for
        // > each of these, but there are a lot of places in Gecko that check
        // > specifically for NS_ERROR_CONNECTION_REFUSED, all of which would need to
        // > be checked.
        //
        // <https://searchfox.org/mozilla-central/rev/a965e3c683ecc035dee1de72bd33a8d91b1203ed/netwerk/base/nsSocketTransport2.cpp#164-168>
        //
        // TODO: `HostUnreachable` and `NetworkUnreachable` available since Rust
        // v1.83.0 only <https://doc.rust-lang.org/std/io/enum.ErrorKind.html>.
        // io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable |
        io::ErrorKind::AddrNotAvailable => NS_ERROR_CONNECTION_REFUSED,

        // <https://searchfox.org/mozilla-central/rev/a965e3c683ecc035dee1de72bd33a8d91b1203ed/netwerk/base/nsSocketTransport2.cpp#156>
        io::ErrorKind::ConnectionAborted => NS_ERROR_NET_RESET,

        io::ErrorKind::NotConnected => NS_ERROR_NOT_CONNECTED,
        io::ErrorKind::AddrInUse => NS_ERROR_SOCKET_ADDRESS_IN_USE,
        io::ErrorKind::AlreadyExists => NS_ERROR_FILE_ALREADY_EXISTS,
        io::ErrorKind::WouldBlock => NS_BASE_STREAM_WOULD_BLOCK,

        // TODO: available since Rust v1.83.0 only
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.NotADirectory>
        // io::ErrorKind::NotADirectory => NS_ERROR_FILE_NOT_DIRECTORY,

        // TODO: available since Rust v1.83.0 only
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.IsADirectory>
        // io::ErrorKind::IsADirectory => NS_ERROR_FILE_IS_DIRECTORY,

        // TODO: available since Rust v1.83.0 only
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.DirectoryNotEmpty>
        // io::ErrorKind::DirectoryNotEmpty => NS_ERROR_FILE_DIR_NOT_EMPTY,

        // TODO: available since Rust v1.83.0 only
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.ReadOnlyFilesystem>
        // io::ErrorKind::ReadOnlyFilesystem => NS_ERROR_FILE_READ_ONLY,

        // TODO: nightly-only for now
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.FilesystemLoop>.
        // io::ErrorKind::FilesystemLoop => NS_ERROR_FILE_UNRESOLVABLE_SYMLINK,
        io::ErrorKind::TimedOut => NS_ERROR_NET_TIMEOUT,
        io::ErrorKind::Interrupted => NS_ERROR_NET_INTERRUPT,

        // <https://searchfox.org/mozilla-central/rev/a965e3c683ecc035dee1de72bd33a8d91b1203ed/netwerk/base/nsSocketTransport2.cpp#160-161>
        io::ErrorKind::UnexpectedEof => NS_ERROR_NET_INTERRUPT,

        io::ErrorKind::OutOfMemory => NS_ERROR_OUT_OF_MEMORY,

        // TODO: nightly-only for now
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html#variant.InProgress>.
        // io::ErrorKind::InProgress => NS_ERROR_IN_PROGRESS,

        // The errors below are either not relevant for `neqo_glue`, or not
        // defined as `nsresult`.
        io::ErrorKind::NotFound
        | io::ErrorKind::PermissionDenied
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::InvalidData
        | io::ErrorKind::WriteZero
        | io::ErrorKind::Unsupported
        | io::ErrorKind::Other => NS_ERROR_NET_RESET,

        // TODO: available since Rust v1.83.0 only
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html>.
        // io::ErrorKind::NotSeekable
        // | io::ErrorKind::FilesystemQuotaExceeded
        // | io::ErrorKind::FileTooLarge
        // | io::ErrorKind::ResourceBusy
        // | io::ErrorKind::ExecutableFileBusy
        // | io::ErrorKind::Deadlock
        // | io::ErrorKind::TooManyLinks
        // | io::ErrorKind::ArgumentListTooLong
        // | io::ErrorKind::NetworkDown
        // | io::ErrorKind::StaleNetworkFileHandle
        // | io::ErrorKind::StorageFull => NS_ERROR_NET_RESET,

        // TODO: nightly-only for now
        // <https://doc.rust-lang.org/std/io/enum.ErrorKind.html>.
        // io::ErrorKind::CrossesDevices
        // | io::ErrorKind::InvalidFilename
        // | io::ErrorKind::InvalidInput => NS_ERROR_NET_RESET,
        _ => NS_ERROR_NET_RESET,
    }
}

#[repr(C)]
pub struct NeqoEncoder {
    encoder: Encoder,
    refcnt: AtomicRefcnt,
}

impl NeqoEncoder {
    fn new() -> Result<RefPtr<NeqoEncoder>, nsresult> {
        let encoder = Encoder::default();
        let encoder = Box::into_raw(Box::new(NeqoEncoder {
            encoder,
            refcnt: unsafe { AtomicRefcnt::new() },
        }));
        unsafe { Ok(RefPtr::from_raw(encoder).unwrap()) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn neqo_encoder_addref(encoder: &NeqoEncoder) {
    encoder.refcnt.inc();
}

#[no_mangle]
pub unsafe extern "C" fn neqo_encoder_release(encoder: &NeqoEncoder) {
    let rc = encoder.refcnt.dec();
    if rc == 0 {
        drop(Box::from_raw(encoder as *const _ as *mut NeqoEncoder));
    }
}

// xpcom::RefPtr support
unsafe impl RefCounted for NeqoEncoder {
    unsafe fn addref(&self) {
        neqo_encoder_addref(self);
    }
    unsafe fn release(&self) {
        neqo_encoder_release(self);
    }
}

#[no_mangle]
pub extern "C" fn neqo_encoder_new(result: &mut *const NeqoEncoder) {
    *result = ptr::null_mut();
    if let Ok(encoder) = NeqoEncoder::new() {
        encoder.forget(result);
    }
}

#[no_mangle]
pub extern "C" fn neqo_encode_byte(encoder: &mut NeqoEncoder, data: u8) {
    encoder.encoder.encode_byte(data);
}

#[no_mangle]
pub extern "C" fn neqo_encode_varint(encoder: &mut NeqoEncoder, data: u64) {
    encoder.encoder.encode_varint(data);
}

#[no_mangle]
pub extern "C" fn neqo_encode_uint(encoder: &mut NeqoEncoder, n: u32, data: u64) {
    encoder.encoder.encode_uint(n as usize, data);
}

#[no_mangle]
pub unsafe extern "C" fn neqo_encode_buffer(encoder: &mut NeqoEncoder, buf: *const u8, len: u32) {
    let array = slice::from_raw_parts(buf, len as usize);
    encoder.encoder.encode(array);
}

#[no_mangle]
pub unsafe extern "C" fn neqo_encode_vvec(encoder: &mut NeqoEncoder, buf: *const u8, len: u32) {
    let array = slice::from_raw_parts(buf, len as usize);
    encoder.encoder.encode_vvec(array);
}

#[no_mangle]
pub unsafe extern "C" fn neqo_encode_get_data(
    encoder: &mut NeqoEncoder,
    buf: *mut *const u8,
    read: &mut u32,
) {
    let data = encoder.encoder.as_ref();
    *read = data.len() as u32;
    unsafe {
        *buf = data.as_ptr();
    }
}

#[no_mangle]
pub extern "C" fn neqo_encode_varint_len(v: u64) -> usize {
    return Encoder::varint_len(v);
}

#[repr(C)]
pub struct NeqoDecoder {
    decoder: *mut Decoder<'static>,
    refcnt: AtomicRefcnt,
}

impl NeqoDecoder {
    fn new(buf: *const u8, len: u32) -> Result<RefPtr<NeqoDecoder>, nsresult> {
        let slice = unsafe { slice::from_raw_parts(buf, len as usize) };
        let decoder = Box::new(Decoder::new(slice));
        let wrapper = Box::into_raw(Box::new(NeqoDecoder {
            decoder: Box::into_raw(decoder),
            refcnt: unsafe { AtomicRefcnt::new() },
        }));

        unsafe { Ok(RefPtr::from_raw(wrapper).unwrap()) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decoder_addref(decoder: &NeqoDecoder) {
    decoder.refcnt.inc();
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decoder_release(decoder: &NeqoDecoder) {
    let rc = decoder.refcnt.dec();
    if rc == 0 {
        unsafe {
            drop(Box::from_raw(decoder.decoder));
            drop(Box::from_raw(decoder as *const _ as *mut NeqoDecoder));
        }
    }
}

// xpcom::RefPtr support
unsafe impl RefCounted for NeqoDecoder {
    unsafe fn addref(&self) {
        neqo_decoder_addref(self);
    }
    unsafe fn release(&self) {
        neqo_decoder_release(self);
    }
}

#[no_mangle]
pub extern "C" fn neqo_decoder_new(buf: *const u8, len: u32, result: &mut *const NeqoDecoder) {
    *result = ptr::null_mut();
    if let Ok(decoder) = NeqoDecoder::new(buf, len) {
        decoder.forget(result);
    }
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decode_uint32(decoder: &mut NeqoDecoder, result: &mut u32) -> bool {
    let decoder = decoder.decoder.as_mut().unwrap();
    if let Some(v) = decoder.decode_uint::<u32>() {
        *result = v;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decode_varint(decoder: &mut NeqoDecoder, result: &mut u64) -> bool {
    let decoder = decoder.decoder.as_mut().unwrap();
    if let Some(v) = decoder.decode_varint() {
        *result = v;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decode(
    decoder: &mut NeqoDecoder,
    n: u32,
    buf: *mut *const u8,
    read: &mut u32,
) -> bool {
    let decoder = decoder.decoder.as_mut().unwrap();
    if let Some(data) = decoder.decode(n as usize) {
        *buf = data.as_ptr();
        *read = data.len() as u32;
        return true;
    }
    false
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decode_remainder(
    decoder: &mut NeqoDecoder,
    buf: *mut *const u8,
    read: &mut u32,
) {
    let decoder = decoder.decoder.as_mut().unwrap();
    let data = decoder.decode_remainder();
    *buf = data.as_ptr();
    *read = data.len() as u32;
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decoder_remaining(decoder: &mut NeqoDecoder) -> u64 {
    let decoder = decoder.decoder.as_mut().unwrap();
    decoder.remaining() as u64
}

#[no_mangle]
pub unsafe extern "C" fn neqo_decoder_offset(decoder: &mut NeqoDecoder) -> u64 {
    let decoder = decoder.decoder.as_mut().unwrap();
    decoder.offset() as u64
}

/// Enables the Apple fast datapath (`sendmsg_x`/`recvmsg_x`) for all
/// subsequently created QUIC sockets. Must only be called after the caller
/// has verified that these private APIs are available and functional.
#[cfg(target_vendor = "apple")]
#[no_mangle]
pub extern "C" fn neqo_glue_enable_apple_fast_path() {
    APPLE_FAST_PATH.store(true, Ordering::Relaxed);
}

/// Inner implementation for [`neqo_glue_probe_apple_fast_path`].
#[cfg(target_vendor = "apple")]
fn probe_apple_fast_path_inner(send_fd: c_int, recv_fd: c_int) -> io::Result<()> {
    use std::os::fd::BorrowedFd;

    use neqo_common::Ecn;
    use rustix::{
        fs::{fcntl_getfl, fcntl_setfl, OFlags},
        net::{
            getsockname,
            sockopt::{set_socket_timeout, Timeout},
        },
    };

    // Wrap a raw fd in neqo_udp::Socket, enable the fast path, restore blocking
    // mode (UdpSocketState::new sets non-blocking), and return the socket's
    // local address.
    let make_socket =
        |fd: c_int| -> io::Result<(neqo_udp::Socket<BorrowedFd<'static>>, SocketAddr)> {
            let bfd = unsafe { BorrowedFd::borrow_raw(fd) };
            let socket = neqo_udp::Socket::new(bfd)?;
            // SAFETY: The C++ caller has verified via dlsym that the APIs are present.
            unsafe { socket.enable_apple_fast_path() };
            fcntl_setfl(bfd, fcntl_getfl(bfd)? & !OFlags::NONBLOCK)?;
            set_socket_timeout(bfd, Timeout::Recv, Some(Duration::from_secs(1)))?;
            let addr: SocketAddr = getsockname(bfd)?
                .try_into()
                .map_err(|e: rustix::io::Errno| io::Error::from_raw_os_error(e.raw_os_error()))?;
            Ok((socket, addr))
        };
    let (sender, send_addr) = make_socket(send_fd)?;
    let (receiver, recv_addr) = make_socket(recv_fd)?;

    if sender.max_gso_segments() <= 1 {
        return Err(io::Error::other("max_gso_segments not increased"));
    }

    // Send two datagrams with distinct single-byte payloads and ECN codepoints,
    // then receive them across one or more recvmsg_x calls, in any order.
    let mut remaining: Vec<(u8, Ecn)> = vec![(0, Ecn::Ect0), (1, Ecn::Ect1)];
    for &(byte, ecn) in &remaining {
        sender.send(&Datagram::new(send_addr, recv_addr, Tos::from(ecn), vec![byte]).into())?;
    }
    let mut recv_buf = neqo_udp::RecvBuf::default();
    while !remaining.is_empty() {
        for d in receiver.recv(recv_addr, &mut recv_buf)? {
            let &byte = d
                .as_ref()
                .first()
                .ok_or_else(|| io::Error::other("empty datagram"))?;
            let idx = remaining
                .iter()
                .position(|&(b, _)| b == byte)
                .ok_or_else(|| io::Error::other("unexpected datagram payload"))?;
            let (_, expected_ecn) = remaining.swap_remove(idx);
            if Ecn::from(d.tos()) != expected_ecn {
                return Err(io::Error::other("ECN mismatch"));
            }
            if d.source() != send_addr {
                return Err(io::Error::other("source address mismatch"));
            }
        }
    }

    Ok(())
}

/// Tests the Apple fast UDP datapath end-to-end using the same neqo-udp
/// code path used in production. Called during socket process
/// initialisation with two pre-created, loopback-bound UDP sockets. Returns
/// `true` only if a datagram with ECN bits set survives the send/receive
/// round-trip through the `sendmsg_x`/`recvmsg_x` APIs.
#[cfg(target_vendor = "apple")]
#[no_mangle]
pub extern "C" fn neqo_glue_probe_apple_fast_path(send_fd: c_int, recv_fd: c_int) -> bool {
    probe_apple_fast_path_inner(send_fd, recv_fd).is_ok()
}

// Test function called from C++ gtest
// Callback signature: fn(user_data, name_ptr, name_len, value_ptr,
// value_len)
type HeaderCallback = extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize);

#[no_mangle]
pub extern "C" fn neqo_glue_test_parse_headers(
    headers_input: &nsACString,
    callback: HeaderCallback,
    user_data: *mut c_void,
) -> bool {
    match parse_headers(headers_input) {
        Ok(headers) => {
            for header in headers {
                let name_bytes = header.name().as_bytes();
                let value_bytes = header.value();
                callback(
                    user_data,
                    name_bytes.as_ptr(),
                    name_bytes.len(),
                    value_bytes.as_ptr(),
                    value_bytes.len(),
                );
            }
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use neqo_http3::Http3Server;
    use nss_rs::{AntiReplay, AuthenticationStatus};

    use super::*;

    const TEST_ADDR: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);

    #[derive(Debug)]
    enum InjectedSend {
        Full,
        Prefix(usize),
        WouldBlock,
        UnsupportedGso,
        Transient,
        Fatal,
        Overlong,
    }

    impl InjectedSend {
        fn outcome(self, segment_count: usize) -> SegmentSendOutcome {
            match self {
                Self::Full => SegmentSendOutcome::Accepted(segment_count),
                Self::Prefix(accepted) => SegmentSendOutcome::Accepted(accepted),
                Self::WouldBlock => SegmentSendOutcome::WouldBlock,
                Self::UnsupportedGso => SegmentSendOutcome::RetryWithoutGso(io::Error::from(
                    io::ErrorKind::Unsupported,
                )),
                Self::Transient => {
                    SegmentSendOutcome::RetryLater(io::Error::from(io::ErrorKind::Interrupted))
                }
                Self::Fatal => SegmentSendOutcome::Fatal(io::Error::from(
                    io::ErrorKind::ConnectionRefused,
                )),
                Self::Overlong => SegmentSendOutcome::Accepted(segment_count + 1),
            }
        }
    }

    fn wrap_test_client(conn: Http3Client) -> NeqoHttp3Conn {
        NeqoHttp3Conn {
            conn,
            local_addr: TEST_ADDR,
            refcnt: unsafe { AtomicRefcnt::new() },
            socket: None,
            buffered_outbound_datagram: None,
            #[cfg(feature = "mcquic")]
            mcquic_client_limits: None,
            datagram_segment_size_sent: networking::http_3_udp_datagram_segment_size_sent
                .start_buffer(),
            datagram_segment_size_received: networking::http_3_udp_datagram_segment_size_received
                .start_buffer(),
            datagram_size_sent: networking::http_3_udp_datagram_size_sent.start_buffer(),
            datagram_size_received: networking::http_3_udp_datagram_size_received.start_buffer(),
            datagram_segments_sent: networking::http_3_udp_datagram_segments_sent.start_buffer(),
            datagram_segments_received: networking::http_3_udp_datagram_segments_received
                .start_buffer(),
            would_block_counter: WouldBlockCounter::new(),
            test_drop_abandon_observer: false,
        }
    }

    fn connected_test_client(now: Instant) -> Http3Client {
        nss_test_fixture::fixture_init();
        let params = Http3Parameters::default();
        let mut client = Http3Client::new(
            "example.com",
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(9))),
            TEST_ADDR,
            TEST_ADDR,
            params.clone(),
            now,
        )
        .expect("create test client");
        let anti_replay = AntiReplay::new(
            now.checked_sub(Duration::from_secs(2))
                .expect("test clock has a baseline"),
            Duration::from_secs(1),
            1,
            3,
        )
        .expect("create anti-replay context");
        let mut server = Http3Server::new(
            now,
            &["key"],
            &["h3"],
            anti_replay,
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(9))),
            params,
            None,
        )
        .expect("create test server");

        let initial = client.process_output(now);
        let second_initial = client.process_output(now);
        drop(server.process(initial.dgram(), now));
        let output = server.process(second_initial.dgram(), now);
        let output = client.process(output.dgram(), now);
        let output = server.process(output.dgram(), now);
        let output = client.process(output.dgram(), now);
        drop(server.process(output.dgram(), now));
        assert!(client
            .events()
            .any(|event| matches!(event, Http3ClientEvent::AuthenticationNeeded)));
        client.authenticated(AuthenticationStatus::Ok, now);

        let output = client.process_output(now);
        assert_eq!(client.state(), Http3State::Connected);
        let output = server.process(output.dgram(), now);
        let output = client.process(output.dgram(), now);
        let output = server.process(output.dgram(), now);
        let mut output = client.process(output.dgram(), now).dgram();

        loop {
            output = client.process(output, now).dgram();
            let client_idle = output.is_none();
            output = server.process(output, now).dgram();
            if client_idle && output.is_none() {
                break;
            }
        }

        client
    }

    fn queued_test_connection(body_len: usize) -> NeqoHttp3Conn {
        let now = Instant::now();
        let mut client = connected_test_client(now);
        let stream_id = client
            .fetch(
                now,
                "POST",
                ("https", "example.com", "/tracked-output"),
                &[],
                Priority::default(),
            )
            .expect("create request stream");
        let body = vec![0x5a; body_len];
        let mut offset = 0;
        while offset < body.len() {
            let sent = client
                .send_data(stream_id, &body[offset..], now)
                .expect("queue request body");
            assert_ne!(sent, 0, "request body send made no progress");
            offset += sent;
        }

        wrap_test_client(client)
    }

    extern "C" fn test_set_timer(context: *mut c_void, timeout: u64) {
        assert!(!context.is_null());
        // SAFETY: Test callers pass a live pointer to a `u64` for this call.
        unsafe {
            context.cast::<u64>().write(timeout);
        }
    }

    fn run_scripted_send(
        conn: &mut NeqoHttp3Conn,
        max_segments: impl IntoIterator<Item = usize>,
        outcomes: impl IntoIterator<Item = InjectedSend>,
        buffer_would_block: bool,
    ) -> (ProcessOutputAndSendResult, Vec<usize>, u64) {
        let mut max_segments = max_segments.into_iter().collect::<VecDeque<_>>();
        let mut outcomes = outcomes.into_iter().collect::<VecDeque<_>>();
        let mut observed_batches = Vec::new();
        let mut timer = u64::MAX;
        let timer_context = ptr::from_mut(&mut timer).cast::<c_void>();
        let result = process_output_and_send_with(
            conn,
            timer_context,
            test_set_timer,
            buffer_would_block,
            |_| {
                NonZeroUsize::new(max_segments.pop_front().unwrap_or(8))
                    .ok_or(NS_ERROR_UNEXPECTED)
            },
            |_, _, segment_count| {
                observed_batches.push(segment_count);
                outcomes
                    .pop_front()
                    .unwrap_or(InjectedSend::Full)
                    .outcome(segment_count)
            },
        );
        (result, observed_batches, timer)
    }

    fn prime_would_block(conn: &mut NeqoHttp3Conn) {
        let (result, batches, _) = run_scripted_send(
            conn,
            [8],
            [InjectedSend::WouldBlock],
            true,
        );
        assert_eq!(result.result, NS_BASE_STREAM_WOULD_BLOCK);
        assert_eq!(result.bytes_written, 0);
        assert_eq!(batches.len(), 1);
        assert!(conn.buffered_outbound_datagram.is_some());
        assert!(matches!(
            conn.conn
                .process_multiple_output_tracked(Instant::now(), NonZeroUsize::MIN),
            Err(Http3Error::Transport(TransportError::OutputPending))
        ));
    }

    fn assert_output_unlocked(conn: &mut NeqoHttp3Conn) {
        let now = Instant::now();
        let tracked = conn
            .conn
            .process_multiple_output_tracked(now, NonZeroUsize::MIN)
            .expect("tracked output must be unlocked");
        let (output, token) = tracked.into_parts();
        if let Some(mut token) = token {
            conn.conn
                .resolve_output(&mut token, 0, now)
                .expect("abandon probe output");
        }
        drop(output);
    }

    #[test]
    fn scripted_socket_send_outcomes_resolve_exactly() {
        let mut full = queued_test_connection(16 * 1024);
        let (result, batches, _) =
            run_scripted_send(&mut full, [8], [InjectedSend::Full], true);
        assert_eq!(result.result, NS_OK);
        assert_ne!(result.bytes_written, 0);
        assert!(!batches.is_empty());
        assert!(full.buffered_outbound_datagram.is_none());

        let mut partial = queued_test_connection(128 * 1024);
        let (result, batches, _) =
            run_scripted_send(&mut partial, [8], [InjectedSend::Prefix(1)], true);
        assert_eq!(result.result, NS_OK);
        assert!(
            batches.first().is_some_and(|count| *count > 1),
            "test requires a real multi-segment GSO batch"
        );
        assert!(batches.len() > 1, "abandoned suffix must be regenerated");
        assert!(partial.buffered_outbound_datagram.is_none());

        let mut unsupported = queued_test_connection(128 * 1024);
        let (result, batches, _) = run_scripted_send(
            &mut unsupported,
            [8, 1],
            [InjectedSend::UnsupportedGso],
            true,
        );
        assert_eq!(result.result, NS_OK);
        assert!(
            batches.first().is_some_and(|count| *count > 1),
            "test requires GSO before injecting unsupported-GSO"
        );
        assert!(
            batches.iter().skip(1).all(|count| *count == 1),
            "retry must regenerate at one UDP segment per output"
        );

        let mut transient = queued_test_connection(16 * 1024);
        let (result, _, timer) =
            run_scripted_send(&mut transient, [8], [InjectedSend::Transient], true);
        assert_eq!(result.result, NS_OK);
        assert_eq!(timer, 1);
        assert!(transient.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut transient);

        let mut fatal = queued_test_connection(16 * 1024);
        let (result, _, _) =
            run_scripted_send(&mut fatal, [8], [InjectedSend::Fatal], true);
        assert_ne!(result.result, NS_OK);
        assert!(fatal.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut fatal);

        let mut overlong = queued_test_connection(16 * 1024);
        let (result, _, _) =
            run_scripted_send(&mut overlong, [8], [InjectedSend::Overlong], true);
        assert_eq!(result.result, NS_ERROR_UNEXPECTED);
        assert!(overlong.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut overlong);
    }

    #[test]
    fn would_block_retains_exactly_one_transaction() {
        let mut conn = queued_test_connection(16 * 1024);
        prime_would_block(&mut conn);
        assert_eq!(conn.would_block_tx_count(), 1);

        let (result, batches, _) =
            run_scripted_send(&mut conn, [8], [InjectedSend::Full], true);
        assert_eq!(result.result, NS_OK);
        assert_ne!(result.bytes_written, 0);
        assert!(!batches.is_empty());
        assert!(conn.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut conn);
    }

    #[test]
    fn every_glue_mutation_gate_abandons_buffered_output_first() {
        let mut input = queued_test_connection(16 * 1024);
        prime_would_block(&mut input);
        let packet = ThinVec::new();
        // SAFETY: A null address intentionally exercises argument validation
        // after the buffered transaction has been abandoned.
        let result = unsafe {
            neqo_http3conn_process_input_use_nspr_for_io(&mut input, ptr::null(), &packet)
        };
        assert_eq!(result, NS_ERROR_INVALID_ARG);
        assert!(input.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut input);

        let mut output = queued_test_connection(16 * 1024);
        prime_would_block(&mut output);
        let (result, _, _) =
            run_scripted_send(&mut output, [8], [InjectedSend::Transient], true);
        assert_eq!(result.result, NS_OK);
        assert!(output.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut output);

        let mut events = queued_test_connection(16 * 1024);
        prime_would_block(&mut events);
        let mut event = Http3Event::NoEvent;
        let mut data = ThinVec::new();
        assert_eq!(neqo_http3conn_event(&mut events, &mut event, &mut data), NS_OK);
        assert!(events.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut events);

        let mut revoked = queued_test_connection(16 * 1024);
        prime_would_block(&mut revoked);
        #[cfg(feature = "mcquic")]
        {
            assert_eq!(
                neqo_http3conn_mcquic_revoke_operation(&mut revoked),
                NS_OK
            );
            assert_eq!(
                revoked.conn.mcquic_operation_state(),
                neqo_transport::mcquic::OperationState::Revoked
            );
        }
        #[cfg(not(feature = "mcquic"))]
        assert_eq!(
            neqo_http3conn_mcquic_revoke_operation(&mut revoked),
            NS_ERROR_NOT_AVAILABLE
        );
        assert!(revoked.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut revoked);

        let mut closed = queued_test_connection(16 * 1024);
        prime_would_block(&mut closed);
        neqo_http3conn_close(&mut closed, 0);
        assert!(closed.buffered_outbound_datagram.is_none());
        assert_output_unlocked(&mut closed);

        let mut destroyed = queued_test_connection(16 * 1024);
        neqo_glue_test_arm_drop_abandon_observer(&mut destroyed);
        prime_would_block(&mut destroyed);
        drop(destroyed);
        assert_eq!(
            neqo_glue_test_take_drop_abandon_result(),
            2,
            "Drop must explicitly abandon pending output"
        );
    }

    #[test]
    fn externally_visible_stats_exclude_unresolved_output() {
        let mut conn = queued_test_connection(16 * 1024);
        let mut before = Http3Stats::default();
        neqo_http3conn_get_stats(&mut conn, &mut before);

        prime_would_block(&mut conn);
        assert!(
            conn.conn.transport_stats().packets_tx > before.packets_tx,
            "raw transport statistics include tentative output"
        );
        let mut pending = Http3Stats::default();
        neqo_http3conn_get_stats(&mut conn, &mut pending);
        assert_eq!(pending.packets_tx, before.packets_tx);

        assert!(conn
            .abandon_buffered_output(Instant::now())
            .expect("abandon pending output"));
        let mut abandoned = Http3Stats::default();
        neqo_http3conn_get_stats(&mut conn, &mut abandoned);
        assert_eq!(abandoned.packets_tx, before.packets_tx);

        let (result, _, _) =
            run_scripted_send(&mut conn, [8], [InjectedSend::Full], true);
        assert_eq!(result.result, NS_OK);
        let mut committed = Http3Stats::default();
        neqo_http3conn_get_stats(&mut conn, &mut committed);
        assert!(committed.packets_tx > before.packets_tx);
    }

    #[test]
    fn glue_rejects_foreign_and_duplicate_output_tokens() {
        let mut first = queued_test_connection(16 * 1024);
        let first_now = Instant::now();
        let first_tracked = first
            .conn
            .process_multiple_output_tracked(first_now, NonZeroUsize::MIN)
            .expect("first output");
        let first_segments = first_tracked.segment_count();
        let (first_output, first_token) = first_tracked.into_parts();
        let mut first_token = first_token.expect("first output token");

        let mut second = queued_test_connection(16 * 1024);
        let second_now = Instant::now();
        let second_tracked = second
            .conn
            .process_multiple_output_tracked(second_now, NonZeroUsize::MIN)
            .expect("second output");
        let second_segments = second_tracked.segment_count();
        let (second_output, second_token) = second_tracked.into_parts();
        let mut second_token = second_token.expect("second output token");

        assert_eq!(
            resolve_tracked_output(&mut second, &mut first_token, 0, second_now),
            Err(NS_ERROR_UNEXPECTED)
        );
        first
            .conn
            .resolve_output(&mut first_token, first_segments, first_now)
            .expect("resolve first token");
        assert_eq!(
            resolve_tracked_output(&mut first, &mut first_token, first_segments, first_now),
            Err(NS_ERROR_UNEXPECTED)
        );
        second
            .conn
            .resolve_output(&mut second_token, second_segments, second_now)
            .expect("resolve second token");
        drop((first_output, second_output));
    }

    #[test]
    fn webtransport_response_exposes_only_status_and_multicast_negotiation() {
        let headers = vec![
            Header::new(":status", "401"),
            Header::new("www-authenticate", "Basic realm=\"secret\""),
            Header::new("location", "/must-not-follow"),
            Header::new("set-cookie", "secret=value"),
            Header::new("wt-multicast", "?1"),
        ];
        let mut converted = ThinVec::new();

        assert_eq!(
            convert_webtransport_response_headers(&headers, &mut converted),
            NS_OK
        );
        assert_eq!(
            converted.as_slice(),
            b"HTTP/3 401\r\nwt-multicast: ?1\r\n\r\n"
        );
    }
}
