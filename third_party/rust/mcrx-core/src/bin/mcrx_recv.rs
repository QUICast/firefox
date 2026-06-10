#[path = "common/recv_args.rs"]
mod recv_args;

#[cfg(feature = "metrics")]
use mcrx_core::jsonl::{
    HARDWARE_ARTIFACT_TYPE, MetricsJsonlOutputConfig, MetricsJsonlWriter, NETWORK_ARTIFACT_TYPE,
    header_json, infer_node_id_from_path, unix_timestamp_secs,
};
use mcrx_core::{Context, SubscriptionConfig};
#[cfg(feature = "metrics")]
use mcrx_core::{
    ContextMetricsDelta, ContextMetricsSampler, ContextMetricsSnapshot, HardwareMetricsDelta,
    HardwareMetricsSampler, HardwareMetricsSnapshot,
};
#[cfg(feature = "metrics")]
use serde_json::{Map, Value, json};
use std::env;
use std::net::IpAddr;
#[cfg(feature = "metrics")]
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::Duration;
#[cfg(feature = "metrics")]
use std::time::{Instant, SystemTime};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_PREVIEW_LEN: usize = 64;
#[cfg(feature = "metrics")]
const RECEIVER_PRODUCER: &str = "mcrx-core/mcrx_recv";

fn main() {
    if let Err(err) = run() {
        eprintln!("mcrx-recv: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage(&args[0]);
        return Err("invalid arguments".to_string());
    }

    let parsed = match recv_args::parse_receive_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(err) => {
            print_usage(&args[0]);
            return Err(err);
        }
    };
    let group = parsed.group;
    let dst_port = parsed.dst_port;
    let source = parsed.source;
    let interface = parsed.interface;
    let interface_index = parsed.interface_index;

    let mut config = match source {
        Some(source) => SubscriptionConfig::ssm_ip(group, source, dst_port),
        None => SubscriptionConfig::asm_ip(group, dst_port),
    };
    config.interface = interface;
    config.interface_index = interface_index;

    let mut ctx = Context::new();
    let subscription_id = ctx
        .add_subscription(config)
        .map_err(|err| format!("failed to add subscription: {err}"))?;
    ctx.join_subscription(subscription_id)
        .map_err(|err| format!("failed to join subscription: {err}"))?;

    println!("mcrx-recv ready");
    println!("  group:      {group}");
    println!("  dst_port:   {dst_port}");
    println!("  source:     {}", source_string(source));
    println!(
        "  interface:  {}",
        interface_string(interface, interface_index)
    );
    println!("  sub_id:     {}", subscription_id.0);

    println!();
    println!("waiting for packets ...");

    #[cfg(feature = "metrics")]
    let summary_interval = summary_interval_from_env();
    #[cfg(feature = "metrics")]
    let summary_output =
        summary_output_from_env(group, dst_port, source, interface, interface_index)?;
    #[cfg(feature = "metrics")]
    let mut metrics_sampler = ContextMetricsSampler::new();
    #[cfg(feature = "metrics")]
    let _ = metrics_sampler.sample(ctx.metrics_snapshot());
    #[cfg(feature = "metrics")]
    let mut hardware_metrics_sampler = init_hardware_metrics_sampler()?;
    #[cfg(feature = "metrics")]
    let mut metrics_jsonl_writers = match &summary_output {
        Some(output) => Some(
            metrics_jsonl_writers_from_output(output, hardware_metrics_sampler.is_some())
                .map_err(|err| format!("failed to initialize metrics JSONL output: {err}"))?,
        ),
        None => None,
    };
    #[cfg(feature = "metrics")]
    let mut next_summary_at = summary_interval.map(|interval| Instant::now() + interval);

    loop {
        match ctx
            .try_recv_any()
            .map_err(|err| format!("receive failed: {err}"))?
        {
            Some(packet) => {
                println!(
                    "[recv] sub={} src={} group={} dst_port={} len={}",
                    packet.subscription_id.0,
                    packet.source,
                    packet.group,
                    packet.dst_port,
                    packet.payload.len()
                );

                println!("       payload: {}", format_payload(&packet.payload));
            }
            None => {
                thread::sleep(POLL_INTERVAL);
            }
        }
        #[cfg(feature = "metrics")]
        if let (Some(interval), Some(deadline)) = (summary_interval, next_summary_at)
            && Instant::now() >= deadline
        {
            let snapshot = ctx.metrics_snapshot();

            if let Some(delta) = metrics_sampler.sample(snapshot.clone()) {
                if let Some(writers) = metrics_jsonl_writers.as_mut() {
                    write_metrics_summary_jsonl(&snapshot, &delta, &mut writers.network)
                        .map_err(|err| format!("failed to write metrics summary: {err}"))?;
                } else {
                    print_metrics_summary(&snapshot, &delta);
                }
            }

            if let Some(hardware_sampler) = hardware_metrics_sampler.as_mut()
                && let Some(hardware_snapshot) = capture_hardware_metrics_snapshot()?
                && let Some(delta) = hardware_sampler.sample(hardware_snapshot.clone())
            {
                if let Some(writers) = metrics_jsonl_writers.as_mut() {
                    if let Some(writer) = writers.hardware.as_mut() {
                        write_hardware_metrics_summary_jsonl(&hardware_snapshot, &delta, writer)
                            .map_err(|err| {
                                format!("failed to write hardware metrics summary: {err}")
                            })?;
                    }
                } else {
                    print_hardware_metrics_summary(&hardware_snapshot, &delta);
                }
            }

            next_summary_at = Some(Instant::now() + interval);
        }
    }
}

fn source_string(source: Option<IpAddr>) -> String {
    match source {
        Some(source) => source.to_string(),
        None => "any".to_string(),
    }
}

fn interface_string(interface: Option<IpAddr>, interface_index: Option<u32>) -> String {
    match (interface, interface_index) {
        (Some(IpAddr::V6(interface)), Some(interface_index)) => {
            format!("{interface}%{interface_index}")
        }
        (Some(interface), _) => interface.to_string(),
        (None, Some(interface_index)) => format!("ifindex:{interface_index}"),
        (None, None) => "default".to_string(),
    }
}

fn format_payload(payload: &[u8]) -> String {
    match std::str::from_utf8(payload) {
        Ok(text) => truncate_preview(text, MAX_PREVIEW_LEN),
        Err(_) => {
            let preview_len = payload.len().min(16);
            let hex_preview = payload[..preview_len]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");

            if payload.len() > preview_len {
                format!("0x{hex_preview} ... ({} bytes total)", payload.len())
            } else {
                format!("0x{hex_preview}")
            }
        }
    }
}

fn truncate_preview(text: &str, max_len: usize) -> String {
    let char_count = text.chars().count();
    if char_count <= max_len {
        return text.to_string();
    }

    let truncated: String = text.chars().take(max_len).collect();
    format!("{truncated}...")
}

#[cfg(feature = "metrics")]
fn summary_interval_from_env() -> Option<Duration> {
    let raw = env::var("MCRX_METRICS_SUMMARY_SECS").ok()?;
    let secs = raw.parse::<u64>().ok()?;
    if secs == 0 {
        None
    } else {
        Some(Duration::from_secs(secs))
    }
}

#[cfg(feature = "metrics")]
fn summary_file_from_env() -> Option<PathBuf> {
    let raw = env::var("MCRX_METRICS_SUMMARY_FILE").ok()?;
    if raw.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(raw))
    }
}

#[cfg(feature = "metrics")]
fn hardware_summary_file_path(network_path: &Path) -> PathBuf {
    let parent = network_path.parent().map(PathBuf::from).unwrap_or_default();
    let stem = network_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("metrics");
    let extension = network_path.extension().and_then(|ext| ext.to_str());

    let file_name = match extension {
        Some(ext) if !ext.is_empty() => format!("{stem}_hardware.{ext}"),
        _ => format!("{stem}_hardware"),
    };

    parent.join(file_name)
}

#[cfg(feature = "metrics")]
fn metrics_node_id_from_env() -> Option<String> {
    env::var("MCRX_METRICS_NODE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(feature = "metrics")]
fn metrics_flags_from_env() -> Result<Map<String, Value>, String> {
    let raw = match env::var("MCRX_METRICS_FLAGS_JSON") {
        Ok(raw) => raw,
        Err(_) => return Ok(Map::new()),
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Map::new());
    }

    let parsed: Value = serde_json::from_str(trimmed)
        .map_err(|err| format!("MCRX_METRICS_FLAGS_JSON must be valid JSON: {err}"))?;

    match parsed {
        Value::Object(map) => Ok(map),
        _ => Err("MCRX_METRICS_FLAGS_JSON must be a JSON object".to_string()),
    }
}

#[cfg(feature = "metrics")]
fn build_receiver_metrics_flags(
    group: IpAddr,
    dst_port: u16,
    source: Option<IpAddr>,
    interface: Option<IpAddr>,
    interface_index: Option<u32>,
) -> Result<Map<String, Value>, String> {
    let mut flags = Map::new();
    flags.insert(
        "transport".to_string(),
        Value::String("udp-multicast".to_string()),
    );
    flags.insert("role".to_string(), Value::String("receiver".to_string()));
    flags.insert(
        "multicast_group".to_string(),
        Value::String(group.to_string()),
    );
    flags.insert("multicast_port".to_string(), json!(dst_port));
    flags.insert(
        "multicast_interface".to_string(),
        Value::String(interface_string(interface, interface_index)),
    );
    flags.insert(
        "join_mode".to_string(),
        Value::String(if source.is_some() { "ssm" } else { "asm" }.to_string()),
    );
    flags.insert(
        "source_filter".to_string(),
        Value::String(
            if source.is_some() {
                "source-specific"
            } else {
                "any"
            }
            .to_string(),
        ),
    );
    flags.insert("batch_receive_enabled".to_string(), Value::Bool(false));

    if let Some(source) = source {
        flags.insert("source_addr".to_string(), Value::String(source.to_string()));
    }

    for (key, value) in metrics_flags_from_env()? {
        flags.entry(key).or_insert(value);
    }

    Ok(flags)
}

#[cfg(feature = "metrics")]
fn summary_output_from_env(
    group: IpAddr,
    dst_port: u16,
    source: Option<IpAddr>,
    interface: Option<IpAddr>,
    interface_index: Option<u32>,
) -> Result<Option<MetricsJsonlOutputConfig>, String> {
    let Some(network_path) = summary_file_from_env() else {
        return Ok(None);
    };

    Ok(Some(MetricsJsonlOutputConfig {
        node_id: metrics_node_id_from_env()
            .unwrap_or_else(|| infer_node_id_from_path(&network_path)),
        flags: build_receiver_metrics_flags(group, dst_port, source, interface, interface_index)?,
        network_path,
    }))
}

#[cfg(feature = "metrics")]
#[derive(Debug)]
struct MetricsJsonlWriters {
    network: MetricsJsonlWriter,
    hardware: Option<MetricsJsonlWriter>,
}

#[cfg(feature = "metrics")]
fn metrics_jsonl_writers_from_output(
    output: &MetricsJsonlOutputConfig,
    include_hardware: bool,
) -> Result<MetricsJsonlWriters, std::io::Error> {
    let created_at = SystemTime::now();
    let network_header = header_json(
        NETWORK_ARTIFACT_TYPE,
        RECEIVER_PRODUCER,
        &output.node_id,
        created_at,
        &output.flags,
    );
    let network = MetricsJsonlWriter::open(output.network_path.clone(), &network_header)?;

    let hardware = if include_hardware {
        let hardware_header = header_json(
            HARDWARE_ARTIFACT_TYPE,
            RECEIVER_PRODUCER,
            &output.node_id,
            created_at,
            &output.flags,
        );
        Some(MetricsJsonlWriter::open(
            hardware_summary_file_path(&output.network_path),
            &hardware_header,
        )?)
    } else {
        None
    };

    Ok(MetricsJsonlWriters { network, hardware })
}

#[cfg(feature = "metrics")]
fn init_hardware_metrics_sampler() -> Result<Option<HardwareMetricsSampler>, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut sampler = HardwareMetricsSampler::new();
        let _ = sampler.sample(
            HardwareMetricsSnapshot::capture_current_process()
                .map_err(|err| format!("failed to capture initial hardware metrics: {err}"))?,
        );
        Ok(Some(sampler))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(None)
    }
}

#[cfg(feature = "metrics")]
fn capture_hardware_metrics_snapshot() -> Result<Option<HardwareMetricsSnapshot>, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        HardwareMetricsSnapshot::capture_current_process()
            .map(Some)
            .map_err(|err| format!("failed to capture hardware metrics: {err}"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Ok(None)
    }
}

#[cfg(feature = "metrics")]
fn write_metrics_summary_jsonl(
    snapshot: &ContextMetricsSnapshot,
    delta: &ContextMetricsDelta,
    writer: &mut MetricsJsonlWriter,
) -> Result<(), std::io::Error> {
    let sample = json!({
        "ts": unix_timestamp_secs(snapshot.captured_at),
        "interval_secs": delta.interval_secs,
        "active_subscriptions": snapshot.active_subscriptions,
        "joined_subscriptions": snapshot.joined_subscriptions,
        "packets_received_total": snapshot.total_packets_received,
        "bytes_received_total": snapshot.total_bytes_received,
        "packets_received_delta": delta.packets_received,
        "bytes_received_delta": delta.bytes_received,
        "would_block_count_total": snapshot.total_would_block_count,
        "would_block_count_delta": delta.would_block_count,
        "receive_errors_total": snapshot.total_receive_errors,
        "receive_errors_delta": delta.receive_errors,
        "join_count_total": snapshot.total_join_count,
        "join_count_delta": delta.join_count,
        "leave_count_total": snapshot.total_leave_count,
        "leave_count_delta": delta.leave_count,
        "batch_calls_total": snapshot.batch_calls,
        "batch_calls_delta": delta.batch_calls,
        "batch_packets_received_total": snapshot.batch_packets_received,
        "batch_packets_received_delta": delta.batch_packets_received,
        "packets_per_sec": delta.packets_per_sec(),
        "bytes_per_sec": delta.bytes_per_sec(),
        "would_block_per_sec": delta.would_block_per_sec(),
        "receive_errors_per_sec": delta.receive_errors_per_sec(),
    });

    writer.append_sample_row(&sample)
}

#[cfg(feature = "metrics")]
fn write_hardware_metrics_summary_jsonl(
    snapshot: &HardwareMetricsSnapshot,
    delta: &HardwareMetricsDelta,
    writer: &mut MetricsJsonlWriter,
) -> Result<(), std::io::Error> {
    let sample = json!({
        "ts": unix_timestamp_secs(snapshot.captured_at),
        "interval_secs": delta.interval_secs,
        "cpu_user_secs": delta.cpu_user_secs,
        "cpu_system_secs": delta.cpu_system_secs,
        "cpu_total_secs": delta.cpu_total_secs,
        "cpu_util_percent": delta.cpu_util_percent,
        "rss_bytes": delta.rss_bytes,
        "virtual_memory_bytes": delta.virtual_memory_bytes,
        "thread_count": delta.thread_count,
        "open_fds": delta.open_fds,
        "page_faults_minor": delta.page_faults_minor,
        "page_faults_major": delta.page_faults_major,
        "ctx_switches_voluntary": delta.ctx_switches_voluntary,
        "ctx_switches_involuntary": delta.ctx_switches_involuntary,
    });

    writer.append_sample_row(&sample)
}

#[cfg(feature = "metrics")]
fn print_metrics_summary(snapshot: &ContextMetricsSnapshot, delta: &ContextMetricsDelta) {
    println!("[metrics]");
    println!("  interval_secs:         {:.3}", delta.interval_secs);
    println!("  active_subscriptions:  {}", snapshot.active_subscriptions);
    println!("  joined_subscriptions:  {}", snapshot.joined_subscriptions);
    println!(
        "  packets_received_total: {}",
        snapshot.total_packets_received
    );
    println!("  packets_received_delta: {}", delta.packets_received);
    println!(
        "  bytes_received_total:   {}",
        snapshot.total_bytes_received
    );
    println!("  bytes_received_delta:   {}", delta.bytes_received);
    println!(
        "  would_block_count_total: {}",
        snapshot.total_would_block_count
    );
    println!("  would_block_count_delta: {}", delta.would_block_count);
    println!(
        "  receive_errors_total:   {}",
        snapshot.total_receive_errors
    );
    println!("  receive_errors_delta:   {}", delta.receive_errors);
    println!("  join_count_total:       {}", snapshot.total_join_count);
    println!("  join_count_delta:       {}", delta.join_count);
    println!("  leave_count_total:      {}", snapshot.total_leave_count);
    println!("  leave_count_delta:      {}", delta.leave_count);
    println!("  batch_calls_total:      {}", snapshot.batch_calls);
    println!("  batch_calls_delta:      {}", delta.batch_calls);
    println!(
        "  batch_packets_received_total: {}",
        snapshot.batch_packets_received
    );
    println!(
        "  batch_packets_received_delta: {}",
        delta.batch_packets_received
    );
    println!("  packets_per_sec:       {:.3}", delta.packets_per_sec());
    println!("  bytes_per_sec:         {:.3}", delta.bytes_per_sec());
    println!(
        "  would_block_per_sec:   {:.3}",
        delta.would_block_per_sec()
    );
    println!(
        "  recv_errors_per_sec:   {:.3}",
        delta.receive_errors_per_sec()
    );
}

#[cfg(feature = "metrics")]
fn print_hardware_metrics_summary(
    _snapshot: &HardwareMetricsSnapshot,
    delta: &HardwareMetricsDelta,
) {
    println!("[hardware]");
    println!("  interval_secs:              {:.3}", delta.interval_secs);
    println!("  cpu_user_secs:              {:.6}", delta.cpu_user_secs);
    println!("  cpu_system_secs:            {:.6}", delta.cpu_system_secs);
    println!("  cpu_total_secs:             {:.6}", delta.cpu_total_secs);
    println!(
        "  cpu_util_percent:           {:.3}",
        delta.cpu_util_percent
    );
    println!("  rss_bytes:                  {}", delta.rss_bytes);
    println!(
        "  virtual_memory_bytes:       {}",
        delta.virtual_memory_bytes
    );
    println!("  thread_count:               {}", delta.thread_count);
    println!("  open_fds:                   {}", delta.open_fds);
    println!("  page_faults_minor:          {}", delta.page_faults_minor);
    println!("  page_faults_major:          {}", delta.page_faults_major);
    println!(
        "  ctx_switches_voluntary:     {}",
        delta.ctx_switches_voluntary
    );
    println!(
        "  ctx_switches_involuntary:   {}",
        delta.ctx_switches_involuntary
    );
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} <group> <dst_port> [source] [interface]");
    eprintln!("  {program} <group> <dst_port> [--source <source>] [--interface <interface>]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {program} 239.1.2.3 5000");
    eprintln!("  {program} 232.1.2.3 5000 192.168.1.10");
    eprintln!("  {program} 232.1.2.3 5000 192.168.1.10 192.168.1.20");
    eprintln!("  {program} ff01::1234 5000");
    eprintln!("  {program} ff01::1234 5000 --interface ::1");
    eprintln!("  {program} ff32::8000:1234 5000 --interface fe80::1%7");
    eprintln!("  {program} ff32::8000:1234 5000 --interface fe80::1%en0");
    eprintln!("  {program} ff3e::8000:1234 5000 --interface 7");
    eprintln!("  {program} ff31::8000:1234 5000 <sender-ipv6> --interface <receiver-ipv6>");
    eprintln!();
    eprintln!("Notes:");
    eprintln!("  - omit <source> for ASM");
    eprintln!("  - provide <source> for SSM");
    eprintln!("  - for IPv4 SSM, use 232.0.0.0/8 groups such as 232.1.2.3");
    eprintln!(
        "  - use --interface for ASM when you want to set the join interface without also setting a source"
    );
    eprintln!("  - <interface> selects the local join interface address");
    eprintln!(
        "  - for IPv6, <interface> may also be a scoped address like fe80::1%7 or fe80::1%en0, or a numeric interface index"
    );
    eprintln!("  - for IPv6 SSM, use ff3x::/32 groups such as ff31::8000:1234 or ff3e::8000:1234");
    eprintln!(
        "  - for IPv6 SSM, pass --interface <receiver-ipv6-or-ifindex>; this is required on macOS"
    );
    eprintln!("  - for link-local IPv6 SSM groups such as ff32::/16, send from a fe80:: source");

    #[cfg(feature = "metrics")]
    {
        eprintln!();
        eprintln!("Metrics (when built with --features metrics):");
        eprintln!("  MCRX_METRICS_SUMMARY_SECS=<n>   emit a delta metrics summary every n seconds");
        eprintln!(
            "  MCRX_METRICS_NODE_ID=<id>       override JSONL header node_id (defaults to parent dir, then file stem)"
        );
        eprintln!(
            "  MCRX_METRICS_FLAGS_JSON=<json>  merge extra JSON object fields into the header flags map"
        );
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        eprintln!(
            "  MCRX_METRICS_SUMMARY_FILE=<p>   write single-header JSONL network metrics to <p> and process hardware metrics to a sibling *_hardware file"
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        eprintln!(
            "  MCRX_METRICS_SUMMARY_FILE=<p>   write single-header JSONL network metrics to <p>"
        );
    }
}

#[cfg(all(test, feature = "metrics"))]
mod tests {
    use super::*;
    use mcrx_core::jsonl::HEIMDALL_JSONL_SCHEMA;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn metrics_jsonl_writes_one_header_then_compact_samples() {
        let parent_name = format!(
            "mcrx_recv_metrics_node_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        );
        let parent = std::env::temp_dir().join(&parent_name);
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("network_metrics.jsonl");
        let mut flags = Map::new();
        flags.insert("role".to_string(), Value::String("receiver".to_string()));
        flags.insert(
            "multicast_group".to_string(),
            Value::String("ff3e::8000:1234".to_string()),
        );
        let output = MetricsJsonlOutputConfig {
            node_id: infer_node_id_from_path(&path),
            flags,
            network_path: path.clone(),
        };
        let mut writers = metrics_jsonl_writers_from_output(&output, false).unwrap();

        let snapshot = ContextMetricsSnapshot {
            subscriptions_added: 1,
            subscriptions_removed: 0,
            active_subscriptions: 1,
            joined_subscriptions: 1,
            total_packets_received: 10,
            total_bytes_received: 1000,
            total_would_block_count: 4,
            total_receive_errors: 2,
            total_join_count: 3,
            total_leave_count: 1,
            batch_calls: 7,
            batch_packets_received: 10,
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(123),
        };

        let delta = ContextMetricsDelta {
            interval_secs: 2.0,
            packets_received: 5,
            bytes_received: 600,
            would_block_count: 1,
            receive_errors: 1,
            join_count: 1,
            leave_count: 0,
            batch_calls: 2,
            batch_packets_received: 5,
        };

        write_metrics_summary_jsonl(&snapshot, &delta, &mut writers.network).unwrap();

        let later_snapshot = ContextMetricsSnapshot {
            total_packets_received: 15,
            total_bytes_received: 1600,
            total_would_block_count: 5,
            total_receive_errors: 2,
            total_join_count: 3,
            total_leave_count: 1,
            batch_calls: 8,
            batch_packets_received: 15,
            captured_at: SystemTime::UNIX_EPOCH + Duration::from_secs(125),
            ..snapshot.clone()
        };
        let later_delta = ContextMetricsDelta {
            interval_secs: 2.0,
            packets_received: 5,
            bytes_received: 600,
            would_block_count: 1,
            receive_errors: 0,
            join_count: 0,
            leave_count: 0,
            batch_calls: 1,
            batch_packets_received: 5,
        };

        write_metrics_summary_jsonl(&later_snapshot, &later_delta, &mut writers.network).unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        let lines = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();

        assert_eq!(lines.len(), 3);

        let header: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header["schema"], HEIMDALL_JSONL_SCHEMA);
        assert_eq!(header["artifact_type"], NETWORK_ARTIFACT_TYPE);
        assert_eq!(header["producer"], RECEIVER_PRODUCER);
        assert_eq!(header["node_id"], parent_name);
        assert!(header["flags"].is_object());

        for sample_line in &lines[1..] {
            let sample: Value = serde_json::from_str(sample_line).unwrap();
            assert!(sample.get("schema").is_none());
            assert!(sample.get("artifact_type").is_none());
            assert!(sample.get("node_id").is_none());
            assert!(sample.get("producer").is_none());
            assert!(sample.get("flags").is_none());
        }

        let sample = &lines[1];
        assert!(sample.contains("\"packets_received_total\":10"));
        assert!(sample.contains("\"bytes_received_total\":1000"));
        assert!(sample.contains("\"packets_received_delta\":5"));
        assert!(sample.contains("\"bytes_received_delta\":600"));
        assert!(sample.contains("\"would_block_count_total\":4"));
        assert!(sample.contains("\"would_block_count_delta\":1"));
        assert!(sample.contains("\"receive_errors_total\":2"));
        assert!(sample.contains("\"receive_errors_delta\":1"));
        assert!(sample.contains("\"join_count_total\":3"));
        assert!(sample.contains("\"join_count_delta\":1"));
        assert!(sample.contains("\"leave_count_total\":1"));
        assert!(sample.contains("\"leave_count_delta\":0"));
        assert!(sample.contains("\"batch_calls_total\":7"));
        assert!(sample.contains("\"batch_calls_delta\":2"));
        assert!(sample.contains("\"batch_packets_received_total\":10"));
        assert!(sample.contains("\"batch_packets_received_delta\":5"));
        assert!(!sample.contains("\"packets_received\":"));
        assert!(!sample.contains("\"bytes_received\":"));
        assert!(!sample.contains("\"would_block_count\":"));
        assert!(!sample.contains("\"receive_errors\":"));
        assert!(!sample.contains("\"join_count\":"));
        assert!(!sample.contains("\"leave_count\":"));
        assert!(!sample.contains("\"batch_calls\":"));
        assert!(!sample.contains("\"batch_packets_received\":"));

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(parent);
    }

    #[test]
    fn node_id_inference_prefers_parent_dir_over_file_stem() {
        let path = PathBuf::from("/tmp/client-0001/network-metrics.jsonl");
        assert_eq!(infer_node_id_from_path(&path), "client-0001");
    }

    #[test]
    fn metrics_jsonl_rejects_mismatched_existing_header_metadata() {
        let parent = std::env::temp_dir().join(format!(
            "mcrx_recv_metrics_mismatch_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        ));
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("network_metrics.jsonl");

        let stale_header = json!({
            "schema": HEIMDALL_JSONL_SCHEMA,
            "artifact_type": NETWORK_ARTIFACT_TYPE,
            "node_id": "old-node",
            "producer": RECEIVER_PRODUCER,
            "created_at": 1.0,
            "flags": {
                "role": "receiver",
                "multicast_group": "239.1.2.3",
            }
        });
        fs::write(&path, format!("{stale_header}\n")).unwrap();

        let mut flags = Map::new();
        flags.insert("role".to_string(), Value::String("receiver".to_string()));
        flags.insert(
            "multicast_group".to_string(),
            Value::String("239.1.2.99".to_string()),
        );
        let output = MetricsJsonlOutputConfig {
            node_id: "client-0002".to_string(),
            flags,
            network_path: path.clone(),
        };

        let err = metrics_jsonl_writers_from_output(&output, false).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(parent);
    }
}
