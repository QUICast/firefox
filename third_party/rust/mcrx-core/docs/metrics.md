# Metrics

Metrics are optional and sit outside the core receive API.

## Enabling Metrics

```bash
cargo run --features metrics --bin mcrx_recv -- 239.1.2.3 5000
```

## Model

The metrics system is split into three layers:

### Snapshot

A snapshot is a point-in-time view.

Counter fields in a snapshot are cumulative.

For `ContextMetricsSnapshot`, packet, byte, would-block, receive-error, join,
leave, and batch counters are true context-lifetime totals. They are not
recomputed from the currently active subscriptions, and they do not decrease
when a subscription is removed.

Gauge-like fields in a snapshot reflect current state only:

- `active_subscriptions`
- `joined_subscriptions`

### Delta

A delta is computed between two snapshots of the same metric type.

Delta fields represent only the change over the sampled interval:

- packets received during the interval
- bytes received during the interval
- receive errors during the interval
- joins, leaves, and public batch receive calls during the interval

### Sampler

A sampler stores the previous snapshot and computes deltas across repeated
samples.

The first call returns `None` because a delta requires two snapshots.

## Cumulative Totals

At the context level, these snapshot fields are cumulative totals:

- `total_packets_received`
- `total_bytes_received`
- `total_would_block_count`
- `total_receive_errors`
- `total_join_count`
- `total_leave_count`
- `batch_calls`
- `batch_packets_received`

`batch_calls` counts public calls to `Context::try_recv_batch_*()` and
`Context::try_recv_all_*()`. A `try_recv_all_*()` call drains through the same
internal batch path and records one public batch call.

At the subscription level, the per-subscription snapshot counters remain
cumulative for the lifetime of that subscription object.

## Rates

Delta types expose average interval rates such as:

- `packets_per_sec()`
- `bytes_per_sec()`
- `would_block_per_sec()`
- `receive_errors_per_sec()`

These are computed from delta counters divided by the sampled interval.

## CLI Integration

`mcrx_recv` can periodically emit:

- terminal summaries
- JSONL file output

The reusable single-header JSONL helper is also exported as
`mcrx_core::jsonl` when the `metrics` feature is enabled.

Configured via:

- `MCRX_METRICS_SUMMARY_SECS`
- `MCRX_METRICS_SUMMARY_FILE`
- `MCRX_METRICS_NODE_ID`
- `MCRX_METRICS_FLAGS_JSON`

## JSONL Schema

The library helper lives in `mcrx_core::jsonl` and provides:

- `MetricsJsonlOutputConfig`
- `HEIMDALL_JSONL_SCHEMA`
- `NETWORK_ARTIFACT_TYPE`
- `HARDWARE_ARTIFACT_TYPE`
- `infer_node_id_from_path()`
- `header_json()`
- `append_jsonl_sample_row()`

Metrics JSONL files use a single-header format:

1. The first non-empty line is a header object.
2. Every later non-empty line is one compact sample row.
3. Header metadata is not repeated on sample rows.

Network output uses `artifact_type = "mcrx-network"`.

When hardware metrics are enabled, the sibling `*_hardware` file uses
`artifact_type = "process-hardware"`.

### Header Row

The header row contains:

- `schema = "heimdall-jsonl-v1"`
- `artifact_type`
- `node_id`
- `producer`
- `created_at`
- `flags`

`producer` is currently `mcrx-core/mcrx_recv`.

`node_id` is resolved in this order:

1. `MCRX_METRICS_NODE_ID`, if set
2. the output file's parent directory name
3. the output file stem

`flags` is a free-form JSON object. `mcrx_recv` populates it with receiver
context such as:

- `transport`
- `role`
- `multicast_group`
- `multicast_port`
- `multicast_interface`
- `join_mode`
- `source_filter`
- `source_addr` when present
- `batch_receive_enabled`

Additional caller-provided flag fields can be merged in with
`MCRX_METRICS_FLAGS_JSON`.

### Sample Rows

The network sample rows keep the existing numeric metric fields and use explicit
names for counter totals and interval deltas.

Packet and byte fields:

- `packets_received_total`
- `bytes_received_total`
- `packets_received_delta`
- `bytes_received_delta`
- `packets_per_sec`
- `bytes_per_sec`

Other counter-style fields follow the same explicit pattern where emitted:

- `would_block_count_total`
- `would_block_count_delta`
- `receive_errors_total`
- `receive_errors_delta`
- `join_count_total`
- `join_count_delta`
- `leave_count_total`
- `leave_count_delta`
- `batch_calls_total`
- `batch_calls_delta`
- `batch_packets_received_total`
- `batch_packets_received_delta`

Current-state gauge fields remain:

- `active_subscriptions`
- `joined_subscriptions`

The header metadata fields are intentionally not repeated on sample rows:

- `schema`
- `artifact_type`
- `node_id`
- `producer`
- `flags`

Hardware sample rows keep their existing compact numeric fields such as:

- `cpu_user_secs`
- `cpu_system_secs`
- `cpu_total_secs`
- `cpu_util_percent`
- `rss_bytes`
- `virtual_memory_bytes`
- `thread_count`
- `open_fds`
- `page_faults_minor`
- `page_faults_major`
- `ctx_switches_voluntary`
- `ctx_switches_involuntary`

## Breaking Schema Change

There is no backward-compatibility layer for the older repeated-metadata JSONL
shape.

Consumers should expect:

- one header object at the top of each file
- compact sample rows afterward
- explicit `*_total` and `*_delta` network counter fields
