# Demo Binaries

## Overview

The repository provides receiver-focused demo binaries:

- `mcrx_recv`
- `mcrx_tokio_recv` (with `--features tokio`)
- `mcrx_recv_meta`
- `mcrx_raw_recv` (with `--features raw-packets`)

These are intended for real-network testing and API validation.

## Receiver

```bash
cargo run --bin mcrx_recv -- <group> <dst_port> [source] [interface]
```

Examples:

```bash
cargo run --bin mcrx_recv -- 239.1.2.3 5000
cargo run --bin mcrx_recv -- 232.1.2.3 5000 192.168.1.10
cargo run --bin mcrx_recv -- 232.1.2.3 5000 192.168.1.10 192.168.1.20
cargo run --bin mcrx_recv -- ff01::1234 5000
cargo run --bin mcrx_recv -- ff01::1234 5000 --interface ::1
cargo run --bin mcrx_recv -- ff31::8000:1234 5000 fd06:ba51:f296:0:1caf:6b66:e6f7:4b10 --interface fd06:ba51:f296:0:1caf:6b66:e6f7:4b10
```

Argument meaning:

- `group` → multicast group address
- `dst_port` → destination UDP port
- `source` → optional SSM source address
- `interface` → optional local interface address

For SSM, use IPv4 `232.0.0.0/8` groups or IPv6 `ff3x::/32` groups. ASM-range
groups such as `239.x.x.x` should omit `source`.

## Tokio Receiver

```bash
cargo run --features tokio --bin mcrx_tokio_recv -- <group> <dst_port> [source] [interface]
```

This variant extracts the joined subscription from the `Context`, wraps it in
`TokioSubscription`, and awaits packets asynchronously.

Example:

```bash
cargo run --features tokio --bin mcrx_tokio_recv -- 239.1.2.3 5000
```

## Metadata-aware Receiver

```bash
cargo run --bin mcrx_recv_meta -- <group> <dst_port> [source] [interface]
```

This variant uses `try_recv_any_with_metadata()` and prints the optional
receive metadata alongside each packet.

Example:

```bash
cargo run --bin mcrx_recv_meta -- 239.1.2.3 5000
cargo run --bin mcrx_recv_meta -- ff01::1234 5000 --interface ::1
cargo run --bin mcrx_recv_meta -- ff3e::8000:1234 5000 <sender-ipv6> --interface <receiver-ipv6>
```

## IPv6 SSM Tips

Use [IPv6 Multicast](ipv6.md) for the full group scope and interface-selection
rules. The important receiver-side split is:

- `source` means the sender's IP address.
- `--interface` means the receiver's local join interface.

Cross-machine IPv6 SSM example:

```bash
cargo run --bin mcrx_recv_meta -- ff3e::8000:1234 5000 <sender-ipv6> --interface <receiver-ipv6>
```

## Raw Packet Receiver

```bash
cargo run --features raw-packets --bin mcrx_raw_recv -- <group> [source] [interface]
```

Examples:

```bash
cargo run --features raw-packets --bin mcrx_raw_recv -- 239.1.2.3 --interface 192.168.1.20
cargo run --features raw-packets --bin mcrx_raw_recv -- ff3e::8000:1234 --interface 7
```

Raw receive has platform-specific privilege and support boundaries. See
[Raw Packet Receive](raw-packets.md).

## Receiver Metrics

When built with `--features metrics`, `mcrx_recv` can emit periodic delta-based
metrics summaries.

### Environment variables

`MCRX_METRICS_SUMMARY_SECS`

```bash
MCRX_METRICS_SUMMARY_SECS=2
```

`MCRX_METRICS_SUMMARY_FILE`

```bash
MCRX_METRICS_SUMMARY_FILE=metrics.jsonl
```

`MCRX_METRICS_NODE_ID`

```bash
MCRX_METRICS_NODE_ID=client-0001
```

`MCRX_METRICS_FLAGS_JSON`

```bash
MCRX_METRICS_FLAGS_JSON='{"transport":"quic","experiment":"baseline-a"}'
```

### Example usage

Print summaries to the terminal:

```bash
MCRX_METRICS_SUMMARY_SECS=2 cargo run --features metrics --bin mcrx_recv -- 239.1.2.3 5000
```

Write summaries to a file:

```bash
MCRX_METRICS_SUMMARY_SECS=2 MCRX_METRICS_SUMMARY_FILE=metrics.jsonl cargo run --features metrics --bin mcrx_recv -- 239.1.2.3 5000
```

Write single-header JSONL with explicit node metadata:

```bash
MCRX_METRICS_SUMMARY_SECS=2 \
MCRX_METRICS_SUMMARY_FILE=results/client-0001/network.jsonl \
MCRX_METRICS_FLAGS_JSON='{"experiment":"baseline-a"}' \
cargo run --features metrics --bin mcrx_recv -- 239.1.2.3 5000
```

## Notes

- `mcrx_recv` uses a simple non-blocking polling loop
- `mcrx_tokio_recv` demonstrates the optional Tokio adapter and subscription handoff path
- `mcrx_recv_meta` is useful when validating interface-sensitive metadata wiring
