# Usage

This guide covers the default UDP receive API. Optional raw packet, metrics,
Python, and detailed IPv6 guidance live in their own docs.

## Core Flow

```rust
use mcrx_core::{Context, SubscriptionConfig};

let mut ctx = Context::new();
let config = SubscriptionConfig::asm(group, port);
let id = ctx.add_subscription(config)?;
ctx.join_subscription(id)?;

if let Some(packet) = ctx.try_recv_any()? {
    println!("received {} bytes", packet.payload_len());
}
```

For SSM:

```rust
let config = SubscriptionConfig::ssm(group, source, port);
```

IPv4 SSM groups must be in `232.0.0.0/8`; IPv6 SSM groups must be in
`ff3x::/32`. Use ASM for groups outside those ranges.

For IPv4 SSM on macOS, mcrx uses `IP_ADD_SOURCE_MEMBERSHIP` with an explicit
local interface address. If tcpdump or Wireshark still shows IGMPv2 reports for
a valid `232/8` SSM join, the macOS IGMP compatibility state may be stale. Stop
older receiver processes and retry; if it persists, rebooting the Mac has been
observed to restore the expected IGMPv3 reports:

```text
192.168.188.107 > 224.0.0.22: igmp v3 report, 1 group record(s) [gaddr 232.1.1.1 to_in { 192.46.235.159 }]
```

To join on a specific local interface:

```rust
let mut config = SubscriptionConfig::asm(group, port);
config.interface = Some(interface.into());
```

For IPv6 link-local or otherwise ambiguous joins, set an interface index too:

```rust
let mut config = SubscriptionConfig::asm_v6(group, port);
config.interface = Some("fe80::1".parse()?);
config.interface_index = Some(7);
```

See [IPv6 Multicast](ipv6.md) for group scoping and interface-selection rules.

## Existing Sockets

Use `add_subscription_with_socket()` when an integration needs to create or
bind the UDP socket itself. The socket must already be bound to
`config.dst_port`.

```rust
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};

let config = SubscriptionConfig::asm(Ipv4Addr::new(239, 1, 2, 3), 5000);

let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
socket.set_reuse_address(true)?;
socket.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5000)))?;

let id = ctx.add_subscription_with_socket(config, socket)?;
ctx.join_subscription(id)?;
```

The supplied socket is switched to non-blocking mode. Multicast join and leave
still flow through `join_subscription()` and `leave_subscription()`.

## Receiving

From any joined subscription:

```rust
if let Some(packet) = ctx.try_recv_any()? {
    println!("received {} bytes", packet.payload_len());
}
```

From one specific subscription:

```rust
let subscription = ctx.get_subscription(id).unwrap();
if let Some(packet) = subscription.try_recv()? {
    println!("received {} bytes", packet.payload_len());
}
```

`try_recv_any()` uses round-robin style fairness across joined subscriptions.
All receive APIs are non-blocking: `Ok(None)` means no packet is currently
available.

## Receive Metadata

Use the metadata-aware APIs when you need local destination or interface
context:

```rust
let subscription = ctx.get_subscription(id).unwrap();
if let Some(packet) = subscription.try_recv_with_metadata()? {
    println!("destination ip: {:?}", packet.metadata.destination_local_ip);
    println!("ingress interface: {:?}", packet.metadata.ingress_interface_index);
}
```

The plain `Packet` type remains small and stable. `PacketWithMetadata` wraps it
with optional platform receive metadata.

## Batch Receive

Bounded batch:

```rust
let mut packets = Vec::new();
ctx.try_recv_batch_into(&mut packets, 64)?;
```

Drain everything currently available:

```rust
let mut packets = Vec::new();
ctx.try_recv_all_into(&mut packets)?;
```

## Event Loop Integration

Borrow a live socket while the subscription stays inside the `Context`:

```rust
let subscription = ctx.get_subscription(id).unwrap();
let socket = subscription.socket();

#[cfg(unix)]
let raw = subscription.as_raw_fd();
```

Extract ownership for handoff into another runtime:

```rust
let subscription = ctx.take_subscription(id).unwrap();
let parts = subscription.into_parts();
let socket = parts.socket;
```

`take_subscription()` preserves the lifecycle state. A joined subscription can
continue receiving after handoff.

## Optional Extensions

- Tokio: enable `tokio` and use `TokioSubscription`; see [Demo Binaries](demo.md).
- Metrics: enable `metrics`; see [Metrics](metrics.md).
- Raw IP datagrams: enable `raw-packets`; see [Raw Packet Receive](raw-packets.md).
- Python bindings: see [Python Bindings](python.md).

## Leaving, Removing, and Taking Ownership

```rust
ctx.leave_subscription(id)?;
ctx.remove_subscription(id);
```

If you need the owned subscription back:

```rust
if let Some(subscription) = ctx.take_subscription(id) {
    let socket = subscription.into_socket();
    drop(socket);
}
```

## Multiple Subscriptions

```rust
let mut ctx = Context::new();

let id1 = ctx.add_subscription(SubscriptionConfig::asm(group1, 5000))?;
let id2 = ctx.add_subscription(SubscriptionConfig::asm(group2, 5001))?;

ctx.join_subscription(id1)?;
ctx.join_subscription(id2)?;

if let Some(packet) = ctx.try_recv_any()? {
    println!("received on subscription {}", packet.subscription_id.0);
}
```
