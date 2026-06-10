# Raw Packet Receive

`mcrx-core` can optionally receive complete multicast IP datagrams instead of
just UDP payloads.

This support is gated behind the `raw-packets` Cargo feature so normal UDP
users do not pay for extra API surface, platform checks, or privileged socket
requirements.

## Status

Current first-pass support:

- Linux: implemented
- macOS: implemented through BPF, with explicit interface selection required
- Windows: implemented for IPv4 raw receive, with explicit IPv4 interface
  selection required

The raw API is intentionally separate from the UDP API. Enabling
`raw-packets` does not change the behavior of `Context`, `Subscription`,
`SubscriptionConfig`, or `Packet`.

## Why It Exists

The default receive path is UDP-centric:

- `SubscriptionConfig` includes `dst_port`
- `Packet` exposes source socket address, destination group, destination port,
  and UDP payload bytes
- the platform layer receives on UDP sockets

That is the right shape for ordinary multicast applications. It is not enough
for applications such as AMT relay forwarding that need the original multicast
IP datagram so it can be wrapped or forwarded intact.

## Feature Enablement

```bash
cargo add mcrx-core --features raw-packets
```

## Raw API Types

The raw feature adds a parallel API:

- `RawSubscriptionConfig`
- `RawContext`
- `RawSubscription`
- `RawPacket`

`RawSubscriptionConfig` keeps the same multicast membership model as the UDP
path:

- ASM with `source = Any`
- SSM with `source = Source(ip)`
- optional interface address
- optional IPv6 interface index

Unlike `SubscriptionConfig`, it does not include a UDP port.

## Example

```rust
use mcrx_core::{RawContext, RawSubscriptionConfig};
use std::net::Ipv4Addr;

let mut ctx = RawContext::new();
let id = ctx.add_subscription(RawSubscriptionConfig::asm(Ipv4Addr::new(239, 1, 2, 3)))?;
ctx.join_subscription(id)?;

if let Some(packet) = ctx.try_recv_any()? {
    println!("received {} raw bytes", packet.datagram_len());
    println!("source ip: {:?}", packet.source_ip);
    println!("group ip: {:?}", packet.group);
    println!("ip protocol: {:?}", packet.ip_protocol);
}
```

The feature also includes a small receiver binary for platform testing:

```bash
cargo run --features raw-packets --bin mcrx_raw_recv -- 239.1.2.3 --interface 192.168.1.20
cargo run --features raw-packets --bin mcrx_raw_recv -- ff3e::8000:1234 --interface 7
```

## Raw Packet Shape

`RawPacket` contains:

- `subscription_id`
- full IP datagram bytes as `Bytes`
- parsed source IP when cheaply available
- parsed destination/group IP when cheaply available
- parsed IP protocol or IPv6 next-header when cheaply available
- `ReceiveMetadata`

The raw path reuses the same `ReceiveMetadata` struct as the UDP metadata API.
The most useful fields are:

- `configured_interface`
- `configured_interface_index`
- `destination_local_ip`
- `ingress_interface_index`

`socket_local_addr` is typically not meaningful for packet-socket, BPF, or raw
capture receive and should be treated as optional.

## Platform Limitations

### Linux

The current implementation uses Linux packet sockets for receive and a normal
UDP socket for multicast membership management.

That gives a useful property for AMT-style use cases: the receive path returns
the complete IP datagram rather than just the UDP payload.

Practical notes:

- raw packet sockets usually require `CAP_NET_RAW` or root
- the packet socket is opened with `ETH_P_ALL` and filters in userspace, matching
  tcpdump-style behavior for same-host outbound multicast paths where the packet
  may only be visible as `PACKET_OUTGOING`
- multicast join and leave still reuse the normal multicast membership logic
- interface selection matters, especially for IPv6 and link-local groups

Manual same-host check:

```bash
sudo ./target/debug/mcrx_raw_recv 239.1.2.3 --interface <receiver-ipv4>
tcpdump -Q out -ni <iface> 'dst host 239.1.2.3'
```

When a local sender emits to `239.1.2.3`, both tcpdump and `mcrx_raw_recv`
should see the packet even if `tcpdump -Q in` stays quiet.

### macOS

The macOS implementation uses BPF devices for receive and a normal UDP socket
for multicast membership management.

Practical notes:

- opening `/dev/bpf*` usually requires elevated privileges or device
  permissions
- raw receive requires an explicit interface address or interface index
- common BPF datalink types are supported: raw IP, loopback/null, Ethernet,
  and VLAN-tagged Ethernet
- unsupported BPF datalink types return
  `McrxError::RawPacketReceiveUnsupported(...)`

### Windows

The Windows implementation currently supports IPv4 raw receive.

Practical notes:

- raw sockets usually require Administrator privileges
- IPv4 raw receive requires an explicit local IPv4 interface address
- the implementation first tries Windows multicast-only capture and falls back
  to ordinary raw capture if needed
- Windows also opens an IPv4/UDP raw receive socket as a pragmatic fallback for
  adapters that expose multicast control traffic through raw capture but do not
  surface UDP multicast data there
- IPv6 raw receive currently returns
  `McrxError::RawPacketReceiveUnsupported(...)`

The crate does not silently fall back to UDP payload receive on any platform.
That would change the semantics of the API and make AMT-style forwarding easy
to misuse.

## Validation Rules

The raw config path reuses the same multicast validation model as the UDP API:

- group must be multicast
- source family must match group family
- interface family must match group family
- IPv6 interface indexes are supported, IPv4 interface indexes are rejected
- IPv4 SSM requires `232.0.0.0/8`
- IPv6 SSM requires `ff3x::/32`

## IPv6 Notes

Raw IPv6 multicast follows the same group and interface guidance as the UDP
receiver. See [IPv6 Multicast](ipv6.md) for the full scoping rules.

- use `ff3x::/32` for IPv6 SSM
- use explicit interface selection when link-local scope is involved
- prefer explicit IPv6 interface indexes for deterministic joins when needed
