# IPv6 Multicast

IPv6 multicast works best when group scope and interface selection are explicit.

## SSM Groups

Use `ff3x::/32` groups for IPv6 SSM. The `x` nibble is the multicast scope:

- `ff31::/16` for interface-local tests on one host
- `ff32::/16` for link-local tests on one L2 link
- `ff35::/16` for site-local tests
- `ff38::/16` for organization-local tests
- `ff3e::/16` for global scope

Prefer dynamic SSM group IDs such as `ff31::8000:1234` or
`ff3e::8000:1234`.

## Source vs Interface

For IPv6 SSM receivers, the two important addresses are different concepts:

- `source` is the sender IP address admitted by the SSM filter.
- `interface` is the receiver's local join interface.

On one machine they may be the same. Across machines they usually differ.
On macOS, IPv6 SSM joins require explicit interface selection; omitting
`interface` leaves too little information for the kernel join request.

```rust
let mut config = SubscriptionConfig::ssm_v6(group, source, port);
config.interface = Some(interface.into());
```

For deterministic link-local joins, also set an interface index:

```rust
let mut config = SubscriptionConfig::asm_v6(group, port);
config.interface = Some("fe80::1".parse()?);
config.interface_index = Some(7);
```

## CLI Interface Forms

Receiver binaries accept:

- `--interface ::1`
- `--interface fe80::1%7`
- `--interface fe80::1%en0`
- `--interface 7`

The mixed SSM form is often the clearest spelling:

```bash
cargo run --bin mcrx_recv_meta -- ff3e::8000:1234 5000 <sender-ipv6> --interface <receiver-ipv6>
```

## Practical Rules

- For `ff32::/16` link-local multicast, use a link-local `fe80::...` source on
  the transmitting host.
- For wider scopes such as `ff35::/16` or `ff3e::/16`, use a ULA or global
  IPv6 source that is valid on that network.
- The configured SSM `source` must match the actual packet source chosen by the
  sender.
- For IPv6 SSM, pass `--interface <receiver-ipv6>` or `--interface <ifindex>`;
  this is required on macOS and recommended everywhere for deterministic joins.

More runnable examples live in [Demo Binaries](demo.md).
