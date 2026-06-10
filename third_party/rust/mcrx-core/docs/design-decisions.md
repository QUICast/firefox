# Design Decisions

## Small Core, Optional Extensions

The crate is centered on one job: receiving multicast traffic through a small,
explicit core API.

Features like Tokio integration, richer receive metadata, and metrics are kept
as optional layers around that core rather than redefining it.

Raw multicast IP datagram receive follows the same pattern. It is available as
an opt-in `raw-packets` feature so the default UDP receiver remains small and
predictable.

## Context vs Subscription

A single `Subscription` models one multicast receive path.

A `Context` coordinates multiple subscriptions and provides behavior that does
not belong to a single one, including:

- fairness across subscriptions
- batch receive
- lifecycle orchestration
- aggregation of metrics
- a stable top-level integration handle

This lets callers work at either level without duplicating logic.

## Non-blocking API

The library uses a pull-based, non-blocking API:

- `Subscription::try_recv()`
- `Subscription::try_recv_with_metadata()`
- `Context::try_recv_any()`
- `Context::try_recv_any_with_metadata()`
- `Context::try_recv_batch_into()`
- `Context::try_recv_all_into()`

Reasons:

- no runtime dependency in the core crate
- fits sync and async environments
- integrates cleanly with custom event loops
- keeps control over pacing and allocation with the caller

## Explicit Join and Leave Lifecycle

Adding a subscription does not automatically join the multicast group.

This makes the lifecycle explicit:

1. create or provide a bound socket
2. add the subscription
3. join when ready
4. leave without destroying the socket
5. remove or extract the subscription when done

That model is easier to reason about for tests, metrics, and runtime
integration.

## Socket Ownership Boundary

`Context::add_subscription()` is the convenience path that creates and binds
the socket internally.

`Context::add_subscription_with_socket()` is the lower-level integration path
for embedders that need to control socket creation themselves.

For event-loop integration, the library supports two ownership modes:

- borrow the socket from a live `Subscription`
- extract the whole `Subscription` from a `Context` with `take_subscription()`

This keeps ownership transfer explicit instead of forcing callers to rebuild
subscription state around a raw socket handle.

## Separate Raw API

Raw multicast receive needs a different packet model:

- there is no UDP destination port in the subscription config
- the receive path returns full IP datagrams instead of UDP payloads
- some platforms require different socket families or elevated privileges

Because of that, the crate exposes `RawSubscriptionConfig`, `RawContext`,
`RawSubscription`, and `RawPacket` as a separate feature-gated surface instead
of overloading the existing UDP types with optional raw behavior.

That separation keeps the default API stable and avoids changing semantics for
existing users. Platform details live in [Raw Packet Receive](raw-packets.md).

## Explicit IPv6 Source and Interface Selection

IPv6 multicast behavior is strongly shaped by scope and interface selection, so
the library keeps those choices explicit in the public model:

- `SubscriptionConfig::source` identifies the admitted sender for SSM
- `SubscriptionConfig::interface` identifies the local join interface

Those are deliberately separate because cross-machine IPv6 SSM usually needs
both values, and they are often different. Practical scoping guidance lives in
[IPv6 Multicast](ipv6.md).

## Optional Receive Metadata

The original `Packet` type stays small and stable for callers that only need
the core addressing tuple plus payload.

The richer path uses `PacketWithMetadata`, which wraps a `Packet` plus a
non-exhaustive `ReceiveMetadata` struct. That metadata currently includes:

- socket local address
- configured join interface
- pktinfo-style destination local IP on supported Unix and Windows IPv4 and IPv6 platforms
- pktinfo-style ingress interface index on supported Unix and Windows IPv4 and IPv6 platforms

Where the platform layer does not provide those ancillary messages yet, the
pktinfo-derived fields remain `None`.

## Optional Tokio Layer

The Tokio adapter builds on the ownership model above instead of changing the
core receive API.

`TokioSubscription` wraps an owned `Subscription` after `take_subscription()`,
so the async path reuses the same join, leave, and receive logic rather than
introducing a separate socket management model.

## Metrics Model

Metrics are split into:

- cumulative snapshots
- deltas between snapshots
- sampler helpers for repeated sampling

This avoids hidden mutable state inside snapshots while still making
interval-based analysis straightforward.

### Why the First Sampler Call Returns `None`

A delta needs a previous sample.

Returning `None` on the first sampler call avoids:

- fake zero-duration intervals
- misleading rates
- hidden baseline assumptions
