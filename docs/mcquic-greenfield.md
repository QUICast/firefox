# Transparent MCQUIC WebTransport

MCQUIC is a transport optimization beneath ordinary HTTP/3 and WebTransport.
Web content opens the same `WebTransport` session and reads the same streams
whether delivery is currently unicast or multicast. MCQUIC control frames,
membership, keys, integrity data, packet recovery, and fallback remain internal
to Firefox and Neqo.

## Protocol and Permission Baseline

This implementation is pinned exclusively to
`draft-jholland-quic-multicast-08`. The transport parameter, control-frame, and
channel-packet codecs must use revision -08 field layouts and semantics.
Revision -09 is intentionally unsupported:

- do not infer a revision from frame length, field values, or remaining bytes;
- do not add heuristic or dual -08/-09 decoding;
- do not reinterpret the -08 `max_ack_delay_ms` field as an authentication
  delay;
- do not change the wire format in Firefox alone.

A later revision requires one coordinated migration across Neqo, Firefox,
quiche, and Yggdrasil. A peer used with this tree must therefore emit revision
-08. The codec's `revision_08_golden_vectors` test fixes the exact transport
parameter and frame bytes for the supported -08 layouts. The transport-
parameter tests independently pin the exact -08 client capability and empty
server-support encodings. Round-trip tests remain in addition to those
independent vectors; there is no heuristic dual decoder.

The pref `network.http.http3.mcquic.enabled` is an implementation-capability
gate, not application permission. Web content opts one operation in with:

```js
const transport = new WebTransport(url, { multicast: "allow" });
```

The default and explicit `"prohibit"` policies remain unicast. An allowed
operation uses a dedicated HTTP/3 connection and becomes MCQUIC-active only
after its successful extended CONNECT response contains the UA-negotiated
Structured Field `WT-Multicast: ?1`. Missing, false, malformed, or unsolicited
response values leave the same WebTransport Session on ordinary unicast.

Operation identity is fail closed. The policy records both each identity value
and whether that field was bound when the operation was created:

- a window operation binds its `ClientContextId` and `BrowsingContextId`;
- a worker operation binds only its `ClientContextId`;
- an explicitly privileged/native operation may bind neither.

Every later check requires the same presence and value for every bound field.
A missing required client or browsing context is not a wildcard. Extra identity
on an intentionally unbound operation is also rejected. IPC reconstruction,
HTTP/3 retry, and connection cloning preserve the presence bits, and
`AsyncConnectWithClient` repeats the exact-presence check. A mismatch
permanently prohibits multicast for that operation while the ordinary
WebTransport connection remains usable over unicast.

The former native `/moq` subscriber, media decoder, browser overlay, query
trigger, and `native_moq_demo.*` preferences have been removed.

## Build Firefox

From the Firefox checkout:

```bash
./mach build
```

## Run Firefox

The QUICast build enables the generic MCQUIC transport pref by default. Run it
with a normal or temporary profile; no profile customization is required:

```bash
MOZ_LOG="timestamp,nsHttp:5,WebTransport:5" \
MOZ_LOG_FILE="$HOME/Desktop/firefox-mcquic.log" \
./mach run \
  --temp-profile \
  -- \
  --no-remote \
  'https://live.quicast.de/clock/'
```

For troubleshooting, MCQUIC can be disabled in `about:config` or by adding this
to the profile's `user.js`:

```js
user_pref("network.http.http3.mcquic.enabled", false);
```

No query parameter, localStorage switch, iframe activation, native GET
navigation, track override, or overlay is involved.

## Expected Data Path

1. Bifrost creates an ordinary WebTransport Session with
   `{ multicast: "allow" }` and subscribes through its normal JavaScript MoQ
   path. The server accepts multicast with `WT-Multicast: ?1`; otherwise this
   list reduces to the ordinary unicast path.
2. Yggdrasil sends the Session-specific 10-byte WebTransport
   unidirectional-stream prefix over unicast.
3. Authenticated MCQUIC STREAM frames contribute the shared stream body from
   offset 10 onward through Neqo's ordinary receive-stream machinery. Firefox
   releases only remote, server-initiated unidirectional streams owned by the
   sole permitted Session.
4. Bifrost reads the resulting `ReadableStream`, decodes the existing object
   envelope, and renders it exactly as it does over unicast.
5. Firefox sends MC_ACKs while multicast is useful. Missing multicast data is
   recovered at the same stream offsets over unicast without a page reload.
6. If multicast is disabled, membership fails, or the multicast path goes
   stale, the same WebTransport stream continues over unicast.

Authenticated legacy channel DATAGRAMs are accepted for mixed-version rollout
compatibility, then discarded below the web API. They cannot be mistaken for
media stream data.

## Tracked Output Contract

Firefox uses Neqo's tracked output API so output generation and UDP socket
acceptance form one explicit transaction:

```rust
Connection::process_multiple_output_tracked(
    now,
    max_datagrams,
) -> Res<TrackedOutputBatch>

Connection::resolve_output(
    token,
    accepted_gso_segments,
    now,
) -> Res<()>
```

`Http3Client` exposes forwarding methods with the same names and semantics.
Existing untracked output APIs retain their historical "returned means sent"
behavior by immediately resolving the generated batch as fully accepted.

### Token and Non-Interleaving Invariants

For datagram output, `TrackedOutputBatch` carries the `OutputBatch`, its UDP/GSO
segment count, and an opaque `OutputToken`. The token is:

- bound to one `Connection` and one monotonically increasing output generation;
- logically consuming and one-use, with private identity fields and redacted
  `Debug`; successful resolution marks the caller's token resolved;
- valid for every coalesced QUIC packet in every UDP/GSO segment in the batch;
- absent when output is only `None` or `Callback`.

Only one tracked output may be unresolved per `Connection`. While it is
unresolved, a second output call and every mutating `Connection` or
`Http3Client` operation other than `resolve_output` is rejected before
mutation. Fallible APIs return `Error::OutputPending`; legacy infallible APIs
trap with the same error payload. Read-only access is permitted only when it
cannot trigger lazy mutation. Dropping `TrackedOutputBatch` does not unlock the
connection; explicit resolution remains mandatory unless the connection itself
is destroyed.

Foreign, stale, duplicate, already-resolved, or wrong-connection tokens return
`Error::InvalidOutputToken`. An accepted prefix longer than the batch returns
`Error::InvalidInput`. These validations happen before transaction state is
removed or the token is marked resolved. A failed validation therefore cannot
strand the rightful connection: the original caller can correct the prefix or
present the token to its owning connection.

### Resolution Semantics

`accepted_gso_segments` is a prefix count at UDP-segment granularity:

- accepting the full segment count commits the full batch;
- accepting zero abandons the full batch;
- accepting an intermediate count commits exactly that prefix and abandons
  exactly the remaining suffix;
- all coalesced QUIC packets inside one accepted segment are accepted together.

Abandoned packets are removed from recovery without being declared lost. Their
bytes leave bytes-in-flight without reducing the congestion window. Reliable
STREAM, CRYPTO, signaling, connection-ID, MCQUIC, and other retransmittable
obligations are immediately made eligible again. ACK state is restored in
every packet-number space because the ACK was never transmitted.

The rollback journals also restore PTO/probe state, pacing, idle accounting,
PMTUD, ECN, anti-amplification and path send state, flow control, stream send
state, statistics, and deferred qlog output. They do not produce RTT, ECN,
PMTUD, network-loss, or congestion events for unsent packets. Packet numbers
remain consumed and are never reused, and cryptographic state that must remain
monotonic is not rewound.

Transaction metadata consists of per-segment fixed checkpoints, sent-packet
identifiers, recovery tokens, and small stream/QUIC-DATAGRAM undo journals. It
scales with generated segments, packets, and frames. It does not clone the
`Connection`, snapshot stream media payloads, or make a second copy of the UDP
payload; the returned `DatagramBatch` remains the sole wire-byte owner.

### Firefox Socket Integration

`neqo_glue` stores a `BufferedTrackedOutput { batch, token, segment_count,
generated_at }` when a socket send reports `EWOULDBLOCK`. A complete send
resolves the full count. `neqo_udp::Socket::send_segments` returns the exact
accepted UDP/GSO prefix, and Firefox resolves that count before regenerating an
abandoned suffix.

The vendored `quinn-udp` platform calls also fail closed on impossible success
lengths. Unix `sendmsg`/`send_single` and Windows `WSASendMsg` report the full
segment count only when the operating system reports exactly
`Transmit::contents.len()` bytes. A short success becomes `WriteZero`; an
overlong result becomes `InvalidData`. Apple's `sendmsg_x` keeps its native
accepted-prefix accounting, and the fallback path keeps its existing exact
length check.

Firefox does not wait for write readiness when input, a timer, an HTTP/3 event,
an application operation, migration, network change, close, destruction, or
revocation needs to mutate Neqo. The glue first resolves a buffered batch with
zero accepted segments and discards its bytes.

Local send errors are classified by `neqo_udp::SendErrorAction` rather than
Unix-only error constants. Linux/Android `EIO` or `EINVAL` and Windows
`WSAEINVAL` or `WSAEMSGSIZE` on a multi-segment batch disable GSO, abandon the
batch, and regenerate it without segmentation. Local message-size or buffer
exhaustion abandons the tentative output and retries later. Neither path reports
the unsent packets as network loss.

Externally visible transport statistics are committed-only.
`Connection::committed_stats()` overlays the earliest unresolved output
checkpoint on the live counters. `Http3Client` forwards that snapshot, and both
`neqo_http3conn_get_stats` and destruction-time Glean recording use it.
Tentative packet, frame, ECN, and PMTUD counts therefore disappear on
abandonment and are never permanently recorded. The normal FFI release helper
abandons first; `NeqoHttp3Conn::drop` repeats the operation idempotently so a
future caller that bypasses the helper cannot record or retain tentative output.

MCQUIC revocation has a stricter order:

1. `Http3Session::RevokeMcquicOperation()` calls `AbandonOutput()`.
2. Neqo revokes the operation and clears all stale pre-revocation MCQUIC
   output.
3. Firefox generates fresh terminal zero limits and `MC_STATE(LEFT)` output.
4. Firefox leaves and removes receiver subscriptions, then clears channel and
   Session ownership state.

After revocation, only freshly generated terminal zero limits and LEFT/RETIRED
states are accepted by the terminal MCQUIC send API. A buffered nonterminal
frame from before revocation cannot leak after it.

## Bounded State

All values below are implementation limits in the current source, not new
revision -08 wire fields. Revision -08 has no authentication-delay field, so
receive memory uses absolute count, byte, and lifetime bounds. In particular,
`max_ack_delay_ms` is not used to derive authentication buffering.

### Firefox Receiver Limits

These checks occur in `Http3Session` before creating an SSM subscription or
joining it:

| Constant | Bound |
| --- | ---: |
| `MCQUIC_MAX_CHANNEL_IDS` | 32 configured channel IDs/subscriptions |
| `MCQUIC_MAX_JOINED_CHANNELS` | 32 joined channels |
| `MCQUIC_MAX_AGGREGATE_RATE_KIBPS` | 100,000 KiB/s |
| `MCQUIC_MAX_PACKETS_PER_POLL` | 32 packets per poll turn |

`MC_ANNOUNCE` accepts only address family 4 or 6 and checks aggregate announced
rate before `AddSsmSubscription`. It configures, but does not join, a
subscription. `MC_JOIN` rechecks joined count and aggregate joined rate,
requires the current `mc_limits_sequence`, synchronized key/state sequences,
and a configured subscription, and emits JOINED only after `Join` succeeds.
Failure emits DECLINED_JOIN where possible and preserves unicast.

### Neqo Connection Limits

| State | Count bound | Byte/time bound |
| --- | ---: | --- |
| Active controls awaiting HTTP/3 | 256 | 1 MiB, 5 s |
| Pre-negotiation operation controls | 256 | 64 KiB, 5 s |
| Controls for unannounced channels | 32/channel, 256 total | 1 MiB, 5 s |
| Active channel receive states | 32 | aggregate limits below |
| Retired-channel tombstones | 256 | 64 KiB, 5 min |
| Resource-limit notices | 32 | count only |
| Outbound MCQUIC frames | 256 | 1 MiB encoded |
| Pending authenticated stream frames | 65,536 total, 256/owner | 16 MiB, 5 s pending-owner lifetime |
| Pending stream owners | 1,024 | one live deadline each |
| Authorized stream owners | 4,096 | 5 min idle lifetime, refreshed at 150 s |
| Pending channel-to-owner links | 32,768 | exact counted reverse index |
| Owner expirations | 64 pending plus 64 authorized/turn | at most 128 aggregate entries/turn |

The connection-wide authenticated receive aggregates are:

| State | Count bound | Byte bound |
| --- | ---: | ---: |
| Keys | 64 | 4 KiB |
| Integrity hashes | 32,768 | 2 MiB |
| Unauthenticated protected packets | 4,096 | 16 MiB |
| Released legacy DATAGRAMs | 256 | 1 MiB |

An allocation that would exceed a channel-local bound limits that channel and
keeps ordinary unicast available where possible. A connection-wide ownership
or tombstone failure revokes only the MCQUIC optimization rather than
authorizing unbounded state. Outbound enqueue, ACK replacement, loss retry,
push-front restoration, and revocation clear all update one `McquicSendQueue`
encoded-byte/count accounting implementation.

### Per-Channel Receive Limits

| State | Count bound | Byte/time bound |
| --- | ---: | --- |
| Keys | 4 | 64 bytes/secret, 256 bytes total; stale non-current keys 60 s |
| Integrity hashes | 4,096 | 256 KiB, 5 s |
| Unauthenticated protected packets | 1,024 | 4 MiB, 3 s |
| Released legacy DATAGRAMs | 64 | 256 KiB, 1 s |
| Tracked ACK ranges | 64 | 4,096-packet history window |

### Ownership Invariant (F11)

Pending and authorized owners each have exactly one live deadline entry.
Refresh, authorization, stream retirement, channel retirement, close, and
revocation remove or replace that entry transactionally. A
channel-to-pending-stream reverse index allows channel retirement without a
whole-pending-owner scan. HTTP/3 calls `mcquic_retire_stream` when receive
streams or extended CONNECT substreams leave its stream maps. Expiration work
is capped independently at 64 pending and 64 authorized entries per turn, so
one turn processes at most 128 owner expirations and never performs an
unbounded whole-set cleanup.

### Secret Lifecycle Invariant (F12)

`Announce` and `Key` redact `header_secret` and `secret` in `Debug` output and
erase their vector allocation on drop. Temporary frame encodings, partially
decoded secrets, decrypted channel packets, and fixed-size intermediate arrays
use erasing wrappers. Replacement, clear, error, and drop paths erase retained
secret storage, including initialized spare vector capacity where practical.
Ordinary media payload is not treated as secret material.

This is module-local best-effort erasure, not a claim that Rust allocators,
external callers holding a copied public frame field, NSS internals, swap, or
hardware have retained no copy.

## Finding-to-Fix and Test Map

This is the implementation audit ledger for F1-F13. A row marked partial is not
a merge-readiness claim.

| Finding | Disposition | Deterministic coverage |
| --- | --- | --- |
| F1: actor/readiness/retarget teardown | Fixed with one idempotent `WebTransportParent` lifecycle, resolver dispatch outside `mMutex`, and `WebTransport` as a `GlobalTeardownObserver` with balanced BFCache blocking. | [`TestWebTransportLifecycle.cpp`](../netwerk/test/gtest/TestWebTransportLifecycle.cpp): `ActorDestroySerializesEveryTransition`, `StaleParentCallbacksCannotReactivate`, and `LateNativeSessionIsRevokedAndClosed`; [`test_mcquic_permission.js`](../dom/webtransport/test/xpcshell/test_mcquic_permission.js): negotiating/active worker and navigation teardown plus idempotent close. |
| F2: callbacks after `Http3Session` close | Fixed: response and revocation callbacks first test the retained session pointer, late native Sessions are revoked and closed, and proxy dispatch retains the target only for the runnable lifetime. | [`TestWebTransportLifecycle.cpp`](../netwerk/test/gtest/TestWebTransportLifecycle.cpp): `StaleParentCallbacksCannotReactivate`, `LateNativeSessionIsRevokedAndClosed`, and `DelayedCloseCallbackIsHarmlessAfterClose`. |
| F3: admission limits and `mc_limits_sequence` | Fixed before receiver allocation/join: channel, joined, family, aggregate-rate, and sequence validation; failed join declines and preserves unicast. | [`TestHttp3SessionMcquic.cpp`](../netwerk/test/gtest/TestHttp3SessionMcquic.cpp): exact/cap+1 channel and join admission, address-family/rate rejection, allocation/join failure transactionality; [`connection/tests/mcquic.rs`](../third_party/rust/neqo-transport/src/connection/tests/mcquic.rs): exact Neqo channel/rate caps; [`TestMcquicMulticastReceiver.cpp`](../netwerk/test/gtest/TestMcquicMulticastReceiver.cpp): receiver join/leave/rejoin/remove behavior. |
| F4: retained-state exhaustion | Fixed with the exact limits in this document and channel-local decline/revoke behavior. | [`connection/tests/mcquic.rs`](../third_party/rust/neqo-transport/src/connection/tests/mcquic.rs): channel/control/tombstone/pending-owner/queue cap and cap+1 tests; [`mcquic/mod.rs`](../third_party/rust/neqo-transport/src/mcquic/mod.rs): key, integrity, packet, DATAGRAM, and expiry cap tests. |
| F5: wrong multicast owner consumes prefix | Fixed transactionally. Only remote/server unidirectional streams owned by the sole permitted Session are eligible; a violation revokes MCQUIC without consuming the ordinary unicast prefix. | [`connection.rs`](../third_party/rust/neqo-http3/src/connection.rs): `mcquic_ownership_targets_only_permitted_webtransport_streams` covers QPACK encoder/decoder, HTTP/3 control, unknown uni, HTTP, push, extended CONNECT, wrong/no Session, remote/local bidirectional, and local unidirectional targets; [`connection/tests/mcquic.rs`](../third_party/rust/neqo-transport/src/connection/tests/mcquic.rs): transactional ineligible IDs and overlap; [`sessions.rs`](../third_party/rust/neqo-http3/src/features/extended_connect/tests/webtransport/sessions.rs): wrong-owner multicast followed by working unicast. |
| F6: auth/redirect behavior | Fixed by WebTransport credentials mode omit, redirect mode error, and filtered response-header conversion. | [`test_mcquic_permission.js`](../dom/webtransport/test/xpcshell/test_mcquic_permission.js): `credentials_are_omitted_without_retry_or_prompt`, `every_3xx_is_redirect_mode_error`, and response-field edge cases. |
| F7: outer H3/MASQUE authorization | Fixed at the binding boundary: target permission is stripped from an outer proxy connection and cannot activate its MCQUIC state. | [`TestWebTransportOperationPolicy.cpp`](../netwerk/test/gtest/TestWebTransportOperationPolicy.cpp): `OuterProxyCannotUseTargetPermission`. An actual loopback MASQUE route is not covered; whether target multicast may bypass an administratively configured proxy remains an architecture decision. |
| F8: retries/clones/direct routes | Fixed with all-or-nothing typed binding validation and `RefreshWebTransportMulticastRequest`, which regenerates or removes `WT-Multicast` before restarted serialization. Bound client and browsing-context fields require exact presence and value; intentionally unbound privileged/native and worker client-only policies remain explicit. | [`TestWebTransportOperationPolicy.cpp`](../netwerk/test/gtest/TestWebTransportOperationPolicy.cpp): binding-presence, IPC, clone, restart, and direct-route cases; [`test_mcquic_permission.js`](../dom/webtransport/test/xpcshell/test_mcquic_permission.js): `retry_revalidates_the_complete_operation_binding` forces a real 421 first attempt and proves a fresh isolated non-resumed H3 connection, one Session, regenerated request field, accepted response, multicast delivery, revocation, and unicast continuation on attempt two. |
| F9: migration/network/receiver failure | Fixed to abandon unresolved output, revoke/leave multicast, erase receiver/ownership state, and continue the same connection over unicast. It does not silently reauthorize multicast. | [`TestHttp3SessionMcquic.cpp`](../netwerk/test/gtest/TestHttp3SessionMcquic.cpp): injected Neqo path migration, production network-link generation change, and receiver poll failure, each beginning with unresolved output; [`test_webtransport_mcquic.js`](../netwerk/test/unit/test_webtransport_mcquic.js): policy revocation continues unicast. |
| F10: unsent output accounting | Fixed by the tracked-output transaction, exact UDP acceptance, committed-only statistics, and portable local-send classification described above. Output in a packet-number space scheduled for accepted key disposal remains out of tentative recovery/pacer accounting while its retransmission tokens stay journaled for abandonment, preserving the legacy handshake boundary without making key erasure reversible. | [`TestNeqoTrackedOutput.cpp`](../netwerk/test/gtest/TestNeqoTrackedOutput.cpp): full/partial/zero/WouldBlock/unsupported-GSO/transient/fatal injection, every Firefox mutation gate, revocation cleanup, Drop, committed stats, final Glean, and invalid token handling; [`output_tracking.rs`](../third_party/rust/neqo-transport/src/connection/tests/output_tracking.rs): full/zero/partial resolution, coalescing, token validation, ACK restoration, bounded metadata, mutation rejection, phantom-flight removal, immediate identical-offset STREAM retry, and ECN disposition; the complete Neqo transport suite also retains the existing handshake pacing/recovery behavior; [`quinn-udp/src/lib.rs`](../third_party/rust/quinn-udp/src/lib.rs): exact/short/overlong platform success lengths; [`neqo-udp`](../third_party/rust/neqo-udp/src/lib.rs): platform error classification. |
| F11: ownership scan/churn | Fixed with one live deadline per owner, reverse channel indexes, stream-lifecycle retirement, and at most 64 expirations per turn. | [`connection/tests/mcquic.rs`](../third_party/rust/neqo-transport/src/connection/tests/mcquic.rs): `ownership_caps_incremental_queue_and_retirement_are_exact`, `owner_churn_releases_deadlines_checks_and_reverse_links`, `retire_discards_only_the_named_channels_unbound_frames_and_secrets`. |
| F12: secret logging/lifetime | Fixed with private erasing storage, redacted `Debug`, and erasing temporary encodings/decryption buffers where practical. | [`mcquic/mod.rs`](../third_party/rust/neqo-transport/src/mcquic/mod.rs): redaction, capacity erasure, success/error, replace/clear/drop, malformed decode, temporary encoding, and decrypted-packet tests. |
| F13: protocol revision | Resolved by an explicit -08 pin. Firefox does not implement -09 and will migrate only through a coordinated -10 change across Neqo, Firefox, quiche, and Yggdrasil. | [`mcquic/mod.rs`](../third_party/rust/neqo-transport/src/mcquic/mod.rs): `revision_08_golden_vectors`; [`tparams.rs`](../third_party/rust/neqo-transport/src/tparams.rs): exact -08 client and server-support vectors; codec round trips remain supplementary. |

`neqo_glue` now has a narrow deterministic send seam around the same
`process_output_and_send_with` implementation used by the real socket path. It
injects full acceptance, an exact partial GSO prefix, `WouldBlock`,
unsupported-GSO, transient failure, fatal failure, and an invalid overlong
acceptance. `TestNeqoTrackedOutput` proves that `WouldBlock` retains exactly one
transaction and that input, timeout/output, event pumping, revocation, close,
and destruction abandon it before further Neqo mutation. Combined with the
transport transaction tests, it also proves immediate identical-offset STREAM
retry, no phantom recovery state, no stale pre-revocation MCQUIC output, and
committed-only statistics.

The seam deliberately does not claim a real kernel produced an impossible short
success. Deterministic production-send injection plus exact-length platform
helper tests are the accepted boundary for that impossible kernel result.

This macOS run also cannot claim native `WSASendMsg` execution. The
target-specific Windows path and shared return-length helper remain covered in
source and deterministic tests, but must execute on Windows CI.

The configured xpcshell build reports `socketprocess_networking=false`.
`TestHttp3SessionMcquic` executes the socket-thread production notification and
revocation paths, including the real network-link observer generation, but does
not provide separate socket-process IPC evidence. That remains a platform
integration item.

The existing MASQUE loopback harness was evaluated but did not reach
WebTransport readiness in this configuration. The direct policy GTest proves
that an outer proxy connection cannot inherit target permission; a later
MASQUE smoke run must additionally show that the outer connection sends no
`WT-Multicast`, creates no MCQUIC state, and that any target-side permitted
connection remains dedicated and unicast-capable on revocation.

These deferred Windows, socket-process, and MASQUE items are reported as
integration evidence gaps rather than skipped deterministic tests. They prevent
this document from making a merge-readiness claim on its own.

### Independent Closure Audit

An independent read-only audit of the final source found no remaining
actionable defect. It first reproduced an ordinary-QUIC handshake pacing
regression in tracked output. `track_output_packet` now keeps packets from a
logically discarded packet-number space out of recovery and pacing while
journaling their retransmission tokens until socket disposition. The exact
`loss_time_past_largest_acked` regression and the complete 840-test transport
unit suite plus integrations pass after that correction.

The audit retained these evidence-granularity limits:

- lifecycle GTests deterministically inject transition states; worker and
  navigation xpcshell tests exercise live DOM teardown, but no single test
  races a live actor against a native `Http3Session` callback;
- the fake receiver reaches exact join limits through the production admission
  helper, but does not inject a wire-originated `MC_JOIN` through Neqo to
  exercise `mc_limits_sequence`, `DECLINED_JOIN`, and JOINED-send rollback in
  one test;
- the complete QPACK/control/unknown/bidirectional target matrix exercises the
  production ownership classifier, while only wrong-WebTransport-Session
  targeting continues through the full ordinary stream handler afterward;
- generic zero and partial tracked-output rollback are covered, and the
  logically discarded handshake-space regression is covered on full
  acceptance, but there is no dedicated test combining that handshake boundary
  with zero or partial GSO acceptance.

These are recorded as remaining deterministic evidence gaps, not known source
defects. Together with the platform and integration gaps above, they keep the
current tree from being described as merge-ready.

## Optional AMT Gateway

Use AMT when the local network cannot receive the live SSM multicast natively.
Run this from the sibling `amt` checkout and replace the relay placeholder with
the active relay endpoint.

```bash
cd ../amt
cargo build --locked --release --features metrics

LOCAL_LAN_IP=$(ipconfig getifaddr en0)

sudo -E target/release/amt gateway \
  --relay "<AMT_RELAY_HOST_OR_IP>:2268" \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface "$LOCAL_LAN_IP" \
  --local-membership-interface "$LOCAL_LAN_IP" \
  --metrics-dir /tmp/amt-metrics \
  --node-id local-amt-gateway
```

Transparent mode observes Firefox's IGMPv3 SSM joins and forwards matching
multicast IP packets from the AMT relay to the local interface.

## Diagnostics

Useful Firefox log filter:

```bash
grep -E "MC_ANNOUNCE|MC_JOIN|MC_STATE|mcrx received|queued MC_ACK|ignored authenticated legacy DATAGRAMs" \
  "$HOME/Desktop/firefox-mcquic.log"
```

Useful packet-path evidence includes:

- per-client unicast QUIC traffic carrying the stream prefix and recovery;
- one shared SSM flow carrying stream bodies;
- advancing client MC_ACKs;
- increased server unicast egress after stopping AMT;
- resumed multicast delivery after membership returns.

Playback behavior alone is not sufficient to distinguish multicast from
seamless unicast fallback. Use Firefox logs, Yggdrasil path counters, and packet
capture together.
