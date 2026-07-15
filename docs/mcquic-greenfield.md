# Transparent MCQUIC WebTransport

MCQUIC is a transport optimization beneath ordinary HTTP/3 and WebTransport.
Web content opens the same `WebTransport` session and reads the same streams
whether delivery is currently unicast or multicast. MCQUIC control frames,
membership, keys, integrity data, packet recovery, and fallback remain internal
to Firefox and Neqo.

The former native `/moq` subscriber, media decoder, browser overlay, query
trigger, and `native_moq_demo.*` preferences have been removed.

## Build Firefox

From the Firefox checkout:

```bash
./mach build
```

## Run Firefox

The generic transport pref is the only MCQUIC switch:

```bash
MOZ_LOG="timestamp,nsHttp:5,WebTransport:5" \
MOZ_LOG_FILE="$HOME/Desktop/firefox-mcquic.log" \
./mach run \
  --temp-profile \
  --setpref=network.http.http3.mcquic.enabled=true \
  -- \
  --no-remote \
  'https://live.quicast.de/clock/'
```

Use a normal profile by adding this to its `user.js`:

```js
user_pref("network.http.http3.mcquic.enabled", true);
```

No query parameter, localStorage switch, iframe activation, native GET
navigation, track override, or overlay is involved.

## Expected Data Path

1. Bifrost creates an ordinary `new WebTransport()` connection and subscribes
   to the clock through its normal JavaScript MoQ path.
2. Yggdrasil sends the connection-specific 10-byte WebTransport
   unidirectional-stream prefix over unicast.
3. Authenticated MCQUIC STREAM frames contribute the shared stream body from
   offset 10 onward through Neqo's ordinary receive-stream machinery.
4. Bifrost reads the resulting `ReadableStream`, decodes the existing object
   envelope, and renders it exactly as it does over unicast.
5. Firefox sends MC_ACKs while multicast is useful. Missing multicast data is
   recovered at the same stream offsets over unicast without a page reload.
6. If multicast is disabled, membership fails, or the multicast path goes
   stale, the same WebTransport stream continues over unicast.

Authenticated legacy channel DATAGRAMs are accepted for mixed-version rollout
compatibility, then discarded below the web API. They cannot be mistaken for
media stream data.

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
