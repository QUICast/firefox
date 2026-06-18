# Native MCQUIC Multicast Demo

This branch can run the native MCQUIC/MoQ debug path against the live Quicast
demo while keeping normal WebTransport playback available as the baseline.
Native MCQUIC is experimental and internal to this branch; do not expose MCQUIC
control frames, keys, integrity data, or multicast packets to web content.

## Build Firefox

From the Firefox checkout:

```bash
git checkout huginn
./mach build
```

## Configure The Demo Profile

The native multicast demo path is controlled by one demo switch plus an origin
allowlist and an explicit temporary track override. `--setpref` is not supported
when running with an explicit profile, so write the prefs to `user.js`.

```bash
PROFILE=/private/tmp/mcquic-firefox-profile-live
mkdir -p "$PROFILE"

cat > "$PROFILE/user.js" <<'EOF'
user_pref("network.http.http3.enable", true);
user_pref("network.http.http3.mcquic.native_moq_demo.enabled", true);
user_pref("network.http.http3.mcquic.native_moq_demo.origin", "live.quicast.de");
user_pref("network.http.http3.mcquic.native_moq_demo.track", "ratatoskr/demo|h264-loc-msf");
EOF
```

If the live stream is currently published as `h264-loc`, use this track line
instead:

```js
user_pref("network.http.http3.mcquic.native_moq_demo.track", "ratatoskr/demo|h264-loc");
```

The old staged prefs are no longer used by the native demo path:

```text
network.http.http3.mcquic.moq_subscribe.*
network.http.http3.mcquic.moq_media_*
```

## Run Firefox

Open the bare site. Do not add `?nativeFirefoxTrigger=1`.

```bash
MOZ_LOG="timestamp,nsHttp:5,WebTransport:5" \
MOZ_LOG_FILE="$HOME/Desktop/firefox-mcquic.log" \
./mach run \
  --profile /private/tmp/mcquic-firefox-profile-live \
  -- \
  --no-remote \
  https://live.quicast.de/
```

Expected behavior:

- With native multicast available, the native debug path joins SSM, validates
  multicast packets, sends MC_ACKs, decodes media, and paints the native overlay
  on the page playback surface.
- Without native multicast, playback should continue via unicast fallback. The
  JS WebTransport path remains the ordinary website baseline.

## Optional AMT Gateway

Use AMT only when the local network cannot receive the live SSM multicast
natively. Run this from the sibling `amt` checkout and replace the relay
placeholder with the live AMT relay endpoint.

```bash
cd ../amt
cargo build --locked --release --features metrics

LOCAL_LAN_IP=$(ipconfig getifaddr en0)
echo "$LOCAL_LAN_IP"

sudo -E target/release/amt gateway \
  --relay "<AMT_RELAY_HOST_OR_IP>:2268" \
  --transparent \
  --protocol igmpv3 \
  --downstream-interface "$LOCAL_LAN_IP" \
  --local-membership-interface "$LOCAL_LAN_IP" \
  --metrics-dir /tmp/amt-metrics \
  --node-id local-amt-gateway
```

Transparent mode listens for Firefox's local IGMPv3 SSM joins and forwards the
corresponding multicast IP packets from the AMT relay to the local interface.

## Quick Diagnostics

Useful log filter:

```bash
grep -E "MoQ setup complete|MoQ subscribed|MC_ANNOUNCE|multicast join attempted|mcrx packet|MC_ACK|unicast object received|media frame decoded|delivery mode" \
  "$HOME/Desktop/firefox-mcquic.log"
```

Useful landmarks:

```text
MCQUIC MoQ setup complete
MCQUIC MoQ subscribed
MCQUIC multicast join attempted
MCQUIC mcrx packet
MCQUIC queued MC_ACK
MCQUIC MoQ unicast object received
MCQUIC MoQ media decoded frame
```

If multicast is unavailable, it is fine to see join attempts without `mcrx`
packets. Playback should remain on unicast fallback.
