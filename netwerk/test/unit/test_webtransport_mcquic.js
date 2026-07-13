/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* import-globals-from head_webtransport.js */

"use strict";

const MCQUIC_PREF = "network.http.http3.mcquic.enabled";
const MCQUIC_NATIVE_DEMO_PREF =
  "network.http.http3.mcquic.native_moq_demo.enabled";
const EVENT_TIMEOUT_MS = 30000;

const { clearTimeout, setTimeout } = ChromeUtils.importESModule(
  "resource://gre/modules/Timer.sys.mjs"
);

function withTimeout(promise, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
    timer = setTimeout(
      () => reject(new Error(`Timed out waiting for ${label}`)),
      EVENT_TIMEOUT_MS
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function makeEventQueue() {
  const values = [];
  const waiters = [];
  return {
    push(value) {
      if (waiters.length) {
        waiters.shift()(value);
      } else {
        values.push(value);
      }
    },
    next(label) {
      if (values.length) {
        return Promise.resolve(values.shift());
      }
      return withTimeout(new Promise(resolve => waiters.push(resolve)), label);
    },
  };
}

function readWebTransportStream(stream, label) {
  return withTimeout(
    new Promise((resolve, reject) => {
      let data = "";
      const input = stream.inputStream;
      const callback = {
        QueryInterface: ChromeUtils.generateQI(["nsIInputStreamCallback"]),
        onInputStreamReady(readyInput) {
          try {
            const available = readyInput.available();
            if (available) {
              data += NetUtil.readInputStreamToString(readyInput, available);
            }
            if (stream.hasReceivedFIN) {
              resolve(data);
              return;
            }
            readyInput.asyncWait(callback, 0, 0, Services.tm.currentThread);
          } catch (error) {
            reject(error);
          }
        },
      };
      input.asyncWait(callback, 0, 0, Services.tm.currentThread);
    }),
    label
  );
}

registerCleanupFunction(() => {
  Services.prefs.clearUserPref(MCQUIC_PREF);
  Services.prefs.clearUserPref(MCQUIC_NATIVE_DEMO_PREF);
  Services.prefs.clearUserPref("network.dns.localDomains");
  Services.prefs.clearUserPref(
    "network.http.http3.alt-svc-mapping-for-testing"
  );
});

add_task(
  async function test_authenticated_mcquic_streams_beneath_webtransport() {
    Services.prefs.setBoolPref(MCQUIC_PREF, true);
    Services.prefs.setBoolPref(MCQUIC_NATIVE_DEMO_PREF, false);
    await http3_setup_tests("h3");

    Assert.ok(Services.prefs.getBoolPref(MCQUIC_PREF));
    Assert.ok(!Services.prefs.getBoolPref(MCQUIC_NATIVE_DEMO_PREF));

    const port = Services.env.get("MOZHTTP3_PORT");
    Assert.notEqual(port, null);
    Assert.notEqual(port, "");

    const streams = makeEventQueue();
    const resets = makeEventQueue();
    const listener = new WebTransportListener().QueryInterface(
      Ci.WebTransportSessionEventListener
    );
    const ready = withTimeout(
      new Promise(resolve => {
        listener.ready = resolve;
      }),
      "the WebTransport session"
    );
    listener.streamAvailable = stream => streams.push(stream);
    listener.onResetReceived = (streamId, error) =>
      resets.push({ streamId, error });
    listener.onStopSending = (streamId, error) => {
      Assert.ok(
        false,
        `Unexpected STOP_SENDING for stream ${streamId}: ${error}`
      );
    };

    const webTransport = NetUtil.newWebTransport().QueryInterface(
      Ci.nsIWebTransport
    );
    webTransport.asyncConnect(
      NetUtil.newURI(
        `https://foo.example.com:${port}/mcquic_webtransport_stream`
      ),
      true,
      [],
      Services.scriptSecurityManager.getSystemPrincipal(),
      Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
      listener
    );
    await ready;

    const firstStream = await streams.next(
      "the initial unicast fallback stream"
    );
    const firstMessage = await readWebTransportStream(
      firstStream,
      "the initial unicast fallback body"
    );
    if (firstMessage.startsWith("MCQUIC-SKIP:")) {
      info(firstMessage);
      webTransport.closeSession(0, "");
      return;
    }
    Assert.ok(!firstMessage.startsWith("MCQUIC-ERROR:"), firstMessage);
    Assert.equal(firstMessage, "unicast-fallback-before-join");

    const beforePrefixStream = await streams.next(
      "the multicast-before-prefix stream"
    );
    Assert.equal(
      await readWebTransportStream(
        beforePrefixStream,
        "the multicast-before-prefix body"
      ),
      "multicast-before-prefix"
    );

    const keyDelayedStream = await streams.next("the KEY-delayed stream");
    Assert.equal(
      await readWebTransportStream(keyDelayedStream, "the KEY-delayed body"),
      "multicast-key-delayed"
    );

    const integrityDelayedStream = await streams.next(
      "the INTEGRITY-delayed stream"
    );
    Assert.equal(
      await readWebTransportStream(
        integrityDelayedStream,
        "the INTEGRITY-delayed body"
      ),
      "multicast-integrity-delayed"
    );

    const resetStream = await streams.next("the authenticated reset stream");
    const reset = await resets.next("the authenticated RESET_STREAM callback");
    Assert.equal(reset.streamId, resetStream.streamId);
    Assert.notEqual(reset.error, Cr.NS_OK);

    const leaveFallbackStream = await streams.next(
      "the post-LEAVE fallback stream"
    );
    Assert.equal(
      await readWebTransportStream(
        leaveFallbackStream,
        "the post-LEAVE unicast fallback body"
      ),
      "unicast-fallback-after-leave"
    );

    const completionStream = await streams.next("the MCQUIC completion stream");
    const completion = await readWebTransportStream(
      completionStream,
      "the MCQUIC completion body"
    );
    Assert.ok(!completion.startsWith("MCQUIC-ERROR:"), completion);
    const match = completion.match(
      /^mcquic-complete:declined,joined,left,retired;acks=(\d+)$/
    );
    Assert.ok(match, `Unexpected MCQUIC completion marker: ${completion}`);
    Assert.greaterOrEqual(Number.parseInt(match[1], 10), 4);

    webTransport.closeSession(0, "");
  }
);
