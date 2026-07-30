/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const MCQUIC_PREF = "network.http.http3.mcquic.enabled";
const WEBTRANSPORT_REDIRECT_PREF = "network.webtransport.redirect.enabled";
const TEST_TIMEOUT_MS = 30000;
const WORKER_URL =
  "chrome://webtransport-test/content/mcquic_permission_worker.js";

const { NetUtil } = ChromeUtils.importESModule(
  "resource://gre/modules/NetUtil.sys.mjs"
);
const { clearTimeout, setTimeout } = ChromeUtils.importESModule(
  "resource://gre/modules/Timer.sys.mjs"
);
do_load_manifest("data/chrome.manifest");

let host;
let secondaryHost;
let noResponseHost;

registerCleanupFunction(() => {
  Services.prefs.clearUserPref(MCQUIC_PREF);
  Services.prefs.clearUserPref(WEBTRANSPORT_REDIRECT_PREF);
  Services.prefs.clearUserPref("network.dns.localDomains");
  Cc["@mozilla.org/network/http-auth-manager;1"]
    .getService(Ci.nsIHttpAuthManager)
    .clearAll();
});

function readFile(file) {
  const stream = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(
    Ci.nsIFileInputStream
  );
  stream.init(file, -1, 0, 0);
  const data = NetUtil.readInputStreamToString(stream, stream.available());
  stream.close();
  return data;
}

function addCertFromFile(certdb, filename, trustString) {
  const certFile = do_get_file(filename, false);
  const pem = readFile(certFile)
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/[\r\n]/g, "");
  certdb.addCertFromBase64(pem, trustString);
}

function withTimeout(promise, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    // eslint-disable-next-line mozilla/no-arbitrary-setTimeout
    timer = setTimeout(
      () => reject(new Error(`Timed out waiting for ${label}`)),
      TEST_TIMEOUT_MS
    );
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function readStreamAsString(readable) {
  const decoder = new (webTransportWindow().TextDecoderStream)();
  const reader = readable.pipeThrough(decoder).getReader();
  let result = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      reader.releaseLock();
      return result;
    }
    result += value;
  }
}

async function readIncomingUnidirectional(transport, label) {
  const reader = transport.incomingUnidirectionalStreams.getReader();
  const { value, done } = await withTimeout(reader.read(), label);
  reader.releaseLock();
  Assert.ok(!done, `${label} produced a stream`);
  return withTimeout(readStreamAsString(value), `${label} body`);
}

async function connectAndRead(path, options, expected) {
  const transport = newWebTransport(`https://${host}${path}`, options);
  await withTimeout(transport.ready, `${path} ready`);
  const value = await readIncomingUnidirectional(
    transport,
    `${path} unicast stream`
  );
  Assert.equal(value, expected);
  transport.close();
  return value;
}

async function expectReadyRejected(path, options, label) {
  const transport = newWebTransport(`https://${host}${path}`, options);
  transport.closed.catch(() => {});
  let rejected = false;
  try {
    await withTimeout(transport.ready, label);
  } catch {
    rejected = true;
  }
  Assert.ok(rejected, `${label} rejected WebTransport.ready`);
  transport.close();
}

async function readMarker(path) {
  const transport = newWebTransport(`https://${host}${path}`);
  await withTimeout(transport.ready, `${path} counter ready`);
  const marker = await readIncomingUnidirectional(
    transport,
    `${path} counter stream`
  );
  transport.close();
  return marker;
}

async function readConnectionMarkerInWorker(url) {
  const win = webTransportWindow();
  const worker = new win.Worker(WORKER_URL);
  try {
    return await withTimeout(
      new Promise((resolve, reject) => {
        worker.onmessage = event => {
          if (event.data.error) {
            reject(new Error(event.data.error));
            return;
          }
          resolve(event.data.result);
        };
        worker.onerror = event => reject(new Error(event.message));
        worker.postMessage(url);
      }),
      "worker WebTransport marker"
    );
  } finally {
    worker.terminate();
  }
}

function parseConnectionMarker(value) {
  const match = /^connection=(\d+);multicast=([01])$/.exec(value);
  Assert.ok(match, `valid connection marker: ${value}`);
  return { connection: match[1], multicast: match[2] === "1" };
}

async function startWorkerAndWait(request, expectedState) {
  const win = webTransportWindow();
  const workerDebuggerRegistered = waitForWorkerRegister();
  const worker = new win.Worker(WORKER_URL);
  const stateReached = new Promise((resolve, reject) => {
    worker.onmessage = event => {
      if (event.data.error) {
        reject(new Error(event.data.error));
        return;
      }
      if (event.data.state === "unexpected-ready") {
        reject(
          new Error("nonresponding WebTransport unexpectedly became ready")
        );
        return;
      }
      if (event.data.state === expectedState) {
        resolve();
      }
    };
    worker.onerror = event => reject(new Error(event.message));
    worker.postMessage(request);
  });
  const [workerDebugger] = await Promise.all([
    withTimeout(workerDebuggerRegistered, "worker debugger registration"),
    withTimeout(stateReached, `worker ${expectedState} state`),
  ]);
  return { worker, workerDebugger };
}

function waitForHttpChannelTopic(url, topic) {
  return new Promise(resolve => {
    const observer = {
      QueryInterface: ChromeUtils.generateQI(["nsIObserver"]),
      observe(subject, observedTopic) {
        if (observedTopic !== topic) {
          return;
        }
        const channel = subject.QueryInterface(Ci.nsIHttpChannel);
        if (channel.URI.spec !== url) {
          return;
        }
        Services.obs.removeObserver(observer, topic);
        resolve();
      },
    };
    Services.obs.addObserver(observer, topic);
  });
}

function workerDebuggerMatchesURL(workerDebugger) {
  return (
    workerDebugger.url === WORKER_URL ||
    workerDebugger.url.endsWith("/mcquic_permission_worker.js")
  );
}

function waitForWorkerRegister() {
  const manager = Cc[
    "@mozilla.org/dom/workers/workerdebuggermanager;1"
  ].getService(Ci.nsIWorkerDebuggerManager);
  return new Promise(resolve => {
    const listener = {
      onRegister(workerDebugger) {
        if (!workerDebuggerMatchesURL(workerDebugger)) {
          return;
        }
        manager.removeListener(listener);
        resolve(workerDebugger);
      },
      onUnregister() {},
    };
    manager.addListener(listener);
  });
}

function waitForWorkerUnregister(expectedWorkerDebugger) {
  const manager = Cc[
    "@mozilla.org/dom/workers/workerdebuggermanager;1"
  ].getService(Ci.nsIWorkerDebuggerManager);
  return new Promise(resolve => {
    const listener = {
      onRegister() {},
      onUnregister(workerDebugger) {
        if (workerDebugger.id !== expectedWorkerDebugger.id) {
          return;
        }
        manager.removeListener(listener);
        resolve();
      },
    };
    manager.addListener(listener);
  });
}

function waitForInnerWindowDestroyed(innerWindowId) {
  const topic = "inner-window-destroyed";
  return new Promise(resolve => {
    const observer = {
      QueryInterface: ChromeUtils.generateQI(["nsIObserver"]),
      observe(subject, observedTopic) {
        if (observedTopic !== topic) {
          return;
        }
        const destroyedId = subject.QueryInterface(Ci.nsISupportsPRUint64).data;
        if (destroyedId !== innerWindowId) {
          return;
        }
        Services.obs.removeObserver(observer, topic);
        resolve();
      },
    };
    Services.obs.addObserver(observer, topic);
  });
}

async function replaceWebTransportBrowser(label) {
  const innerWindowId = webTransportWindow().windowGlobalChild.innerWindowId;
  const destroyed = waitForInnerWindowDestroyed(innerWindowId);
  gWebTransportBrowser.close();
  await withTimeout(destroyed, `${label} inner-window destruction`);
  gWebTransportBrowser = Services.appShell.createWindowlessBrowser(true);
}

add_setup(async function setup() {
  Services.prefs.setCharPref("network.dns.localDomains", "foo.example.com");
  const port = Services.env.get("MOZHTTP3_PORT");
  const secondaryPort = Services.env.get("MOZHTTP3_PORT_ECH");
  const noResponsePort = Services.env.get("MOZHTTP3_PORT_NO_RESPONSE");
  Assert.notEqual(port, null);
  Assert.notEqual(port, "");
  Assert.notEqual(secondaryPort, null);
  Assert.notEqual(secondaryPort, "");
  Assert.notEqual(noResponsePort, null);
  Assert.notEqual(noResponsePort, "");
  host = `foo.example.com:${port}`;
  secondaryHost = `foo.example.com:${secondaryPort}`;
  noResponseHost = `foo.example.com:${noResponsePort}`;
  do_get_profile();

  const certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(
    Ci.nsIX509CertDB
  );
  addCertFromFile(
    certdb,
    "../../../../netwerk/test/unit/http2-ca.pem",
    "CTu,u,u"
  );
  addCertFromFile(
    certdb,
    "../../../../netwerk/test/unit/proxy-ca.pem",
    "CTu,u,u"
  );
});

add_task(async function option_is_typed_and_default_deny() {
  Assert.throws(
    () => newWebTransport(`https://${host}/success`, { multicast: "yes" }),
    /not a valid value/,
    "the experimental option is a typed enum"
  );

  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  await connectAndRead(
    "/mcquic_webtransport_stream",
    undefined,
    "permission-absent-unicast"
  );
  await connectAndRead(
    "/mcquic_webtransport_stream",
    { multicast: "prohibit" },
    "permission-absent-unicast"
  );
  await connectAndRead(
    "/mcquic_unsolicited_response",
    undefined,
    "unsolicited-response-unicast"
  );
});

add_task(async function pref_is_capability_only() {
  Services.prefs.setBoolPref(MCQUIC_PREF, false);
  await connectAndRead(
    "/mcquic_webtransport_stream",
    { multicast: "allow" },
    "permission-absent-unicast"
  );
});

add_task(async function response_field_declines_without_failing_ready() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  const cases = [
    ["/mcquic_permission_missing", "permission-missing-unicast"],
    ["/mcquic_permission_false", "permission-false-unicast"],
    ["/mcquic_permission_malformed", "permission-malformed-unicast"],
    ["/mcquic_permission_unsolicited", "unsolicited-controls-unicast"],
  ];
  for (const [path, expected] of cases) {
    await connectAndRead(path, { multicast: "allow" }, expected);
  }
});

add_task(async function response_field_edge_cases_are_deterministic() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);

  await connectAndRead(
    "/mcquic_response_duplicate",
    { multicast: "allow" },
    "duplicate-response-unicast"
  );
  await connectAndRead(
    "/mcquic_response_parameter",
    { multicast: "allow" },
    "parameterized-response-unicast"
  );
  await expectReadyRejected(
    "/mcquic_non_success_true",
    { multicast: "allow" },
    "non-2xx response carrying WT-Multicast"
  );
});

add_task(async function credentials_are_omitted_without_retry_or_prompt() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  const authManager = Cc["@mozilla.org/network/http-auth-manager;1"].getService(
    Ci.nsIHttpAuthManager
  );
  authManager.clearAll();
  const port = Number(host.slice(host.lastIndexOf(":") + 1));
  authManager.setAuthIdentity(
    "https",
    "foo.example.com",
    port,
    "basic",
    "mcquic-test",
    "/",
    "",
    "cached-user",
    "cached-password"
  );

  await expectReadyRejected(
    "/mcquic_auth_challenge",
    undefined,
    "ordinary WebTransport 401 challenge"
  );
  await expectReadyRejected(
    "/mcquic_auth_challenge",
    { multicast: "allow" },
    "multicast-permitted WebTransport 401 challenge"
  );

  Assert.equal(
    await readMarker("/mcquic_auth_count"),
    "requests=2;authorization=0",
    "no cached Authorization header, authentication retry, or prompt request occurred"
  );
  authManager.clearAll();
});

add_task(async function every_3xx_is_redirect_mode_error() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  const statuses = [300, 301, 302, 303, 304, 305, 306, 307, 308];

  for (const redirectPref of [false, true]) {
    Services.prefs.setBoolPref(WEBTRANSPORT_REDIRECT_PREF, redirectPref);
    for (const options of [undefined, { multicast: "allow" }]) {
      for (const status of statuses) {
        await expectReadyRejected(
          `/mcquic_redirect_${status}`,
          options,
          `${status} response with redirect pref ${redirectPref}`
        );
        const expectedSourceRequests =
          (redirectPref ? 2 : 0) + (options ? 2 : 1);
        Assert.equal(
          await readMarker(`/mcquic_redirect_count_${status}`),
          `source=${expectedSourceRequests};target=0`,
          `${status} did not issue a replacement request`
        );
      }
    }
  }
});

add_task(async function permitted_operations_use_dedicated_connections() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  const url = `https://${host}/mcquic_permission_connection`;
  const ordinary = newWebTransport(url, { allowPooling: true });
  const firstAllowed = newWebTransport(url, {
    allowPooling: true,
    multicast: "allow",
  });
  const secondAllowed = newWebTransport(url, {
    allowPooling: true,
    multicast: "allow",
  });

  await withTimeout(
    Promise.all([ordinary.ready, firstAllowed.ready, secondAllowed.ready]),
    "isolated WebTransport Sessions ready"
  );
  const [ordinaryMarker, firstAllowedMarker, secondAllowedMarker] =
    await Promise.all([
      readIncomingUnidirectional(ordinary, "ordinary Session marker"),
      readIncomingUnidirectional(firstAllowed, "first allowed Session marker"),
      readIncomingUnidirectional(
        secondAllowed,
        "second allowed Session marker"
      ),
    ]).then(values => values.map(parseConnectionMarker));

  Assert.ok(
    !ordinaryMarker.multicast,
    "ordinary Session did not request MCQUIC"
  );
  Assert.ok(firstAllowedMarker.multicast, "first operation negotiated MCQUIC");
  Assert.ok(
    secondAllowedMarker.multicast,
    "second operation negotiated MCQUIC"
  );
  Assert.notEqual(
    firstAllowedMarker.connection,
    secondAllowedMarker.connection,
    "two permitted operations cannot share one HTTP/3 connection"
  );
  Assert.notEqual(
    ordinaryMarker.connection,
    firstAllowedMarker.connection,
    "permission does not transfer from an ordinary pooled connection"
  );
  Assert.notEqual(
    ordinaryMarker.connection,
    secondAllowedMarker.connection,
    "the second permitted operation is also isolated from ordinary traffic"
  );

  ordinary.close();
  firstAllowed.close();
  secondAllowed.close();
});

add_task(async function retry_revalidates_the_complete_operation_binding() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);
  Services.prefs.setBoolPref(
    "network.http.http3.mcquic.force_webtransport_421_retry_for_testing",
    true
  );
  const ordinary = newWebTransport(
    `https://${host}/mcquic_permission_connection`,
    { allowPooling: true }
  );
  const retried = newWebTransport(
    `https://${host}/mcquic_permission_retry_once`,
    { allowPooling: true, multicast: "allow" }
  );

  try {
    await withTimeout(
      Promise.all([ordinary.ready, retried.ready]),
      "ordinary and retried Sessions ready"
    );
    const ordinaryMarker = parseConnectionMarker(
      await readIncomingUnidirectional(ordinary, "ordinary retry peer")
    );
    const retryMetadata = await readIncomingUnidirectional(
      retried,
      "second-attempt retry metadata"
    );
    const match =
      /^attempts=(\d+);connection=(\d+);changed=([01]);sessions=(\d+);multicast=([01]);resumed=([01])$/.exec(
        retryMetadata
      );
    Assert.ok(match, `valid retry metadata: ${retryMetadata}`);
    Assert.equal(Number.parseInt(match[1], 10), 2, "exactly two attempts");
    Assert.notEqual(
      match[2],
      ordinaryMarker.connection,
      "the permitted retry remained isolated from the ordinary Session"
    );
    Assert.equal(match[3], "1", "the retry used a new H3 connection");
    Assert.equal(
      Number.parseInt(match[4], 10),
      1,
      "the second connection contains only the permitted Session"
    );
    Assert.equal(
      match[5],
      "1",
      "the second CONNECT regenerated WT-Multicast from typed policy"
    );
    Assert.equal(match[6], "0", "the second connection did not resume TLS");

    Assert.equal(
      await readIncomingUnidirectional(retried, "retry pre-join fallback"),
      "unicast-fallback-before-join"
    );
    Assert.equal(
      await readIncomingUnidirectional(
        retried,
        "retry authenticated multicast proof"
      ),
      "multicast-before-revocation",
      "the second response authorized transparent multicast"
    );

    Services.prefs.setBoolPref(MCQUIC_PREF, false);
    Assert.equal(
      await readIncomingUnidirectional(retried, "retry post-revoke fallback"),
      "unicast-fallback-after-revocation",
      "the retried Session continued over ordinary unicast after revocation"
    );
  } finally {
    Services.prefs.clearUserPref(
      "network.http.http3.mcquic.force_webtransport_421_retry_for_testing"
    );
    Services.prefs.setBoolPref(MCQUIC_PREF, true);
    retried.close();
    ordinary.close();
    await Promise.allSettled([retried.closed, ordinary.closed]);
  }
});

add_task(async function permission_is_per_operation_and_overrides_pooling() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);

  const prohibited = newWebTransport(
    `https://${host}/mcquic_webtransport_stream`
  );
  await withTimeout(prohibited.ready, "prohibited same-origin Session ready");
  Assert.equal(
    await readIncomingUnidirectional(prohibited, "prohibited Session"),
    "permission-absent-unicast"
  );

  const allowed = newWebTransport(
    `https://${host}/mcquic_webtransport_stream`,
    { allowPooling: true, multicast: "allow" }
  );
  await withTimeout(allowed.ready, "allowed same-origin Session ready");
  const fallback = await readIncomingUnidirectional(
    allowed,
    "allowed Session initial fallback"
  );
  Assert.ok(!fallback.startsWith("MCQUIC-ERROR:"), fallback);
  Assert.equal(fallback, "unicast-fallback-before-join");
  Assert.equal(
    await readIncomingUnidirectional(allowed, "allowed multicast Session"),
    "multicast-before-prefix"
  );

  allowed.close();
  prohibited.close();
});

add_task(
  async function permission_is_not_inherited_by_origin_navigation_or_worker() {
    Services.prefs.setBoolPref(MCQUIC_PREF, true);
    const path = "/mcquic_permission_connection";
    let allowed;
    let otherOrigin;
    try {
      allowed = newWebTransport(`https://${host}${path}`, {
        multicast: "allow",
      });
      await withTimeout(allowed.ready, "allowed source operation ready");
      const allowedMarker = parseConnectionMarker(
        await readIncomingUnidirectional(allowed, "allowed source operation")
      );
      Assert.ok(allowedMarker.multicast, "source operation negotiated MCQUIC");

      otherOrigin = newWebTransport(`https://${secondaryHost}${path}`);
      await withTimeout(otherOrigin.ready, "different target origin ready");
      const originMarker = parseConnectionMarker(
        await readIncomingUnidirectional(otherOrigin, "different target origin")
      );
      Assert.ok(
        !originMarker.multicast,
        "permission did not cross target origins"
      );

      const workerMarker = parseConnectionMarker(
        await readConnectionMarkerInWorker(`https://${host}${path}`)
      );
      Assert.ok(
        !workerMarker.multicast,
        "permission did not cross into a worker"
      );
      Assert.notEqual(
        allowedMarker.connection,
        workerMarker.connection,
        "the worker operation did not reuse the permitted connection"
      );
    } finally {
      otherOrigin?.close();
      allowed?.close();
      await Promise.allSettled(
        [otherOrigin?.closed, allowed?.closed].filter(Boolean)
      );
    }

    gWebTransportBrowser.close();
    gWebTransportBrowser = Services.appShell.createWindowlessBrowser(true);
    const afterNavigation = newWebTransport(`https://${host}${path}`);
    await withTimeout(
      afterNavigation.ready,
      "replacement client context ready"
    );
    const navigationMarker = parseConnectionMarker(
      await readIncomingUnidirectional(
        afterNavigation,
        "replacement client context"
      )
    );
    Assert.ok(
      !navigationMarker.multicast,
      "permission did not survive navigation/client replacement"
    );
    afterNavigation.close();
  }
);

add_task(async function worker_teardown_is_safe_while_negotiating_and_active() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);

  const negotiatingURL = `https://${noResponseHost}/mcquic-never-responds`;
  const negotiationStarted = waitForHttpChannelTopic(
    negotiatingURL,
    "http-on-before-connect"
  );
  const { worker: negotiatingWorker, workerDebugger: negotiatingDebugger } =
    await startWorkerAndWait(
      {
        action: "hold-negotiating",
        multicast: true,
        url: negotiatingURL,
      },
      "constructed"
    );
  await withTimeout(negotiationStarted, "worker negotiation start");
  const negotiationStopped = waitForHttpChannelTopic(
    negotiatingURL,
    "http-on-stop-request"
  );
  const negotiatingWorkerGone = waitForWorkerUnregister(negotiatingDebugger);
  negotiatingWorker.terminate();
  await withTimeout(negotiatingWorkerGone, "negotiating worker shutdown");
  await withTimeout(negotiationStopped, "negotiating worker request teardown");

  const { worker: activeWorker, workerDebugger: activeDebugger } =
    await startWorkerAndWait(
      {
        action: "hold-active",
        multicast: true,
        url: `https://${host}/mcquic_permission_connection`,
      },
      "active"
    );
  const activeWorkerGone = waitForWorkerUnregister(activeDebugger);
  activeWorker.terminate();
  await withTimeout(activeWorkerGone, "active worker shutdown");

  const marker = parseConnectionMarker(
    await readMarker("/mcquic_permission_connection")
  );
  Assert.ok(
    !marker.multicast,
    "worker teardown did not authorize a later ordinary operation"
  );
});

add_task(
  async function navigation_teardown_is_safe_while_negotiating_and_active() {
    Services.prefs.setBoolPref(MCQUIC_PREF, true);

    const negotiatingURL = `https://${noResponseHost}/mcquic-never-responds`;
    const negotiationStarted = waitForHttpChannelTopic(
      negotiatingURL,
      "http-on-before-connect"
    );
    const negotiating = newWebTransport(negotiatingURL, {
      multicast: "allow",
    });
    let negotiatingSettled = false;
    negotiating.ready.then(
      () => {
        negotiatingSettled = true;
      },
      () => {
        negotiatingSettled = true;
      }
    );
    negotiating.closed.catch(() => {});
    await withTimeout(negotiationStarted, "navigation negotiation start");
    Assert.ok(!negotiatingSettled, "operation is still negotiating");
    const negotiationStopped = waitForHttpChannelTopic(
      negotiatingURL,
      "http-on-stop-request"
    );
    await replaceWebTransportBrowser("negotiating navigation");
    await withTimeout(
      negotiationStopped,
      "negotiating navigation request teardown"
    );

    const active = newWebTransport(
      `https://${host}/mcquic_permission_connection`,
      { multicast: "allow" }
    );
    active.closed.catch(() => {});
    await withTimeout(active.ready, "navigation teardown active Session");
    const activeMarker = parseConnectionMarker(
      await readIncomingUnidirectional(active, "active navigation Session")
    );
    Assert.ok(activeMarker.multicast, "active operation negotiated multicast");
    await replaceWebTransportBrowser("active navigation");

    const replacementMarker = parseConnectionMarker(
      await readMarker("/mcquic_permission_connection")
    );
    Assert.ok(
      !replacementMarker.multicast,
      "navigation teardown did not authorize the replacement client"
    );
  }
);

add_task(async function explicit_teardown_is_idempotent() {
  Services.prefs.setBoolPref(MCQUIC_PREF, true);

  const negotiatingURL = `https://${noResponseHost}/mcquic-never-responds`;
  const negotiationStarted = waitForHttpChannelTopic(
    negotiatingURL,
    "http-on-before-connect"
  );
  const negotiating = newWebTransport(negotiatingURL, {
    multicast: "allow",
  });
  const readyResult = negotiating.ready.then(
    () => "resolved",
    () => "rejected"
  );
  negotiating.closed.catch(() => {});
  await withTimeout(negotiationStarted, "idempotent-close negotiation start");
  const negotiationStopped = waitForHttpChannelTopic(
    negotiatingURL,
    "http-on-stop-request"
  );
  negotiating.close();
  negotiating.close();
  Assert.equal(
    await withTimeout(readyResult, "idempotent-close ready rejection"),
    "rejected",
    "repeated close while negotiating rejects ready once"
  );
  await withTimeout(
    negotiationStopped,
    "idempotent-close negotiating request teardown"
  );

  const active = newWebTransport(
    `https://${host}/mcquic_permission_connection`,
    { multicast: "allow" }
  );
  await withTimeout(active.ready, "idempotent-close active Session");
  const activeMarker = parseConnectionMarker(
    await readIncomingUnidirectional(active, "idempotent-close active Session")
  );
  Assert.ok(activeMarker.multicast, "active operation negotiated multicast");

  const closed = active.closed;
  active.close({ closeCode: 17, reason: "idempotent teardown" });
  active.close({ closeCode: 17, reason: "idempotent teardown" });
  const closeInfo = await withTimeout(closed, "idempotent active close");
  Assert.equal(closeInfo.closeCode, 17);
  Assert.equal(closeInfo.reason, "idempotent teardown");
  active.close({ closeCode: 17, reason: "idempotent teardown" });

  const replacementMarker = parseConnectionMarker(
    await readMarker("/mcquic_permission_connection")
  );
  Assert.ok(
    !replacementMarker.multicast,
    "repeated teardown did not authorize a later ordinary operation"
  );
});
