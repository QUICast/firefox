/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { HttpServer } = ChromeUtils.importESModule(
  "resource://testing-common/httpd.sys.mjs"
);

function writeHtml(response, body, csp = null) {
  response.setStatusLine(null, 200, "OK");
  response.setHeader("Content-Type", "text/html; charset=utf-8", false);
  if (csp) {
    response.setHeader("Content-Security-Policy", csp, false);
  }
  response.write(body);
}

function startServer() {
  let server = new HttpServer();
  server.registerPathHandler("/", (request, response) => {
    writeHtml(
      response,
      `<!doctype html>
       <html>
         <body>
           <iframe id="player" src="/moq" width="1000" height="800"></iframe>
         </body>
       </html>`
    );
  });
  server.registerPathHandler("/moq", (request, response) => {
    writeHtml(
      response,
      `<!doctype html>
       <html>
         <body>yggdrasil h3/moq native mcquic playback surface</body>
       </html>`,
      "default-src 'none'"
    );
  });
  server.start(-1);
  registerCleanupFunction(
    () =>
      new Promise(resolve => {
        server.stop(resolve);
      })
  );
  return `http://localhost:${server.identity.primaryPort}`;
}

function recordCspInlineStyleViolations() {
  let violations = [];
  let sentinelSeen = new Promise(resolve => {
    SpecialPowers.registerConsoleListener(msg => {
      let text = msg.message || msg.errorMessage || "";
      if (text === "SENTINEL") {
        resolve();
        return;
      }
      if (
        text.includes("Content-Security-Policy") &&
        (text.includes("inline style") || text.includes("style-src-attr"))
      ) {
        violations.push(text);
      }
    });
  });

  return {
    violations,
    async flush() {
      SpecialPowers.postConsoleSentinel();
      await sentinelSeen;
    },
  };
}

async function sampleBrowserMiddlePixel(browser) {
  let canvas = PageThumbs.createCanvas(window);
  await PageThumbs.captureToCanvas(browser, canvas, { fullViewport: true });
  let ctx = canvas.getContext("2d", { willReadFrequently: true });
  return Array.from(
    ctx.getImageData(
      Math.floor(canvas.width / 2),
      Math.floor(canvas.height / 2),
      1,
      1
    ).data
  );
}

function isDarkOverlayPixel([r, g, b]) {
  return r < 40 && g < 40 && b < 40;
}

function notifyMcquicSessionReady(origin, event = "subscribe-ok") {
  let subject = Cc["@mozilla.org/supports-cstring;1"].createInstance(
    Ci.nsISupportsCString
  );
  subject.data = JSON.stringify({
    event,
    origin,
    authority: new URL(origin).host,
    trackNamespace: "ratatoskr/demo",
    trackName: "h264-loc-msf",
  });
  Services.obs.notifyObservers(subject, "mcquic-moq-session-ready");
}

add_task(async function test_mcquic_overlay_ignores_page_csp_style_blocking() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      ["network.http.http3.mcquic.moq_media_overlay.enabled", true],
      ["network.http.http3.mcquic.moq_subscribe.origin", origin],
    ],
  });

  let consoleRecorder = recordCspInlineStyleViolations();

  await BrowserTestUtils.withNewTab(`${origin}/`, async browser => {
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded"
      );
    });

    let before = await sampleBrowserMiddlePixel(browser);
    ok(
      !isDarkOverlayPixel(before),
      `The overlay waits for H3/MCQUIC readiness before painting: ${before}`
    );

    notifyMcquicSessionReady(origin, "setup-subscribe");
    await TestUtils.waitForTick();
    let afterSetupSubscribe = await sampleBrowserMiddlePixel(browser);
    ok(
      !isDarkOverlayPixel(afterSetupSubscribe),
      "The overlay ignores queued setup/subscribe and keeps page fallback " +
        `content visible: ${afterSetupSubscribe}`
    );

    notifyMcquicSessionReady(origin);

    let pixel = await BrowserTestUtils.waitForCondition(async () => {
      let sampled = await sampleBrowserMiddlePixel(browser);
      return isDarkOverlayPixel(sampled) && sampled;
    }, "MCQUIC anonymous overlay painted over strict-CSP native surface");
    ok(isDarkOverlayPixel(pixel), `The overlay painted a dark pixel: ${pixel}`);
  });

  await consoleRecorder.flush();
  Assert.deepEqual(
    consoleRecorder.violations,
    [],
    "MCQUIC overlay did not trigger CSP inline-style violations"
  );
});
