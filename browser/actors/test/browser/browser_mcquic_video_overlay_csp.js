/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { HttpServer } = ChromeUtils.importESModule(
  "resource://testing-common/httpd.sys.mjs"
);

const NATIVE_MOQ_DEMO_PREF =
  "network.http.http3.mcquic.native_moq_demo.enabled";
const NATIVE_MOQ_DEMO_ORIGIN_PREF =
  "network.http.http3.mcquic.native_moq_demo.origin";

const IS_HEADLESS = Services.env.get("MOZ_HEADLESS");

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
  server.registerPathHandler("/scroll", (request, response) => {
    writeHtml(
      response,
      `<!doctype html>
       <html>
         <body style="margin:0; background:white; color:black">
           <iframe
             id="player"
             src="/moq"
             width="640"
             height="360"
             style="display:block; margin:40px auto"
           ></iframe>
           <main style="height:1800px; background:white"></main>
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

function recordCspViolations() {
  let violations = [];
  let sentinelSeen = new Promise(resolve => {
    SpecialPowers.registerConsoleListener(msg => {
      let text = msg.message || msg.errorMessage || "";
      if (text === "SENTINEL") {
        resolve();
        return;
      }
      if (text.includes("Content-Security-Policy")) {
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
  return sampleBrowserPixel(browser, 0.5, 0.5);
}

async function sampleBrowserViewportMiddlePixel(browser) {
  return sampleBrowserPixel(browser, 0.5, 0.5, { fullViewport: false });
}

async function sampleBrowserPixel(
  browser,
  xRatio,
  yRatio,
  { fullViewport = true } = {}
) {
  let canvas = PageThumbs.createCanvas(window);
  await PageThumbs.captureToCanvas(browser, canvas, { fullViewport });
  let ctx = canvas.getContext("2d", { willReadFrequently: true });
  return Array.from(
    ctx.getImageData(
      Math.floor(canvas.width * xRatio),
      Math.floor(canvas.height * yRatio),
      1,
      1
    ).data
  );
}

function isDarkOverlayPixel([r, g, b]) {
  return r < 40 && g < 40 && b < 40;
}

function isColorPixel([r, g, b], [wantR, wantG, wantB]) {
  return (
    Math.abs(r - wantR) < 30 &&
    Math.abs(g - wantG) < 30 &&
    Math.abs(b - wantB) < 30
  );
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

function notifyMcquicVideoFrame({
  color = "rgb(220,0,0)",
  sequence = 1,
  ptsMs = 1,
  decodedFrames = 1,
} = {}) {
  let subject = Cc["@mozilla.org/supports-cstring;1"].createInstance(
    Ci.nsISupportsCString
  );
  let dataUrls = {
    "rgb(220,0,0)":
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6eAAABoElEQVR42u3TMQ0AMAzAsPDHWC4rgSKYfJhApDT1gFsigEHAIGAQMAgYBAwCBgGDgEEAg4BBwCBgEDAIGAQMAgYBg4BBhACDgEHAIGAQMAgYBAwCBgGDAAYBg4BBwCBgEDAIGAQMAgYBgwAGAYOAQcAgYBAwCBgEDAIGAQwCBgGDgEHAIGAQMAgYBAwCBgEMAgYBg4BBwCBgEDAIGAQMAhgEDAIGAYOAQcAgYBAwCBgEDAIYBAwCBgGDgEHAIGAQMAgYBAwiAhgEDAIGAYOAQcAgYBAwCBgEMAgYBAwCBgGDgEHAIGAQMAgYRAgwCBgEDAIGAYOAQcAgYBAwCGAQMAgYBAwCBgGDgEHAIGAQMAhgEDAIGAQMAgYBg4BBwCBgEMAgYBAwCBgEDAIGAYOAQcAgYBDAIGAQMAgYBAwCBgGDgEHAIIBBwCBgEDAIGAQMAgYBg4BBwCCAQcAgYBAwCBgEDAIGAYOAQcAgIoBBwCBgEDAIGAQMAgYBg4BBAIOAQcAgYBAwCBgEDAIGAYOAQYQAg4BBwCBgEDAIGAQMAj9a3AP7sBJAa2sAAAAASUVORK5CYII=",
    "rgb(0,180,40)":
      "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAADICAYAAACtWK6eAAABnklEQVR42u3TQQ0AAAjEsJOD/+APFGCA9FEDS5Z0DXAQAQwCBgGDgEHAIGAQMAgYBAwCGAQMAgYBg4BBwCBgEDAIGAQMIgIYBAwCBgGDgEHAIGAQMAgYBDAIGAQMAgYBg4BBwCBgEDAIGAQwCBgEDAIGAYOAQcAgYBAwCGAQMAgYBAwCBgGDgEHAIGAQMAhgEDAIGAQMAgYBg4BBwCBgEMAgYBAwCBgEDAIGAYOAQcAgYBDAIGAQMAgYBAwCBgGDgEHAIIAIYBAwCBgEDAIGAYOAQcAgYBDAIGAQMAgYBAwCBgGDgEHAIGAQEcAgYBAwCBgEDAIGAYOAQcAggEHAIGAQMAgYBAwCBgGDgEHAIIBBwCBgEDAIGAQMAgYBg4BBAIOAQcAgYBAwCBgEDAIGAYOAQQCDgEHAIGAQMAgYBAwCBgGDAAYBg4BBwCBgEDAIGAQMAgYBgwAGAYOAQcAgYBAwCBgEDAIGAUQAg4BBwCBgEDAIGAQMAgYBgwAGAYOAQcAgYBAwCBgEDAIGAYOIAAYBg4BBwCBgEDAIGAQ+WiHB+7DGzHGlAAAAAElFTkSuQmCC",
  };
  subject.data = JSON.stringify({
    width: 200,
    height: 200,
    sequence,
    ptsMs,
    decodedFrames,
    dataUrl: dataUrls[color] || dataUrls["rgb(220,0,0)"],
  });
  Services.obs.notifyObservers(subject, "mcquic-moq-video-frame");
}

async function waitForFramePixel(browser, color, message) {
  if (IS_HEADLESS) {
    info(
      `${message}: skipping color-pixel capture because headless ` +
        "PageThumbs does not consistently expose native-anonymous image pixels"
    );
    await TestUtils.waitForTick();
    return null;
  }

  let framePixel = await BrowserTestUtils.waitForCondition(async () => {
    let sampled = await sampleBrowserMiddlePixel(browser);
    return isColorPixel(sampled, color) && sampled;
  }, message);
  ok(
    isColorPixel(framePixel, color),
    `The overlay rendered the notified video frame: ${framePixel}`
  );
  return framePixel;
}

add_task(async function test_mcquic_overlay_ignores_page_csp_style_blocking() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, origin],
    ],
  });

  let consoleRecorder = recordCspViolations();

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

    await TestUtils.waitForTick();
    let afterSubscribeOk = await sampleBrowserMiddlePixel(browser);
    ok(
      !isDarkOverlayPixel(afterSubscribeOk),
      "The overlay waits for decoded native media before painting over page " +
        `fallback content: ${afterSubscribeOk}`
    );

    notifyMcquicVideoFrame();

    await waitForFramePixel(
      browser,
      [220, 0, 0],
      "MCQUIC video frame notification painted on the visible overlay"
    );

    let corner = await sampleBrowserPixel(browser, 0.001, 0.001);
    ok(
      !isDarkOverlayPixel(corner),
      `The native overlay stayed bounded to the player surface: ${corner}`
    );
  });

  await consoleRecorder.flush();
  Assert.deepEqual(
    consoleRecorder.violations,
    [],
    "MCQUIC overlay did not trigger page CSP violations"
  );
});

add_task(async function test_mcquic_overlay_accepts_decoded_frame_as_readiness() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, origin],
    ],
  });

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
      `The overlay does not paint before native media exists: ${before}`
    );

    notifyMcquicVideoFrame({
      color: "rgb(0,180,40)",
      sequence: 33,
      ptsMs: 33,
      decodedFrames: 33,
    });

    if (IS_HEADLESS) {
      await waitForFramePixel(
        browser,
        [0, 180, 40],
        "MCQUIC decoded frame acted as native readiness in headless mode"
      );
    } else {
      await waitForFramePixel(
        browser,
        [0, 180, 40],
        "MCQUIC decoded frame acted as native readiness and painted"
      );
    }
  });
});

add_task(async function test_mcquic_overlay_accepts_transport_child_origin() {
  let origin = startServer();
  let transportOrigin = origin.replace("://localhost:", "://moq.localhost:");
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, transportOrigin],
    ],
  });

  await BrowserTestUtils.withNewTab(`${origin}/`, async browser => {
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded"
      );
    });

    notifyMcquicSessionReady(transportOrigin);
    await TestUtils.waitForTick();
    let pixel = await sampleBrowserMiddlePixel(browser);
    ok(
      !isDarkOverlayPixel(pixel),
      "The child transport origin arms the overlay without painting before " +
        `decoded media: ${pixel}`
    );

    notifyMcquicVideoFrame();
    await waitForFramePixel(
      browser,
      [220, 0, 0],
      "MCQUIC video frame painted on the parent playback origin"
    );
  });
});

add_task(async function test_mcquic_overlay_coalesces_frame_bursts() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, origin],
    ],
  });

  await BrowserTestUtils.withNewTab(`${origin}/`, async browser => {
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded"
      );
    });

    notifyMcquicSessionReady(origin);

    for (let i = 1; i <= 20; ++i) {
      notifyMcquicVideoFrame({
        color: i === 20 ? "rgb(0,180,40)" : "rgb(220,0,0)",
        sequence: i,
        ptsMs: i,
        decodedFrames: i,
      });
    }

    await waitForFramePixel(
      browser,
      [0, 180, 40],
      "MCQUIC overlay presented the newest frame from a burst"
    );
  });
});

add_task(async function test_mcquic_overlay_replays_ready_state_after_reload() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, origin],
    ],
  });

  await BrowserTestUtils.withNewTab(`${origin}/`, async browser => {
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded"
      );
    });

    notifyMcquicSessionReady(origin);
    notifyMcquicVideoFrame({
      color: "rgb(0,180,40)",
      sequence: 101,
      ptsMs: 101,
      decodedFrames: 101,
    });

    BrowserTestUtils.startLoadingURIString(browser, `${origin}/?after-ready`);
    await BrowserTestUtils.browserLoaded(browser);
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded after reload"
      );
    });

    await waitForFramePixel(
      browser,
      [0, 180, 40],
      "MCQUIC overlay replayed readiness and latest frame after reload"
    );
  });
});

add_task(async function test_mcquic_overlay_tracks_scroll_position() {
  let origin = startServer();
  await SpecialPowers.pushPrefEnv({
    set: [
      [NATIVE_MOQ_DEMO_PREF, true],
      [NATIVE_MOQ_DEMO_ORIGIN_PREF, origin],
    ],
  });

  await BrowserTestUtils.withNewTab(`${origin}/scroll`, async browser => {
    await SpecialPowers.spawn(browser, [], async () => {
      let frame = content.document.getElementById("player");
      await ContentTaskUtils.waitForCondition(
        () => frame.contentDocument?.readyState === "complete",
        "MCQUIC native surface iframe loaded"
      );
    });

    notifyMcquicSessionReady(origin);
    notifyMcquicVideoFrame({
      sequence: 202,
      ptsMs: 202,
      decodedFrames: 202,
    });

    await waitForFramePixel(
      browser,
      [220, 0, 0],
      "MCQUIC overlay painted before scrolling the playback surface"
    );

    await SpecialPowers.spawn(browser, [], async () => {
      content.scrollTo(0, 700);
      await new Promise(resolve => {
        content.requestAnimationFrame(() => {
          content.requestAnimationFrame(resolve);
        });
      });
    });

    let scrolledPixel = await sampleBrowserViewportMiddlePixel(browser);
    ok(
      !isColorPixel(scrolledPixel, [220, 0, 0]) &&
        !isDarkOverlayPixel(scrolledPixel),
      `The native overlay did not float over scrolled page content: ${scrolledPixel}`
    );
  });
});
