/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const OVERLAY_ENABLED_PREF =
  "network.http.http3.mcquic.native_moq_demo.enabled";
const SUBSCRIBE_ORIGIN_PREF =
  "network.http.http3.mcquic.native_moq_demo.origin";
const SESSION_READY_EVENT = "subscribe-ok";
const FRAME_STALE_MS = 1500;
const OVERLAY_SHEET_URI =
  "data:text/css;charset=utf-8," +
  encodeURIComponent(`
#mcquic-video-overlay,
#mcquic-video-overlay:-moz-native-anonymous {
  position: fixed !important;
  z-index: 2147483647 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  background: transparent !important;
  overflow: hidden !important;
  pointer-events: none !important;
}

#mcquic-video-overlay-frame,
#mcquic-video-overlay-frame:-moz-native-anonymous {
  width: 100% !important;
  height: 100% !important;
  object-fit: contain !important;
  background: #000 !important;
}

#mcquic-video-overlay-label,
#mcquic-video-overlay-label:-moz-native-anonymous {
  position: fixed !important;
  left: 16px !important;
  top: 16px !important;
  padding: 6px 8px !important;
  border-radius: 4px !important;
  background: rgb(0 0 0 / 72%) !important;
  color: white !important;
  font: 12px system-ui, sans-serif !important;
  letter-spacing: 0 !important;
}
`);

export class McquicVideoOverlayChild extends JSWindowActorChild {
  #content = null;
  #lastFrame = null;
  #loadingFrame = null;
  #loadingFrameKey = null;
  #pendingFrame = null;
  #pendingFrameKey = null;
  #presentedFrameKey = null;
  #framePumpScheduled = false;
  #imageLoadInProgress = false;
  #geometryUpdateScheduled = false;
  #staleFrameTimer = 0;
  #readySent = false;
  #sheetLoaded = false;
  #sessionReady = false;
  #diagnosticLoggedFor = null;
  #currentDocument = null;
  #eventWindow = null;

  actorCreated() {
    this.#syncDocumentState();
    this.#notifyReady();
  }

  didDestroy() {
    this.#removeGeometryEventListeners();
    this.#removeOverlay();
  }

  handleEvent(event) {
    if (
      (event.type === "scroll" || event.type === "resize") &&
      event.currentTarget === this.contentWindow
    ) {
      this.#syncDocumentState();
      this.#scheduleOverlayGeometryUpdate();
      return;
    }

    if (!this.#eventTargetsContentWindow(event)) {
      return;
    }
    this.#syncDocumentState();
    if (event.type === "scroll" || event.type === "resize") {
      this.#scheduleOverlayGeometryUpdate();
      return;
    }
    this.#maybeAttachNativeSurface();
    this.#notifyReady();
    if (this.#lastFrame) {
      this.#renderFrame(this.#lastFrame);
    }
  }

  receiveMessage(message) {
    this.#syncDocumentState();
    if (message.name === "McquicVideoOverlay:SessionReady") {
      if (message.data?.event !== SESSION_READY_EVENT) {
        return;
      }
      if (!this.#sessionMatchesDocument(message.data)) {
        return;
      }
      this.#sessionReady = true;
      if (this.#lastFrame && !this.#lastFrame.sticky) {
        this.#renderFrame(this.#lastFrame);
      }
      return;
    }

    if (message.name === "McquicVideoOverlay:Frame") {
      this.#lastFrame = message.data;
      this.#markReadyFromNativeFrame(message.data);
      this.#renderFrame(message.data);
    }
  }

  #markReadyFromNativeFrame(frame) {
    if (this.#sessionReady || frame?.sticky || !this.#enabledForDocument()) {
      return;
    }

    // A decoded native frame is stronger readiness proof than subscribe-ok: it
    // can only be published after native H3/MoQ media reached the decoder.
    this.#sessionReady = true;
  }

  #enabledForDocument() {
    if (!Services.prefs.getBoolPref(OVERLAY_ENABLED_PREF, false)) {
      return false;
    }

    if (!this.contentWindow) {
      return false;
    }

    let allowedOrigin = Services.prefs.getStringPref(SUBSCRIBE_ORIGIN_PREF, "");
    if (!allowedOrigin) {
      return false;
    }

    let location = this.contentWindow.location;
    if (location.protocol !== "https:" && location.protocol !== "http:") {
      return false;
    }

    return this.#isNativeSurfaceLocation(location, allowedOrigin);
  }

  #eventTargetsContentWindow(event) {
    let target = event.originalTarget;
    if (target === this.contentWindow) {
      return true;
    }
    let targetWindow =
      target?.defaultView ??
      target?.ownerGlobal ??
      target?.ownerDocument?.documentGlobal;
    return targetWindow === this.contentWindow;
  }

  #maybeAttachNativeSurface() {
    if (!this.#enabledForDocument()) {
      this.#removeOverlay();
      return;
    }

    if (!this.#sessionReady) {
      this.#logWaitingForH3();
      this.#removeOverlay();
      return;
    }
  }

  #syncDocumentState() {
    if (this.#currentDocument === this.document) {
      this.#addGeometryEventListeners();
      return;
    }

    this.#removeGeometryEventListeners();
    this.#currentDocument = this.document;
    this.#readySent = false;
    this.#sessionReady = false;
    this.#diagnosticLoggedFor = null;
    this.#removeOverlay();
    this.#addGeometryEventListeners();
  }

  #logWaitingForH3() {
    let href = this.contentWindow.location.href;
    if (this.#diagnosticLoggedFor === href) {
      return;
    }
    this.#diagnosticLoggedFor = href;
    console.warn(
      "MCQUIC overlay candidate matched, but no Http3Session/MCQUIC " +
        `readiness notification has arrived for ${href}; ` +
        "if this persists, the document is likely HTTP/2/non-H3."
    );
  }

  #isNativeSurfaceLocation(location, allowedOrigin) {
    if (
      !this.#locationMatchesAllowedOriginOrTransportParent(
        location,
        allowedOrigin
      )
    ) {
      return false;
    }
    if (this.browsingContext?.top !== this.browsingContext) {
      return false;
    }

    return this.#topLevelMatchesAllowedOrigin(allowedOrigin);
  }

  #topLevelMatchesAllowedOrigin(allowedOrigin) {
    let surfaceLocation = this.contentWindow.location;
    let topPrincipal = this.manager?.topWindowContext?.documentPrincipal;
    let topOrigin = topPrincipal?.originNoSuffix ?? topPrincipal?.origin;
    if (topOrigin) {
      try {
        return this.#topLevelOriginAllowed(
          new URL(topOrigin),
          allowedOrigin,
          surfaceLocation
        );
      } catch (ex) {}
    }

    try {
      return this.#topLevelOriginAllowed(
        this.contentWindow.top.location,
        allowedOrigin,
        surfaceLocation
      );
    } catch (ex) {}

    return this.browsingContext?.top === this.browsingContext;
  }

  #topLevelOriginAllowed(topLocation, allowedOrigin, surfaceLocation) {
    if (
      this.#locationMatchesAllowedOriginOrTransportParent(
        topLocation,
        allowedOrigin
      )
    ) {
      return true;
    }
    if (
      !this.#locationMatchesAllowedOriginOrTransportParent(
        surfaceLocation,
        allowedOrigin
      )
    ) {
      return false;
    }
    return this.#hostIsParentOf(
      surfaceLocation.hostname,
      topLocation.hostname
    );
  }

  #hostIsParentOf(childHost, parentHost) {
    childHost = childHost.toLowerCase();
    parentHost = parentHost.toLowerCase();
    return childHost !== parentHost && childHost.endsWith(`.${parentHost}`);
  }

  #locationMatchesAllowedOrigin(location, allowedOrigin) {
    for (let allowed of this.#allowedOriginEntries(allowedOrigin)) {
      if (allowed.hasExplicitPort) {
        if (allowed.host === location.host) {
          return true;
        }
        continue;
      }

      if (
        allowed.hostname === location.hostname ||
        location.hostname.endsWith(`.${allowed.hostname}`)
      ) {
        return true;
      }
    }
    return false;
  }

  #locationMatchesAllowedOriginOrTransportParent(location, allowedOrigin) {
    if (this.#locationMatchesAllowedOrigin(location, allowedOrigin)) {
      return true;
    }

    for (let allowed of this.#allowedOriginEntries(allowedOrigin)) {
      if (this.#hostIsDirectParentOf(allowed.hostname, location.hostname)) {
        return true;
      }
    }
    return false;
  }

  #hostIsDirectParentOf(childHost, parentHost) {
    childHost = childHost.toLowerCase();
    parentHost = parentHost.toLowerCase();
    if (childHost === parentHost || !childHost.endsWith(`.${parentHost}`)) {
      return false;
    }

    let childPrefix = childHost.slice(0, -(parentHost.length + 1));
    return !!childPrefix && !childPrefix.includes(".");
  }

  #allowedOriginEntries(allowedOrigin) {
    return allowedOrigin
      .split(/[\s,]+/)
      .map(value => this.#originEntryFromValue(value))
      .filter(Boolean);
  }

  #originEntryFromValue(value) {
    try {
      let url = value.includes("://")
        ? new URL(value)
        : new URL(`https://${value}`);
      return {
        host: url.host,
        hostname: url.hostname,
        hasExplicitPort: !!url.port,
      };
    } catch (ex) {
      let host = value.split("/", 1)[0] || "";
      let hostname = host.split(":", 1)[0] || null;
      if (!hostname) {
        return null;
      }
      return {
        host,
        hostname,
        hasExplicitPort: host.includes(":"),
      };
    }
  }

  #hostFromOrigin(value) {
    try {
      let url = value.includes("://")
        ? new URL(value)
        : new URL(`https://${value}`);
      return url.hostname;
    } catch (ex) {
      return value.split("/", 1)[0].split(":", 1)[0] || null;
    }
  }

  #sessionMatchesDocument(session) {
    if (!this.#enabledForDocument()) {
      return false;
    }

    let location = this.contentWindow.location;
    let candidates = [
      session?.authority,
      session?.origin,
      session?.host,
    ].filter(Boolean);
    return candidates.some(candidate => {
      if (this.#locationMatchesAllowedOrigin(location, candidate)) {
        return true;
      }

      let candidateHost = this.#hostFromOrigin(candidate);
      if (!candidateHost) {
        return false;
      }

      return this.#hostIsParentOf(candidateHost, location.hostname);
    });
  }

  #notifyReady() {
    if (this.#readySent || !this.#enabledForDocument()) {
      return;
    }
    this.#readySent = true;
    this.sendAsyncMessage("McquicVideoOverlay:Ready");
  }

  #ensureOverlay(frame = null) {
    if (!this.#enabledForDocument() || !this.#sessionReady) {
      this.#removeOverlay();
      return false;
    }

    if (this.#content && !Cu.isDeadWrapper(this.#content)) {
      this.#applyOverlayGeometry(frame);
      return true;
    }

    let document = this.document;
    if (!document?.documentElement) {
      return false;
    }
    this.#loadOverlaySheet();

    let fragment = document.createDocumentFragment();
    let container = document.createElement("div");
    container.setAttribute("id", "mcquic-video-overlay");

    let image = document.createElement("img");
    image.setAttribute("id", "mcquic-video-overlay-frame");
    container.appendChild(image);

    let label = document.createElement("div");
    label.setAttribute("id", "mcquic-video-overlay-label");
    label.textContent = "MCQUIC video";
    container.appendChild(label);

    fragment.appendChild(container);
    this.#content = document.insertAnonymousContent();
    this.#content.root.appendChild(fragment);
    this.#installImageLoadHandlers();
    this.#applyOverlayGeometry(frame);
    return true;
  }

  #applyOverlayGeometry(frame = null) {
    let container = this.#content?.root.getElementById("mcquic-video-overlay");
    if (!container) {
      return;
    }

    let surface = this.#nativeSurfaceGeometry();
    if (!surface.rect && surface.foundSurface) {
      container.style.display = "none";
      return;
    }

    let rect = surface.rect || this.#fallbackFrameRect(frame);
    container.style.display = "flex";
    container.style.left = `${Math.round(rect.left)}px`;
    container.style.top = `${Math.round(rect.top)}px`;
    container.style.width = `${Math.round(rect.width)}px`;
    container.style.height = `${Math.round(rect.height)}px`;
  }

  #nativeSurfaceGeometry() {
    let document = this.document;
    let allowedOrigin = Services.prefs.getStringPref(SUBSCRIBE_ORIGIN_PREF, "");
    let best = null;
    let foundSurface = false;

    for (let frame of document.querySelectorAll("iframe")) {
      let src = frame.getAttribute("src");
      if (!src) {
        continue;
      }
      let url;
      try {
        url = new URL(src, document.baseURI);
      } catch (ex) {
        continue;
      }
      if (
        url.pathname !== "/moq" &&
        !this.#locationMatchesAllowedOriginOrTransportParent(
          url,
          allowedOrigin
        )
      ) {
        continue;
      }

      foundSurface = true;
      let rect = this.#visibleElementRect(frame);
      if (rect) {
        return { rect, foundSurface };
      }
    }

    for (let element of document.querySelectorAll("video, canvas")) {
      foundSurface = true;
      let rect = this.#visibleElementRect(element);
      if (!rect) {
        continue;
      }
      if (!best || rect.width * rect.height > best.width * best.height) {
        best = rect;
      }
    }
    return { rect: best, foundSurface };
  }

  #visibleElementRect(element) {
    let rect = element.getBoundingClientRect();
    if (rect.width < 32 || rect.height < 32) {
      return null;
    }

    let style = this.contentWindow.getComputedStyle(element);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return null;
    }

    let viewportWidth = this.contentWindow.innerWidth;
    let viewportHeight = this.contentWindow.innerHeight;
    let left = Math.max(0, Math.min(rect.left, viewportWidth));
    let top = Math.max(0, Math.min(rect.top, viewportHeight));
    let right = Math.max(left, Math.min(rect.right, viewportWidth));
    let bottom = Math.max(top, Math.min(rect.bottom, viewportHeight));
    if (right - left < 32 || bottom - top < 32) {
      return null;
    }

    return {
      left,
      top,
      width: right - left,
      height: bottom - top,
    };
  }

  #fallbackFrameRect(frame) {
    let viewportWidth = this.contentWindow.innerWidth;
    let viewportHeight = this.contentWindow.innerHeight;
    let frameWidth = Math.max(1, frame?.width || 640);
    let frameHeight = Math.max(1, frame?.height || 360);
    let scale = Math.min(
      1,
      viewportWidth / frameWidth,
      viewportHeight / frameHeight
    );
    let width = Math.max(1, frameWidth * scale);
    let height = Math.max(1, frameHeight * scale);
    return {
      left: (viewportWidth - width) / 2,
      top: (viewportHeight - height) / 2,
      width,
      height,
    };
  }

  #installImageLoadHandlers() {
    let image = this.#content?.root.getElementById(
      "mcquic-video-overlay-frame"
    );
    if (!image) {
      return;
    }

    image.addEventListener("load", () => this.#finishImageLoad(image, true));
    image.addEventListener("error", () => this.#finishImageLoad(image, false));
  }

  #loadOverlaySheet() {
    if (this.#sheetLoaded) {
      return;
    }

    let { windowUtils } = this.contentWindow;
    try {
      windowUtils.loadSheetUsingURIString(
        OVERLAY_SHEET_URI,
        windowUtils.AGENT_SHEET
      );
    } catch (ex) {}
    this.#sheetLoaded = true;
  }

  #unloadOverlaySheet() {
    if (!this.#sheetLoaded) {
      return;
    }

    let contentWindow = this.contentWindow;
    if (!contentWindow) {
      this.#sheetLoaded = false;
      return;
    }

    let { windowUtils } = contentWindow;
    try {
      windowUtils.removeSheetUsingURIString(
        OVERLAY_SHEET_URI,
        windowUtils.AGENT_SHEET
      );
    } catch (ex) {}
    this.#sheetLoaded = false;
  }

  #removeOverlay() {
    if (this.#content) {
      try {
        this.document.removeAnonymousContent(this.#content);
      } catch (ex) {}
    }
    this.#content = null;
    this.#loadingFrame = null;
    this.#loadingFrameKey = null;
    this.#pendingFrame = null;
    this.#pendingFrameKey = null;
    this.#presentedFrameKey = null;
    this.#framePumpScheduled = false;
    this.#imageLoadInProgress = false;
    this.#geometryUpdateScheduled = false;
    this.#clearStaleFrameTimer();
    this.#unloadOverlaySheet();
  }

  #addGeometryEventListeners() {
    let win = this.contentWindow;
    if (!win || this.#eventWindow === win) {
      return;
    }

    this.#eventWindow = win;
    win.addEventListener("scroll", this, { capture: true, passive: true });
    win.addEventListener("resize", this);
  }

  #removeGeometryEventListeners() {
    if (!this.#eventWindow) {
      return;
    }

    try {
      this.#eventWindow.removeEventListener("scroll", this, { capture: true });
      this.#eventWindow.removeEventListener("resize", this);
    } catch (ex) {}
    this.#eventWindow = null;
  }

  #renderFrame(frame) {
    if (!this.#ensureOverlay(frame)) {
      return;
    }

    let key = this.#frameKey(frame);
    if (
      key &&
      (key === this.#presentedFrameKey ||
        key === this.#loadingFrameKey ||
        key === this.#pendingFrameKey)
    ) {
      return;
    }

    this.#pendingFrame = frame;
    this.#pendingFrameKey = key;
    this.#scheduleFramePump();
  }

  #scheduleOverlayGeometryUpdate() {
    if (!this.#content || this.#geometryUpdateScheduled) {
      return;
    }

    this.#geometryUpdateScheduled = true;
    let document = this.document;
    try {
      this.contentWindow.requestAnimationFrame(() => {
        this.#geometryUpdateScheduled = false;
        if (this.#currentDocument !== document || !this.contentWindow) {
          return;
        }
        this.#applyOverlayGeometry(this.#lastFrame);
      });
    } catch (ex) {
      this.#geometryUpdateScheduled = false;
    }
  }

  #scheduleFramePump() {
    if (this.#framePumpScheduled || this.#imageLoadInProgress) {
      return;
    }

    this.#framePumpScheduled = true;
    let document = this.document;
    Services.tm.dispatchToMainThread(() => {
      this.#framePumpScheduled = false;
      if (this.#currentDocument !== document || !this.contentWindow) {
        return;
      }
      this.#pumpFrame();
    });
  }

  #pumpFrame() {
    if (this.#imageLoadInProgress || !this.#pendingFrame) {
      return;
    }
    if (!this.#ensureOverlay(this.#pendingFrame)) {
      return;
    }

    let image = this.#content.root.getElementById(
      "mcquic-video-overlay-frame"
    );
    if (image) {
      this.#clearStaleFrameTimer();
      this.#loadingFrame = this.#pendingFrame;
      this.#loadingFrameKey = this.#pendingFrameKey;
      this.#pendingFrame = null;
      this.#pendingFrameKey = null;
      this.#imageLoadInProgress = true;
      image.setAttribute("src", this.#loadingFrame.dataUrl);
    }
  }

  #finishImageLoad(image, loaded) {
    if (
      image !==
      this.#content?.root.getElementById("mcquic-video-overlay-frame")
    ) {
      return;
    }

    let frame = this.#loadingFrame;
    let frameKey = this.#loadingFrameKey;
    this.#loadingFrame = null;
    this.#loadingFrameKey = null;
    this.#imageLoadInProgress = false;

    if (loaded && frame) {
      this.#presentedFrameKey = frameKey;
      this.#updateLabel(frame);
      this.#scheduleStaleFrameTimer(frameKey);
    }

    if (this.#pendingFrame) {
      this.#scheduleFramePump();
    }
  }

  #updateLabel(frame) {
    let label = this.#content.root.getElementById(
      "mcquic-video-overlay-label"
    );
    if (label) {
      label.textContent =
        `MCQUIC video ${frame.width}x${frame.height} ` +
        `frame ${frame.decodedFrames}`;
    }
  }

  #frameKey(frame) {
    if (!frame) {
      return null;
    }
    return `${frame.sequence}:${frame.ptsMs}:${frame.decodedFrames}`;
  }

  #scheduleStaleFrameTimer(frameKey) {
    this.#clearStaleFrameTimer();
    this.#staleFrameTimer = this.contentWindow.setTimeout(() => {
      this.#staleFrameTimer = 0;
      if (frameKey && frameKey !== this.#presentedFrameKey) {
        return;
      }

      console.warn(
        "MCQUIC native video frame stream is stale; hiding native overlay " +
          "so page unicast fallback can remain visible."
      );
      this.#lastFrame = null;
      this.#sessionReady = false;
      this.#removeOverlay();
    }, FRAME_STALE_MS);
  }

  #clearStaleFrameTimer() {
    if (!this.#staleFrameTimer) {
      return;
    }
    this.contentWindow?.clearTimeout(this.#staleFrameTimer);
    this.#staleFrameTimer = 0;
  }
}
