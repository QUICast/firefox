/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const OVERLAY_ENABLED_PREF =
  "network.http.http3.mcquic.moq_media_overlay.enabled";
const SUBSCRIBE_ORIGIN_PREF = "network.http.http3.mcquic.moq_subscribe.origin";
const SESSION_READY_EVENT = "subscribe-ok";
const OVERLAY_SHEET_URI =
  "data:text/css;charset=utf-8," +
  encodeURIComponent(`
#mcquic-video-overlay,
#mcquic-video-overlay:-moz-native-anonymous {
  position: fixed !important;
  inset: 0 !important;
  z-index: 2147483647 !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  background: #101014 !important;
  pointer-events: none !important;
}

#mcquic-video-overlay-frame,
#mcquic-video-overlay-frame:-moz-native-anonymous {
  max-width: 100vw !important;
  max-height: 100vh !important;
  width: auto !important;
  height: auto !important;
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
  #readySent = false;
  #sheetLoaded = false;
  #sessionReady = false;
  #diagnosticLoggedFor = null;
  #currentDocument = null;

  actorCreated() {
    this.#syncDocumentState();
    this.#notifyReady();
  }

  didDestroy() {
    this.#removeOverlay();
  }

  handleEvent(event) {
    if (!this.#eventTargetsContentWindow(event)) {
      return;
    }
    this.#syncDocumentState();
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
      this.#ensureOverlay();
      if (this.#lastFrame) {
        this.#renderFrame(this.#lastFrame);
      }
      return;
    }

    if (message.name === "McquicVideoOverlay:Frame") {
      this.#lastFrame = message.data;
      this.#renderFrame(message.data);
    }
  }

  #enabledForDocument() {
    if (!Services.prefs.getBoolPref(OVERLAY_ENABLED_PREF, false)) {
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

    this.#ensureOverlay();
  }

  #syncDocumentState() {
    if (this.#currentDocument === this.document) {
      return;
    }

    this.#currentDocument = this.document;
    this.#readySent = false;
    this.#sessionReady = false;
    this.#diagnosticLoggedFor = null;
    this.#removeOverlay();
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
    if (!this.#locationMatchesAllowedOrigin(location, allowedOrigin)) {
      return false;
    }
    if (location.pathname !== "/moq") {
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
    if (this.#locationMatchesAllowedOrigin(topLocation, allowedOrigin)) {
      return true;
    }
    if (!this.#locationMatchesAllowedOrigin(surfaceLocation, allowedOrigin)) {
      return false;
    }
    return this.#hostIsParentOf(surfaceLocation.hostname, topLocation.hostname);
  }

  #hostIsParentOf(childHost, parentHost) {
    childHost = childHost.toLowerCase();
    parentHost = parentHost.toLowerCase();
    return childHost !== parentHost && childHost.endsWith(`.${parentHost}`);
  }

  #locationMatchesAllowedOrigin(location, allowedOrigin) {
    for (let allowedHost of this.#allowedOriginHosts(allowedOrigin)) {
      if (
        allowedHost === location.hostname ||
        allowedHost === location.host ||
        location.hostname.endsWith(`.${allowedHost}`)
      ) {
        return true;
      }
    }
    return false;
  }

  #allowedOriginHosts(allowedOrigin) {
    return allowedOrigin
      .split(/[\s,]+/)
      .map(value => this.#hostFromOrigin(value))
      .filter(Boolean);
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
    return candidates.some(candidate =>
      this.#locationMatchesAllowedOrigin(location, candidate)
    );
  }

  #notifyReady() {
    if (this.#readySent || !this.#enabledForDocument()) {
      return;
    }
    this.#readySent = true;
    this.sendAsyncMessage("McquicVideoOverlay:Ready");
  }

  #ensureOverlay() {
    if (!this.#enabledForDocument() || !this.#sessionReady) {
      this.#removeOverlay();
      return false;
    }

    if (this.#content && !Cu.isDeadWrapper(this.#content)) {
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
    return true;
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

    let { windowUtils } = this.contentWindow;
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
    this.#unloadOverlaySheet();
  }

  #renderFrame(frame) {
    if (!this.#ensureOverlay()) {
      return;
    }

    let image = this.#content.root.getElementById("mcquic-video-overlay-frame");
    if (image) {
      image.setAttribute("src", frame.dataUrl);
    }

    let label = this.#content.root.getElementById("mcquic-video-overlay-label");
    if (label) {
      label.textContent =
        `MCQUIC video ${frame.width}x${frame.height} ` +
        `frame ${frame.decodedFrames}`;
    }
  }
}
