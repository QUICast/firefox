/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const OVERLAY_ENABLED_PREF =
  "network.http.http3.mcquic.moq_media_overlay.enabled";
const SUBSCRIBE_ORIGIN_PREF = "network.http.http3.mcquic.moq_subscribe.origin";

export class McquicVideoOverlayChild extends JSWindowActorChild {
  #content = null;
  #lastFrame = null;
  #readySent = false;

  actorCreated() {
    this.#notifyReady();
  }

  didDestroy() {
    this.#removeOverlay();
  }

  handleEvent(event) {
    if (event.originalTarget?.defaultView !== this.contentWindow) {
      return;
    }
    this.#notifyReady();
    if (this.#lastFrame) {
      this.#renderFrame(this.#lastFrame);
    }
  }

  receiveMessage(message) {
    if (message.name !== "McquicVideoOverlay:Frame") {
      return;
    }
    this.#lastFrame = message.data;
    this.#renderFrame(message.data);
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

    return this.#locationMatchesAllowedOrigin(location, allowedOrigin);
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

  #notifyReady() {
    if (this.#readySent || !this.#enabledForDocument()) {
      return;
    }
    this.#readySent = true;
    this.sendAsyncMessage("McquicVideoOverlay:Ready");
  }

  #ensureOverlay() {
    if (!this.#enabledForDocument()) {
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

    let fragment = document.createDocumentFragment();
    let container = document.createElement("div");
    container.setAttribute("id", "mcquic-video-overlay");
    container.setAttribute(
      "style",
      [
        "position:fixed",
        "inset:0",
        "z-index:2147483647",
        "display:flex",
        "align-items:center",
        "justify-content:center",
        "background:#101014",
        "pointer-events:none",
      ].join(";")
    );

    let image = document.createElement("img");
    image.setAttribute("id", "mcquic-video-overlay-frame");
    image.setAttribute(
      "style",
      [
        "max-width:100vw",
        "max-height:100vh",
        "width:auto",
        "height:auto",
        "object-fit:contain",
        "background:#000",
      ].join(";")
    );
    container.appendChild(image);

    let label = document.createElement("div");
    label.setAttribute("id", "mcquic-video-overlay-label");
    label.setAttribute(
      "style",
      [
        "position:fixed",
        "left:16px",
        "top:16px",
        "padding:6px 8px",
        "border-radius:4px",
        "background:rgba(0,0,0,.72)",
        "color:white",
        "font:12px system-ui,sans-serif",
        "letter-spacing:0",
      ].join(";")
    );
    label.textContent = "MCQUIC video";
    container.appendChild(label);

    fragment.appendChild(container);
    this.#content = document.insertAnonymousContent();
    this.#content.root.appendChild(fragment);
    return true;
  }

  #removeOverlay() {
    if (!this.#content) {
      return;
    }

    try {
      this.document.removeAnonymousContent(this.#content);
    } catch (ex) {}
    this.#content = null;
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
