/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const MCQUIC_FRAME_TOPIC = "mcquic-moq-video-frame";
const MCQUIC_SESSION_READY_TOPIC = "mcquic-moq-session-ready";
const SESSION_READY_EVENT = "subscribe-ok";

let gActors = new Set();
let gObserverRegistered = false;
let gLastFrame = null;
let gLastSessionReady = null;

const gMcquicObserver = {
  observe(subject, topic) {
    try {
      let payload = subject.QueryInterface(Ci.nsISupportsCString).data;
      let parsed = JSON.parse(payload);
      if (topic === MCQUIC_FRAME_TOPIC) {
        gLastFrame = parsed;
        for (let actor of gActors) {
          actor.sendFrame(parsed);
        }
        return;
      }
      if (topic === MCQUIC_SESSION_READY_TOPIC) {
        if (parsed?.event === SESSION_READY_EVENT) {
          gLastSessionReady = parsed;
        }
        for (let actor of gActors) {
          actor.sendSessionReady(parsed);
        }
      }
    } catch (ex) {
      console.error(`Malformed MCQUIC overlay notification ${topic}`, ex);
    }
  },
};

function ensureObserver() {
  if (gObserverRegistered) {
    return;
  }
  Services.obs.addObserver(gMcquicObserver, MCQUIC_FRAME_TOPIC);
  Services.obs.addObserver(gMcquicObserver, MCQUIC_SESSION_READY_TOPIC);
  gObserverRegistered = true;
}

function maybeRemoveObserver() {
  if (!gObserverRegistered || gActors.size) {
    return;
  }
  Services.obs.removeObserver(gMcquicObserver, MCQUIC_FRAME_TOPIC);
  Services.obs.removeObserver(gMcquicObserver, MCQUIC_SESSION_READY_TOPIC);
  gObserverRegistered = false;
}

export class McquicVideoOverlayParent extends JSWindowActorParent {
  actorCreated() {
    gActors.add(this);
    ensureObserver();
    this.sendStickyState();
  }

  didDestroy() {
    gActors.delete(this);
    maybeRemoveObserver();
  }

  receiveMessage(message) {
    if (message.name !== "McquicVideoOverlay:Ready") {
      return;
    }
    ensureObserver();
    this.sendStickyState();
  }

  sendStickyState() {
    if (gLastSessionReady) {
      this.sendSessionReady(gLastSessionReady);
    }
    if (gLastFrame) {
      this.sendFrame(gLastFrame, true);
    }
  }

  sendSessionReady(session) {
    try {
      this.sendAsyncMessage("McquicVideoOverlay:SessionReady", session);
    } catch (ex) {}
  }

  sendFrame(frame, sticky = false) {
    try {
      this.sendAsyncMessage("McquicVideoOverlay:Frame", { ...frame, sticky });
    } catch (ex) {}
  }
}
