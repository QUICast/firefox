/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const MCQUIC_FRAME_TOPIC = "mcquic-moq-video-frame";
const MCQUIC_SESSION_READY_TOPIC = "mcquic-moq-session-ready";

let gActors = new Set();
let gObserverRegistered = false;

const gMcquicObserver = {
  observe(subject, topic) {
    try {
      let payload = subject.QueryInterface(Ci.nsISupportsCString).data;
      let parsed = JSON.parse(payload);
      if (topic === MCQUIC_FRAME_TOPIC) {
        for (let actor of gActors) {
          actor.sendFrame(parsed);
        }
        return;
      }
      if (topic === MCQUIC_SESSION_READY_TOPIC) {
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
  }

  sendSessionReady(session) {
    try {
      this.sendAsyncMessage("McquicVideoOverlay:SessionReady", session);
    } catch (ex) {}
  }

  sendFrame(frame) {
    try {
      this.sendAsyncMessage("McquicVideoOverlay:Frame", frame);
    } catch (ex) {}
  }
}
