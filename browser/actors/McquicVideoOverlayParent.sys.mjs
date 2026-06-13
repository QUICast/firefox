/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const MCQUIC_FRAME_TOPIC = "mcquic-moq-video-frame";

let gActors = new Set();
let gLatestFrame = null;
let gObserverRegistered = false;

const gFrameObserver = {
  observe(subject, topic) {
    if (topic !== MCQUIC_FRAME_TOPIC) {
      return;
    }

    let frame;
    try {
      let payload = subject.QueryInterface(Ci.nsISupportsCString).data;
      frame = JSON.parse(payload);
    } catch (ex) {
      console.error("Malformed MCQUIC video frame notification", ex);
      return;
    }

    gLatestFrame = frame;
    for (let actor of gActors) {
      actor.sendFrame(frame);
    }
  },
};

function ensureObserver() {
  if (gObserverRegistered) {
    return;
  }
  Services.obs.addObserver(gFrameObserver, MCQUIC_FRAME_TOPIC);
  gObserverRegistered = true;
}

function maybeRemoveObserver() {
  if (!gObserverRegistered || gActors.size) {
    return;
  }
  Services.obs.removeObserver(gFrameObserver, MCQUIC_FRAME_TOPIC);
  gObserverRegistered = false;
}

export class McquicVideoOverlayParent extends JSWindowActorParent {
  actorCreated() {
    gActors.add(this);
    ensureObserver();
    if (gLatestFrame) {
      this.sendFrame(gLatestFrame);
    }
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
    if (gLatestFrame) {
      this.sendFrame(gLatestFrame);
    }
  }

  sendFrame(frame) {
    try {
      this.sendAsyncMessage("McquicVideoOverlay:Frame", frame);
    } catch (ex) {}
  }
}
