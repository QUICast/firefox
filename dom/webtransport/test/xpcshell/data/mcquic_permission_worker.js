/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

self.onmessage = async event => {
  let transport;
  try {
    const request =
      typeof event.data === "string"
        ? { action: "read", url: event.data }
        : event.data;
    const options = request.multicast ? { multicast: "allow" } : undefined;
    transport = new WebTransport(request.url, options);
    if (request.action === "hold-negotiating") {
      self.postMessage({ state: "constructed" });
      await transport.ready;
      self.postMessage({ state: "unexpected-ready" });
      await new Promise(() => {});
    }

    await transport.ready;
    if (request.action === "hold-active") {
      self.postMessage({ state: "active" });
      await new Promise(() => {});
    }

    const incoming = transport.incomingUnidirectionalStreams.getReader();
    const { value, done } = await incoming.read();
    incoming.releaseLock();
    if (done) {
      throw new Error("worker WebTransport produced no stream");
    }

    const reader = value.getReader();
    const decoder = new TextDecoder();
    let result = "";
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) {
        break;
      }
      result += decoder.decode(chunk.value, { stream: true });
    }
    result += decoder.decode();
    self.postMessage({ result });
  } catch (error) {
    self.postMessage({ error: String(error?.stack || error) });
  } finally {
    transport?.close();
  }
};
