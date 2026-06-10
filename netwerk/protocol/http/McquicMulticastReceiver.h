/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef McquicMulticastReceiver_h_
#define McquicMulticastReceiver_h_

#include <cstdint>

#include "mozilla/Maybe.h"
#include "mozilla/net/neqo_glue_ffi_generated.h"
#include "nsError.h"
#include "nsString.h"

namespace mozilla::net {

class McquicMulticastReceiver final {
 public:
  McquicMulticastReceiver() = default;
  ~McquicMulticastReceiver();

  static bool Enabled();

  nsresult Init();
  nsresult AddSsmSubscription(const nsACString& aSource,
                              const nsACString& aGroup, uint16_t aPort,
                              const nsACString& aInterface,
                              Maybe<uint32_t> aInterfaceIndex,
                              uint64_t* aSubscriptionId);
  nsresult Join(uint64_t aSubscriptionId);
  nsresult Leave(uint64_t aSubscriptionId);
  nsresult Remove(uint64_t aSubscriptionId);
  nsresult Poll(McquicMcrxPacket& aPacket);

 private:
  nsresult EnsureReady() const;

  McquicMcrxReceiver* mReceiver = nullptr;
};

}  // namespace mozilla::net

#endif  // McquicMulticastReceiver_h_
