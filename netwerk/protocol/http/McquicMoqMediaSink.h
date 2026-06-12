/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef McquicMoqMediaSink_h_
#define McquicMoqMediaSink_h_

#include <cstdint>

#include "mozilla/net/neqo_glue_ffi_generated.h"
#include "nsError.h"
#include "nsHashKeys.h"
#include "nsString.h"
#include "nsTHashMap.h"
#include "nsTArray.h"
#include "mozilla/UniquePtr.h"

namespace mozilla::net {

struct McquicMoqAccessUnit {
  nsCString mNamespace;
  nsCString mTrackName;
  nsTArray<uint8_t> mChannelId;
  uint64_t mAccessUnitSequence = 0;
  uint64_t mPtsMillis = 0;
  uint64_t mFirstPacketNumber = 0;
  uint64_t mLastPacketNumber = 0;
  bool mKeyframe = false;
  bool mConfig = false;
  bool mIndependent = false;
  nsTArray<uint8_t> mPayload;
};

class McquicMoqAccessUnitConsumer {
 public:
  virtual ~McquicMoqAccessUnitConsumer() = default;

  static bool Enabled();

  virtual nsresult OnMcquicMoqAccessUnit(
      const McquicMoqAccessUnit& aAccessUnit) = 0;
};

UniquePtr<McquicMoqAccessUnitConsumer> CreateMcquicMoqAccessUnitConsumer();

class McquicMoqMediaSink final {
 public:
  McquicMoqMediaSink() = default;

  static bool Enabled();

  nsresult ProcessObject(const nsACString& aNamespace,
                         const nsACString& aTrackName,
                         const nsTArray<uint8_t>& aChannelId,
                         uint64_t aPacketNumber,
                         const McquicMoqDatagramExternal& aObject);

  bool PopAccessUnit(McquicMoqAccessUnit& aAccessUnit);
  nsresult DrainAccessUnits(McquicMoqAccessUnitConsumer& aConsumer);

 private:
  struct FragmentSlot {
    bool mPresent = false;
    nsTArray<uint8_t> mPayload;
  };

  struct PendingAccessUnit {
    nsCString mNamespace;
    nsCString mTrackName;
    nsTArray<uint8_t> mChannelId;
    uint64_t mAccessUnitSequence = 0;
    uint64_t mPtsMillis = 0;
    uint64_t mFirstPacketNumber = 0;
    uint64_t mLastPacketNumber = 0;
    uint16_t mFragmentCount = 0;
    uint16_t mReceivedFragments = 0;
    bool mKeyframe = false;
    bool mConfig = false;
    bool mIndependent = false;
    nsTArray<FragmentSlot> mFragments;
  };

  nsresult EmitIfComplete(const nsCString& aKey, PendingAccessUnit& aPending);

  nsTHashMap<nsCStringHashKey, PendingAccessUnit> mPendingAccessUnits;
  nsTArray<McquicMoqAccessUnit> mCompletedAccessUnits;
};

}  // namespace mozilla::net

#endif  // McquicMoqMediaSink_h_
