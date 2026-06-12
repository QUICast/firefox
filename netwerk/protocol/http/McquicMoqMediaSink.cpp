/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "McquicMoqMediaSink.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>

#include "HttpLog.h"
#include "mozilla/StaticPrefs_network.h"

namespace mozilla::net {

namespace {

constexpr size_t QVF1_FIXED_HEADER_LEN = 32;
constexpr uint8_t QVF1_VERSION = 1;
constexpr uint8_t QVF1_CODEC_H264 = 1;
constexpr uint8_t QVF1_FLAG_KEYFRAME = 0x01;
constexpr uint8_t QVF1_FLAG_CONFIG = 0x02;
constexpr uint8_t QVF1_FLAG_END_OF_ACCESS_UNIT = 0x04;
constexpr uint16_t QVF1_MAX_FRAGMENTS = 1024;

struct Qvf1FragmentMetadata {
  uint8_t mFlags = 0;
  uint64_t mAccessUnitSequence = 0;
  uint16_t mFragmentIndex = 0;
  uint16_t mFragmentCount = 0;
  uint64_t mPtsMillis = 0;
  uint32_t mPayloadLen = 0;
};

static uint16_t ReadBigEndianUint16(const uint8_t* aData) {
  return (static_cast<uint16_t>(aData[0]) << 8) | aData[1];
}

static uint32_t ReadBigEndianUint32(const uint8_t* aData) {
  return (static_cast<uint32_t>(aData[0]) << 24) |
         (static_cast<uint32_t>(aData[1]) << 16) |
         (static_cast<uint32_t>(aData[2]) << 8) | aData[3];
}

static uint64_t ReadBigEndianUint64(const uint8_t* aData) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) {
    value = (value << 8) | aData[i];
  }
  return value;
}

static nsCString AccessUnitKey(const nsACString& aNamespace,
                               const nsACString& aTrackName,
                               uint64_t aAccessUnitSequence) {
  nsCString key(aNamespace);
  key.Append('\0');
  key.Append(aTrackName);
  key.Append('\0');
  key.AppendPrintf("%" PRIu64, aAccessUnitSequence);
  return key;
}

static nsresult ParseQvf1Payload(const nsTArray<uint8_t>& aPayload,
                                 Qvf1FragmentMetadata& aMetadata) {
  if (aPayload.Length() < QVF1_FIXED_HEADER_LEN) {
    return NS_ERROR_INVALID_ARG;
  }

  const uint8_t* data = aPayload.Elements();
  if (std::memcmp(data, "QVF1", 4) != 0 || data[4] != QVF1_VERSION ||
      data[5] != QVF1_CODEC_H264) {
    return NS_ERROR_INVALID_ARG;
  }

  aMetadata.mFlags = data[6];
  aMetadata.mAccessUnitSequence = ReadBigEndianUint64(&data[8]);
  aMetadata.mFragmentIndex = ReadBigEndianUint16(&data[16]);
  aMetadata.mFragmentCount = ReadBigEndianUint16(&data[18]);
  aMetadata.mPtsMillis = ReadBigEndianUint64(&data[20]);
  aMetadata.mPayloadLen = ReadBigEndianUint32(&data[28]);

  if (aMetadata.mFragmentCount == 0 ||
      aMetadata.mFragmentCount > QVF1_MAX_FRAGMENTS ||
      aMetadata.mFragmentIndex >= aMetadata.mFragmentCount) {
    return NS_ERROR_INVALID_ARG;
  }

  if (aPayload.Length() != QVF1_FIXED_HEADER_LEN + aMetadata.mPayloadLen) {
    return NS_ERROR_INVALID_ARG;
  }

  return NS_OK;
}

class McquicMoqLoggingAccessUnitConsumer final
    : public McquicMoqAccessUnitConsumer {
 public:
  nsresult OnMcquicMoqAccessUnit(
      const McquicMoqAccessUnit& aAccessUnit) override {
    LOG(
        ("MCQUIC MoQ media handoff accepted access unit [track=%s/%s "
         "sequence=%" PRIu64 " pts_ms=%" PRIu64 " payload_len=%zu "
         "keyframe=%d config=%d independent=%d]",
         aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
         aAccessUnit.mAccessUnitSequence, aAccessUnit.mPtsMillis,
         aAccessUnit.mPayload.Length(), aAccessUnit.mKeyframe,
         aAccessUnit.mConfig, aAccessUnit.mIndependent));
    return NS_OK;
  }
};

}  // namespace

bool McquicMoqAccessUnitConsumer::Enabled() {
  return McquicMoqMediaSink::Enabled() &&
         StaticPrefs::network_http_http3_mcquic_moq_media_handoff_enabled();
}

UniquePtr<McquicMoqAccessUnitConsumer> CreateMcquicMoqAccessUnitConsumer() {
  if (!McquicMoqAccessUnitConsumer::Enabled()) {
    return nullptr;
  }
  return MakeUnique<McquicMoqLoggingAccessUnitConsumer>();
}

bool McquicMoqMediaSink::Enabled() {
  return StaticPrefs::network_http_http3_mcquic_enabled() &&
         StaticPrefs::network_http_http3_mcquic_moq_media_sink_enabled();
}

nsresult McquicMoqMediaSink::ProcessObject(
    const nsACString& aNamespace, const nsACString& aTrackName,
    const nsTArray<uint8_t>& aChannelId, uint64_t aPacketNumber,
    const McquicMoqDatagramExternal& aObject) {
  if (!StringEndsWith(aTrackName, "h264-qvf1"_ns)) {
    return NS_OK;
  }

  Qvf1FragmentMetadata metadata;
  nsresult rv = ParseQvf1Payload(aObject.payload, metadata);
  if (NS_FAILED(rv)) {
    LOG(
        ("MCQUIC MoQ media sink rejected non-QVF1 payload [track=%s/%s "
         "group=%" PRIu64 " object=%" PRIu64 " payload_len=%zu]",
         PromiseFlatCString(aNamespace).get(),
         PromiseFlatCString(aTrackName).get(), aObject.group_id,
         aObject.object_id, aObject.payload.Length()));
    return rv;
  }

  nsCString key =
      AccessUnitKey(aNamespace, aTrackName, metadata.mAccessUnitSequence);
  PendingAccessUnit& pending = mPendingAccessUnits.LookupOrInsert(key);
  if (pending.mFragmentCount == 0) {
    pending.mNamespace.Assign(aNamespace);
    pending.mTrackName.Assign(aTrackName);
    pending.mChannelId = aChannelId.Clone();
    pending.mAccessUnitSequence = metadata.mAccessUnitSequence;
    pending.mPtsMillis = metadata.mPtsMillis;
    pending.mFirstPacketNumber = aPacketNumber;
    pending.mLastPacketNumber = aPacketNumber;
    pending.mFragmentCount = metadata.mFragmentCount;
    pending.mFragments.SetLength(metadata.mFragmentCount);
  } else if (pending.mFragmentCount != metadata.mFragmentCount ||
             pending.mPtsMillis != metadata.mPtsMillis) {
    return NS_ERROR_INVALID_ARG;
  }

  pending.mFirstPacketNumber =
      std::min(pending.mFirstPacketNumber, aPacketNumber);
  pending.mLastPacketNumber =
      std::max(pending.mLastPacketNumber, aPacketNumber);
  pending.mKeyframe |= metadata.mFlags & QVF1_FLAG_KEYFRAME;
  pending.mConfig |= metadata.mFlags & QVF1_FLAG_CONFIG;
  pending.mIndependent |=
      metadata.mFlags & (QVF1_FLAG_KEYFRAME | QVF1_FLAG_CONFIG);

  FragmentSlot& slot = pending.mFragments[metadata.mFragmentIndex];
  if (!slot.mPresent) {
    slot.mPresent = true;
    ++pending.mReceivedFragments;
  }
  slot.mPayload.Clear();
  slot.mPayload.AppendElements(
      aObject.payload.Elements() + QVF1_FIXED_HEADER_LEN, metadata.mPayloadLen);

  if ((metadata.mFlags & QVF1_FLAG_END_OF_ACCESS_UNIT) &&
      pending.mReceivedFragments != pending.mFragmentCount) {
    LOG(
        ("MCQUIC MoQ media sink saw end-of-access-unit before all fragments "
         "[track=%s/%s sequence=%" PRIu64 " received=%u expected=%u]",
         pending.mNamespace.get(), pending.mTrackName.get(),
         pending.mAccessUnitSequence, pending.mReceivedFragments,
         pending.mFragmentCount));
  }

  return EmitIfComplete(key, pending);
}

bool McquicMoqMediaSink::PopAccessUnit(McquicMoqAccessUnit& aAccessUnit) {
  if (mCompletedAccessUnits.IsEmpty()) {
    return false;
  }

  aAccessUnit = std::move(mCompletedAccessUnits[0]);
  mCompletedAccessUnits.RemoveElementAt(0);
  return true;
}

nsresult McquicMoqMediaSink::DrainAccessUnits(
    McquicMoqAccessUnitConsumer& aConsumer) {
  McquicMoqAccessUnit accessUnit;
  while (PopAccessUnit(accessUnit)) {
    nsresult rv = aConsumer.OnMcquicMoqAccessUnit(accessUnit);
    if (NS_FAILED(rv)) {
      return rv;
    }
  }
  return NS_OK;
}

nsresult McquicMoqMediaSink::EmitIfComplete(const nsCString& aKey,
                                            PendingAccessUnit& aPending) {
  if (aPending.mReceivedFragments != aPending.mFragmentCount) {
    return NS_OK;
  }

  McquicMoqAccessUnit accessUnit;
  accessUnit.mNamespace = aPending.mNamespace;
  accessUnit.mTrackName = aPending.mTrackName;
  accessUnit.mChannelId = aPending.mChannelId.Clone();
  accessUnit.mAccessUnitSequence = aPending.mAccessUnitSequence;
  accessUnit.mPtsMillis = aPending.mPtsMillis;
  accessUnit.mFirstPacketNumber = aPending.mFirstPacketNumber;
  accessUnit.mLastPacketNumber = aPending.mLastPacketNumber;
  accessUnit.mKeyframe = aPending.mKeyframe;
  accessUnit.mConfig = aPending.mConfig;
  accessUnit.mIndependent = aPending.mIndependent;

  for (const FragmentSlot& fragment : aPending.mFragments) {
    if (!fragment.mPresent) {
      return NS_OK;
    }
    accessUnit.mPayload.AppendElements(fragment.mPayload);
  }

  LOG(("MCQUIC MoQ media access unit [track=%s/%s sequence=%" PRIu64
       " pts_ms=%" PRIu64 " fragments=%u payload_len=%zu keyframe=%d "
       "config=%d independent=%d first_packet=%" PRIu64 " last_packet=%" PRIu64
       "]",
       accessUnit.mNamespace.get(), accessUnit.mTrackName.get(),
       accessUnit.mAccessUnitSequence, accessUnit.mPtsMillis,
       aPending.mFragmentCount, accessUnit.mPayload.Length(),
       accessUnit.mKeyframe, accessUnit.mConfig, accessUnit.mIndependent,
       accessUnit.mFirstPacketNumber, accessUnit.mLastPacketNumber));

  mCompletedAccessUnits.AppendElement(std::move(accessUnit));
  mPendingAccessUnits.Remove(aKey);
  return NS_OK;
}

}  // namespace mozilla::net
