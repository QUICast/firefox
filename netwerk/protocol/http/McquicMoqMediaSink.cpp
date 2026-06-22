/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "McquicMoqMediaSink.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <limits>

#include "AnnexB.h"
#include "H264.h"
#include "HttpLog.h"
#include "ImageConversion.h"
#include "ImageContainer.h"
#include "MediaData.h"
#include "MediaDataDecoderProxy.h"
#include "MediaInfo.h"
#include "mozilla/Maybe.h"
#include "PDMFactory.h"
#include "VideoUtils.h"
#include "gfxUtils.h"
#include "imgIEncoder.h"
#include "mozilla/Base64.h"
#include "mozilla/CheckedInt.h"
#include "mozilla/Services.h"
#include "mozilla/StaticPrefs_network.h"
#include "mozilla/gfx/2D.h"
#include "mozilla/layers/ImageBridgeChild.h"
#include "mozilla/media/MediaUtils.h"
#include "nsComponentManagerUtils.h"
#include "nsIObserverService.h"
#include "nsISupportsPrimitives.h"
#include "nsSupportsPrimitives.h"
#include "nsThreadUtils.h"

namespace mozilla::net {

namespace {

constexpr size_t QVF1_FIXED_HEADER_LEN = 32;
constexpr size_t LOC_MSF_FIXED_HEADER_LEN = 28;
constexpr size_t LOC_H264_ANNEXB_FRAGMENT_HEADER_LEN = 20;
constexpr size_t COMPACT_LOC_MSF_H264_FRAGMENT_HEADER_LEN = 15;
constexpr uint8_t QVF1_VERSION = 1;
constexpr uint8_t QVF1_CODEC_H264 = 1;
constexpr uint8_t QVF1_FLAG_KEYFRAME = 0x01;
constexpr uint8_t QVF1_FLAG_CONFIG = 0x02;
constexpr uint8_t QVF1_FLAG_END_OF_ACCESS_UNIT = 0x04;
constexpr uint8_t MCQUIC_MEDIA_FLAG_INDEPENDENT = 0x08;
constexpr uint8_t LOC_H264_ANNEXB_FRAGMENT_VERSION = 1;
constexpr uint8_t LOC_H264_ANNEXB_FRAGMENT_HEADER_BYTE = 20;
constexpr uint16_t LOC_H264_FLAG_KEYFRAME = 0x0001;
constexpr uint16_t LOC_H264_FLAG_CONFIG = 0x0002;
constexpr uint16_t LOC_H264_FLAG_END_OF_ACCESS_UNIT = 0x0008;
constexpr uint16_t QVF1_MAX_FRAGMENTS = 1024;
constexpr size_t MCQUIC_MOQ_DEDUP_WINDOW = 4096;
constexpr gfx::IntSize QVF1_DECODE_SIZE{640, 480};
constexpr const char* MCQUIC_MOQ_VIDEO_FRAME_TOPIC = "mcquic-moq-video-frame";

enum class McquicMoqMediaPayloadFormat {
  Qvf1,
  LocMsf,
};

struct McquicMoqMediaFragmentMetadata {
  McquicMoqMediaPayloadFormat mFormat = McquicMoqMediaPayloadFormat::Qvf1;
  uint8_t mFlags = 0;
  uint64_t mAccessUnitSequence = 0;
  uint16_t mFragmentIndex = 0;
  uint16_t mFragmentCount = 1;
  uint64_t mPtsMillis = 0;
  size_t mPayloadOffset = 0;
  uint32_t mPayloadLen = 0;
  bool mOpenEnded = false;
};

static const char* McquicMoqMediaPayloadFormatName(
    McquicMoqMediaPayloadFormat aFormat) {
  switch (aFormat) {
    case McquicMoqMediaPayloadFormat::Qvf1:
      return "qvf1";
    case McquicMoqMediaPayloadFormat::LocMsf:
      return "loc-msf";
  }
  return "unknown";
}

static const char* McquicMoqMediaObjectStatusName(
    McquicMoqObjectStatus aStatus) {
  switch (aStatus) {
    case McquicMoqObjectStatus::Normal:
      return "Normal";
    case McquicMoqObjectStatus::EndOfGroup:
      return "EndOfGroup";
    case McquicMoqObjectStatus::EndOfTrack:
      return "EndOfTrack";
    case McquicMoqObjectStatus::Unknown:
      return "Unknown";
  }
  return "unknown";
}

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

static Maybe<uint32_t> ReadAvccNalLength(const uint8_t* aData, size_t aLength,
                                         size_t aNalLengthSize) {
  if (aLength < aNalLengthSize) {
    return Nothing();
  }

  uint32_t nalLength = 0;
  for (size_t i = 0; i < aNalLengthSize; ++i) {
    nalLength = (nalLength << 8) | aData[i];
  }
  return Some(nalLength);
}

static media::TimeUnit TimeUnitFromMillis(uint64_t aMillis) {
  constexpr uint64_t MAX_SAFE_MILLIS =
      std::numeric_limits<int64_t>::max() / 1000;
  return media::TimeUnit::FromMicroseconds(
      static_cast<int64_t>(std::min(aMillis, MAX_SAFE_MILLIS) * 1000));
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

static nsCString TrackKey(const nsACString& aNamespace,
                          const nsACString& aTrackName) {
  nsCString key(aNamespace);
  key.Append('\0');
  key.Append(aTrackName);
  return key;
}

static nsCString ObjectKey(const nsACString& aNamespace,
                           const nsACString& aTrackName, uint64_t aGroupId,
                           uint64_t aObjectId) {
  nsCString key(aNamespace);
  key.Append('\0');
  key.Append(aTrackName);
  key.Append('\0');
  key.AppendPrintf("%" PRIu64, aGroupId);
  key.Append('\0');
  key.AppendPrintf("%" PRIu64, aObjectId);
  return key;
}

static bool MediaByteBuffersEqual(const MediaByteBuffer* aLeft,
                                  const MediaByteBuffer* aRight) {
  if (aLeft == aRight) {
    return true;
  }
  if (!aLeft || !aRight || aLeft->Length() != aRight->Length()) {
    return false;
  }
  return std::equal(aLeft->Elements(), aLeft->Elements() + aLeft->Length(),
                    aRight->Elements());
}

struct AnnexBNalSummary {
  bool mContainsIdr = false;
  bool mContainsSps = false;
  bool mContainsPps = false;
};

static Maybe<size_t> FindAnnexBStartCode(const nsTArray<uint8_t>& aPayload,
                                         size_t aOffset) {
  if (aPayload.Length() < 4 || aOffset >= aPayload.Length() - 3) {
    return Nothing();
  }

  const uint8_t* data = aPayload.Elements();
  for (size_t i = aOffset; i + 3 < aPayload.Length(); ++i) {
    if (data[i] != 0 || data[i + 1] != 0) {
      continue;
    }
    if (data[i + 2] == 1) {
      return Some(i);
    }
    if (i + 4 <= aPayload.Length() && data[i + 2] == 0 && data[i + 3] == 1) {
      return Some(i);
    }
  }
  return Nothing();
}

static size_t AnnexBStartCodeLength(const nsTArray<uint8_t>& aPayload,
                                    size_t aOffset) {
  const uint8_t* data = aPayload.Elements();
  if (aOffset + 3 < aPayload.Length() && data[aOffset] == 0 &&
      data[aOffset + 1] == 0 && data[aOffset + 2] == 0 &&
      data[aOffset + 3] == 1) {
    return 4;
  }
  return 3;
}

static AnnexBNalSummary SummarizeAnnexBNals(const nsTArray<uint8_t>& aPayload) {
  AnnexBNalSummary summary;
  size_t offset = 0;
  while (auto start = FindAnnexBStartCode(aPayload, offset)) {
    size_t nalOffset = *start + AnnexBStartCodeLength(aPayload, *start);
    if (nalOffset >= aPayload.Length()) {
      break;
    }

    uint8_t nalType = aPayload[nalOffset] & 0x1f;
    summary.mContainsIdr |= nalType == 5;
    summary.mContainsSps |= nalType == 7;
    summary.mContainsPps |= nalType == 8;
    if (summary.mContainsIdr && summary.mContainsSps && summary.mContainsPps) {
      break;
    }
    offset = nalOffset + 1;
  }
  return summary;
}

static const char* H264FrameTypeName(H264::FrameType aFrameType) {
  switch (aFrameType) {
    case H264::FrameType::I_FRAME_IDR:
      return "idr";
    case H264::FrameType::I_FRAME_OTHER:
      return "i";
    case H264::FrameType::OTHER:
      return "other";
    case H264::FrameType::INVALID:
      return "invalid";
  }
  return "unknown";
}

static nsCString SummarizeAvccNals(const MediaRawData* aSample) {
  nsCString summary;
  if (!aSample || !aSample->Data()) {
    return "empty"_ns;
  }

  auto avcc = AVCCConfig::Parse(aSample);
  if (avcc.isErr()) {
    return "invalid-avcc"_ns;
  }

  const uint8_t nalLengthSize = avcc.unwrap().NALUSize();
  const uint8_t* data = aSample->Data();
  size_t offset = 0;
  uint32_t nalCount = 0;
  while (offset + nalLengthSize <= aSample->Size() && nalCount < 8) {
    Maybe<uint32_t> nalLength = ReadAvccNalLength(
        data + offset, aSample->Size() - offset, nalLengthSize);
    if (!nalLength || *nalLength == 0) {
      break;
    }
    offset += nalLengthSize;
    if (offset + *nalLength > aSample->Size()) {
      summary.AppendPrintf("%sbad:%u", summary.IsEmpty() ? "" : ",",
                           *nalLength);
      break;
    }

    uint8_t nalType = data[offset] & 0x1f;
    summary.AppendPrintf("%s%u:%u", summary.IsEmpty() ? "" : ",", nalType,
                         *nalLength);
    offset += *nalLength;
    ++nalCount;
  }

  if (summary.IsEmpty()) {
    summary = "none"_ns;
  }
  return summary;
}

static bool WriteAvccNalLength(nsTArray<uint8_t>& aOutput, uint32_t aNalLength,
                               size_t aNalLengthSize) {
  if (aNalLengthSize == 0 || aNalLengthSize > 4) {
    return false;
  }

  uint8_t lengthBytes[4];
  for (size_t i = 0; i < aNalLengthSize; ++i) {
    lengthBytes[aNalLengthSize - 1 - i] = aNalLength & 0xff;
    aNalLength >>= 8;
  }
  aOutput.AppendElements(lengthBytes, aNalLengthSize);
  return true;
}

static bool StripAvccParameterSetNals(MediaRawData* aSample,
                                      nsCString& aRemovedNals) {
  if (!aSample || !aSample->Data()) {
    return false;
  }

  auto avcc = AVCCConfig::Parse(aSample);
  if (avcc.isErr()) {
    return false;
  }

  const uint8_t nalLengthSize = avcc.unwrap().NALUSize();
  const uint8_t* data = aSample->Data();
  size_t offset = 0;
  nsTArray<uint8_t> filtered;
  while (offset + nalLengthSize <= aSample->Size()) {
    Maybe<uint32_t> nalLength = ReadAvccNalLength(
        data + offset, aSample->Size() - offset, nalLengthSize);
    if (!nalLength || *nalLength == 0) {
      break;
    }
    offset += nalLengthSize;
    if (offset + *nalLength > aSample->Size()) {
      return false;
    }

    uint8_t nalType = data[offset] & 0x1f;
    bool stripNal = nalType == H264_NAL_AUD || nalType == H264_NAL_SPS ||
                    nalType == H264_NAL_PPS;
    if (stripNal) {
      aRemovedNals.AppendPrintf("%s%u:%u", aRemovedNals.IsEmpty() ? "" : ",",
                                nalType, *nalLength);
    } else {
      if (!WriteAvccNalLength(filtered, *nalLength, nalLengthSize)) {
        return false;
      }
      filtered.AppendElements(data + offset, *nalLength);
    }
    offset += *nalLength;
  }

  if (filtered.IsEmpty() || aRemovedNals.IsEmpty()) {
    return true;
  }

  UniquePtr<MediaRawDataWriter> writer(aSample->CreateWriter());
  return writer->Replace(filtered.Elements(), filtered.Length());
}

static nsresult EncodeVideoFrameAsPngDataUrl(layers::Image* aImage,
                                             nsCString& aDataUrl) {
  if (!aImage) {
    return NS_ERROR_INVALID_ARG;
  }

  RefPtr<gfx::SourceSurface> surface = GetSourceSurface(aImage);
  if (!surface) {
    return NS_ERROR_FAILURE;
  }

  RefPtr<gfx::DataSourceSurface> dataSurface;
  if (surface->GetFormat() == gfx::SurfaceFormat::B8G8R8A8 ||
      surface->GetFormat() == gfx::SurfaceFormat::B8G8R8X8) {
    dataSurface = surface->GetDataSurface();
  } else {
    dataSurface = gfxUtils::CopySurfaceToDataSourceSurfaceWithFormat(
        surface, gfx::SurfaceFormat::B8G8R8A8);
  }

  if (!dataSurface) {
    return NS_ERROR_FAILURE;
  }

  gfx::DataSourceSurface::ScopedMap map(dataSurface,
                                        gfx::DataSourceSurface::READ);
  if (!map.IsMapped() || map.GetStride() <= 0) {
    return NS_ERROR_FAILURE;
  }

  const gfx::IntSize size = dataSurface->GetSize();
  CheckedInt<uint32_t> dataLength =
      CheckedInt<uint32_t>(map.GetStride()) * CheckedInt<uint32_t>(size.height);
  if (!dataLength.isValid()) {
    return NS_ERROR_OUT_OF_MEMORY;
  }

  nsCOMPtr<imgIEncoder> encoder =
      do_CreateInstance("@mozilla.org/image/encoder;2?type=image/png");
  if (!encoder) {
    return NS_ERROR_FAILURE;
  }

  nsresult rv = encoder->InitFromData(map.GetData(), dataLength.value(),
                                      size.width, size.height, map.GetStride(),
                                      imgIEncoder::INPUT_FORMAT_HOSTARGB,
                                      u""_ns, VoidCString());
  if (NS_FAILED(rv)) {
    return rv;
  }

  uint32_t pngLength = 0;
  rv = encoder->GetImageBufferUsed(&pngLength);
  if (NS_FAILED(rv) || pngLength == 0) {
    return NS_FAILED(rv) ? rv : NS_ERROR_FAILURE;
  }

  char* pngData = nullptr;
  rv = encoder->GetImageBuffer(&pngData);
  if (NS_FAILED(rv) || !pngData) {
    return NS_FAILED(rv) ? rv : NS_ERROR_FAILURE;
  }

  nsCString encoded;
  rv = mozilla::Base64Encode(pngData, pngLength, encoded);
  if (NS_FAILED(rv)) {
    return rv;
  }

  aDataUrl.AssignLiteral("data:image/png;base64,");
  aDataUrl.Append(encoded);
  return NS_OK;
}

static void NotifyMcquicMoqVideoFrame(nsCString aPayload) {
  if (!NS_IsMainThread()) {
    NS_DispatchToMainThread(NS_NewRunnableFunction(
        "NotifyMcquicMoqVideoFrame", [payload = std::move(aPayload)]() mutable {
          NotifyMcquicMoqVideoFrame(std::move(payload));
        }));
    return;
  }

  nsCOMPtr<nsIObserverService> obs = services::GetObserverService();
  if (!obs) {
    return;
  }

  nsCOMPtr<nsISupportsCString> subject = new nsSupportsCString();
  subject->SetData(aPayload);
  obs->NotifyObservers(subject, MCQUIC_MOQ_VIDEO_FRAME_TOPIC, nullptr);
}

static void MaybeNotifyOverlayFrame(const McquicMoqAccessUnit& aAccessUnit,
                                    uint64_t aDecodedFrames,
                                    VideoData* aVideo) {
  if (!StaticPrefs::network_http_http3_mcquic_native_moq_demo_enabled()) {
    return;
  }

  nsCString dataUrl;
  nsresult rv = EncodeVideoFrameAsPngDataUrl(aVideo->mImage, dataUrl);
  if (NS_FAILED(rv)) {
    LOG((
        "MCQUIC MoQ media overlay failed to encode video frame [rv=0x%08" PRIx32
        " track=%s/%s sequence=%" PRIu64 " decoded_frames=%" PRIu64 "]",
        static_cast<uint32_t>(rv), aAccessUnit.mNamespace.get(),
        aAccessUnit.mTrackName.get(), aAccessUnit.mAccessUnitSequence,
        aDecodedFrames));
    return;
  }

  nsCString payload;
  payload.AppendLiteral("{\"width\":");
  payload.AppendInt(aVideo->mDisplay.width);
  payload.AppendLiteral(",\"height\":");
  payload.AppendInt(aVideo->mDisplay.height);
  payload.AppendLiteral(",\"sequence\":");
  payload.AppendInt(aAccessUnit.mAccessUnitSequence);
  payload.AppendLiteral(",\"ptsMs\":");
  payload.AppendInt(aAccessUnit.mPtsMillis);
  payload.AppendLiteral(",\"decodedFrames\":");
  payload.AppendInt(aDecodedFrames);
  payload.AppendLiteral(",\"dataUrl\":\"");
  payload.Append(dataUrl);
  payload.AppendLiteral("\"}");

  LOG(
      ("MCQUIC MoQ media overlay publishing video frame [track=%s/%s "
       "sequence=%" PRIu64 " decoded_frames=%" PRIu64 " display=%dx%d "
       "data_url_len=%zu]",
       aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
       aAccessUnit.mAccessUnitSequence, aDecodedFrames, aVideo->mDisplay.width,
       aVideo->mDisplay.height, dataUrl.Length()));
  NotifyMcquicMoqVideoFrame(std::move(payload));
}

static bool PayloadStartsWith(const nsTArray<uint8_t>& aPayload,
                              const char (&aMagic)[5]) {
  return aPayload.Length() >= 4 &&
         std::memcmp(aPayload.Elements(), aMagic, 4) == 0;
}

static bool PayloadLooksLikeLocH264AnnexBFragment(
    const nsTArray<uint8_t>& aPayload) {
  return aPayload.Length() >= LOC_H264_ANNEXB_FRAGMENT_HEADER_LEN &&
         aPayload[0] == LOC_H264_ANNEXB_FRAGMENT_VERSION &&
         aPayload[1] == LOC_H264_ANNEXB_FRAGMENT_HEADER_BYTE;
}

static bool PayloadLooksLikeCompactLocMsfH264Fragment(
    const nsTArray<uint8_t>& aPayload) {
  if (aPayload.Length() < COMPACT_LOC_MSF_H264_FRAGMENT_HEADER_LEN) {
    return false;
  }

  const uint8_t* data = aPayload.Elements();
  uint32_t payloadLen = ReadBigEndianUint32(&data[11]);
  return aPayload.Length() ==
         COMPACT_LOC_MSF_H264_FRAGMENT_HEADER_LEN + payloadLen;
}

static bool IsLocMsfTrackName(const nsACString& aTrackName) {
  nsCString trackName(aTrackName);
  return trackName.Find("-loc") >= 0 || trackName.Find("-msf") >= 0;
}

static nsresult ParseQvf1Payload(const nsTArray<uint8_t>& aPayload,
                                 McquicMoqMediaFragmentMetadata& aMetadata) {
  if (aPayload.Length() < QVF1_FIXED_HEADER_LEN) {
    return NS_ERROR_INVALID_ARG;
  }

  const uint8_t* data = aPayload.Elements();
  if (std::memcmp(data, "QVF1", 4) != 0 || data[4] != QVF1_VERSION ||
      data[5] != QVF1_CODEC_H264) {
    return NS_ERROR_INVALID_ARG;
  }

  aMetadata.mFormat = McquicMoqMediaPayloadFormat::Qvf1;
  aMetadata.mFlags = data[6];
  aMetadata.mAccessUnitSequence = ReadBigEndianUint64(&data[8]);
  aMetadata.mFragmentIndex = ReadBigEndianUint16(&data[16]);
  aMetadata.mFragmentCount = ReadBigEndianUint16(&data[18]);
  aMetadata.mPtsMillis = ReadBigEndianUint64(&data[20]);
  aMetadata.mPayloadOffset = QVF1_FIXED_HEADER_LEN;
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

static nsresult ParseLocMsfPayload(const nsTArray<uint8_t>& aPayload,
                                   McquicMoqMediaFragmentMetadata& aMetadata) {
  if (aPayload.Length() < LOC_MSF_FIXED_HEADER_LEN) {
    return NS_ERROR_INVALID_ARG;
  }

  const uint8_t* data = aPayload.Elements();
  if ((std::memcmp(data, "MSF1", 4) != 0 &&
       std::memcmp(data, "LOC1", 4) != 0) ||
      data[4] != QVF1_VERSION || data[5] != QVF1_CODEC_H264) {
    return NS_ERROR_INVALID_ARG;
  }

  aMetadata.mFormat = McquicMoqMediaPayloadFormat::LocMsf;
  aMetadata.mFlags = data[6];
  aMetadata.mAccessUnitSequence = ReadBigEndianUint64(&data[8]);
  aMetadata.mFragmentIndex = 0;
  aMetadata.mFragmentCount = 1;
  aMetadata.mPtsMillis = ReadBigEndianUint64(&data[16]);
  aMetadata.mPayloadOffset = LOC_MSF_FIXED_HEADER_LEN;
  aMetadata.mPayloadLen = ReadBigEndianUint32(&data[24]);

  if (aPayload.Length() != LOC_MSF_FIXED_HEADER_LEN + aMetadata.mPayloadLen) {
    return NS_ERROR_INVALID_ARG;
  }

  return NS_OK;
}

static nsresult ParseLocH264AnnexBFragmentPayload(
    const nsTArray<uint8_t>& aPayload,
    McquicMoqMediaFragmentMetadata& aMetadata) {
  if (!PayloadLooksLikeLocH264AnnexBFragment(aPayload)) {
    return NS_ERROR_INVALID_ARG;
  }

  const uint8_t* data = aPayload.Elements();
  uint16_t locFlags = ReadBigEndianUint16(&data[2]);
  uint64_t ptsMillis = ReadBigEndianUint64(&data[4]);
  uint16_t fragmentIndex = ReadBigEndianUint16(&data[12]);
  uint16_t fragmentCount = ReadBigEndianUint16(&data[14]);
  uint32_t payloadLen = ReadBigEndianUint32(&data[16]);

  if (fragmentCount == 0 || fragmentCount > QVF1_MAX_FRAGMENTS ||
      fragmentIndex >= fragmentCount) {
    return NS_ERROR_INVALID_ARG;
  }
  if (aPayload.Length() != LOC_H264_ANNEXB_FRAGMENT_HEADER_LEN + payloadLen) {
    return NS_ERROR_INVALID_ARG;
  }

  aMetadata.mFormat = McquicMoqMediaPayloadFormat::LocMsf;
  aMetadata.mFlags = 0;
  if (locFlags & LOC_H264_FLAG_KEYFRAME) {
    aMetadata.mFlags |= QVF1_FLAG_KEYFRAME;
  }
  if (locFlags & LOC_H264_FLAG_CONFIG) {
    aMetadata.mFlags |= QVF1_FLAG_CONFIG;
  }
  if ((locFlags & LOC_H264_FLAG_END_OF_ACCESS_UNIT) ||
      fragmentIndex + 1 == fragmentCount) {
    aMetadata.mFlags |= QVF1_FLAG_END_OF_ACCESS_UNIT;
  }
  if (locFlags & (LOC_H264_FLAG_KEYFRAME | LOC_H264_FLAG_CONFIG)) {
    aMetadata.mFlags |= MCQUIC_MEDIA_FLAG_INDEPENDENT;
  }
  aMetadata.mAccessUnitSequence = ptsMillis;
  aMetadata.mFragmentIndex = fragmentIndex;
  aMetadata.mFragmentCount = fragmentCount;
  aMetadata.mPtsMillis = ptsMillis;
  aMetadata.mPayloadOffset = LOC_H264_ANNEXB_FRAGMENT_HEADER_LEN;
  aMetadata.mPayloadLen = payloadLen;
  return NS_OK;
}

static nsresult ParseCompactLocMsfH264FragmentPayload(
    const nsTArray<uint8_t>& aPayload, bool aEndOfGroup,
    McquicMoqMediaFragmentMetadata& aMetadata) {
  if (!PayloadLooksLikeCompactLocMsfH264Fragment(aPayload)) {
    return NS_ERROR_INVALID_ARG;
  }

  const uint8_t* data = aPayload.Elements();
  uint64_t accessUnitSequence = ReadBigEndianUint64(&data[0]);
  uint32_t payloadLen = ReadBigEndianUint32(&data[11]);

  aMetadata.mFormat = McquicMoqMediaPayloadFormat::LocMsf;
  aMetadata.mFlags = 0;
  AnnexBNalSummary summary = SummarizeAnnexBNals(aPayload);
  if (summary.mContainsIdr) {
    aMetadata.mFlags |= QVF1_FLAG_KEYFRAME;
  }
  if (summary.mContainsSps || summary.mContainsPps) {
    aMetadata.mFlags |= QVF1_FLAG_CONFIG;
  }
  if (summary.mContainsIdr || summary.mContainsSps || summary.mContainsPps) {
    aMetadata.mFlags |= MCQUIC_MEDIA_FLAG_INDEPENDENT;
  }
  if (aEndOfGroup) {
    aMetadata.mFlags |= QVF1_FLAG_END_OF_ACCESS_UNIT;
  }
  aMetadata.mAccessUnitSequence = accessUnitSequence;
  aMetadata.mFragmentIndex = 0;
  aMetadata.mFragmentCount = 1;
  aMetadata.mPtsMillis = 0;
  aMetadata.mPayloadOffset = COMPACT_LOC_MSF_H264_FRAGMENT_HEADER_LEN;
  aMetadata.mPayloadLen = payloadLen;
  aMetadata.mOpenEnded = !aEndOfGroup;
  return NS_OK;
}

static nsresult PopulateDirectLocMsfMetadata(
    const McquicMoqDatagramExternal& aObject,
    McquicMoqMediaFragmentMetadata& aMetadata) {
  if (aObject.payload.Length() > std::numeric_limits<uint32_t>::max()) {
    return NS_ERROR_INVALID_ARG;
  }

  aMetadata.mFormat = McquicMoqMediaPayloadFormat::LocMsf;
  aMetadata.mFlags = 0;
  if (aObject.keyframe) {
    aMetadata.mFlags |= QVF1_FLAG_KEYFRAME;
  }
  if (aObject.config) {
    aMetadata.mFlags |= QVF1_FLAG_CONFIG;
  }
  if (aObject.independent) {
    aMetadata.mFlags |= MCQUIC_MEDIA_FLAG_INDEPENDENT;
  }
  aMetadata.mAccessUnitSequence = aObject.publisher_sequence;
  aMetadata.mFragmentIndex = 0;
  aMetadata.mFragmentCount = 1;
  aMetadata.mPtsMillis = aObject.pts_millis;
  aMetadata.mPayloadOffset = 0;
  aMetadata.mPayloadLen = static_cast<uint32_t>(aObject.payload.Length());
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

class McquicMoqPdmAccessUnitConsumer final
    : public McquicMoqAccessUnitConsumer {
 public:
  McquicMoqPdmAccessUnitConsumer()
      : mThreadPool(GetMediaThreadPool(MediaThreadType::SUPERVISOR)),
        mTaskQueue(TaskQueue::Create(do_AddRef(mThreadPool),
                                     "McquicMoqPdmAccessUnitConsumer")),
        mImageContainer(MakeAndAddRef<layers::ImageContainer>(
            layers::ImageUsageType::Webrtc,
            layers::ImageContainer::ASYNCHRONOUS)),
        mFactory(new PDMFactory()),
        mInfo(QVF1_DECODE_SIZE) {
    mInfo.mMimeType = "video/avc"_ns;
  }

  ~McquicMoqPdmAccessUnitConsumer() override { ReleaseDecoder(); }

  nsresult OnMcquicMoqAccessUnit(
      const McquicMoqAccessUnit& aAccessUnit) override {
    if (mNeedKeyframe && !aAccessUnit.mKeyframe) {
      LOG(
          ("MCQUIC MoQ media decode waiting for key access unit [track=%s/%s "
           "sequence=%" PRIu64 "]",
           aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
           aAccessUnit.mAccessUnitSequence));
      return NS_OK;
    }

    Maybe<size_t> annexBStartCode =
        FindAnnexBStartCode(aAccessUnit.mPayload, 0);
    size_t payloadOffset = annexBStartCode.valueOr(0);
    RefPtr compressedFrame = MakeRefPtr<MediaRawData>(
        aAccessUnit.mPayload.Elements() + payloadOffset,
        aAccessUnit.mPayload.Length() - payloadOffset);
    if (!compressedFrame->Data()) {
      return NS_ERROR_OUT_OF_MEMORY;
    }

    compressedFrame->mTime = TimeUnitFromMillis(aAccessUnit.mPtsMillis);
    compressedFrame->mTimecode = compressedFrame->mTime;
    compressedFrame->mDuration = TimeUnitFromMillis(33);
    compressedFrame->mKeyframe = aAccessUnit.mKeyframe;

    Span<const uint8_t> frameSpan(compressedFrame->Data(),
                                  compressedFrame->Size());
    if (annexBStartCode) {
      if (payloadOffset > 0) {
        LOG(
            ("MCQUIC MoQ media decode trimmed H.264 prefix before Annex B "
             "[track=%s/%s sequence=%" PRIu64 " offset=%zu payload_len=%zu]",
             aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
             aAccessUnit.mAccessUnitSequence, payloadOffset,
             aAccessUnit.mPayload.Length()));
      }

      if (aAccessUnit.mConfig || aAccessUnit.mKeyframe || !mInfo.mExtraData) {
        RefPtr<MediaByteBuffer> avccExtraData =
            AnnexB::ExtractExtraDataForAVCC(frameSpan);
        if (avccExtraData &&
            !MediaByteBuffersEqual(mInfo.mExtraData, avccExtraData)) {
          mInfo.mExtraData = avccExtraData;
          UpdateVideoInfoFromExtraData(aAccessUnit);
          if (mDecoder) {
            ReleaseDecoder();
          }
          LOG(
              ("MCQUIC MoQ media decode updated H.264 avcC extradata "
               "[track=%s/%s sequence=%" PRIu64 " bytes=%zu]",
               aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
               aAccessUnit.mAccessUnitSequence, mInfo.mExtraData->Length()));
        }
      }

      if (!mInfo.mExtraData || !H264::HasSPS(mInfo.mExtraData)) {
        LOG(
            ("MCQUIC MoQ media decode waiting for H.264 avcC extradata "
             "[track=%s/%s sequence=%" PRIu64 " keyframe=%d config=%d]",
             aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
             aAccessUnit.mAccessUnitSequence, aAccessUnit.mKeyframe,
             aAccessUnit.mConfig));
        return NS_OK;
      }

      if (!AnnexB::ConvertSampleToAVCC(compressedFrame, mInfo.mExtraData)) {
        LOG(
            ("MCQUIC MoQ media decode failed to convert Annex B to AVCC "
             "[track=%s/%s sequence=%" PRIu64 " payload_len=%zu]",
             aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
             aAccessUnit.mAccessUnitSequence, aAccessUnit.mPayload.Length()));
        ReleaseDecoder();
        return NS_OK;
      }
      nsCString strippedNals;
      if (!StripAvccParameterSetNals(compressedFrame, strippedNals)) {
        LOG(
            ("MCQUIC MoQ media decode failed to strip AVCC parameter sets "
             "[track=%s/%s sequence=%" PRIu64 " payload_len=%zu nals=%s]",
             aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
             aAccessUnit.mAccessUnitSequence, compressedFrame->Size(),
             SummarizeAvccNals(compressedFrame).get()));
        ReleaseDecoder();
        return NS_OK;
      }
      if (!strippedNals.IsEmpty()) {
        LOG((
            "MCQUIC MoQ media decode stripped AVCC parameter sets [track=%s/%s "
            "sequence=%" PRIu64 " removed=%s payload_len=%zu]",
            aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
            aAccessUnit.mAccessUnitSequence, strippedNals.get(),
            compressedFrame->Size()));
      }
      LOG(
          ("MCQUIC MoQ media decode converted Annex B to AVCC [track=%s/%s "
           "sequence=%" PRIu64 " payload_len=%zu avcc_len=%zu frame_type=%s "
           "nals=%s]",
           aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
           aAccessUnit.mAccessUnitSequence, compressedFrame->Size(),
           mInfo.mExtraData->Length(),
           H264FrameTypeName(H264::GetFrameType(compressedFrame)),
           SummarizeAvccNals(compressedFrame).get()));
    }

    if (!mDecoder) {
      nsresult rv = CreateDecoder();
      if (NS_FAILED(rv)) {
        LOG(
            ("MCQUIC MoQ media decode failed to create decoder "
             "[rv=0x%08" PRIx32 " track=%s/%s sequence=%" PRIu64 "]",
             static_cast<uint32_t>(rv), aAccessUnit.mNamespace.get(),
             aAccessUnit.mTrackName.get(), aAccessUnit.mAccessUnitSequence));
        return rv;
      }
    }

    LOG(
        ("MCQUIC MoQ media decode accepted access unit [track=%s/%s "
         "sequence=%" PRIu64 " pts_ms=%" PRIu64 " payload_len=%zu "
         "keyframe=%d config=%d independent=%d]",
         aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
         aAccessUnit.mAccessUnitSequence, aAccessUnit.mPtsMillis,
         aAccessUnit.mPayload.Length(), aAccessUnit.mKeyframe,
         aAccessUnit.mConfig, aAccessUnit.mIndependent));

    media::Await(
        do_AddRef(mThreadPool), mDecoder->Decode(compressedFrame),
        [&](const MediaDataDecoder::DecodedData& aResults) {
          mResults = aResults.Clone();
          mError = NS_OK;
        },
        [&](const MediaResult& aError) { mError = aError; });

    if (NS_FAILED(mError)) {
      LOG(("MCQUIC MoQ media decode failed [rv=0x%08" PRIx32
           " error=%s detail=%s track=%s/%s sequence=%" PRIu64 "]",
           static_cast<uint32_t>(mError.Code()), mError.ErrorName().get(),
           mError.Description().get(), aAccessUnit.mNamespace.get(),
           aAccessUnit.mTrackName.get(), aAccessUnit.mAccessUnitSequence));
      ReleaseDecoder();
      return NS_OK;
    }

    mNeedKeyframe = false;
    for (const auto& frame : mResults) {
      if (frame->mType != MediaData::Type::VIDEO_DATA) {
        continue;
      }
      RefPtr<VideoData> video = frame->As<VideoData>();
      if (!video) {
        continue;
      }
      ++mDecodedFrames;
      LOG(("MCQUIC MoQ media frame decoded [track=%s/%s sequence=%" PRIu64
           " pts_ms=%" PRIu64 " decoded_frames=%" PRIu64
           " display=%dx%d image=%p]",
           aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
           aAccessUnit.mAccessUnitSequence, aAccessUnit.mPtsMillis,
           mDecodedFrames, video->mDisplay.width, video->mDisplay.height,
           video->mImage.get()));
      MaybeNotifyOverlayFrame(aAccessUnit, mDecodedFrames, video);
    }
    mResults.Clear();

    return NS_OK;
  }

 private:
  static CreateDecoderParams::OptionSet DecoderOptions() {
    return CreateDecoderParams::OptionSet(
        CreateDecoderParams::Option::LowLatency,
        CreateDecoderParams::Option::FullH264Parsing,
        CreateDecoderParams::Option::ErrorIfNoInitializationData,
        CreateDecoderParams::Option::KeepOriginalPts);
  }

  nsresult CreateDecoder() {
    if (!mInfo.mExtraData || !H264::HasSPS(mInfo.mExtraData)) {
      return NS_ERROR_DOM_MEDIA_FATAL_ERR;
    }

    RefPtr<layers::KnowsCompositor> knowsCompositor =
        layers::ImageBridgeChild::GetSingleton();

    RefPtr<TaskQueue> decodeTaskQueue =
        TaskQueue::Create(GetMediaThreadPool(MediaThreadType::PLATFORM_DECODER),
                          "mcquic moq decode TaskQueue");
    RefPtr<MediaDataDecoder> decoder;
    auto options = DecoderOptions();

    media::Await(
        do_AddRef(mThreadPool), InvokeAsync(decodeTaskQueue, __func__, [&] {
          RefPtr<GenericPromise> promise =
              mFactory
                  ->CreateDecoder({mInfo, options, TrackInfo::kVideoTrack,
                                   mImageContainer, knowsCompositor})
                  ->Then(
                      decodeTaskQueue, __func__,
                      [&](RefPtr<MediaDataDecoder>&& aDecoder) {
                        decoder = std::move(aDecoder);
                        return GenericPromise::CreateAndResolve(true, __func__);
                      },
                      [](const MediaResult&) {
                        return GenericPromise::CreateAndReject(
                            NS_ERROR_DOM_MEDIA_FATAL_ERR, __func__);
                      });
          return promise;
        }));

    if (!decoder) {
      return NS_ERROR_DOM_MEDIA_FATAL_ERR;
    }

    mDecoder =
        new MediaDataDecoderProxy(decoder.forget(), decodeTaskQueue.forget());

    media::Await(
        do_AddRef(mThreadPool), mDecoder->Init(),
        [&](TrackInfo::TrackType) { mError = NS_OK; },
        [&](const MediaResult& aError) { mError = aError; });

    if (NS_FAILED(mError)) {
      mDecoder = nullptr;
      return mError.Code();
    }

    LOG(
        ("MCQUIC MoQ media decode created H.264 decoder [image=%dx%d "
         "display=%dx%d] ",
         mInfo.mImage.width, mInfo.mImage.height, mInfo.mDisplay.width,
         mInfo.mDisplay.height));
    return NS_OK;
  }

  void UpdateVideoInfoFromExtraData(const McquicMoqAccessUnit& aAccessUnit) {
    SPSData spsdata;
    if (!H264::DecodeSPSFromExtraData(mInfo.mExtraData, spsdata) ||
        spsdata.pic_width == 0 || spsdata.pic_height == 0) {
      LOG(
          ("MCQUIC MoQ media decode failed to parse H.264 SPS [track=%s/%s "
           "sequence=%" PRIu64 " avcc_len=%zu]",
           aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
           aAccessUnit.mAccessUnitSequence,
           mInfo.mExtraData ? mInfo.mExtraData->Length() : 0));
      return;
    }

    H264::EnsureSPSIsSane(spsdata);
    mInfo.mImage.width = spsdata.pic_width;
    mInfo.mImage.height = spsdata.pic_height;
    mInfo.mDisplay.width = spsdata.display_width;
    mInfo.mDisplay.height = spsdata.display_height;
    mInfo.mColorDepth = spsdata.ColorDepth();
    mInfo.mColorSpace = Some(spsdata.ColorSpace());
    mInfo.mColorPrimaries = gfxUtils::CicpToColorPrimaries(
        static_cast<gfx::CICP::ColourPrimaries>(spsdata.colour_primaries),
        gHttpLog);
    mInfo.mTransferFunction = gfxUtils::CicpToTransferFunction(
        static_cast<gfx::CICP::TransferCharacteristics>(
            spsdata.transfer_characteristics));
    mInfo.mColorRange = spsdata.video_full_range_flag
                            ? gfx::ColorRange::FULL
                            : gfx::ColorRange::LIMITED;

    LOG(
        ("MCQUIC MoQ media decode parsed H.264 SPS [track=%s/%s "
         "sequence=%" PRIu64
         " image=%ux%u display=%ux%u profile=%u level=%u chroma=%u refs=%u]",
         aAccessUnit.mNamespace.get(), aAccessUnit.mTrackName.get(),
         aAccessUnit.mAccessUnitSequence, spsdata.pic_width, spsdata.pic_height,
         spsdata.display_width, spsdata.display_height, spsdata.profile_idc,
         spsdata.level_idc, spsdata.chroma_format_idc,
         spsdata.max_num_ref_frames));
  }

  void ReleaseDecoder() {
    if (mDecoder) {
      RefPtr<MediaDataDecoder> decoder = std::move(mDecoder);
      decoder->Flush()->Then(mTaskQueue, __func__,
                             [decoder]() { decoder->Shutdown(); });
    }
    mResults.Clear();
    mNeedKeyframe = true;
    mError = NS_OK;
  }

  const RefPtr<SharedThreadPool> mThreadPool;
  const RefPtr<TaskQueue> mTaskQueue;
  const RefPtr<layers::ImageContainer> mImageContainer;
  const RefPtr<PDMFactory> mFactory;
  RefPtr<MediaDataDecoder> mDecoder;
  VideoInfo mInfo;
  bool mNeedKeyframe = true;
  MediaResult mError = NS_OK;
  MediaDataDecoder::DecodedData mResults;
  uint64_t mDecodedFrames = 0;
};

}  // namespace

bool McquicMoqAccessUnitConsumer::Enabled() {
  return McquicMoqMediaSink::Enabled();
}

UniquePtr<McquicMoqAccessUnitConsumer> CreateMcquicMoqAccessUnitConsumer() {
  if (!McquicMoqAccessUnitConsumer::Enabled()) {
    return nullptr;
  }
  return MakeUnique<McquicMoqPdmAccessUnitConsumer>();
}

bool McquicMoqMediaSink::Enabled() {
  return StaticPrefs::network_http_http3_mcquic_native_moq_demo_enabled();
}

nsresult McquicMoqMediaSink::ProcessObject(
    const nsACString& aNamespace, const nsACString& aTrackName,
    const nsTArray<uint8_t>& aChannelId, uint64_t aPacketNumber,
    const McquicMoqDatagramExternal& aObject,
    McquicMoqMediaSinkProcessResult* aResult) {
  if (aResult) {
    *aResult = {};
  }

  if (aObject.status != McquicMoqObjectStatus::Normal) {
    LOG(
        ("MCQUIC MoQ media sink ignored non-media status object "
         "[track=%s/%s group=%" PRIu64 " object=%" PRIu64 " status=%s]",
         PromiseFlatCString(aNamespace).get(),
         PromiseFlatCString(aTrackName).get(), aObject.group_id,
         aObject.object_id, McquicMoqMediaObjectStatusName(aObject.status)));
    return NS_OK;
  }

  if (aObject.payload.IsEmpty()) {
    LOG(
        ("MCQUIC MoQ media sink ignored empty media object "
         "[track=%s/%s group=%" PRIu64 " object=%" PRIu64 "]",
         PromiseFlatCString(aNamespace).get(),
         PromiseFlatCString(aTrackName).get(), aObject.group_id,
         aObject.object_id));
    return NS_OK;
  }

  McquicMoqMediaFragmentMetadata metadata;
  nsresult rv = NS_OK;
  bool locMsfTrack = IsLocMsfTrackName(aTrackName);
  nsCString trackKey;
  if (locMsfTrack) {
    trackKey = TrackKey(aNamespace, aTrackName);
  }
  bool continuationOfOpenEndedAccessUnit = false;
  if (PayloadStartsWith(aObject.payload, "QVF1") ||
      StringEndsWith(aTrackName, "h264-qvf1"_ns)) {
    rv = ParseQvf1Payload(aObject.payload, metadata);
  } else if (PayloadStartsWith(aObject.payload, "MSF1") ||
             PayloadStartsWith(aObject.payload, "LOC1")) {
    rv = ParseLocMsfPayload(aObject.payload, metadata);
  } else if (locMsfTrack &&
             PayloadLooksLikeLocH264AnnexBFragment(aObject.payload)) {
    rv = ParseLocH264AnnexBFragmentPayload(aObject.payload, metadata);
  } else if (locMsfTrack &&
             PayloadLooksLikeCompactLocMsfH264Fragment(aObject.payload)) {
    rv = ParseCompactLocMsfH264FragmentPayload(
        aObject.payload, aObject.end_of_group, metadata);
    if (NS_SUCCEEDED(rv)) {
      auto open = mOpenEndedAccessUnitsByTrack.Lookup(trackKey);
      if (open &&
          open.Data().mAccessUnitSequence == metadata.mAccessUnitSequence) {
        if (open.Data().mNextFragmentIndex >= QVF1_MAX_FRAGMENTS) {
          rv = NS_ERROR_INVALID_ARG;
        } else {
          metadata.mFragmentIndex = open.Data().mNextFragmentIndex;
          metadata.mFragmentCount = open.Data().mNextFragmentIndex + 1;
          metadata.mOpenEnded = !aObject.end_of_group;
          continuationOfOpenEndedAccessUnit = true;
        }
      }
    }
  } else if (locMsfTrack) {
    auto open = mOpenEndedAccessUnitsByTrack.Lookup(trackKey);
    if (!open) {
      rv = PopulateDirectLocMsfMetadata(aObject, metadata);
      if (NS_SUCCEEDED(rv)) {
        metadata.mOpenEnded = !aObject.end_of_group;
        if (aObject.end_of_group) {
          metadata.mFlags |= QVF1_FLAG_END_OF_ACCESS_UNIT;
        }
      }
    } else {
      const OpenEndedAccessUnit& openAccessUnit = open.Data();
      if (openAccessUnit.mNextFragmentIndex >= QVF1_MAX_FRAGMENTS) {
        rv = NS_ERROR_INVALID_ARG;
      } else if (aObject.payload.Length() >
                 std::numeric_limits<uint32_t>::max()) {
        rv = NS_ERROR_INVALID_ARG;
      } else {
        metadata.mFormat = McquicMoqMediaPayloadFormat::LocMsf;
        metadata.mAccessUnitSequence = openAccessUnit.mAccessUnitSequence;
        metadata.mFragmentIndex = openAccessUnit.mNextFragmentIndex;
        metadata.mFragmentCount = openAccessUnit.mNextFragmentIndex + 1;
        metadata.mPayloadOffset = 0;
        metadata.mPayloadLen = static_cast<uint32_t>(aObject.payload.Length());
        metadata.mOpenEnded = !aObject.end_of_group;
        continuationOfOpenEndedAccessUnit = true;
        if (aObject.end_of_group) {
          metadata.mFlags |= QVF1_FLAG_END_OF_ACCESS_UNIT;
        }
        AnnexBNalSummary summary = SummarizeAnnexBNals(aObject.payload);
        if (summary.mContainsIdr) {
          metadata.mFlags |= QVF1_FLAG_KEYFRAME;
        }
        if (summary.mContainsSps || summary.mContainsPps) {
          metadata.mFlags |= QVF1_FLAG_CONFIG;
        }
        if (summary.mContainsIdr || summary.mContainsSps ||
            summary.mContainsPps) {
          metadata.mFlags |= MCQUIC_MEDIA_FLAG_INDEPENDENT;
        }
      }
    }
  } else {
    return NS_OK;
  }

  if (NS_FAILED(rv)) {
    LOG(
        ("MCQUIC MoQ media sink rejected malformed media payload "
         "[track=%s/%s group=%" PRIu64 " object=%" PRIu64 " payload_len=%zu]",
         PromiseFlatCString(aNamespace).get(),
         PromiseFlatCString(aTrackName).get(), aObject.group_id,
         aObject.object_id, aObject.payload.Length()));
    return rv;
  }

  if (metadata.mFormat == McquicMoqMediaPayloadFormat::LocMsf &&
      metadata.mAccessUnitSequence == 0) {
    metadata.mAccessUnitSequence = aObject.publisher_sequence != 0
                                       ? aObject.publisher_sequence
                                       : aObject.group_id;
  }
  if (metadata.mFormat == McquicMoqMediaPayloadFormat::LocMsf &&
      metadata.mPtsMillis == 0 && aObject.pts_millis != 0) {
    metadata.mPtsMillis = aObject.pts_millis;
  }

  nsCString objectKey =
      ObjectKey(aNamespace, aTrackName, aObject.group_id, aObject.object_id);
  if (mAcceptedObjects.Contains(objectKey)) {
    if (aResult) {
      aResult->mDuplicateObject = true;
    }
    LOG(
        ("MCQUIC MoQ media sink deduplicated object [track=%s/%s "
         "group=%" PRIu64 " object=%" PRIu64 " payload_len=%zu]",
         PromiseFlatCString(aNamespace).get(),
         PromiseFlatCString(aTrackName).get(), aObject.group_id,
         aObject.object_id, aObject.payload.Length()));
    return NS_OK;
  }

  bool startsOpenEndedAccessUnit =
      metadata.mOpenEnded && metadata.mFragmentIndex == 0;
  if (startsOpenEndedAccessUnit) {
    if (auto oldOpen = mOpenEndedAccessUnitsByTrack.Lookup(trackKey)) {
      nsCString oldKey = AccessUnitKey(aNamespace, aTrackName,
                                       oldOpen.Data().mAccessUnitSequence);
      mPendingAccessUnits.Remove(oldKey);
    }
    mOpenEndedAccessUnitsByTrack.InsertOrUpdate(
        trackKey, OpenEndedAccessUnit{metadata.mAccessUnitSequence, 1});
  }

  LOG(
      ("MCQUIC MoQ media payload accepted [format=%s track=%s/%s "
       "sequence=%" PRIu64 " fragment=%u/%u pts_ms=%" PRIu64 " payload_len=%u]",
       McquicMoqMediaPayloadFormatName(metadata.mFormat),
       PromiseFlatCString(aNamespace).get(),
       PromiseFlatCString(aTrackName).get(), metadata.mAccessUnitSequence,
       metadata.mFragmentIndex + 1, metadata.mFragmentCount,
       metadata.mPtsMillis, metadata.mPayloadLen));

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
    pending.mOpenEnded = metadata.mOpenEnded;
    pending.mFragments.SetLength(metadata.mFragmentIndex + 1);
  } else if (pending.mOpenEnded) {
    if (pending.mPtsMillis != metadata.mPtsMillis) {
      return NS_ERROR_INVALID_ARG;
    }
  } else if (pending.mFragmentCount != metadata.mFragmentCount ||
             pending.mPtsMillis != metadata.mPtsMillis) {
    return NS_ERROR_INVALID_ARG;
  }

  mAcceptedObjects.Insert(objectKey);
  mAcceptedObjectOrder.AppendElement(objectKey);
  if (mAcceptedObjectOrder.Length() > MCQUIC_MOQ_DEDUP_WINDOW) {
    mAcceptedObjects.Remove(mAcceptedObjectOrder[0]);
    mAcceptedObjectOrder.RemoveElementAt(0);
  }
  if (aResult) {
    aResult->mAcceptedObject = true;
  }

  pending.mFirstPacketNumber =
      std::min(pending.mFirstPacketNumber, aPacketNumber);
  pending.mLastPacketNumber =
      std::max(pending.mLastPacketNumber, aPacketNumber);
  pending.mKeyframe |= metadata.mFlags & QVF1_FLAG_KEYFRAME;
  pending.mConfig |= metadata.mFlags & QVF1_FLAG_CONFIG;
  pending.mIndependent |=
      metadata.mFlags &
      (QVF1_FLAG_KEYFRAME | QVF1_FLAG_CONFIG | MCQUIC_MEDIA_FLAG_INDEPENDENT);

  if (pending.mFragments.Length() <= metadata.mFragmentIndex) {
    pending.mFragments.SetLength(metadata.mFragmentIndex + 1);
  }
  FragmentSlot& slot = pending.mFragments[metadata.mFragmentIndex];
  if (!slot.mPresent) {
    slot.mPresent = true;
    ++pending.mReceivedFragments;
  }
  slot.mPayload.Clear();
  slot.mPayload.AppendElements(
      aObject.payload.Elements() + metadata.mPayloadOffset,
      metadata.mPayloadLen);

  if (metadata.mOpenEnded && continuationOfOpenEndedAccessUnit) {
    if (auto open = mOpenEndedAccessUnitsByTrack.Lookup(trackKey)) {
      open.Data().mNextFragmentIndex = metadata.mFragmentIndex + 1;
    }
  }
  if ((metadata.mFlags & QVF1_FLAG_END_OF_ACCESS_UNIT) &&
      pending.mOpenEnded) {
    pending.mOpenEnded = false;
    pending.mFragmentCount = metadata.mFragmentIndex + 1;
    mOpenEndedAccessUnitsByTrack.Remove(trackKey);
  }

  if ((metadata.mFlags & QVF1_FLAG_END_OF_ACCESS_UNIT) &&
      pending.mReceivedFragments != pending.mFragmentCount) {
    LOG(
        ("MCQUIC MoQ media sink saw end-of-access-unit before all fragments "
         "[track=%s/%s sequence=%" PRIu64 " received=%u expected=%u]",
         pending.mNamespace.get(), pending.mTrackName.get(),
         pending.mAccessUnitSequence, pending.mReceivedFragments,
         pending.mFragmentCount));
  }

  return EmitIfComplete(key, pending, aResult);
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

nsresult McquicMoqMediaSink::EmitIfComplete(
    const nsCString& aKey, PendingAccessUnit& aPending,
    McquicMoqMediaSinkProcessResult* aResult) {
  if (aPending.mOpenEnded) {
    return NS_OK;
  }
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

  AnnexBNalSummary nalSummary = SummarizeAnnexBNals(accessUnit.mPayload);
  accessUnit.mKeyframe |= nalSummary.mContainsIdr;
  accessUnit.mConfig |= nalSummary.mContainsSps || nalSummary.mContainsPps;
  accessUnit.mIndependent |= accessUnit.mKeyframe || accessUnit.mConfig;

  LOG(("MCQUIC MoQ media access unit [track=%s/%s sequence=%" PRIu64
       " pts_ms=%" PRIu64 " fragments=%u payload_len=%zu keyframe=%d "
       "config=%d independent=%d annexb_idr=%d annexb_sps=%d annexb_pps=%d "
       "first_packet=%" PRIu64 " last_packet=%" PRIu64 "]",
       accessUnit.mNamespace.get(), accessUnit.mTrackName.get(),
       accessUnit.mAccessUnitSequence, accessUnit.mPtsMillis,
       aPending.mFragmentCount, accessUnit.mPayload.Length(),
       accessUnit.mKeyframe, accessUnit.mConfig, accessUnit.mIndependent,
       nalSummary.mContainsIdr, nalSummary.mContainsSps,
       nalSummary.mContainsPps, accessUnit.mFirstPacketNumber,
       accessUnit.mLastPacketNumber));

  if (aResult) {
    aResult->mCompletedAccessUnit = true;
    aResult->mKeyframeCapableAccessUnit =
        accessUnit.mKeyframe || accessUnit.mConfig || accessUnit.mIndependent;
  }

  mCompletedAccessUnits.AppendElement(std::move(accessUnit));
  mPendingAccessUnits.Remove(aKey);
  return NS_OK;
}

}  // namespace mozilla::net
