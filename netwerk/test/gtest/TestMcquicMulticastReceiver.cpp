/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"

#include <cstring>
#include <utility>

#include "McquicMoqMediaSink.h"
#include "McquicMulticastReceiver.h"
#include "mozilla/Preferences.h"
#include "mozilla/ScopeExit.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"
#include "prio.h"
#include "prnetdb.h"

namespace mozilla::net {

constexpr auto kMcquicNativeMoqDemoPref =
    "network.http.http3.mcquic.native_moq_demo.enabled";
constexpr auto kSource = "127.0.0.1"_ns;
constexpr auto kGroup = "232.0.0.1"_ns;
constexpr auto kInterface = "127.0.0.1"_ns;
constexpr char kPayload[] = "mcquic mcrx gtest";

static void AppendUint(nsTArray<uint8_t>& aOut, uint64_t aValue, size_t aLen) {
  for (size_t i = aLen; i > 0; --i) {
    aOut.AppendElement(static_cast<uint8_t>(aValue >> ((i - 1) * 8)));
  }
}

static void AppendVarint(nsTArray<uint8_t>& aOut, uint64_t aValue) {
  if (aValue < (1ULL << 6)) {
    aOut.AppendElement(static_cast<uint8_t>(aValue));
  } else if (aValue < (1ULL << 14)) {
    AppendUint(aOut, aValue | 0x4000, 2);
  } else if (aValue < (1ULL << 30)) {
    AppendUint(aOut, aValue | 0x80000000, 4);
  } else {
    AppendUint(aOut, aValue | 0xc000000000000000, 8);
  }
}

static nsTArray<uint8_t> Qvf1Payload(uint64_t aAccessUnitSequence,
                                     uint16_t aFragmentIndex,
                                     uint16_t aFragmentCount,
                                     uint64_t aPtsMillis, uint8_t aFlags,
                                     const uint8_t* aPayload,
                                     size_t aPayloadLen) {
  nsTArray<uint8_t> out;
  out.AppendElements("QVF1", 4);
  out.AppendElement(1);
  out.AppendElement(1);
  out.AppendElement(aFlags);
  out.AppendElement(0);
  AppendUint(out, aAccessUnitSequence, 8);
  AppendUint(out, aFragmentIndex, 2);
  AppendUint(out, aFragmentCount, 2);
  AppendUint(out, aPtsMillis, 8);
  AppendUint(out, aPayloadLen, 4);
  out.AppendElements(aPayload, aPayloadLen);
  return out;
}

static nsTArray<uint8_t> LocMsfPayload(uint64_t aAccessUnitSequence,
                                       uint64_t aPtsMillis, uint8_t aFlags,
                                       const uint8_t* aPayload,
                                       size_t aPayloadLen) {
  nsTArray<uint8_t> out;
  out.AppendElements("MSF1", 4);
  out.AppendElement(1);
  out.AppendElement(1);
  out.AppendElement(aFlags);
  out.AppendElement(0);
  AppendUint(out, aAccessUnitSequence, 8);
  AppendUint(out, aPtsMillis, 8);
  AppendUint(out, aPayloadLen, 4);
  out.AppendElements(aPayload, aPayloadLen);
  return out;
}

static nsTArray<uint8_t> LocH264FragmentPayload(uint64_t aPtsMillis,
                                                uint16_t aFlags,
                                                uint16_t aFragmentIndex,
                                                uint16_t aFragmentCount,
                                                const uint8_t* aPayload,
                                                size_t aPayloadLen) {
  nsTArray<uint8_t> out;
  out.AppendElement(1);
  out.AppendElement(20);
  AppendUint(out, aFlags, 2);
  AppendUint(out, aPtsMillis, 8);
  AppendUint(out, aFragmentIndex, 2);
  AppendUint(out, aFragmentCount, 2);
  AppendUint(out, aPayloadLen, 4);
  out.AppendElements(aPayload, aPayloadLen);
  return out;
}

static McquicMoqDatagramExternal NativeMoqObject(nsTArray<uint8_t>&& aPayload,
                                                 uint64_t aGroupId = 7,
                                                 uint64_t aObjectId = 0) {
  McquicMoqDatagramExternal object{};
  object.format = McquicMoqDatagramFormat::NativeMoqtObject;
  object.track_alias = 9;
  object.has_track_alias = true;
  object.group_id = aGroupId;
  object.object_id = aObjectId;
  object.publisher_sequence = aObjectId;
  object.status = McquicMoqObjectStatus::Normal;
  object.end_of_group = true;
  object.payload_len = aPayload.Length();
  object.payload = std::move(aPayload);
  return object;
}

static nsresult PickUnusedUdpPort(uint16_t* aPort) {
  PRFileDesc* fd = PR_OpenUDPSocket(PR_AF_INET);
  if (!fd) {
    return NS_ERROR_FAILURE;
  }
  auto closeFd = MakeScopeExit([&] { PR_Close(fd); });

  PRNetAddr addr;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, 0, &addr) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }
  if (PR_Bind(fd, &addr) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }
  if (PR_GetSockName(fd, &addr) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }

  *aPort = PR_ntohs(addr.inet.port);
  return NS_OK;
}

static nsresult SendLoopbackMulticast(uint16_t aPort) {
  PRFileDesc* fd = PR_OpenUDPSocket(PR_AF_INET);
  if (!fd) {
    return NS_ERROR_FAILURE;
  }
  auto closeFd = MakeScopeExit([&] { PR_Close(fd); });

  PRNetAddr source;
  if (PR_InitializeNetAddr(PR_IpAddrLoopback, 0, &source) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }
  if (PR_Bind(fd, &source) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }

  PRSocketOptionData opt;
  opt.option = PR_SockOpt_McastLoopback;
  opt.value.mcast_loopback = PR_TRUE;
  if (PR_SetSocketOption(fd, &opt) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }

  opt.option = PR_SockOpt_McastTimeToLive;
  opt.value.mcast_ttl = 1;
  if (PR_SetSocketOption(fd, &opt) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }

  opt.option = PR_SockOpt_McastInterface;
  if (PR_StringToNetAddr(kInterface.BeginReading(), &opt.value.mcast_if) !=
      PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }
  if (PR_SetSocketOption(fd, &opt) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }

  PRNetAddr destination;
  if (PR_StringToNetAddr(kGroup.BeginReading(), &destination) != PR_SUCCESS) {
    return NS_ERROR_FAILURE;
  }
  destination.inet.port = PR_htons(aPort);

  const PRInt32 sent = PR_SendTo(fd, kPayload, std::strlen(kPayload), 0,
                                 &destination, PR_MillisecondsToInterval(100));
  if (sent != static_cast<PRInt32>(std::strlen(kPayload))) {
    return NS_ERROR_FAILURE;
  }

  return NS_OK;
}

class RecordingMcquicMoqAccessUnitConsumer final
    : public McquicMoqAccessUnitConsumer {
 public:
  nsresult OnMcquicMoqAccessUnit(
      const McquicMoqAccessUnit& aAccessUnit) override {
    ++mAccessUnitCount;
    mTrackName = aAccessUnit.mTrackName;
    mAccessUnitSequence = aAccessUnit.mAccessUnitSequence;
    mPtsMillis = aAccessUnit.mPtsMillis;
    mPayload.Clear();
    mPayload.AppendElements(aAccessUnit.mPayload);
    return NS_OK;
  }

  uint32_t mAccessUnitCount = 0;
  nsCString mTrackName;
  uint64_t mAccessUnitSequence = 0;
  uint64_t mPtsMillis = 0;
  nsTArray<uint8_t> mPayload;
};

TEST(TestMcquicMulticastReceiver, PrefOffIsInert)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicNativeMoqDemoPref, false));
  auto clearPref =
      MakeScopeExit(
          [] { Preferences::ClearUser(kMcquicNativeMoqDemoPref); });

  auto* sts = gSocketTransportService;
  ASSERT_TRUE(sts);

  nsresult rv = NS_OK;
  NS_DispatchAndSpinEventLoopUntilComplete(
      "TestMcquicMulticastReceiver::PrefOffIsInert"_ns, sts,
      NS_NewRunnableFunction("TestMcquicMulticastReceiver::PrefOffIsInert",
                             [&] {
                               McquicMulticastReceiver receiver;
                               rv = receiver.Init();
                             }));

  ASSERT_EQ(rv, NS_ERROR_NOT_AVAILABLE);
}

TEST(TestMcquicMulticastReceiver, LoopbackSsmLogsPacketWhenPrefOn)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicNativeMoqDemoPref, true));
  auto clearPref =
      MakeScopeExit(
          [] { Preferences::ClearUser(kMcquicNativeMoqDemoPref); });

  uint16_t port = 0;
  ASSERT_NS_SUCCEEDED(PickUnusedUdpPort(&port));

  auto* sts = gSocketTransportService;
  ASSERT_TRUE(sts);

  nsresult rv = NS_OK;
  bool received = false;
  McquicMcrxPacket packet{};

  NS_DispatchAndSpinEventLoopUntilComplete(
      "TestMcquicMulticastReceiver::LoopbackSsmLogsPacketWhenPrefOn"_ns, sts,
      NS_NewRunnableFunction(
          "TestMcquicMulticastReceiver::LoopbackSsmLogsPacketWhenPrefOn", [&] {
            McquicMulticastReceiver receiver;
            rv = receiver.Init();
            if (NS_FAILED(rv)) {
              return;
            }

            uint64_t subscriptionId = 0;
            rv = receiver.AddSsmSubscription(kSource, kGroup, port, kInterface,
                                             Nothing(), &subscriptionId);
            if (NS_FAILED(rv)) {
              return;
            }

            rv = receiver.Join(subscriptionId);
            if (NS_FAILED(rv)) {
              return;
            }

            rv = SendLoopbackMulticast(port);
            if (NS_FAILED(rv)) {
              return;
            }

            const PRIntervalTime deadline =
                PR_IntervalNow() + PR_MillisecondsToInterval(1000);
            do {
              rv = receiver.Poll(packet);
              if (rv == NS_OK) {
                received = true;
                return;
              }
              if (rv != NS_BASE_STREAM_WOULD_BLOCK) {
                return;
              }
              PR_Sleep(PR_MillisecondsToInterval(10));
            } while (PR_IntervalNow() < deadline);
          }));

  if (rv == NS_BASE_STREAM_WOULD_BLOCK && !received) {
    GTEST_SKIP() << "loopback multicast packet was not delivered by the OS";
  }

  ASSERT_NS_SUCCEEDED(rv);
  ASSERT_TRUE(received);
  ASSERT_TRUE(packet.source_ip.Equals(kSource));
  ASSERT_TRUE(packet.group_ip.Equals(kGroup));
  ASSERT_EQ(packet.dst_port, port);
  ASSERT_EQ(packet.payload.Length(), std::strlen(kPayload));
  ASSERT_EQ(
      std::memcmp(packet.payload.Elements(), kPayload, std::strlen(kPayload)),
      0);
}

TEST(TestMcquicMoqDecoder, NativeMoqtObjectDatagram)
{
  nsTArray<uint8_t> payload;
  AppendVarint(payload, 0x08 | 0x02);
  AppendVarint(payload, 9);
  AppendVarint(payload, 42);
  AppendVarint(payload, 7);
  payload.AppendElements("qvf1", 4);

  McquicMoqDatagramExternal decoded{};
  ASSERT_TRUE(neqo_mcquic_decode_moq_datagram(&payload, &decoded));

  ASSERT_EQ(decoded.format, McquicMoqDatagramFormat::NativeMoqtObject);
  ASSERT_TRUE(decoded.has_track_alias);
  ASSERT_EQ(decoded.track_alias, 9U);
  ASSERT_EQ(decoded.group_id, 42U);
  ASSERT_EQ(decoded.object_id, 7U);
  ASSERT_EQ(decoded.publisher_sequence, 42U);
  ASSERT_EQ(decoded.status, McquicMoqObjectStatus::Normal);
  ASSERT_TRUE(decoded.end_of_group);
  ASSERT_EQ(decoded.payload_len, 4U);
  ASSERT_EQ(decoded.payload.Length(), 4U);
  ASSERT_EQ(std::memcmp(decoded.payload.Elements(), "qvf1", 4), 0);
}

TEST(TestMcquicMoqDecoder, LegacyHuginnMoq1ObjectDatagram)
{
  constexpr char kNamespace[] = "ratatoskr/demo";
  constexpr char kTrackName[] = "h264-qvf1";
  constexpr char kChannel[] = "qcast-demo-v1";
  constexpr char kObjectPayload[] = "qvf1";
  constexpr uint8_t kFlags = 0x01 | 0x04 | 0x08 | 0x10;

  nsTArray<uint8_t> payload;
  payload.AppendElements("MOQ1", 4);
  payload.AppendElement(1);
  payload.AppendElement(kFlags);
  AppendUint(payload, std::strlen(kNamespace), 2);
  AppendUint(payload, std::strlen(kTrackName), 2);
  AppendUint(payload, std::strlen(kChannel), 2);
  AppendUint(payload, std::strlen(kObjectPayload), 4);
  AppendUint(payload, 44, 8);
  AppendUint(payload, 9, 8);
  AppendUint(payload, 1044, 8);
  AppendUint(payload, 1466, 8);
  AppendUint(payload, 88, 8);
  payload.AppendElements(kNamespace, std::strlen(kNamespace));
  payload.AppendElements(kTrackName, std::strlen(kTrackName));
  payload.AppendElements(kChannel, std::strlen(kChannel));
  payload.AppendElements(kObjectPayload, std::strlen(kObjectPayload));

  McquicMoqDatagramExternal decoded{};
  ASSERT_TRUE(neqo_mcquic_decode_moq_datagram(&payload, &decoded));

  ASSERT_EQ(decoded.format, McquicMoqDatagramFormat::LegacyMoq1Object);
  ASSERT_FALSE(decoded.has_track_alias);
  ASSERT_TRUE(decoded.namespace_.EqualsLiteral("ratatoskr/demo"));
  ASSERT_TRUE(decoded.track_name.EqualsLiteral("h264-qvf1"));
  ASSERT_EQ(decoded.multicast_channel.Length(), std::strlen(kChannel));
  ASSERT_EQ(std::memcmp(decoded.multicast_channel.Elements(), kChannel,
                        std::strlen(kChannel)),
            0);
  ASSERT_EQ(decoded.group_id, 44U);
  ASSERT_EQ(decoded.object_id, 9U);
  ASSERT_EQ(decoded.publisher_sequence, 1044U);
  ASSERT_EQ(decoded.pts_millis, 1466U);
  ASSERT_TRUE(decoded.keyframe);
  ASSERT_TRUE(decoded.independent);
  ASSERT_TRUE(decoded.end_of_group);
  ASSERT_EQ(decoded.payload_len, 4U);
  ASSERT_EQ(decoded.payload.Length(), 4U);
  ASSERT_EQ(std::memcmp(decoded.payload.Elements(), kObjectPayload,
                        std::strlen(kObjectPayload)),
            0);
  ASSERT_TRUE(decoded.has_multicast_packet_number);
  ASSERT_EQ(decoded.multicast_packet_number, 88U);
}

TEST(TestMcquicMoqDecoder, RejectsUnknownPayload)
{
  nsTArray<uint8_t> payload;
  payload.AppendElements("not a moq object", 16);
  McquicMoqDatagramExternal decoded{};
  decoded.format = McquicMoqDatagramFormat::NativeMoqtObject;

  ASSERT_FALSE(neqo_mcquic_decode_moq_datagram(&payload, &decoded));
  ASSERT_EQ(decoded.format, McquicMoqDatagramFormat::Unknown);
}

TEST(TestMcquicMoqMediaSink, AssemblesSingleFragmentQvf1AccessUnit)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFrame[] = {0xaa, 0xbb, 0xcc};
  auto object = NativeMoqObject(
      Qvf1Payload(7, 0, 1, 280, 0x01 | 0x04, kFrame, sizeof(kFrame)));

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-qvf1"_ns,
                                         channelId, 42, object));

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_TRUE(accessUnit.mNamespace.EqualsLiteral("ratatoskr/demo"));
  ASSERT_TRUE(accessUnit.mTrackName.EqualsLiteral("h264-qvf1"));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 7U);
  ASSERT_EQ(accessUnit.mPtsMillis, 280U);
  ASSERT_EQ(accessUnit.mFirstPacketNumber, 42U);
  ASSERT_EQ(accessUnit.mLastPacketNumber, 42U);
  ASSERT_TRUE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(), sizeof(kFrame));
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements(), kFrame, sizeof(kFrame)),
            0);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, WaitsForAndOrdersQvf1Fragments)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFirst[] = {0x01, 0x02};
  constexpr uint8_t kSecond[] = {0x03, 0x04, 0x05};
  auto second = NativeMoqObject(
      Qvf1Payload(9, 1, 2, 360, 0x04, kSecond, sizeof(kSecond)), 9, 1);
  auto first = NativeMoqObject(
      Qvf1Payload(9, 0, 2, 360, 0x01, kFirst, sizeof(kFirst)), 9, 0);

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-qvf1"_ns,
                                         channelId, 44, second));
  McquicMoqAccessUnit accessUnit;
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-qvf1"_ns,
                                         channelId, 43, first));
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));

  constexpr uint8_t kExpected[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 9U);
  ASSERT_EQ(accessUnit.mPtsMillis, 360U);
  ASSERT_EQ(accessUnit.mFirstPacketNumber, 43U);
  ASSERT_EQ(accessUnit.mLastPacketNumber, 44U);
  ASSERT_TRUE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(), sizeof(kExpected));
  ASSERT_EQ(
      std::memcmp(accessUnit.mPayload.Elements(), kExpected, sizeof(kExpected)),
      0);
}

TEST(TestMcquicMoqMediaSink, LocMsfPayloadReachesAccessUnit)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFrame[] = {0x00, 0x00, 0x01, 0x65, 0x88};
  auto object = NativeMoqObject(
      LocMsfPayload(21, 700, 0x01 | 0x08, kFrame, sizeof(kFrame)), 21, 0);
  McquicMoqMediaSinkProcessResult result;

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns,
                                         "h264-loc-msf"_ns, channelId, 61,
                                         object, &result));
  ASSERT_TRUE(result.mAcceptedObject);
  ASSERT_FALSE(result.mDuplicateObject);
  ASSERT_TRUE(result.mCompletedAccessUnit);
  ASSERT_TRUE(result.mKeyframeCapableAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_TRUE(accessUnit.mNamespace.EqualsLiteral("ratatoskr/demo"));
  ASSERT_TRUE(accessUnit.mTrackName.EqualsLiteral("h264-loc-msf"));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 21U);
  ASSERT_EQ(accessUnit.mPtsMillis, 700U);
  ASSERT_EQ(accessUnit.mFirstPacketNumber, 61U);
  ASSERT_EQ(accessUnit.mLastPacketNumber, 61U);
  ASSERT_TRUE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(), sizeof(kFrame));
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements(), kFrame, sizeof(kFrame)),
            0);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, DeduplicatesObjectByTrackGroupAndObject)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFrame[] = {0x00, 0x00, 0x01, 0x65, 0x99};
  auto object = NativeMoqObject(
      LocMsfPayload(55, 900, 0x01 | 0x08, kFrame, sizeof(kFrame)), 55, 0);

  McquicMoqMediaSinkProcessResult first;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns,
                                         "h264-loc-msf"_ns, channelId, 70,
                                         object, &first));
  ASSERT_TRUE(first.mAcceptedObject);
  ASSERT_TRUE(first.mCompletedAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));

  McquicMoqMediaSinkProcessResult duplicate;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns,
                                         "h264-loc-msf"_ns, channelId, 71,
                                         object, &duplicate));
  ASSERT_FALSE(duplicate.mAcceptedObject);
  ASSERT_TRUE(duplicate.mDuplicateObject);
  ASSERT_FALSE(duplicate.mCompletedAccessUnit);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, IgnoresNonMediaStatusObjects)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  nsTArray<uint8_t> payload;
  auto object = NativeMoqObject(std::move(payload), 56, 0);
  object.status = McquicMoqObjectStatus::EndOfGroup;
  object.end_of_group = true;
  object.payload_len = 0;

  McquicMoqMediaSinkProcessResult result;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 72, object, &result));
  ASSERT_FALSE(result.mAcceptedObject);
  ASSERT_FALSE(result.mDuplicateObject);
  ASSERT_FALSE(result.mCompletedAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, IgnoresEmptyLocMediaObjects)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  nsTArray<uint8_t> payload;
  auto object = NativeMoqObject(std::move(payload), 57, 0);

  McquicMoqMediaSinkProcessResult result;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 73, object, &result));
  ASSERT_FALSE(result.mAcceptedObject);
  ASSERT_FALSE(result.mDuplicateObject);
  ASSERT_FALSE(result.mCompletedAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, LocMsfUsesObjectSequenceWhenHeaderSequenceIsZero)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFirstFrame[] = {0x00, 0x00, 0x01, 0x65, 0x99};
  constexpr uint8_t kSecondFrame[] = {0x00, 0x00, 0x01, 0x41, 0x9a};
  auto first = NativeMoqObject(
      LocMsfPayload(0, 0, 0x01 | 0x08, kFirstFrame, sizeof(kFirstFrame)), 77,
      0);
  first.publisher_sequence = 77;
  first.pts_millis = 77;
  auto second = NativeMoqObject(
      LocMsfPayload(0, 0, 0x08, kSecondFrame, sizeof(kSecondFrame)), 78, 0);
  second.publisher_sequence = 78;
  second.pts_millis = 78;

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns,
                                         "h264-loc-msf"_ns, channelId, 77,
                                         first));
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns,
                                         "h264-loc-msf"_ns, channelId, 78,
                                         second));

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 77U);
  ASSERT_EQ(accessUnit.mPtsMillis, 77U);
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 78U);
  ASSERT_EQ(accessUnit.mPtsMillis, 78U);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, DirectLocMsfObjectReachesAccessUnit)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFrame[] = {0x00, 0x00, 0x01, 0x41, 0x9a};
  nsTArray<uint8_t> payload;
  payload.AppendElements(kFrame, sizeof(kFrame));
  auto object = NativeMoqObject(std::move(payload), 34, 2);
  object.publisher_sequence = 34;
  object.pts_millis = 1122;
  object.keyframe = false;
  object.independent = true;

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-msf"_ns,
                                         channelId, 62, object));

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_TRUE(accessUnit.mTrackName.EqualsLiteral("h264-msf"));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 34U);
  ASSERT_EQ(accessUnit.mPtsMillis, 1122U);
  ASSERT_FALSE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(), sizeof(kFrame));
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements(), kFrame, sizeof(kFrame)),
            0);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, LocH264FragmentsAssembleAccessUnit)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFirst[] = {0x00, 0x00, 0x00, 0x01, 0x67};
  constexpr uint8_t kSecond[] = {0x68, 0xce};
  constexpr uint8_t kThird[] = {0x00, 0x00, 0x01, 0x65, 0x88};
  auto first =
      NativeMoqObject(LocH264FragmentPayload(1343925, 0x0005, 0, 3, kFirst,
                                             sizeof(kFirst)),
                      98638, 0);
  auto second =
      NativeMoqObject(LocH264FragmentPayload(1343925, 0x0000, 1, 3, kSecond,
                                             sizeof(kSecond)),
                      98639, 1);
  auto third =
      NativeMoqObject(LocH264FragmentPayload(1343925, 0x0008, 2, 3, kThird,
                                             sizeof(kThird)),
                      98640, 2);

  McquicMoqMediaSinkProcessResult firstResult;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 98638, first,
                                         &firstResult));
  ASSERT_TRUE(firstResult.mAcceptedObject);
  ASSERT_FALSE(firstResult.mCompletedAccessUnit);

  McquicMoqMediaSinkProcessResult secondResult;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 98639, second,
                                         &secondResult));
  ASSERT_TRUE(secondResult.mAcceptedObject);
  ASSERT_FALSE(secondResult.mCompletedAccessUnit);

  McquicMoqMediaSinkProcessResult thirdResult;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 98640, third,
                                         &thirdResult));
  ASSERT_TRUE(thirdResult.mAcceptedObject);
  ASSERT_TRUE(thirdResult.mCompletedAccessUnit);
  ASSERT_TRUE(thirdResult.mKeyframeCapableAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_EQ(accessUnit.mAccessUnitSequence, 1343925U);
  ASSERT_EQ(accessUnit.mPtsMillis, 1343925U);
  ASSERT_TRUE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(),
            sizeof(kFirst) + sizeof(kSecond) + sizeof(kThird));
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements(), kFirst, sizeof(kFirst)),
            0);
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements() + sizeof(kFirst),
                        kSecond, sizeof(kSecond)),
            0);
  ASSERT_EQ(std::memcmp(accessUnit.mPayload.Elements() + sizeof(kFirst) +
                            sizeof(kSecond),
                        kThird, sizeof(kThird)),
            0);
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, LocH264AnnexBIdrMarksKeyframeWithoutFlags)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFirst[] = {
      0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1f,
      0x00, 0x00, 0x01, 0x68, 0xce,
  };
  constexpr uint8_t kSecond[] = {0x00, 0x00, 0x01, 0x65, 0x88};
  auto first =
      NativeMoqObject(LocH264FragmentPayload(1344000, 0x0000, 0, 2, kFirst,
                                             sizeof(kFirst)),
                      98700, 0);
  auto second =
      NativeMoqObject(LocH264FragmentPayload(1344000, 0x0008, 1, 2, kSecond,
                                             sizeof(kSecond)),
                      98701, 1);

  McquicMoqMediaSinkProcessResult firstResult;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 98700, first,
                                         &firstResult));
  ASSERT_TRUE(firstResult.mAcceptedObject);
  ASSERT_FALSE(firstResult.mCompletedAccessUnit);

  McquicMoqMediaSinkProcessResult secondResult;
  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-loc"_ns,
                                         channelId, 98701, second,
                                         &secondResult));
  ASSERT_TRUE(secondResult.mAcceptedObject);
  ASSERT_TRUE(secondResult.mCompletedAccessUnit);
  ASSERT_TRUE(secondResult.mKeyframeCapableAccessUnit);

  McquicMoqAccessUnit accessUnit;
  ASSERT_TRUE(sink.PopAccessUnit(accessUnit));
  ASSERT_TRUE(accessUnit.mKeyframe);
  ASSERT_TRUE(accessUnit.mConfig);
  ASSERT_TRUE(accessUnit.mIndependent);
  ASSERT_EQ(accessUnit.mPayload.Length(), sizeof(kFirst) + sizeof(kSecond));
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, DrainsCompletedAccessUnitsToConsumer)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  constexpr uint8_t kFrame[] = {0x65, 0x88, 0x84};
  auto object = NativeMoqObject(
      Qvf1Payload(12, 0, 1, 480, 0x01 | 0x04, kFrame, sizeof(kFrame)));

  ASSERT_NS_SUCCEEDED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-qvf1"_ns,
                                         channelId, 51, object));

  RecordingMcquicMoqAccessUnitConsumer consumer;
  ASSERT_NS_SUCCEEDED(sink.DrainAccessUnits(consumer));
  ASSERT_EQ(consumer.mAccessUnitCount, 1U);
  ASSERT_TRUE(consumer.mTrackName.EqualsLiteral("h264-qvf1"));
  ASSERT_EQ(consumer.mAccessUnitSequence, 12U);
  ASSERT_EQ(consumer.mPtsMillis, 480U);
  ASSERT_EQ(consumer.mPayload.Length(), sizeof(kFrame));
  ASSERT_EQ(std::memcmp(consumer.mPayload.Elements(), kFrame, sizeof(kFrame)),
            0);

  McquicMoqAccessUnit accessUnit;
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqMediaSink, RejectsMalformedQvf1Payload)
{
  McquicMoqMediaSink sink;
  nsTArray<uint8_t> channelId;
  channelId.AppendElements("qcast-demo-v1", 13);
  nsTArray<uint8_t> malformed;
  malformed.AppendElements("QVF1", 4);
  auto object = NativeMoqObject(std::move(malformed));

  ASSERT_NS_FAILED(sink.ProcessObject("ratatoskr/demo"_ns, "h264-qvf1"_ns,
                                      channelId, 1, object));
  McquicMoqAccessUnit accessUnit;
  ASSERT_FALSE(sink.PopAccessUnit(accessUnit));
}

TEST(TestMcquicMoqControl, EncodesSetupAndSubscribe)
{
  nsCString authority("localhost:7443"_ns);
  nsCString trackNamespace("ratatoskr/demo"_ns);
  nsCString trackName("h264-qvf1"_ns);
  nsTArray<uint8_t> payload;
  ASSERT_NS_SUCCEEDED(neqo_mcquic_moq_encode_setup_subscribe(
      &authority, &trackNamespace, &trackName, &payload));
  ASSERT_GT(payload.Length(), 0U);

  McquicMoqControlMessageExternal setup{};
  ASSERT_TRUE(neqo_mcquic_moq_decode_control_message(&payload, &setup));
  ASSERT_EQ(setup.tag, McquicMoqControlMessageTag::Setup);
  ASSERT_GT(setup.consumed, 0U);
  ASSERT_LT(setup.consumed, payload.Length());

  nsTArray<uint8_t> subscribePayload;
  subscribePayload.AppendElements(
      payload.Elements() + setup.consumed,
      payload.Length() - static_cast<size_t>(setup.consumed));

  McquicMoqControlMessageExternal subscribe{};
  ASSERT_TRUE(
      neqo_mcquic_moq_decode_control_message(&subscribePayload, &subscribe));
  ASSERT_EQ(subscribe.tag, McquicMoqControlMessageTag::Subscribe);
  ASSERT_EQ(subscribe.request_id, 0U);
  ASSERT_TRUE(subscribe.namespace_.EqualsLiteral("ratatoskr/demo"));
  ASSERT_TRUE(subscribe.track_name.EqualsLiteral("h264-qvf1"));
  ASSERT_EQ(subscribe.consumed, subscribePayload.Length());
}

TEST(TestMcquicMoqControl, DecodesSubscribeOk)
{
  nsTArray<uint8_t> payload;
  AppendVarint(payload, 0x04);
  AppendUint(payload, 3, 2);
  AppendVarint(payload, 77);
  AppendVarint(payload, 0);

  McquicMoqControlMessageExternal decoded{};
  ASSERT_TRUE(neqo_mcquic_moq_decode_control_message(&payload, &decoded));
  ASSERT_EQ(decoded.tag, McquicMoqControlMessageTag::SubscribeOk);
  ASSERT_EQ(decoded.track_alias, 77U);
  ASSERT_EQ(decoded.consumed, payload.Length());
}

TEST(TestMcquicMoqControl, RejectsMalformedControl)
{
  nsTArray<uint8_t> payload;
  AppendVarint(payload, 0x04);
  AppendUint(payload, 4, 2);
  AppendVarint(payload, 77);

  McquicMoqControlMessageExternal decoded{};
  decoded.tag = McquicMoqControlMessageTag::Setup;
  ASSERT_FALSE(neqo_mcquic_moq_decode_control_message(&payload, &decoded));
  ASSERT_EQ(decoded.tag, McquicMoqControlMessageTag::Unknown);
}

}  // namespace mozilla::net
