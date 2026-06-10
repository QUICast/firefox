/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"

#include <cstring>

#include "McquicMulticastReceiver.h"
#include "mozilla/Preferences.h"
#include "mozilla/ScopeExit.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"
#include "prio.h"
#include "prnetdb.h"

namespace mozilla::net {

constexpr auto kMcquicMcrxPref = "network.http.http3.mcquic.enabled";
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

TEST(TestMcquicMulticastReceiver, PrefOffIsInert)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicMcrxPref, false));
  auto clearPref =
      MakeScopeExit([] { Preferences::ClearUser(kMcquicMcrxPref); });

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
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicMcrxPref, true));
  auto clearPref =
      MakeScopeExit([] { Preferences::ClearUser(kMcquicMcrxPref); });

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
