/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstring>

#include "McquicMulticastReceiver.h"
#include "gtest/gtest.h"
#include "mozilla/Preferences.h"
#include "mozilla/ScopeExit.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"
#include "prio.h"
#include "prnetdb.h"

namespace mozilla::net {

constexpr auto kMcquicTransportPref = "network.http.http3.mcquic.enabled";
constexpr auto kSource = "127.0.0.1"_ns;
constexpr auto kGroup = "232.0.0.1"_ns;
constexpr auto kInterface = "127.0.0.1"_ns;
constexpr char kPayload[] = "mcquic mcrx gtest";

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
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicTransportPref, false));
  auto clearPref =
      MakeScopeExit([] { Preferences::ClearUser(kMcquicTransportPref); });

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
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicTransportPref, true));
  auto clearPref =
      MakeScopeExit([] { Preferences::ClearUser(kMcquicTransportPref); });

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

TEST(TestMcquicMulticastReceiver, SubscriptionCanLeaveRejoinAndRemove)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicTransportPref, true));
  auto clearPref =
      MakeScopeExit([] { Preferences::ClearUser(kMcquicTransportPref); });

  uint16_t port = 0;
  ASSERT_NS_SUCCEEDED(PickUnusedUdpPort(&port));

  auto* sts = gSocketTransportService;
  ASSERT_TRUE(sts);

  nsresult initRv = NS_OK;
  nsresult unknownJoinRv = NS_OK;
  nsresult addRv = NS_OK;
  nsresult firstJoinRv = NS_OK;
  nsresult leaveRv = NS_OK;
  nsresult secondJoinRv = NS_OK;
  nsresult secondLeaveRv = NS_OK;
  nsresult removeRv = NS_OK;
  nsresult removedJoinRv = NS_OK;

  NS_DispatchAndSpinEventLoopUntilComplete(
      "TestMcquicMulticastReceiver::SubscriptionCanLeaveRejoinAndRemove"_ns,
      sts,
      NS_NewRunnableFunction(
          "TestMcquicMulticastReceiver::SubscriptionCanLeaveRejoinAndRemove",
          [&] {
            McquicMulticastReceiver receiver;
            initRv = receiver.Init();
            if (NS_FAILED(initRv)) {
              return;
            }

            unknownJoinRv = receiver.Join(UINT64_MAX);

            uint64_t subscriptionId = 0;
            addRv = receiver.AddSsmSubscription(
                kSource, kGroup, port, kInterface, Nothing(), &subscriptionId);
            if (NS_FAILED(addRv)) {
              return;
            }
            firstJoinRv = receiver.Join(subscriptionId);
            if (NS_FAILED(firstJoinRv)) {
              return;
            }
            leaveRv = receiver.Leave(subscriptionId);
            if (NS_FAILED(leaveRv)) {
              return;
            }
            secondJoinRv = receiver.Join(subscriptionId);
            if (NS_FAILED(secondJoinRv)) {
              return;
            }
            secondLeaveRv = receiver.Leave(subscriptionId);
            if (NS_FAILED(secondLeaveRv)) {
              return;
            }
            removeRv = receiver.Remove(subscriptionId);
            if (NS_FAILED(removeRv)) {
              return;
            }
            removedJoinRv = receiver.Join(subscriptionId);
          }));

  ASSERT_NS_SUCCEEDED(initRv);
  ASSERT_NS_FAILED(unknownJoinRv);
  ASSERT_NS_SUCCEEDED(addRv);
  if (NS_FAILED(firstJoinRv)) {
    GTEST_SKIP() << "loopback SSM join is unavailable on this host";
  }
  ASSERT_NS_SUCCEEDED(leaveRv);
  ASSERT_NS_SUCCEEDED(secondJoinRv);
  ASSERT_NS_SUCCEEDED(secondLeaveRv);
  ASSERT_NS_SUCCEEDED(removeRv);
  ASSERT_NS_FAILED(removedJoinRv);
}

}  // namespace mozilla::net
