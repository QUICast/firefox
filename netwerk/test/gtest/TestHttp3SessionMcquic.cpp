/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "DNS.h"
#include "Http3Session.h"
#include "McquicMulticastReceiver.h"
#include "gtest/gtest.h"
#include "mozilla/Preferences.h"
#include "mozilla/ScopeExit.h"
#include "mozilla/net/NeqoHttp3Conn.h"
#include "nsIHttpProtocolHandler.h"
#include "nsINetworkLinkService.h"
#include "nsServiceManagerUtils.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"
#include "prnetdb.h"

using namespace mozilla;
using namespace mozilla::literals;

namespace mozilla::net {

namespace {

constexpr auto kMcquicPref = "network.http.http3.mcquic.enabled";

struct FakeReceiverState {
  nsresult mInitResult = NS_OK;
  nsresult mAddResult = NS_OK;
  nsresult mJoinResult = NS_OK;
  nsresult mPollResult = NS_BASE_STREAM_WOULD_BLOCK;
  uint64_t mNextSubscriptionId = 1;
  uint32_t mInitCalls = 0;
  uint32_t mAddCalls = 0;
  uint32_t mJoinCalls = 0;
  uint32_t mLeaveCalls = 0;
  uint32_t mRemoveCalls = 0;
  uint32_t mPollCalls = 0;
};

class FakeMcquicReceiver final : public McquicMulticastReceiver {
 public:
  explicit FakeMcquicReceiver(FakeReceiverState* aState) : mState(aState) {}

  nsresult Init() override {
    ++mState->mInitCalls;
    return mState->mInitResult;
  }

  nsresult AddSsmSubscription(const nsACString&, const nsACString&, uint16_t,
                              const nsACString&, Maybe<uint32_t>,
                              uint64_t* aSubscriptionId) override {
    ++mState->mAddCalls;
    if (NS_FAILED(mState->mAddResult)) {
      return mState->mAddResult;
    }
    *aSubscriptionId = mState->mNextSubscriptionId++;
    return NS_OK;
  }

  nsresult Join(uint64_t) override {
    ++mState->mJoinCalls;
    return mState->mJoinResult;
  }

  nsresult Leave(uint64_t) override {
    ++mState->mLeaveCalls;
    return NS_OK;
  }

  nsresult Remove(uint64_t) override {
    ++mState->mRemoveCalls;
    return NS_OK;
  }

  nsresult Poll(McquicMcrxPacket&) override {
    ++mState->mPollCalls;
    return mState->mPollResult;
  }

 private:
  FakeReceiverState* const mState;
};

RefPtr<NeqoHttp3Conn> NewMcquicConnection() {
  NetAddr local;
  local.inet.family = AF_INET;
  local.inet.port = PR_htons(4433);
  local.inet.ip = PR_htonl(0xc0000201);

  NetAddr remote;
  remote.inet.family = AF_INET;
  remote.inet.port = PR_htons(4434);
  remote.inet.ip = PR_htonl(0xc0000202);

  RefPtr<NeqoHttp3Conn> conn;
  nsresult rv = NeqoHttp3Conn::InitUseNSPRForIO(
      "example.com"_ns, "h3"_ns, local, remote, 64 * 1024, 100, 1024 * 1024,
      1024 * 1024, false, true, McquicOperationPolicyExternal::Allow, ""_ns, 30,
      0, getter_AddRefs(conn));
  EXPECT_EQ(rv, NS_OK);
  return conn;
}

McquicControlFrameExternal Announcement(const nsACString& aChannelId,
                                        uint64_t aRateKibps = 1,
                                        uint8_t aAddressFamily = 4) {
  McquicControlFrameExternal frame{};
  frame.tag = McquicControlFrameTag::Announce;
  for (uint32_t i = 0; i < aChannelId.Length(); ++i) {
    frame.channel_id.AppendElement(static_cast<uint8_t>(aChannelId[i]));
  }
  frame.source_ip.AssignLiteral("127.0.0.1");
  frame.group_ip.AssignLiteral("232.0.0.1");
  frame.udp_port = 4433;
  frame.address_family = aAddressFamily;
  frame.max_rate_kibps = aRateKibps;
  return frame;
}

void RunOnSocketThread(const char* aName, std::function<void()>&& aTask) {
  nsCOMPtr<nsIHttpProtocolHandler> http =
      do_GetService("@mozilla.org/network/protocol;1?name=http");
  ASSERT_TRUE(http);
  ASSERT_TRUE(gSocketTransportService);
  NS_DispatchAndSpinEventLoopUntilComplete(
      nsDependentCString(aName), gSocketTransportService,
      NS_NewRunnableFunction(aName, std::move(aTask)));
}

}  // namespace

class Http3SessionMcquicTestPeer {
 public:
  enum class Disruption : uint8_t {
    PathMigration,
    ReceiverFailure,
  };

  static void Activate(Http3Session* aSession, RefPtr<NeqoHttp3Conn> aConn,
                       UniquePtr<McquicMulticastReceiver> aReceiver) {
    aSession->mHttp3Connection = std::move(aConn);
    aSession->mMcquicReceiver = std::move(aReceiver);
    aSession->mMcquicOperationState =
        Http3Session::McquicOperationState::Active;
    aSession->mMcquicPermittedSessionId = Some(0);
    aSession->mMcquicNetworkGeneration =
        gSocketTransportService->NetworkLinkChangeGeneration();
  }

  static nsresult Admit(Http3Session* aSession,
                        const McquicControlFrameExternal& aFrame) {
    return aSession->AdmitMcquicAnnouncement(aFrame);
  }

  static uint32_t ChannelCount(const Http3Session* aSession) {
    return aSession->mMcquicChannels.Count();
  }

  static void AddJoinCandidate(Http3Session* aSession,
                               const nsACString& aChannelId,
                               uint64_t aRateKibps, uint64_t aSubscriptionId,
                               bool aJoined) {
    Http3Session::McquicChannelInfo info;
    info.mSource.AssignLiteral("127.0.0.1");
    info.mGroup.AssignLiteral("232.0.0.1");
    info.mPort = 4433;
    info.mAddressFamily = 4;
    info.mMaxRateKibps = aRateKibps;
    info.mSubscriptionId = aSubscriptionId;
    info.mJoined = aJoined;
    aSession->mMcquicChannels.InsertOrUpdate(nsCString(aChannelId), info);
    aSession->mMcquicSubscriptionToChannel.InsertOrUpdate(
        aSubscriptionId, nsCString(aChannelId));
  }

  static bool JoinForTest(Http3Session* aSession,
                          const nsACString& aChannelId) {
    if (!aSession->McquicJoinWithinLimits(aChannelId) ||
        !aSession->mMcquicReceiver) {
      return false;
    }
    auto channel = aSession->mMcquicChannels.Lookup(aChannelId);
    if (!channel || channel.Data().mSubscriptionId == 0 ||
        NS_FAILED(
            aSession->mMcquicReceiver->Join(channel.Data().mSubscriptionId))) {
      return false;
    }
    channel.Data().mJoined = true;
    return true;
  }

  static nsresult Disrupt(Http3Session* aSession, Disruption aDisruption) {
    return aSession->HandleMcquicDisruption(
        aDisruption == Disruption::PathMigration
            ? Http3Session::McquicDisruption::PathMigration
            : Http3Session::McquicDisruption::ReceiverFailure);
  }

  static nsresult CheckNetworkChange(Http3Session* aSession) {
    return aSession->CheckMcquicNetworkChange();
  }

  static nsresult ProcessPackets(Http3Session* aSession) {
    return aSession->ProcessMcquicPackets();
  }

  static bool IsRevokedAndCleared(const Http3Session* aSession) {
    return aSession->mMcquicOperationState ==
               Http3Session::McquicOperationState::Revoked &&
           aSession->mMcquicPermittedSessionId.isNothing() &&
           aSession->mMcquicChannels.Count() == 0 &&
           aSession->mMcquicSubscriptionToChannel.Count() == 0 &&
           !aSession->mMcquicReceiver;
  }
};

TEST(TestHttp3SessionMcquic, ReceiverAdmissionIsTransactionalAtExactCaps)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicPref, true));
  auto clearPref = MakeScopeExit([] { Preferences::ClearUser(kMcquicPref); });

  RunOnSocketThread(
      "TestHttp3SessionMcquic::ReceiverAdmissionIsTransactionalAtExactCaps",
      [] {
        {
          FakeReceiverState state;
          RefPtr<Http3Session> session = new Http3Session();
          Http3SessionMcquicTestPeer::Activate(
              session, nullptr, MakeUnique<FakeMcquicReceiver>(&state));

          for (uint32_t i = 0; i < 32; ++i) {
            ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
                session, Announcement(nsPrintfCString("channel-%u", i))));
          }
          EXPECT_EQ(Http3SessionMcquicTestPeer::ChannelCount(session), 32U);
          EXPECT_EQ(state.mAddCalls, 32U);

          ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
              session, Announcement("channel-over-cap"_ns)));
          EXPECT_EQ(Http3SessionMcquicTestPeer::ChannelCount(session), 32U);
          EXPECT_EQ(state.mAddCalls, 32U);
        }

        {
          FakeReceiverState state;
          state.mAddResult = NS_ERROR_FAILURE;
          RefPtr<Http3Session> session = new Http3Session();
          Http3SessionMcquicTestPeer::Activate(
              session, nullptr, MakeUnique<FakeMcquicReceiver>(&state));

          for (uint32_t i = 0; i < 32; ++i) {
            ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
                session, Announcement(nsPrintfCString("failed-%u", i))));
          }
          EXPECT_EQ(Http3SessionMcquicTestPeer::ChannelCount(session), 0U);
          EXPECT_EQ(state.mAddCalls, 32U);

          state.mAddResult = NS_OK;
          ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
              session, Announcement("working-after-failures"_ns)));
          EXPECT_EQ(Http3SessionMcquicTestPeer::ChannelCount(session), 1U);
        }

        {
          FakeReceiverState state;
          RefPtr<Http3Session> session = new Http3Session();
          Http3SessionMcquicTestPeer::Activate(
              session, nullptr, MakeUnique<FakeMcquicReceiver>(&state));

          ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
              session, Announcement("rate-at-cap"_ns, 100000)));
          ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
              session, Announcement("rate-over-cap"_ns, 1)));
          ASSERT_NS_SUCCEEDED(Http3SessionMcquicTestPeer::Admit(
              session, Announcement("bad-family"_ns, 1, 5)));
          EXPECT_EQ(Http3SessionMcquicTestPeer::ChannelCount(session), 1U);
          EXPECT_EQ(state.mAddCalls, 1U);
        }
      });
}

TEST(TestHttp3SessionMcquic, ReceiverJoinAdmissionIsExactAndTransactional)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicPref, true));
  auto clearPref = MakeScopeExit([] { Preferences::ClearUser(kMcquicPref); });

  RunOnSocketThread(
      "TestHttp3SessionMcquic::ReceiverJoinAdmissionIsExactAndTransactional",
      [] {
        FakeReceiverState state;
        RefPtr<Http3Session> session = new Http3Session();
        Http3SessionMcquicTestPeer::Activate(
            session, nullptr, MakeUnique<FakeMcquicReceiver>(&state));

        for (uint32_t i = 0; i < 32; ++i) {
          nsCString channel = nsPrintfCString("join-%u", i);
          Http3SessionMcquicTestPeer::AddJoinCandidate(session, channel, 1,
                                                       i + 1, false);
          EXPECT_TRUE(
              Http3SessionMcquicTestPeer::JoinForTest(session, channel));
        }
        EXPECT_EQ(state.mJoinCalls, 32U);

        Http3SessionMcquicTestPeer::AddJoinCandidate(
            session, "join-over-cap"_ns, 1, 33, false);
        EXPECT_FALSE(Http3SessionMcquicTestPeer::JoinForTest(
            session, "join-over-cap"_ns));
        EXPECT_EQ(state.mJoinCalls, 32U);

        FakeReceiverState rateState;
        RefPtr<Http3Session> rateSession = new Http3Session();
        Http3SessionMcquicTestPeer::Activate(
            rateSession, nullptr, MakeUnique<FakeMcquicReceiver>(&rateState));
        Http3SessionMcquicTestPeer::AddJoinCandidate(
            rateSession, "joined-rate"_ns, 99999, 1, true);
        Http3SessionMcquicTestPeer::AddJoinCandidate(
            rateSession, "rate-at-cap"_ns, 1, 2, false);
        EXPECT_TRUE(Http3SessionMcquicTestPeer::JoinForTest(rateSession,
                                                            "rate-at-cap"_ns));
        Http3SessionMcquicTestPeer::AddJoinCandidate(
            rateSession, "rate-over-cap"_ns, 1, 3, false);
        EXPECT_FALSE(Http3SessionMcquicTestPeer::JoinForTest(
            rateSession, "rate-over-cap"_ns));

        FakeReceiverState failedState;
        failedState.mJoinResult = NS_ERROR_FAILURE;
        RefPtr<Http3Session> failedSession = new Http3Session();
        Http3SessionMcquicTestPeer::Activate(
            failedSession, nullptr,
            MakeUnique<FakeMcquicReceiver>(&failedState));
        Http3SessionMcquicTestPeer::AddJoinCandidate(
            failedSession, "failed-join"_ns, 1, 1, false);
        EXPECT_FALSE(Http3SessionMcquicTestPeer::JoinForTest(failedSession,
                                                             "failed-join"_ns));
        EXPECT_EQ(failedState.mJoinCalls, 1U);
      });
}

TEST(TestHttp3SessionMcquic, DisruptionsAbandonRevokeAndPreserveConnection)
{
  ASSERT_NS_SUCCEEDED(Preferences::SetBool(kMcquicPref, true));
  auto clearPref = MakeScopeExit([] { Preferences::ClearUser(kMcquicPref); });

  RunOnSocketThread(
      "TestHttp3SessionMcquic::DisruptionsAbandonRevokeAndPreserveConnection",
      [] {
        const auto runDisruption =
            [](Http3SessionMcquicTestPeer::Disruption reason) {
              FakeReceiverState state;
              RefPtr<NeqoHttp3Conn> conn = NewMcquicConnection();
              ASSERT_TRUE(conn);
              RefPtr<Http3Session> session = new Http3Session();
              Http3SessionMcquicTestPeer::Activate(
                  session, conn, MakeUnique<FakeMcquicReceiver>(&state));
              Http3SessionMcquicTestPeer::AddJoinCandidate(session, "joined"_ns,
                                                           1, 1, true);

              auto pending = neqo_glue_test_process_output_and_send(
                  conn, NeqoGlueTestSendOutcome::WouldBlock, 0, 8, true);
              ASSERT_EQ(pending.result, NS_BASE_STREAM_WOULD_BLOCK);
              ASSERT_TRUE(neqo_glue_test_has_pending_output(conn));

              ASSERT_NS_SUCCEEDED(
                  Http3SessionMcquicTestPeer::Disrupt(session, reason));
              EXPECT_FALSE(neqo_glue_test_has_pending_output(conn));
              EXPECT_TRUE(neqo_glue_test_mcquic_revoked_clean(conn));
              EXPECT_TRUE(
                  Http3SessionMcquicTestPeer::IsRevokedAndCleared(session));
              EXPECT_EQ(state.mLeaveCalls, 1U);
              EXPECT_EQ(state.mRemoveCalls, 1U);
              EXPECT_FALSE(session->IsClosing());

              auto ordinaryOutput = neqo_glue_test_process_output_and_send(
                  conn, NeqoGlueTestSendOutcome::Transient, 0, 8, true);
              EXPECT_NE(ordinaryOutput.result, NS_ERROR_UNEXPECTED);
              EXPECT_FALSE(ordinaryOutput.output_pending);
            };

        runDisruption(Http3SessionMcquicTestPeer::Disruption::PathMigration);

        {
          FakeReceiverState state;
          RefPtr<NeqoHttp3Conn> conn = NewMcquicConnection();
          ASSERT_TRUE(conn);
          RefPtr<Http3Session> session = new Http3Session();
          Http3SessionMcquicTestPeer::Activate(
              session, conn, MakeUnique<FakeMcquicReceiver>(&state));
          Http3SessionMcquicTestPeer::AddJoinCandidate(
              session, "network-change"_ns, 1, 1, true);
          auto pending = neqo_glue_test_process_output_and_send(
              conn, NeqoGlueTestSendOutcome::WouldBlock, 0, 8, true);
          ASSERT_TRUE(pending.output_pending);

          ASSERT_NS_SUCCEEDED(gSocketTransportService->Observe(
              nullptr, NS_NETWORK_LINK_TOPIC,
              u"" NS_NETWORK_LINK_DATA_CHANGED));
          ASSERT_NS_SUCCEEDED(
              Http3SessionMcquicTestPeer::CheckNetworkChange(session));
          EXPECT_FALSE(neqo_glue_test_has_pending_output(conn));
          EXPECT_TRUE(neqo_glue_test_mcquic_revoked_clean(conn));
          EXPECT_TRUE(Http3SessionMcquicTestPeer::IsRevokedAndCleared(session));
          EXPECT_EQ(state.mLeaveCalls, 1U);
          EXPECT_EQ(state.mRemoveCalls, 1U);
          EXPECT_FALSE(session->IsClosing());
          auto ordinaryOutput = neqo_glue_test_process_output_and_send(
              conn, NeqoGlueTestSendOutcome::Transient, 0, 8, true);
          EXPECT_NE(ordinaryOutput.result, NS_ERROR_UNEXPECTED);
          EXPECT_FALSE(ordinaryOutput.output_pending);
        }

        {
          FakeReceiverState state;
          state.mPollResult = NS_ERROR_FAILURE;
          RefPtr<NeqoHttp3Conn> conn = NewMcquicConnection();
          ASSERT_TRUE(conn);
          RefPtr<Http3Session> session = new Http3Session();
          Http3SessionMcquicTestPeer::Activate(
              session, conn, MakeUnique<FakeMcquicReceiver>(&state));
          Http3SessionMcquicTestPeer::AddJoinCandidate(
              session, "poll-failure"_ns, 1, 1, true);
          auto pending = neqo_glue_test_process_output_and_send(
              conn, NeqoGlueTestSendOutcome::WouldBlock, 0, 8, true);
          ASSERT_TRUE(pending.output_pending);

          ASSERT_NS_SUCCEEDED(
              Http3SessionMcquicTestPeer::ProcessPackets(session));
          EXPECT_EQ(state.mPollCalls, 1U);
          EXPECT_FALSE(neqo_glue_test_has_pending_output(conn));
          EXPECT_TRUE(neqo_glue_test_mcquic_revoked_clean(conn));
          EXPECT_TRUE(Http3SessionMcquicTestPeer::IsRevokedAndCleared(session));
          EXPECT_EQ(state.mLeaveCalls, 1U);
          EXPECT_EQ(state.mRemoveCalls, 1U);
          EXPECT_FALSE(session->IsClosing());
          auto ordinaryOutput = neqo_glue_test_process_output_and_send(
              conn, NeqoGlueTestSendOutcome::Transient, 0, 8, true);
          EXPECT_NE(ordinaryOutput.result, NS_ERROR_UNEXPECTED);
          EXPECT_FALSE(ordinaryOutput.output_pending);
        }
      });
}

}  // namespace mozilla::net
