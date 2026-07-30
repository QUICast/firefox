/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "mozilla/Preferences.h"
#include "mozilla/gtest/MozAssertions.h"
#include "mozilla/net/NeckoChannelParams.h"
#include "mozilla/net/WebTransportOperationPolicy.h"
#include "nsHttpConnectionInfo.h"

using namespace mozilla;
using namespace mozilla::net;

namespace {

void AssertSamePolicy(const WebTransportOperationPolicy& aExpected,
                      const WebTransportOperationPolicy& aActual) {
  EXPECT_EQ(aExpected.mMulticast, aActual.mMulticast);
  EXPECT_EQ(aExpected.mEffectiveMulticast, aActual.mEffectiveMulticast);
  EXPECT_EQ(aExpected.mOperationId, aActual.mOperationId);
  EXPECT_EQ(aExpected.mInitiatingOrigin, aActual.mInitiatingOrigin);
  EXPECT_EQ(aExpected.mTargetOrigin, aActual.mTargetOrigin);
  EXPECT_EQ(aExpected.mOriginAttributes, aActual.mOriginAttributes);
  EXPECT_EQ(aExpected.mClientContextBound, aActual.mClientContextBound);
  EXPECT_EQ(aExpected.mClientContextId, aActual.mClientContextId);
  EXPECT_EQ(aExpected.mBrowsingContextBound, aActual.mBrowsingContextBound);
  EXPECT_EQ(aExpected.mBrowsingContextId, aActual.mBrowsingContextId);
  EXPECT_EQ(aExpected.mWebTransportId, aActual.mWebTransportId);
}

WebTransportOperationPolicy MakePolicy() {
  WebTransportOperationPolicy policy;
  policy.mMulticast = WebTransportMulticastPolicy::Allow;
  policy.mEffectiveMulticast = WebTransportMulticastPolicy::Allow;
  policy.mOperationId = nsID::GenerateUUID();
  policy.mInitiatingOrigin.AssignLiteral("https://initiator.example");
  policy.mTargetOrigin.AssignLiteral("https://target.example");
  policy.mClientContextBound = true;
  policy.mClientContextId = nsID::GenerateUUID();
  policy.mBrowsingContextBound = true;
  policy.mBrowsingContextId = 42;
  policy.mWebTransportId = 17;
  return policy;
}

}  // namespace

TEST(TestWebTransportOperationPolicy, ConnectionInfoCloneAndIpcRoundTrip)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);

  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  ASSERT_TRUE(policy.IsValid());
  info->SetWebTransportOperationPolicy(policy);

  RefPtr<nsHttpConnectionInfo> clone = info->Clone();
  ASSERT_TRUE(clone->GetWebTransportOperationPolicy().isSome());
  AssertSamePolicy(policy, clone->GetWebTransportOperationPolicy().ref());
  EXPECT_EQ(info->GetWebTransportId(), clone->GetWebTransportId());
  EXPECT_EQ(info->HashKey(), clone->HashKey());

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(info, args);
  RefPtr<nsHttpConnectionInfo> roundTrip =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  ASSERT_TRUE(roundTrip->GetWebTransportOperationPolicy().isSome());
  AssertSamePolicy(policy, roundTrip->GetWebTransportOperationPolicy().ref());
  EXPECT_EQ(info->GetWebTransportId(), roundTrip->GetWebTransportId());
  EXPECT_EQ(info->HashKey(), roundTrip->HashKey());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, IpcCannotAuthorizeAnotherConnection)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(info, args);
  args.webTransportId() = 18;
  RefPtr<nsHttpConnectionInfo> rebound =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  ASSERT_TRUE(rebound->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(
      rebound->GetWebTransportOperationPolicy().ref().IsValidForConnection(
          rebound->GetWebTransportId(), rebound->GetOriginAttributes()));
  EXPECT_FALSE(
      rebound->GetWebTransportOperationPolicy().ref().AllowsMulticast());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, CapabilityGateIsRecomputedAfterIpc)
{
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(info, args);
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", false));
  RefPtr<nsHttpConnectionInfo> roundTrip =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  ASSERT_TRUE(roundTrip->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(
      roundTrip->GetWebTransportOperationPolicy().ref().IsMulticastEligible());
  EXPECT_FALSE(
      roundTrip->GetWebTransportOperationPolicy().ref().IsValidForConnection(
          roundTrip->GetWebTransportId(), roundTrip->GetOriginAttributes()));

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, ProcessRestartDoesNotRestorePermission)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> restarted =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  restarted->SetWebTransportId(17);

  EXPECT_TRUE(restarted->GetWebTransportOperationPolicy().isNothing());

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(restarted, args);
  RefPtr<nsHttpConnectionInfo> roundTrip =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  EXPECT_TRUE(roundTrip->GetWebTransportOperationPolicy().isNothing());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, OuterProxyCannotUseTargetPermission)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  WebTransportOperationPolicy policy = MakePolicy();
  Maybe<WebTransportOperationPolicy> binding = Some(policy);
  OriginAttributes originAttributes;

  EXPECT_TRUE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId, true, true, false, originAttributes));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId, true, true, true, originAttributes));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId + 1, true, true, false,
      originAttributes));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId, false, true, false, originAttributes));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId, true, false, false, originAttributes));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      Nothing(), policy.mWebTransportId, true, true, false, originAttributes));

  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", false));
  EXPECT_FALSE(IsWebTransportMulticastConnectionEligible(
      binding, policy.mWebTransportId, true, true, false, originAttributes));
  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, RetryCloneBindingIsAllOrNothing)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);

  RefPtr<nsHttpConnectionInfo> h3Retry = info->CloneAndAdoptPortAndAlpn(
      443, happy_eyeballs::ConnectionAttemptHttpVersions::H3);
  ASSERT_TRUE(h3Retry->GetWebTransportOperationPolicy().isSome());
  AssertSamePolicy(policy, h3Retry->GetWebTransportOperationPolicy().ref());
  EXPECT_EQ(h3Retry->GetWebTransportId(), policy.mWebTransportId);
  EXPECT_TRUE(h3Retry->IsWebTransportMulticastEligible());

  RefPtr<nsHttpConnectionInfo> tcpRetry = info->CloneAndAdoptPortAndAlpn(
      443, happy_eyeballs::ConnectionAttemptHttpVersions::H2OrH1);
  EXPECT_FALSE(tcpRetry->IsHttp3());
  EXPECT_TRUE(tcpRetry->GetWebTransportOperationPolicy().isNothing());
  EXPECT_FALSE(tcpRetry->IsWebTransportMulticastEligible());

  RefPtr<nsHttpConnectionInfo> direct;
  info->CloneAsDirectRoute(getter_AddRefs(direct));
  ASSERT_TRUE(direct);
  EXPECT_EQ(direct->GetWebTransportId(), 0U);
  EXPECT_TRUE(direct->GetWebTransportOperationPolicy().isNothing());
  EXPECT_FALSE(direct->IsWebTransportMulticastEligible());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, RequestSecurityProfile)
{
  EXPECT_FALSE(WebTransportOperationAllowsCredentials());
  EXPECT_FALSE(WebTransportOperationMustRejectRedirectStatus(299));
  for (uint32_t status = 300; status < 400; ++status) {
    EXPECT_TRUE(WebTransportOperationMustRejectRedirectStatus(status))
        << "status=" << status;
  }
  EXPECT_FALSE(WebTransportOperationMustRejectRedirectStatus(400));
}

TEST(TestWebTransportOperationPolicy, ContextBindingChecksEveryAvailableField)
{
  WebTransportOperationPolicy policy = MakePolicy();
  OriginAttributes originAttributes;
  policy.mOriginAttributes = originAttributes;
  Maybe<nsID> clientContextId = Some(policy.mClientContextId);
  Maybe<uint64_t> browsingContextId = Some(policy.mBrowsingContextId);

  EXPECT_TRUE(policy.MatchesContext(policy.mInitiatingOrigin,
                                    policy.mTargetOrigin, originAttributes,
                                    clientContextId, browsingContextId));
  EXPECT_FALSE(policy.MatchesContext("https://other-initiator.example"_ns,
                                     policy.mTargetOrigin, originAttributes,
                                     clientContextId, browsingContextId));
  EXPECT_FALSE(policy.MatchesContext(
      policy.mInitiatingOrigin, "https://other-target.example"_ns,
      originAttributes, clientContextId, browsingContextId));

  OriginAttributes otherOriginAttributes = originAttributes;
  otherOriginAttributes.mPrivateBrowsingId = 1;
  EXPECT_FALSE(policy.MatchesContext(
      policy.mInitiatingOrigin, policy.mTargetOrigin, otherOriginAttributes,
      clientContextId, browsingContextId));
  EXPECT_FALSE(policy.MatchesContext(
      policy.mInitiatingOrigin, policy.mTargetOrigin, originAttributes,
      Some(nsID::GenerateUUID()), browsingContextId));
  EXPECT_FALSE(policy.MatchesContext(
      policy.mInitiatingOrigin, policy.mTargetOrigin, originAttributes,
      clientContextId, Some(policy.mBrowsingContextId + 1)));

  EXPECT_FALSE(policy.MatchesContext(policy.mInitiatingOrigin,
                                     policy.mTargetOrigin, originAttributes,
                                     Nothing(), browsingContextId));
  EXPECT_FALSE(policy.MatchesContext(policy.mInitiatingOrigin,
                                     policy.mTargetOrigin, originAttributes,
                                     clientContextId, Nothing()));
  EXPECT_FALSE(policy.MatchesContext(policy.mInitiatingOrigin,
                                     policy.mTargetOrigin, originAttributes,
                                     Nothing(), Nothing()));
}

TEST(TestWebTransportOperationPolicy, WorkerAndNativeBindingPresence)
{
  WebTransportOperationPolicy worker = MakePolicy();
  worker.mBrowsingContextBound = false;
  worker.mBrowsingContextId = 0;
  Maybe<nsID> workerClient = Some(worker.mClientContextId);
  EXPECT_TRUE(worker.MatchesIdentity(workerClient, Nothing()));
  EXPECT_FALSE(worker.MatchesIdentity(Nothing(), Nothing()));
  EXPECT_FALSE(worker.MatchesIdentity(workerClient, Some(42)));

  WebTransportOperationPolicy native = MakePolicy();
  native.mClientContextBound = false;
  native.mClientContextId = nsID{};
  native.mBrowsingContextBound = false;
  native.mBrowsingContextId = 0;
  EXPECT_TRUE(native.IsValid());
  EXPECT_TRUE(native.MatchesIdentity(Nothing(), Nothing()));
  EXPECT_FALSE(native.MatchesIdentity(Some(nsID::GenerateUUID()), Nothing()));
  EXPECT_FALSE(native.MatchesIdentity(Nothing(), Some(42)));
}

TEST(TestWebTransportOperationPolicy, MalformedBindingPresenceFailsClosed)
{
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mClientContextBound = false;
  EXPECT_FALSE(policy.IsValid());

  policy = MakePolicy();
  policy.mBrowsingContextBound = false;
  EXPECT_FALSE(policy.IsValid());
}

TEST(TestWebTransportOperationPolicy,
     InvalidConnectionBindingIsPermanentlyProhibited)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("other-target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);

  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);
  ASSERT_TRUE(info->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(info->GetWebTransportOperationPolicy().ref().AllowsMulticast());
  EXPECT_FALSE(info->IsWebTransportMulticastEligible());

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(info, args);
  RefPtr<nsHttpConnectionInfo> roundTrip =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  ASSERT_TRUE(roundTrip->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(
      roundTrip->GetWebTransportOperationPolicy().ref().AllowsMulticast());
  EXPECT_FALSE(roundTrip->IsWebTransportMulticastEligible());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, ConnectionMutationCannotRestorePermission)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);
  ASSERT_TRUE(info->IsWebTransportMulticastEligible());

  info->SetWebTransport(false);
  EXPECT_FALSE(info->IsWebTransportMulticastEligible());
  ASSERT_TRUE(info->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(info->GetWebTransportOperationPolicy().ref().AllowsMulticast());

  info->SetWebTransport(true);
  info->SetWebTransportId(17);
  EXPECT_FALSE(info->IsWebTransportMulticastEligible());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, IpcBindingCannotMoveToHttp1OrHttp2)
{
  ASSERT_NS_SUCCEEDED(
      Preferences::SetBool("network.http.http3.mcquic.enabled", true));
  OriginAttributes originAttributes;
  RefPtr<nsHttpConnectionInfo> info =
      new nsHttpConnectionInfo("target.example"_ns, 443, "h3"_ns, ""_ns,
                               nullptr, originAttributes, true, true, true);
  info->SetWebTransportId(17);
  WebTransportOperationPolicy policy = MakePolicy();
  policy.mOriginAttributes = originAttributes;
  info->SetWebTransportOperationPolicy(policy);

  HttpConnectionInfoCloneArgs args;
  nsHttpConnectionInfo::SerializeHttpConnectionInfo(info, args);
  args.isHttp3() = false;
  args.npnToken().Truncate();
  RefPtr<nsHttpConnectionInfo> tcp =
      nsHttpConnectionInfo::DeserializeHttpConnectionInfoCloneArgs(args);
  ASSERT_TRUE(tcp->GetWebTransportOperationPolicy().isSome());
  EXPECT_FALSE(tcp->GetWebTransportOperationPolicy().ref().AllowsMulticast());
  EXPECT_FALSE(tcp->IsWebTransportMulticastEligible());

  Preferences::ClearUser("network.http.http3.mcquic.enabled");
}

TEST(TestWebTransportOperationPolicy, TargetOriginCanonicalConnectionMatch)
{
  WebTransportOperationPolicy policy = MakePolicy();
  EXPECT_TRUE(WebTransportTargetOriginMatchesConnection(
      policy, "target.example"_ns, 443));
  EXPECT_FALSE(WebTransportTargetOriginMatchesConnection(
      policy, "other.example"_ns, 443));

  policy.mTargetOrigin.AssignLiteral("https://target.example:7443");
  EXPECT_TRUE(WebTransportTargetOriginMatchesConnection(
      policy, "target.example"_ns, 7443));
  policy.mTargetOrigin.AssignLiteral("https://[2001:db8::1]");
  EXPECT_TRUE(
      WebTransportTargetOriginMatchesConnection(policy, "2001:db8::1"_ns, 443));
}
