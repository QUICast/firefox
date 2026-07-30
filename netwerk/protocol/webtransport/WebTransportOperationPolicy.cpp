/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/net/WebTransportOperationPolicy.h"

#include "mozilla/StaticPrefs_network.h"
#include "mozilla/dom/ClientInfo.h"
#include "nsContentUtils.h"
#include "nsIPrincipal.h"
#include "nsIURI.h"

namespace mozilla::net {

bool WebTransportOperationPolicy::MatchesContext(
    const nsACString& aInitiatingOrigin, const nsACString& aTargetOrigin,
    const OriginAttributes& aOriginAttributes,
    const Maybe<nsID>& aClientContextId,
    const Maybe<uint64_t>& aBrowsingContextId) const {
  return IsValid() && mInitiatingOrigin.Equals(aInitiatingOrigin) &&
         mTargetOrigin.Equals(aTargetOrigin) &&
         mOriginAttributes == aOriginAttributes &&
         MatchesIdentity(aClientContextId, aBrowsingContextId);
}

bool WebTransportOperationPolicy::MatchesIdentity(
    const Maybe<nsID>& aClientContextId,
    const Maybe<uint64_t>& aBrowsingContextId) const {
  if (!IsValid() || mClientContextBound != aClientContextId.isSome() ||
      mBrowsingContextBound != aBrowsingContextId.isSome()) {
    return false;
  }
  return (!mClientContextBound || mClientContextId == aClientContextId.ref()) &&
         (!mBrowsingContextBound ||
          mBrowsingContextId == aBrowsingContextId.ref());
}

void ApplyWebTransportMulticastCapabilityGate(
    WebTransportOperationPolicy& aPolicy) {
  aPolicy.mEffectiveMulticast =
      aPolicy.mMulticast == WebTransportMulticastPolicy::Allow &&
              StaticPrefs::network_http_http3_mcquic_enabled()
          ? WebTransportMulticastPolicy::Allow
          : WebTransportMulticastPolicy::Prohibit;
}

nsresult GetWebTransportInitiatingOrigin(nsIPrincipal* aPrincipal,
                                         nsACString& aOrigin) {
  if (!aPrincipal) {
    return NS_ERROR_INVALID_ARG;
  }

  nsresult rv = aPrincipal->GetWebExposedOriginSerialization(aOrigin);
  if (NS_SUCCEEDED(rv) && !aOrigin.IsEmpty()) {
    return NS_OK;
  }

  aOrigin.Truncate();
  return aPrincipal->GetOrigin(aOrigin);
}

Result<WebTransportOperationPolicy, nsresult> CreateWebTransportOperationPolicy(
    nsIPrincipal* aPrincipal, nsIURI* aTarget,
    const Maybe<dom::ClientInfo>& aClientInfo, uint64_t aBrowsingContextId,
    WebTransportMulticastPolicy aMulticast, const nsID& aOperationId) {
  if (!aPrincipal || !aTarget || aOperationId == nsID{}) {
    return Err(NS_ERROR_INVALID_ARG);
  }

  WebTransportOperationPolicy policy;
  policy.mMulticast = aMulticast;
  ApplyWebTransportMulticastCapabilityGate(policy);
  policy.mOperationId = aOperationId;
  policy.mOriginAttributes = aPrincipal->OriginAttributesRef();
  if (aBrowsingContextId != 0) {
    policy.mBrowsingContextBound = true;
    policy.mBrowsingContextId = aBrowsingContextId;
  }

  nsresult rv =
      GetWebTransportInitiatingOrigin(aPrincipal, policy.mInitiatingOrigin);
  if (NS_FAILED(rv)) {
    return Err(rv);
  }

  rv = nsContentUtils::GetWebExposedOriginSerialization(aTarget,
                                                        policy.mTargetOrigin);
  if (NS_FAILED(rv)) {
    return Err(rv);
  }

  if (aClientInfo.isSome()) {
    auto clientPrincipal = aClientInfo.ref().GetPrincipal();
    if (clientPrincipal.isErr()) {
      return Err(clientPrincipal.unwrapErr());
    }
    nsCOMPtr<nsIPrincipal> clientPrincipalValue = clientPrincipal.unwrap();
    if (!aPrincipal->Equals(clientPrincipalValue.get())) {
      return Err(NS_ERROR_DOM_SECURITY_ERR);
    }
    policy.mClientContextBound = true;
    policy.mClientContextId = aClientInfo.ref().Id();
  }

  return policy;
}

bool IsWebTransportMulticastConnectionEligible(
    const Maybe<WebTransportOperationPolicy>& aPolicy, uint64_t aWebTransportId,
    bool aIsWebTransport, bool aIsHttp3, bool aIsOuterProxyConnection,
    const OriginAttributes& aOriginAttributes) {
  return StaticPrefs::network_http_http3_mcquic_enabled() &&
         IsWebTransportMulticastBindingValid(
             aPolicy, aWebTransportId, aIsWebTransport, aIsHttp3,
             aIsOuterProxyConnection, aOriginAttributes) &&
         aPolicy.ref().IsMulticastEligible();
}

bool IsWebTransportMulticastBindingValid(
    const Maybe<WebTransportOperationPolicy>& aPolicy, uint64_t aWebTransportId,
    bool aIsWebTransport, bool aIsHttp3, bool aIsOuterProxyConnection,
    const OriginAttributes& aOriginAttributes) {
  return aIsWebTransport && aIsHttp3 && !aIsOuterProxyConnection &&
         aPolicy.isSome() &&
         aPolicy.ref().IsBoundToConnection(aWebTransportId, aOriginAttributes);
}

bool WebTransportTargetOriginMatchesConnection(
    const WebTransportOperationPolicy& aPolicy, const nsACString& aHost,
    int32_t aPort) {
  if (aHost.IsEmpty() || aPort <= 0) {
    return false;
  }

  nsAutoCString targetOrigin("https://");
  const bool needsIpv6Brackets =
      aHost.FindChar(':') != kNotFound && aHost.First() != '[';
  if (needsIpv6Brackets) {
    targetOrigin.Append('[');
  }
  targetOrigin.Append(aHost);
  if (needsIpv6Brackets) {
    targetOrigin.Append(']');
  }
  if (aPort != 443) {
    targetOrigin.Append(':');
    targetOrigin.AppendInt(aPort);
  }
  return aPolicy.mTargetOrigin.Equals(targetOrigin);
}

bool WebTransportOperationMustRejectRedirectStatus(uint32_t aStatus) {
  return aStatus >= 300 && aStatus < 400;
}

}  // namespace mozilla::net
