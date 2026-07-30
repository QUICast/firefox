/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_net_WebTransportOperationPolicy_h
#define mozilla_net_WebTransportOperationPolicy_h

#include <cstdint>

#include "mozilla/Maybe.h"
#include "mozilla/OriginAttributes.h"
#include "mozilla/Result.h"
#include "nsID.h"
#include "nsString.h"

class nsIPrincipal;
class nsIURI;

namespace mozilla::dom {
class ClientInfo;
}

namespace mozilla::net {

enum class WebTransportMulticastPolicy : uint8_t {
  Prohibit,
  Allow,
};

struct WebTransportOperationPolicy {
  WebTransportMulticastPolicy mMulticast =
      WebTransportMulticastPolicy::Prohibit;
  WebTransportMulticastPolicy mEffectiveMulticast =
      WebTransportMulticastPolicy::Prohibit;
  nsID mOperationId{};
  nsCString mInitiatingOrigin;
  nsCString mTargetOrigin;
  OriginAttributes mOriginAttributes;
  bool mClientContextBound = false;
  nsID mClientContextId{};
  bool mBrowsingContextBound = false;
  uint64_t mBrowsingContextId = 0;
  uint64_t mWebTransportId = 0;

  bool AllowsMulticast() const {
    return mMulticast == WebTransportMulticastPolicy::Allow;
  }

  bool IsMulticastEligible() const {
    return mEffectiveMulticast == WebTransportMulticastPolicy::Allow;
  }

  bool IsValid() const {
    return mOperationId != nsID{} && !mInitiatingOrigin.IsEmpty() &&
           !mTargetOrigin.IsEmpty() &&
           mClientContextBound == (mClientContextId != nsID{}) &&
           mBrowsingContextBound == (mBrowsingContextId != 0);
  }

  void ProhibitMulticast() {
    mMulticast = WebTransportMulticastPolicy::Prohibit;
    mEffectiveMulticast = WebTransportMulticastPolicy::Prohibit;
  }

  bool IsBoundToConnection(uint64_t aWebTransportId,
                           const OriginAttributes& aOriginAttributes) const {
    return IsValid() && AllowsMulticast() && aWebTransportId != 0 &&
           mWebTransportId == aWebTransportId &&
           mOriginAttributes == aOriginAttributes;
  }

  bool IsValidForConnection(uint64_t aWebTransportId,
                            const OriginAttributes& aOriginAttributes) const {
    return IsMulticastEligible() &&
           IsBoundToConnection(aWebTransportId, aOriginAttributes);
  }

  bool MatchesContext(const nsACString& aInitiatingOrigin,
                      const nsACString& aTargetOrigin,
                      const OriginAttributes& aOriginAttributes,
                      const Maybe<nsID>& aClientContextId,
                      const Maybe<uint64_t>& aBrowsingContextId) const;

  bool MatchesIdentity(const Maybe<nsID>& aClientContextId,
                       const Maybe<uint64_t>& aBrowsingContextId) const;
};

void ApplyWebTransportMulticastCapabilityGate(
    WebTransportOperationPolicy& aPolicy);

nsresult GetWebTransportInitiatingOrigin(nsIPrincipal* aPrincipal,
                                         nsACString& aOrigin);

Result<WebTransportOperationPolicy, nsresult> CreateWebTransportOperationPolicy(
    nsIPrincipal* aPrincipal, nsIURI* aTarget,
    const Maybe<dom::ClientInfo>& aClientInfo, uint64_t aBrowsingContextId,
    WebTransportMulticastPolicy aMulticast, const nsID& aOperationId);

bool IsWebTransportMulticastConnectionEligible(
    const Maybe<WebTransportOperationPolicy>& aPolicy, uint64_t aWebTransportId,
    bool aIsWebTransport, bool aIsHttp3, bool aIsOuterProxyConnection,
    const OriginAttributes& aOriginAttributes);

bool IsWebTransportMulticastBindingValid(
    const Maybe<WebTransportOperationPolicy>& aPolicy, uint64_t aWebTransportId,
    bool aIsWebTransport, bool aIsHttp3, bool aIsOuterProxyConnection,
    const OriginAttributes& aOriginAttributes);

bool WebTransportTargetOriginMatchesConnection(
    const WebTransportOperationPolicy& aPolicy, const nsACString& aHost,
    int32_t aPort);

constexpr bool WebTransportOperationAllowsCredentials() { return false; }

bool WebTransportOperationMustRejectRedirectStatus(uint32_t aStatus);

}  // namespace mozilla::net

#include "ipc/EnumSerializer.h"

namespace IPC {

template <>
struct ParamTraits<mozilla::net::WebTransportMulticastPolicy>
    : public ContiguousEnumSerializerInclusive<
          mozilla::net::WebTransportMulticastPolicy,
          mozilla::net::WebTransportMulticastPolicy::Prohibit,
          mozilla::net::WebTransportMulticastPolicy::Allow> {};

}  // namespace IPC

#endif  // mozilla_net_WebTransportOperationPolicy_h
