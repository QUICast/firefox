/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef DOM_WEBTRANSPORT_PARENT_WEBTRANSPORTPARENT_H_
#define DOM_WEBTRANSPORT_PARENT_WEBTRANSPORTPARENT_H_

#include "ErrorList.h"
#include "mozilla/Maybe.h"
#include "mozilla/dom/ClientIPCTypes.h"
#include "mozilla/dom/PWebTransportParent.h"
#include "mozilla/ipc/Endpoint.h"
#include "mozilla/ipc/PBackgroundSharedTypes.h"
#include "mozilla/net/WebTransportOperationPolicy.h"
#include "nsIPrincipal.h"
#include "nsISupports.h"
#include "nsIWebTransport.h"
#include "nsIWebTransportStream.h"
#include "nsTHashMap.h"

namespace mozilla::dom {

enum class WebTransportReliabilityMode : uint8_t;
class WebTransportParentLifecycleTestPeer;

class WebTransportParent : public PWebTransportParent,
                           public WebTransportSessionEventListener {
  using IPCResult = mozilla::ipc::IPCResult;

 public:
  WebTransportParent() = default;

  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_WEBTRANSPORTSESSIONEVENTLISTENER

  void Create(const nsAString& aURL, nsIPrincipal* aPrincipal,
              const uint64_t& aBrowsingContextID,
              const IPCClientInfo& aClientInfo, const bool& aDedicated,
              const net::WebTransportMulticastPolicy& aMulticast,
              const bool& aRequireUnreliable,
              const uint32_t& aCongestionControl,
              nsTArray<WebTransportHash>&& aServerCertHashes,
              Endpoint<PWebTransportParent>&& aParentEndpoint,
              std::function<void(std::tuple<const nsresult&, const uint8_t&>)>&&
                  aResolver);

  IPCResult RecvClose(const uint32_t& aCode, const nsACString& aReason);

  IPCResult RecvSetSendOrder(uint64_t aStreamId, Maybe<int64_t> aSendOrder);

  IPCResult RecvCreateUnidirectionalStream(
      Maybe<int64_t> aSendOrder,
      CreateUnidirectionalStreamResolver&& aResolver);
  IPCResult RecvCreateBidirectionalStream(
      Maybe<int64_t> aSendOrder, CreateBidirectionalStreamResolver&& aResolver);

  ::mozilla::ipc::IPCResult RecvOutgoingDatagram(
      nsTArray<uint8_t>&& aData, const TimeStamp& aExpirationTime,
      OutgoingDatagramResolver&& aResolver);

  ::mozilla::ipc::IPCResult RecvGetMaxDatagramSize(
      GetMaxDatagramSizeResolver&& aResolver);

  ::mozilla::ipc::IPCResult RecvGetHttpChannelID(
      GetHttpChannelIDResolver&& aResolver);

  void ActorDestroy(ActorDestroyReason aWhy) override;

  class OnResetOrStopSendingCallback final {
   public:
    explicit OnResetOrStopSendingCallback(
        std::function<void(nsresult)>&& aCallback)
        : mCallback(std::move(aCallback)) {}
    ~OnResetOrStopSendingCallback() = default;

    void OnResetOrStopSending(nsresult aError) { mCallback(aError); }

   private:
    std::function<void(nsresult)> mCallback;
  };

 protected:
  virtual ~WebTransportParent();

 private:
  friend class WebTransportParentLifecycleTestPeer;

  enum class Lifecycle : uint8_t {
    Init,
    ConnectQueued,
    Negotiating,
    Retargeting,
    ReadyPending,
    Active,
    RemoteClosedPending,
    RemoteClosed,
    CreateFailed,
    Closing,
    Closed,
  };

  struct RemoteCloseInfo {
    bool mCleanly;
    uint32_t mErrorCode;
    nsCString mReason;
  };

  void CompleteCreate(nsresult aResult, uint8_t aReliability);
  nsresult DispatchCreateResult(nsresult aResult, uint8_t aReliability);
  nsresult Shutdown(uint32_t aCode, const nsACString& aReason);
  void NotifyRemoteClosed(bool aCleanly, uint32_t aErrorCode,
                          const nsACString& aReason);

  using ResolveType = std::tuple<const nsresult&, const uint8_t&>;
  nsCOMPtr<nsISerialEventTarget> mSocketThread;

  mozilla::Mutex mMutex{"WebTransportParent::mMutex"};
  Lifecycle mLifecycle MOZ_GUARDED_BY(mMutex) = Lifecycle::Init;
  std::function<void(ResolveType)> mResolver MOZ_GUARDED_BY(mMutex);
  Maybe<RemoteCloseInfo> mRemoteClose MOZ_GUARDED_BY(mMutex);
  OutgoingDatagramResolver mOutgoingDatagramResolver;
  GetMaxDatagramSizeResolver mMaxDatagramSizeResolver;

  nsCOMPtr<nsIWebTransport> mWebTransport;
  nsCOMPtr<nsIEventTarget> mOwningEventTarget;

  // What we need to be able to lookup by streamId
  template <typename T>
  struct StreamHash {
    OnResetOrStopSendingCallback mCallback;
    nsCOMPtr<T> mStream;
  };
  nsTHashMap<NoMemMoveKey<nsUint64HashKey>,
             StreamHash<nsIWebTransportBidirectionalStream>>
      mBidiStreamCallbackMap;
  nsTHashMap<NoMemMoveKey<nsUint64HashKey>,
             StreamHash<nsIWebTransportSendStream>>
      mUniStreamCallbackMap;
};

}  // namespace mozilla::dom

#endif  // DOM_WEBTRANSPORT_PARENT_WEBTRANSPORTPARENT_H_
