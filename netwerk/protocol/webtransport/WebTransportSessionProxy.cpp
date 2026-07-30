/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WebTransportSessionProxy.h"

#include "Http3WebTransportSession.h"
#include "Http3WebTransportStream.h"
#include "ScopedNSSTypes.h"
#include "WebTransportEventService.h"
#include "WebTransportLog.h"
#include "WebTransportStreamProxy.h"
#include "mozilla/LoadInfo.h"
#include "mozilla/Logging.h"
#include "mozilla/ScopeExit.h"
#include "nsContentUtils.h"
#include "nsIAsyncVerifyRedirectCallback.h"
#include "nsIHttpChannel.h"
#include "nsIHttpChannelInternal.h"
#include "nsILoadInfo.h"
#include "nsIRequest.h"
#include "nsITransportSecurityInfo.h"
#include "nsIX509Cert.h"
#include "nsNetUtil.h"
#include "nsProxyRelease.h"
#include "nsSocketTransportService2.h"

namespace mozilla::net {

LazyLogModule webTransportLog("nsWebTransport");

namespace {

nsresult CancelWebTransportChannel(nsIChannel* aChannel) {
  if (!aChannel) {
    return NS_OK;
  }
  if (NS_IsMainThread()) {
    return aChannel->Cancel(NS_ERROR_ABORT);
  }

  nsCOMPtr<nsIChannel> channel = aChannel;
  return NS_DispatchToMainThread(NS_NewRunnableFunction(
      "WebTransportSessionProxy::CancelChannel",
      [channel = std::move(channel)]() {
        nsresult rv = channel->Cancel(NS_ERROR_ABORT);
        if (NS_FAILED(rv)) {
          LOG(("Cancel WebTransport channel failed rv=0x%08" PRIx32,
               static_cast<uint32_t>(rv)));
        }
      }));
}

}  // namespace

NS_IMPL_ISUPPORTS(WebTransportSessionProxy, WebTransportSessionEventListener,
                  WebTransportSessionEventListenerInternal,
                  WebTransportConnectionSettings, nsIWebTransport,
                  nsIRedirectResultListener, nsIStreamListener,
                  nsIChannelEventSink, nsIInterfaceRequestor);

WebTransportSessionProxy::WebTransportSessionProxy()
    : mMutex("WebTransportSessionProxy::mMutex"),
      mTarget(GetMainThreadSerialEventTarget()) {
  LOG(("WebTransportSessionProxy constructor"));
}

WebTransportSessionProxy::~WebTransportSessionProxy() {
  if (OnSocketThread()) {
    return;
  }

  RefPtr<WebTransportSessionBase> session;
  {
    MutexAutoLock lock(mMutex);
    if ((mState != WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED) &&
        (mState != WebTransportSessionProxyState::ACTIVE) &&
        (mState != WebTransportSessionProxyState::SESSION_CLOSE_PENDING)) {
      return;
    }
    session = std::move(mWebTransportSession);
  }

  nsresult rv = NS_ProxyRelease(
      "WebTransportSessionProxy::ProxyHttp3WebTransportSessionRelease",
      gSocketTransportService, session.forget());
  if (NS_FAILED(rv)) {
    LOG(("Proxy WebTransport session release failed rv=0x%08" PRIx32,
         static_cast<uint32_t>(rv)));
  }
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::nsIWebTransport
//-----------------------------------------------------------------------------

nsresult WebTransportSessionProxy::AsyncConnect(
    nsIURI* aURI, bool aDedicated,
    const nsTArray<RefPtr<nsIWebTransportHash>>& aServerCertHashes,
    nsIPrincipal* aPrincipal, uint32_t aSecurityFlags,
    WebTransportSessionEventListener* aListener,
    nsIWebTransport::HTTPVersion aVersion,
    nsIWebTransport::MulticastPolicy aMulticast) {
  auto operationPolicy = CreateWebTransportOperationPolicy(
      aPrincipal, aURI, Nothing(), 0,
      aMulticast == nsIWebTransport::MulticastPolicy::allow
          ? WebTransportMulticastPolicy::Allow
          : WebTransportMulticastPolicy::Prohibit,
      nsID::GenerateUUID());
  if (operationPolicy.isErr()) {
    return operationPolicy.unwrapErr();
  }
  return AsyncConnectWithClient(aURI, aDedicated, std::move(aServerCertHashes),
                                aPrincipal, 0, aSecurityFlags, aListener,
                                Maybe<dom::ClientInfo>(),
                                operationPolicy.unwrap(), aVersion);
}

nsresult WebTransportSessionProxy::AsyncConnectWithClient(
    nsIURI* aURI, bool aDedicated,
    const nsTArray<RefPtr<nsIWebTransportHash>>& aServerCertHashes,
    nsIPrincipal* aPrincipal, uint64_t aBrowsingContextID,
    uint32_t aSecurityFlags, WebTransportSessionEventListener* aListener,
    const Maybe<dom::ClientInfo>& aClientInfo,
    const WebTransportOperationPolicy& aOperationPolicy,
    nsIWebTransport::HTTPVersion aVersion) {
  MOZ_ASSERT(NS_IsMainThread());

  if (!aPrincipal || !aOperationPolicy.IsValid() ||
      aOperationPolicy.mOriginAttributes != aPrincipal->OriginAttributesRef()) {
    return NS_ERROR_DOM_SECURITY_ERR;
  }

  nsAutoCString initiatingOrigin;
  nsAutoCString targetOrigin;
  nsresult rv = GetWebTransportInitiatingOrigin(aPrincipal, initiatingOrigin);
  NS_ENSURE_SUCCESS(rv, rv);
  rv = nsContentUtils::GetWebExposedOriginSerialization(aURI, targetOrigin);
  NS_ENSURE_SUCCESS(rv, rv);
  if (!aOperationPolicy.mInitiatingOrigin.Equals(initiatingOrigin) ||
      !aOperationPolicy.mTargetOrigin.Equals(targetOrigin)) {
    return NS_ERROR_DOM_SECURITY_ERR;
  }

  mOperationPolicy = aOperationPolicy;
  Maybe<nsID> clientContextId;
  if (aClientInfo.isSome()) {
    clientContextId = Some(aClientInfo.ref().Id());
  }
  Maybe<uint64_t> browsingContextId;
  if (aBrowsingContextID != 0) {
    browsingContextId = Some(aBrowsingContextID);
  }
  if (!mOperationPolicy.MatchesIdentity(clientContextId, browsingContextId)) {
    mOperationPolicy.ProhibitMulticast();
  }
  if (aVersion == nsIWebTransport::HTTPVersion::h2) {
    mHTTPVersion = nsIWebTransport::HTTPVersion::h2;
    mOperationPolicy.mEffectiveMulticast =
        WebTransportMulticastPolicy::Prohibit;
  }
  LOG(("WebTransportSessionProxy::AsyncConnect"));
  {
    MutexAutoLock lock(mMutex);
    if (mState != WebTransportSessionProxyState::INIT) {
      return NS_ERROR_ALREADY_INITIALIZED;
    }
    mListener = aListener;
    ChangeState(WebTransportSessionProxyState::NEGOTIATING);
  }
  auto cleanup = MakeScopeExit([self = RefPtr<WebTransportSessionProxy>(this)] {
    nsCOMPtr<WebTransportSessionEventListener> listener;
    {
      MutexAutoLock lock(self->mMutex);
      if (self->mState != WebTransportSessionProxyState::NEGOTIATING) {
        return;
      }
      self->mChannel = nullptr;
      listener = std::move(self->mListener);
      self->ChangeState(WebTransportSessionProxyState::DONE);
    }
    if (listener) {
      listener->OnSessionClosed(false, 0,
                                ""_ns);  // TODO: find a better error.
    }
  });

  nsSecurityFlags flags = nsILoadInfo::SEC_COOKIES_OMIT | aSecurityFlags;
  nsLoadFlags loadFlags = nsIRequest::LOAD_NORMAL |
                          nsIRequest::LOAD_BYPASS_CACHE |
                          nsIRequest::INHIBIT_CACHING;
  rv = NS_ERROR_FAILURE;
  nsCOMPtr<nsIChannel> channel;

  if (aClientInfo.isSome()) {
    rv = NS_NewChannel(getter_AddRefs(channel), aURI, aPrincipal,
                       aClientInfo.ref(), Maybe<dom::ServiceWorkerDescriptor>(),
                       flags, nsContentPolicyType::TYPE_WEB_TRANSPORT,
                       /* aCookieJarSettings */ nullptr,
                       /* aPerformanceStorage */ nullptr,
                       /* aLoadGroup */ nullptr,
                       /* aCallbacks */ this, loadFlags);
  } else {
    rv = NS_NewChannel(getter_AddRefs(channel), aURI, aPrincipal, flags,
                       nsContentPolicyType::TYPE_WEB_TRANSPORT,
                       /* aCookieJarSettings */ nullptr,
                       /* aPerformanceStorage */ nullptr,
                       /* aLoadGroup */ nullptr,
                       /* aCallbacks */ this, loadFlags);
  }

  NS_ENSURE_SUCCESS(rv, rv);

  // configure HTTP specific stuff
  nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(channel);
  if (!httpChannel) {
    return NS_ERROR_ABORT;
  }

  mDedicatedConnection = aDedicated || mOperationPolicy.IsMulticastEligible();

  {
    MutexAutoLock lock(mMutex);
    if (mState != WebTransportSessionProxyState::NEGOTIATING) {
      return NS_ERROR_ABORT;
    }
    if (!aServerCertHashes.IsEmpty()) {
      mServerCertHashes.Clear();
      mServerCertHashes.AppendElements(aServerCertHashes);
    }
  }

  // https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-04.html#section-6
  rv = httpChannel->SetRequestHeader("Sec-Webtransport-Http3-Draft02"_ns,
                                     "1"_ns, false);
  if (NS_FAILED(rv)) {
    return rv;
  }

  // To establish a WebTransport session with an origin origin, follow
  // [WEB-TRANSPORT-HTTP3] section 3.3, with using origin, serialized and
  // isomorphic encoded, as the `Origin` header of the request.
  // https://www.w3.org/TR/webtransport/#protocol-concepts
  nsAutoCString serializedOrigin;
  if (NS_FAILED(
          aPrincipal->GetWebExposedOriginSerialization(serializedOrigin))) {
    // origin/URI will be missing for system principals
    // assign null origin
    serializedOrigin = "null"_ns;
  }

  rv = httpChannel->SetRequestHeader("Origin"_ns, serializedOrigin, false);
  if (NS_FAILED(rv)) {
    return rv;
  }

  if (mOperationPolicy.IsMulticastEligible()) {
    rv = httpChannel->SetRequestHeader("WT-Multicast"_ns, "?1"_ns, false);
    if (NS_FAILED(rv)) {
      return rv;
    }
  }

  nsCOMPtr<nsIHttpChannelInternal> internalChannel = do_QueryInterface(channel);
  if (!internalChannel) {
    return NS_ERROR_ABORT;
  }
  (void)internalChannel->SetWebTransportSessionEventListener(this);

  {
    MutexAutoLock lock(mMutex);
    if (mState != WebTransportSessionProxyState::NEGOTIATING) {
      return NS_ERROR_ABORT;
    }
    mChannel = channel;
  }

  rv = channel->AsyncOpen(this);
  if (NS_SUCCEEDED(rv)) {
    cleanup.release();
  }

  mHttpChannelID = httpChannel->ChannelId();

  // Setting the BrowsingContextID here to let WebTransport requests show up in
  // devtools. Normally that would automatically happen if we would pass the
  // nsILoadGroup in ns_NewChannel above, but the nsILoadGroup is inaccessible
  // here in the ParentProcess. The nsILoadGroup only exists in ContentProcess
  // as part of the document and nsDocShell. It is also not yet determined which
  // ContentProcess this load belongs to.
  if (aBrowsingContextID != 0) {
    nsCOMPtr<nsILoadInfo> loadInfo = channel->LoadInfo();
    static_cast<LoadInfo*>(loadInfo.get())
        ->UpdateBrowsingContextID(aBrowsingContextID);
  }

  return rv;
}

NS_IMETHODIMP
WebTransportSessionProxy::RetargetTo(nsIEventTarget* aTarget) {
  if (!aTarget) {
    return NS_ERROR_INVALID_ARG;
  }

  {
    MutexAutoLock lock(mMutex);
    LOG(("WebTransportSessionProxy::RetargetTo mState=%d", mState));
    // RetargetTo should be only called after the session is ready.
    if (mState != WebTransportSessionProxyState::ACTIVE) {
      return NS_ERROR_UNEXPECTED;
    }

    mTarget = aTarget;
  }

  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::GetStats() { return NS_ERROR_NOT_IMPLEMENTED; }

NS_IMETHODIMP
WebTransportSessionProxy::CloseSession(uint32_t status,
                                       const nsACString& reason) {
  nsCOMPtr<nsIChannel> channel;
  bool closeTransportSession = false;
  {
    MutexAutoLock lock(mMutex);
    if (mState == WebTransportSessionProxyState::DONE) {
      return NS_OK;
    }
    if (mState == WebTransportSessionProxyState::SESSION_CLOSE_PENDING) {
      closeTransportSession = true;
    } else {
      mCloseStatus = status;
      mReason = reason;
      mListener = nullptr;
      mPendingEvents.Clear();
      mServerCertHashes.Clear();
      mCloseCallbackTarget = nullptr;
      switch (mState) {
        case WebTransportSessionProxyState::INIT:
          ChangeState(WebTransportSessionProxyState::DONE);
          break;
        case WebTransportSessionProxyState::NEGOTIATING:
          channel = std::move(mChannel);
          ChangeState(WebTransportSessionProxyState::DONE);
          break;
        case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
          channel = std::move(mChannel);
          ChangeState(WebTransportSessionProxyState::SESSION_CLOSE_PENDING);
          closeTransportSession = true;
          break;
        case WebTransportSessionProxyState::ACTIVE:
          ChangeState(WebTransportSessionProxyState::SESSION_CLOSE_PENDING);
          closeTransportSession = true;
          break;
        case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
          ChangeState(WebTransportSessionProxyState::DONE);
          break;
        case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
        case WebTransportSessionProxyState::DONE:
          MOZ_ASSERT_UNREACHABLE("handled before switch");
          break;
      }
    }
  }

  nsresult cancelRv = CancelWebTransportChannel(channel);
  nsresult closeRv = closeTransportSession ? CloseSessionInternal() : NS_OK;
  return NS_FAILED(cancelRv) ? cancelRv : closeRv;
}

NS_IMETHODIMP WebTransportSessionProxy::RevokeMulticast() {
  RefPtr<WebTransportSessionBase> session;
  {
    MutexAutoLock lock(mMutex);
    if ((mState != WebTransportSessionProxyState::ACTIVE &&
         mState != WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED) ||
        !mWebTransportSession) {
      return NS_OK;
    }
    session = mWebTransportSession;
  }

  if (!OnSocketThread()) {
    return gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::RevokeMulticast",
        [session = std::move(session)]() { session->RevokeMulticast(); }));
  }

  session->RevokeMulticast();
  return NS_OK;
}

NS_IMETHODIMP WebTransportSessionProxy::GetDedicated(bool* dedicated) {
  *dedicated = mDedicatedConnection;
  return NS_OK;
}

NS_IMETHODIMP WebTransportSessionProxy::GetServerCertificateHashes(
    nsTArray<RefPtr<nsIWebTransportHash>>& aServerCertHashes) {
  MutexAutoLock lock(mMutex);
  aServerCertHashes.Clear();
  aServerCertHashes.AppendElements(mServerCertHashes);
  return NS_OK;
}

NS_IMETHODIMP WebTransportSessionProxy::GetHttpVersion(
    nsIWebTransport::HTTPVersion* aVersion) {
  *aVersion = mHTTPVersion;
  return NS_OK;
}

const WebTransportOperationPolicy&
WebTransportSessionProxy::GetOperationPolicy() {
  return mOperationPolicy;
}

nsresult WebTransportSessionProxy::CloseSessionInternal() {
  if (!OnSocketThread()) {
    RefPtr<WebTransportSessionProxy> self(this);
    return gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::CallCloseWebTransportSession",
        [self{std::move(self)}]() {
          nsresult rv = self->CloseSessionInternal();
          if (NS_FAILED(rv)) {
            LOG(("Close WebTransport session failed rv=0x%08" PRIx32,
                 static_cast<uint32_t>(rv)));
          }
        }));
  }

  RefPtr<WebTransportSessionBase> wt;
  uint32_t closeStatus = 0;
  nsCString reason;
  {
    MutexAutoLock lock(mMutex);
    if (mState == WebTransportSessionProxyState::DONE) {
      return NS_OK;
    }
    if (mState != WebTransportSessionProxyState::SESSION_CLOSE_PENDING) {
      return NS_ERROR_UNEXPECTED;
    }
    wt = std::move(mWebTransportSession);
    closeStatus = mCloseStatus;
    reason = mReason;
    ChangeState(WebTransportSessionProxyState::DONE);
  }

  if (wt) {
    wt->RevokeMulticast();
    wt->CloseSession(closeStatus, reason);
  }
  return NS_OK;
}

class WebTransportStreamCallbackWrapper final {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(WebTransportStreamCallbackWrapper)

  explicit WebTransportStreamCallbackWrapper(
      nsIWebTransportStreamCallback* aCallback, bool aBidi)
      : mCallback(aCallback),
        mTarget(GetCurrentSerialEventTarget()),
        mBidi(aBidi) {}

  void CallOnError(nsresult aError) {
    if (!mTarget->IsOnCurrentThread()) {
      RefPtr<WebTransportStreamCallbackWrapper> self(this);
      (void)mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportStreamCallbackWrapper::CallOnError",
          [self{std::move(self)}, error{aError}]() {
            self->CallOnError(error);
          }));
      return;
    }

    LOG(("WebTransportStreamCallbackWrapper::OnError aError=0x%" PRIx32,
         static_cast<uint32_t>(aError)));
    (void)mCallback->OnError(nsIWebTransport::INVALID_STATE_ERROR);
  }

  void CallOnStreamReady(WebTransportStreamProxy* aStream) {
    if (!mTarget->IsOnCurrentThread()) {
      RefPtr<WebTransportStreamCallbackWrapper> self(this);
      RefPtr<WebTransportStreamProxy> stream = aStream;
      (void)mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportStreamCallbackWrapper::CallOnStreamReady",
          [self{std::move(self)}, stream{std::move(stream)}]() {
            self->CallOnStreamReady(stream);
          }));
      return;
    }

    if (mBidi) {
      (void)mCallback->OnBidirectionalStreamReady(aStream);
      return;
    }

    (void)mCallback->OnUnidirectionalStreamReady(aStream);
  }

 private:
  virtual ~WebTransportStreamCallbackWrapper() {
    NS_ProxyRelease(
        "WebTransportStreamCallbackWrapper::~WebTransportStreamCallbackWrapper",
        mTarget, mCallback.forget());
  }

  nsCOMPtr<nsIWebTransportStreamCallback> mCallback;
  nsCOMPtr<nsIEventTarget> mTarget;
  bool mBidi = false;
};

void WebTransportSessionProxy::CreateStreamInternal(
    nsIWebTransportStreamCallback* callback, bool aBidi) {
  mMutex.AssertCurrentThreadOwns();
  LOG(
      ("WebTransportSessionProxy::CreateStreamInternal %p "
       "mState=%d, bidi=%d",
       this, mState, aBidi));
  switch (mState) {
    case WebTransportSessionProxyState::INIT:
    case WebTransportSessionProxyState::NEGOTIATING:
    case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
    case WebTransportSessionProxyState::ACTIVE: {
      RefPtr<WebTransportStreamCallbackWrapper> wrapper =
          new WebTransportStreamCallbackWrapper(callback, aBidi);
      if (mState == WebTransportSessionProxyState::ACTIVE &&
          mWebTransportSession) {
        DoCreateStream(wrapper, mWebTransportSession, aBidi);
      } else {
        LOG(
            ("WebTransportSessionProxy::CreateStreamInternal %p "
             " queue create stream event",
             this));
        auto task = [self = RefPtr{this}, wrapper{std::move(wrapper)},
                     bidi(aBidi)](nsresult aStatus) {
          if (NS_FAILED(aStatus)) {
            wrapper->CallOnError(aStatus);
            return;
          }

          self->DoCreateStream(wrapper, nullptr, bidi);
        };
        // TODO: we should do this properly in bug 1830362.
        mPendingCreateStreamEvents.AppendElement(std::move(task));
      }
    } break;
    case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
    case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
    case WebTransportSessionProxyState::DONE: {
      nsCOMPtr<nsIWebTransportStreamCallback> cb(callback);
      NS_DispatchToCurrentThread(NS_NewRunnableFunction(
          "WebTransportSessionProxy::CreateStreamInternal",
          [cb{std::move(cb)}]() {
            cb->OnError(nsIWebTransport::INVALID_STATE_ERROR);
          }));
    } break;
  }
}

void WebTransportSessionProxy::DoCreateStream(
    WebTransportStreamCallbackWrapper* aCallback,
    WebTransportSessionBase* aSession, bool aBidi) {
  if (!OnSocketThread()) {
    RefPtr<WebTransportSessionProxy> self(this);
    RefPtr<WebTransportStreamCallbackWrapper> wrapper(aCallback);
    (void)gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::DoCreateStream",
        [self{std::move(self)}, wrapper{std::move(wrapper)}, bidi(aBidi)]() {
          self->DoCreateStream(wrapper, nullptr, bidi);
        }));
    return;
  }

  LOG(("WebTransportSessionProxy::DoCreateStream %p bidi=%d", this, aBidi));

  RefPtr<WebTransportSessionBase> session = aSession;
  // Having no session here means that this is called by dispatching tasks.
  // The mState may be already changed, so we need to check it again.
  if (!aSession) {
    MutexAutoLock lock(mMutex);
    switch (mState) {
      case WebTransportSessionProxyState::INIT:
      case WebTransportSessionProxyState::NEGOTIATING:
      case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
        MOZ_ASSERT(false, "DoCreateStream called with invalid state");
        aCallback->CallOnError(NS_ERROR_UNEXPECTED);
        return;
      case WebTransportSessionProxyState::ACTIVE: {
        session = mWebTransportSession;
      } break;
      case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
      case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
      case WebTransportSessionProxyState::DONE:
        // Session is going to be closed.
        aCallback->CallOnError(NS_ERROR_NOT_AVAILABLE);
        return;
    }
  }

  if (!session) {
    MOZ_ASSERT_UNREACHABLE("This should not happen");
    aCallback->CallOnError(NS_ERROR_UNEXPECTED);
    return;
  }

  RefPtr<WebTransportStreamCallbackWrapper> wrapper(aCallback);
  auto callback =
      [wrapper{std::move(wrapper)}](
          Result<RefPtr<WebTransportStreamBase>, nsresult>&& aResult) {
        if (aResult.isErr()) {
          wrapper->CallOnError(aResult.unwrapErr());
          return;
        }

        RefPtr<WebTransportStreamBase> stream = aResult.unwrap();
        RefPtr<WebTransportStreamProxy> streamProxy =
            new WebTransportStreamProxy(stream);
        wrapper->CallOnStreamReady(streamProxy);
      };

  if (aBidi) {
    session->CreateOutgoingBidirectionalStream(std::move(callback));
  } else {
    session->CreateOutgoingUnidirectionalStream(std::move(callback));
  }
}

NS_IMETHODIMP
WebTransportSessionProxy::CreateOutgoingUnidirectionalStream(
    nsIWebTransportStreamCallback* callback) {
  if (!callback) {
    return NS_ERROR_INVALID_ARG;
  }

  MutexAutoLock lock(mMutex);
  CreateStreamInternal(callback, false);
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::CreateOutgoingBidirectionalStream(
    nsIWebTransportStreamCallback* callback) {
  if (!callback) {
    return NS_ERROR_INVALID_ARG;
  }

  MutexAutoLock lock(mMutex);
  CreateStreamInternal(callback, true);
  return NS_OK;
}

void WebTransportSessionProxy::SendDatagramInternal(
    const RefPtr<WebTransportSessionBase>& aSession, nsTArray<uint8_t>&& aData,
    uint64_t aTrackingId) {
  MOZ_ASSERT(OnSocketThread());

  aSession->SendDatagram(std::move(aData), aTrackingId);
}

NS_IMETHODIMP
WebTransportSessionProxy::SendDatagram(const nsTArray<uint8_t>& aData,
                                       uint64_t aTrackingId) {
  RefPtr<WebTransportSessionBase> session;
  {
    MutexAutoLock lock(mMutex);
    if (mState != WebTransportSessionProxyState::ACTIVE ||
        !mWebTransportSession) {
      return NS_ERROR_NOT_AVAILABLE;
    }
    session = mWebTransportSession;
  }

  nsTArray<uint8_t> copied;
  copied.Assign(aData);
  if (!OnSocketThread()) {
    return gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::SendDatagramInternal",
        [self = RefPtr{this}, session{std::move(session)},
         data{std::move(copied)}, trackingId(aTrackingId)]() mutable {
          self->SendDatagramInternal(session, std::move(data), trackingId);
        }));
  }

  SendDatagramInternal(session, std::move(copied), aTrackingId);
  return NS_OK;
}

void WebTransportSessionProxy::GetMaxDatagramSizeInternal(
    const RefPtr<WebTransportSessionBase>& aSession) {
  MOZ_ASSERT(OnSocketThread());

  aSession->GetMaxDatagramSize();
}

NS_IMETHODIMP
WebTransportSessionProxy::GetMaxDatagramSize() {
  RefPtr<WebTransportSessionBase> session;
  {
    MutexAutoLock lock(mMutex);
    if (mState != WebTransportSessionProxyState::ACTIVE ||
        !mWebTransportSession) {
      return NS_ERROR_NOT_AVAILABLE;
    }
    session = mWebTransportSession;
  }

  if (!OnSocketThread()) {
    return gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::GetMaxDatagramSizeInternal",
        [self = RefPtr{this}, session{std::move(session)}]() {
          self->GetMaxDatagramSizeInternal(session);
        }));
  }

  GetMaxDatagramSizeInternal(session);
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::GetHttpChannelID(uint64_t* _retval) {
  *_retval = mHttpChannelID;
  return NS_OK;
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::nsIStreamListener
//-----------------------------------------------------------------------------

NS_IMETHODIMP
WebTransportSessionProxy::OnStartRequest(nsIRequest* aRequest) {
  MOZ_ASSERT(NS_IsMainThread());
  LOG(("WebTransportSessionProxy::OnStartRequest\n"));
  nsCOMPtr<WebTransportSessionEventListener> listener;
  nsAutoCString reason;
  uint32_t closeStatus = 0;
  nsresult closeRv = NS_OK;
  {
    MutexAutoLock lock(mMutex);
    switch (mState) {
      case WebTransportSessionProxyState::INIT:
      case WebTransportSessionProxyState::DONE:
      case WebTransportSessionProxyState::ACTIVE:
      case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
        break;
      case WebTransportSessionProxyState::NEGOTIATING:
      case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING: {
        nsresult rv;
        if (NS_SUCCEEDED(mChannel->GetStatus(&rv)) &&
            rv == NS_ERROR_WEBTRANSPORT_SESSION_LIMIT_EXCEEDED) {
          mReason = "WebTransport session limit exceeded"_ns;
          mCloseStatus = 0;
        }
        listener = mListener;
        mListener = nullptr;
        mChannel = nullptr;
        mCloseCallbackTarget = nullptr;
        reason = mReason;
        closeStatus = mCloseStatus;
        ChangeState(WebTransportSessionProxyState::DONE);
        break;
      }
      case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED: {
        uint32_t status;

        nsCOMPtr<nsIHttpChannel> httpChannel = do_QueryInterface(mChannel);
        if (!httpChannel ||
            NS_FAILED(httpChannel->GetResponseStatus(&status)) ||
            !(status >= 200 && status < 300)) {
          listener = mListener;
          mListener = nullptr;
          mChannel = nullptr;
          mReason = ""_ns;
          reason = ""_ns;
          mCloseStatus =
              0;  // TODO: find a better error. Currently error code 0 is used
          ChangeState(WebTransportSessionProxyState::SESSION_CLOSE_PENDING);
          closeRv = CloseSessionInternal();  // TODO: find a better error.
        }
        // The success cases will be handled in OnStopRequest.
      } break;
    }
  }
  if (listener) {
    listener->OnSessionClosed(false, closeStatus, reason);
  }
  return closeRv;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnDataAvailable(nsIRequest* aRequest,
                                          nsIInputStream* aStream,
                                          uint64_t aOffset, uint32_t aCount) {
  MOZ_ASSERT(NS_IsMainThread());
  MOZ_RELEASE_ASSERT(
      false, "WebTransportSessionProxy::OnDataAvailable should not be called");
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnStopRequest(nsIRequest* aRequest,
                                        nsresult aStatus) {
  MOZ_ASSERT(NS_IsMainThread());
  nsCOMPtr<WebTransportSessionEventListener> listener;
  nsAutoCString reason;
  uint32_t closeStatus = 0;
  uint64_t sessionId;
  bool succeeded = false;
  nsresult closeRv = NS_OK;
  nsTArray<std::function<void()>> pendingEvents;
  nsTArray<std::function<void(nsresult)>> pendingCreateStreamEvents;
  {
    MutexAutoLock lock(mMutex);
    mChannel = nullptr;
    switch (mState) {
      case WebTransportSessionProxyState::INIT:
      case WebTransportSessionProxyState::ACTIVE:
      case WebTransportSessionProxyState::NEGOTIATING:
        break;
      case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
        reason = mReason;
        closeStatus = mCloseStatus;
        listener = mListener;
        mListener = nullptr;
        mCloseCallbackTarget = nullptr;
        ChangeState(WebTransportSessionProxyState::DONE);
        break;
      case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
        if (NS_FAILED(aStatus)) {
          listener = mListener;
          mListener = nullptr;
          mReason = ""_ns;
          reason = ""_ns;
          mCloseStatus = 0;
          ChangeState(WebTransportSessionProxyState::SESSION_CLOSE_PENDING);
          closeRv = CloseSessionInternal();  // TODO: find a better error.
        } else {
          succeeded = true;
          sessionId = mSessionId;
          listener = mListener;
          ChangeState(WebTransportSessionProxyState::ACTIVE);
        }
        break;
      case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
      case WebTransportSessionProxyState::DONE:
        break;
    }
    pendingEvents = std::move(mPendingEvents);
    pendingCreateStreamEvents = std::move(mPendingCreateStreamEvents);
    if (!pendingCreateStreamEvents.IsEmpty()) {
      if (NS_SUCCEEDED(aStatus) &&
          (mState == WebTransportSessionProxyState::DONE ||
           mState == WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING ||
           mState == WebTransportSessionProxyState::SESSION_CLOSE_PENDING)) {
        aStatus = NS_ERROR_FAILURE;
      }
    }

    mStopRequestCalled = true;
  }

  if (!pendingCreateStreamEvents.IsEmpty()) {
    (void)gSocketTransportService->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::DispatchPendingCreateStreamEvents",
        [pendingCreateStreamEvents = std::move(pendingCreateStreamEvents),
         status(aStatus)]() {
          for (const auto& event : pendingCreateStreamEvents) {
            event(status);
          }
        }));
  }  // otherwise let the CreateStreams just go away

  if (listener) {
    if (succeeded) {
      listener->OnSessionReady(sessionId);
      if (!pendingEvents.IsEmpty()) {
        (void)gSocketTransportService->Dispatch(NS_NewRunnableFunction(
            "WebTransportSessionProxy::DispatchPendingEvents",
            [pendingEvents = std::move(pendingEvents)]() {
              for (const auto& event : pendingEvents) {
                event();
              }
            }));
      }
    } else {
      listener->OnSessionClosed(false, closeStatus,
                                reason);  // TODO: find a better error.
                                          // Currently error code 0 is used.
    }
  }
  return closeRv;
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::nsIChannelEventSink
//-----------------------------------------------------------------------------

NS_IMETHODIMP
WebTransportSessionProxy::AsyncOnChannelRedirect(
    nsIChannel* aOldChannel, nsIChannel* aNewChannel, uint32_t aFlags,
    nsIAsyncVerifyRedirectCallback* callback) {
  LOG(("Channel redirects are disabled for WebTransport sessions"));
  callback->OnRedirectVerifyCallback(NS_ERROR_ABORT);
  return NS_OK;
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::nsIRedirectResultListener
//-----------------------------------------------------------------------------

NS_IMETHODIMP
WebTransportSessionProxy::OnRedirectResult(nsresult aStatus) {
  if (NS_SUCCEEDED(aStatus) && mRedirectChannel) {
    MutexAutoLock lock(mMutex);
    if (mState == WebTransportSessionProxyState::NEGOTIATING) {
      mChannel = mRedirectChannel;
    }
  }

  mRedirectChannel = nullptr;

  return NS_OK;
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::nsIInterfaceRequestor
//-----------------------------------------------------------------------------

NS_IMETHODIMP
WebTransportSessionProxy::GetInterface(const nsIID& aIID, void** aResult) {
  if (aIID.Equals(NS_GET_IID(nsIChannelEventSink))) {
    NS_ADDREF_THIS();
    *aResult = static_cast<nsIChannelEventSink*>(this);
    return NS_OK;
  }

  if (aIID.Equals(NS_GET_IID(nsIRedirectResultListener))) {
    NS_ADDREF_THIS();
    *aResult = static_cast<nsIRedirectResultListener*>(this);
    return NS_OK;
  }

  return NS_ERROR_NO_INTERFACE;
}

//-----------------------------------------------------------------------------
// WebTransportSessionProxy::WebTransportSessionEventListener
//-----------------------------------------------------------------------------

// This function is called when the WebTransportSessionBase is ready. After
// this call WebTransportSessionProxy is responsible for the
// WebTransportSessionBase, i.e. it is responsible for closing it.
// The listener of the WebTransportSessionProxy will be informed during
// OnStopRequest call.
NS_IMETHODIMP
WebTransportSessionProxy::OnSessionReadyInternal(
    WebTransportSessionBase* aSession) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  LOG(("WebTransportSessionProxy::OnSessionReadyInternal"));
  RefPtr<WebTransportSessionBase> lateSession;
  {
    MutexAutoLock lock(mMutex);
    switch (mState) {
      case WebTransportSessionProxyState::NEGOTIATING:
        mWebTransportSession = aSession;
        mSessionId = aSession->GetStreamId();
        ChangeState(WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED);
        mWebTransportSession->StartReading();
        return NS_OK;
      case WebTransportSessionProxyState::INIT:
      case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
      case WebTransportSessionProxyState::ACTIVE:
      case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
      case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
      case WebTransportSessionProxyState::DONE:
        lateSession = aSession;
        break;
    }
  }
  lateSession->RevokeMulticast();
  lateSession->CloseSession(0, ""_ns);
  return NS_ERROR_ABORT;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnIncomingStreamAvailableInternal(
    WebTransportStreamBase* aStream) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);

    LOG(
        ("WebTransportSessionProxy::OnIncomingStreamAvailableInternal %p "
         "mState=%d "
         "mStopRequestCalled=%d",
         this, mState, mStopRequestCalled));
    // Since OnSessionReady on the listener is called on the main thread,
    // OnIncomingStreamAvailableInternal and OnSessionReady can be racy. If
    // OnStopRequest is not called yet, OnIncomingStreamAvailableInternal needs
    // to wait.
    if (!mStopRequestCalled) {
      mPendingEvents.AppendElement(
          [self = RefPtr{this}, stream = RefPtr{aStream}]() {
            self->OnIncomingStreamAvailableInternal(stream);
          });
      return NS_OK;
    }

    if (!mTarget->IsOnCurrentThread()) {
      RefPtr<WebTransportSessionProxy> self(this);
      RefPtr<WebTransportStreamBase> stream = aStream;
      (void)mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportSessionProxy::OnIncomingStreamAvailableInternal",
          [self{std::move(self)}, stream{std::move(stream)}]() {
            self->OnIncomingStreamAvailableInternal(stream);
          }));
      return NS_OK;
    }

    LOG(
        ("WebTransportSessionProxy::OnIncomingStreamAvailableInternal %p "
         "mState=%d mListener=%p",
         this, mState, mListener.get()));
    if (mState == WebTransportSessionProxyState::ACTIVE) {
      listener = mListener;
    }
  }

  if (!listener) {
    // Session can be already closed.
    return NS_OK;
  }

  RefPtr<WebTransportStreamProxy> streamProxy =
      new WebTransportStreamProxy(aStream);
  if (aStream->StreamType() == WebTransportStreamType::BiDi) {
    (void)listener->OnIncomingBidirectionalStreamAvailable(streamProxy);
  } else {
    (void)listener->OnIncomingUnidirectionalStreamAvailable(streamProxy);
  }
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnIncomingBidirectionalStreamAvailable(
    nsIWebTransportBidirectionalStream* aStream) {
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnIncomingUnidirectionalStreamAvailable(
    nsIWebTransportReceiveStream* aStream) {
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnSessionReady(uint64_t ready) {
  MOZ_ASSERT(false, "Should not be called");
  return NS_OK;
}

NS_IMETHODIMP
WebTransportSessionProxy::OnSessionClosed(bool aCleanly, uint32_t aStatus,
                                          const nsACString& aReason) {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");
  MutexAutoLock lock(mMutex);
  LOG(
      ("WebTransportSessionProxy::OnSessionClosed %p mState=%d "
       "mStopRequestCalled=%d",
       this, mState, mStopRequestCalled));
  if (mState == WebTransportSessionProxyState::DONE) {
    return NS_OK;
  }
  if (mState == WebTransportSessionProxyState::SESSION_CLOSE_PENDING) {
    mWebTransportSession = nullptr;
    ChangeState(WebTransportSessionProxyState::DONE);
    return NS_OK;
  }
  // Since OnSessionReady on the listener is called on the main thread,
  // OnSessionClosed and OnSessionReady can be racy. If OnStopRequest is not
  // called yet, OnSessionClosed needs to wait.
  if (!mStopRequestCalled) {
    nsCString closeReason(aReason);
    mPendingEvents.AppendElement([self = RefPtr{this}, status(aStatus),
                                  closeReason(std::move(closeReason)),
                                  cleanly(aCleanly)]() {
      (void)self->OnSessionClosed(cleanly, status, closeReason);
    });
    return NS_OK;
  }

  switch (mState) {
    case WebTransportSessionProxyState::INIT:
    case WebTransportSessionProxyState::NEGOTIATING:
    case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
      return NS_OK;
    case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
    case WebTransportSessionProxyState::ACTIVE: {
      mCleanly = aCleanly;
      mCloseStatus = aStatus;
      mReason = aReason;
      mWebTransportSession = nullptr;
      ChangeState(WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING);
      mCloseCallbackTarget = mTarget;
      return CallOnSessionClosed();
    }
    case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
    case WebTransportSessionProxyState::DONE:
      MOZ_ASSERT_UNREACHABLE("handled before deferred callback processing");
      return NS_OK;
  }
  return NS_OK;
}

void WebTransportSessionProxy::CallOnSessionClosedLocked() {
  MutexAutoLock lock(mMutex);
  nsresult rv = CallOnSessionClosed();
  if (NS_FAILED(rv)) {
    LOG(("Call WebTransport OnSessionClosed failed rv=0x%08" PRIx32,
         static_cast<uint32_t>(rv)));
  }
}

nsresult WebTransportSessionProxy::CallOnSessionClosed() MOZ_REQUIRES(mMutex) {
  mMutex.AssertCurrentThreadOwns();

  nsCOMPtr<nsIEventTarget> callbackTarget =
      mCloseCallbackTarget ? mCloseCallbackTarget : mTarget;
  if (!callbackTarget->IsOnCurrentThread()) {
    RefPtr<WebTransportSessionProxy> self(this);
    nsresult rv = callbackTarget->Dispatch(NS_NewRunnableFunction(
        "WebTransportSessionProxy::CallOnSessionClosed",
        [self{std::move(self)}]() { self->CallOnSessionClosedLocked(); }));
    if (NS_FAILED(rv)) {
      mListener = nullptr;
      mCloseCallbackTarget = nullptr;
      ChangeState(WebTransportSessionProxyState::DONE);
    }
    return rv;
  }

  MOZ_ASSERT(callbackTarget->IsOnCurrentThread());
  nsCOMPtr<WebTransportSessionEventListener> listener;
  bool cleanly = false;
  nsAutoCString reason;
  uint32_t closeStatus = 0;

  switch (mState) {
    case WebTransportSessionProxyState::INIT:
    case WebTransportSessionProxyState::NEGOTIATING:
    case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
    case WebTransportSessionProxyState::ACTIVE:
    case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
      MOZ_ASSERT(false, "CallOnSessionClosed cannot be called in this state.");
      break;
    case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
      listener = mListener;
      mListener = nullptr;
      cleanly = mCleanly;
      reason = mReason;
      closeStatus = mCloseStatus;
      mCloseCallbackTarget = nullptr;
      ChangeState(WebTransportSessionProxyState::DONE);
      break;
    case WebTransportSessionProxyState::DONE:
      break;
  }

  if (listener) {
    // Don't invoke the callback under the lock.
    MutexAutoUnlock unlock(mMutex);
    listener->OnSessionClosed(cleanly, closeStatus, reason);
  }
  return NS_OK;
}

void WebTransportSessionProxy::ChangeState(
    WebTransportSessionProxyState newState) {
  mMutex.AssertCurrentThreadOwns();
  LOG(("WebTransportSessionProxy::ChangeState %d -> %d [this=%p]", mState,
       newState, this));
  switch (newState) {
    case WebTransportSessionProxyState::INIT:
      MOZ_ASSERT(false, "Cannot change into INIT sate.");
      break;
    case WebTransportSessionProxyState::NEGOTIATING:
      MOZ_ASSERT(mState == WebTransportSessionProxyState::INIT,
                 "Only from INIT can be change into NEGOTIATING");
      MOZ_ASSERT(mListener);
      break;
    case WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED:
      MOZ_ASSERT(
          mState == WebTransportSessionProxyState::NEGOTIATING,
          "Only from NEGOTIATING can be change into NEGOTIATING_SUCCEEDED");
      MOZ_ASSERT(mChannel);
      MOZ_ASSERT(mWebTransportSession);
      MOZ_ASSERT(mListener);
      break;
    case WebTransportSessionProxyState::ACTIVE:
      MOZ_ASSERT(mState == WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED,
                 "Only from NEGOTIATING_SUCCEEDED can be change into ACTIVE");
      MOZ_ASSERT(!mChannel);
      MOZ_ASSERT(mWebTransportSession);
      MOZ_ASSERT(mListener);
      break;
    case WebTransportSessionProxyState::SESSION_CLOSE_PENDING:
      MOZ_ASSERT(
          (mState == WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED) ||
              (mState == WebTransportSessionProxyState::ACTIVE),
          "Only from NEGOTIATING_SUCCEEDED and ACTIVE can be change into"
          " SESSION_CLOSE_PENDING");
      MOZ_ASSERT(!mChannel);
      MOZ_ASSERT(mWebTransportSession);
      MOZ_ASSERT(!mListener);
      break;
    case WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING:
      MOZ_ASSERT(
          (mState == WebTransportSessionProxyState::NEGOTIATING_SUCCEEDED) ||
              (mState == WebTransportSessionProxyState::ACTIVE),
          "Only from NEGOTIATING_SUCCEEDED and ACTIVE can be change into"
          " CLOSE_CALLBACK_PENDING");
      MOZ_ASSERT(!mWebTransportSession);
      MOZ_ASSERT(mListener);
      break;
    case WebTransportSessionProxyState::DONE:
      MOZ_ASSERT(
          (mState == WebTransportSessionProxyState::INIT) ||
              (mState == WebTransportSessionProxyState::NEGOTIATING) ||
              (mState ==
               WebTransportSessionProxyState::SESSION_CLOSE_PENDING) ||
              (mState == WebTransportSessionProxyState::CLOSE_CALLBACK_PENDING),
          "Only from INIT, NEGOTIATING, SESSION_CLOSE_PENDING and "
          "CLOSE_CALLBACK_PENDING can be change into DONE");
      MOZ_ASSERT(!mChannel);
      MOZ_ASSERT(!mWebTransportSession);
      MOZ_ASSERT(!mListener);
      break;
  }
  mState = newState;
}

void WebTransportSessionProxy::NotifyDatagramReceived(
    nsTArray<uint8_t>&& aData) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);
    MOZ_ASSERT(mTarget->IsOnCurrentThread());

    if (mState != WebTransportSessionProxyState::ACTIVE || !mListener) {
      return;
    }
    listener = mListener;
  }

  listener->OnDatagramReceived(aData);
}

NS_IMETHODIMP WebTransportSessionProxy::OnDatagramReceivedInternal(
    nsTArray<uint8_t>&& aData) {
  MOZ_ASSERT(OnSocketThread());

  {
    MutexAutoLock lock(mMutex);
    if (!mStopRequestCalled) {
      CopyableTArray<uint8_t> copied(aData);
      mPendingEvents.AppendElement(
          [self = RefPtr{this}, data = std::move(copied)]() mutable {
            self->OnDatagramReceivedInternal(std::move(data));
          });
      return NS_OK;
    }

    if (!mTarget->IsOnCurrentThread()) {
      return mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportSessionProxy::OnDatagramReceived",
          [self = RefPtr{this}, data{std::move(aData)}]() mutable {
            self->NotifyDatagramReceived(std::move(data));
          }));
    }
  }

  NotifyDatagramReceived(std::move(aData));
  return NS_OK;
}

NS_IMETHODIMP WebTransportSessionProxy::OnDatagramReceived(
    const nsTArray<uint8_t>& aData) {
  return NS_ERROR_NOT_IMPLEMENTED;
}

void WebTransportSessionProxy::OnMaxDatagramSizeInternal(uint64_t aSize) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);
    MOZ_ASSERT(mTarget->IsOnCurrentThread());

    if (!mStopRequestCalled) {
      mPendingEvents.AppendElement([self = RefPtr{this}, size(aSize)]() {
        self->OnMaxDatagramSizeInternal(size);
      });
      return;
    }

    if (mState != WebTransportSessionProxyState::ACTIVE || !mListener) {
      return;
    }
    listener = mListener;
  }

  listener->OnMaxDatagramSize(aSize);
}

NS_IMETHODIMP WebTransportSessionProxy::OnMaxDatagramSize(uint64_t aSize) {
  MOZ_ASSERT(OnSocketThread());

  {
    MutexAutoLock lock(mMutex);
    if (!mTarget->IsOnCurrentThread()) {
      return mTarget->Dispatch(
          NS_NewRunnableFunction("WebTransportSessionProxy::OnMaxDatagramSize",
                                 [self = RefPtr{this}, size(aSize)] {
                                   self->OnMaxDatagramSizeInternal(size);
                                 }));
    }
  }

  OnMaxDatagramSizeInternal(aSize);
  return NS_OK;
}

void WebTransportSessionProxy::OnOutgoingDatagramOutComeInternal(
    uint64_t aId, WebTransportSessionEventListener::DatagramOutcome aOutCome) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);
    MOZ_ASSERT(mTarget->IsOnCurrentThread());
    if (mState != WebTransportSessionProxyState::ACTIVE || !mListener) {
      return;
    }
    listener = mListener;
  }

  listener->OnOutgoingDatagramOutCome(aId, aOutCome);
}

NS_IMETHODIMP
WebTransportSessionProxy::OnOutgoingDatagramOutCome(
    uint64_t aId, WebTransportSessionEventListener::DatagramOutcome aOutCome) {
  MOZ_ASSERT(OnSocketThread());

  {
    MutexAutoLock lock(mMutex);
    if (!mTarget->IsOnCurrentThread()) {
      return mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportSessionProxy::OnOutgoingDatagramOutCome",
          [self = RefPtr{this}, id(aId), outcome(aOutCome)] {
            self->OnOutgoingDatagramOutComeInternal(id, outcome);
          }));
    }
  }

  OnOutgoingDatagramOutComeInternal(aId, aOutCome);
  return NS_OK;
}

void WebTransportSessionProxy::OnStopSendingInternal(uint64_t aStreamId,
                                                     nsresult aError) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);
    MOZ_ASSERT(mTarget->IsOnCurrentThread());
    if (mState != WebTransportSessionProxyState::ACTIVE || !mListener) {
      return;
    }
    listener = mListener;
  }

  listener->OnStopSending(aStreamId, aError);
}

NS_IMETHODIMP WebTransportSessionProxy::OnStopSending(uint64_t aStreamId,
                                                      nsresult aError) {
  MOZ_ASSERT(OnSocketThread());

  {
    MutexAutoLock lock(mMutex);
    if (!mTarget->IsOnCurrentThread()) {
      return mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportSessionProxy::OnStopSending",
          [self = RefPtr{this}, aStreamId, aError] {
            self->OnStopSendingInternal(aStreamId, aError);
          }));
    }
  }

  OnStopSendingInternal(aStreamId, aError);
  return NS_OK;
}

void WebTransportSessionProxy::OnResetReceivedInternal(uint64_t aStreamId,
                                                       nsresult aError) {
  nsCOMPtr<WebTransportSessionEventListener> listener;
  {
    MutexAutoLock lock(mMutex);
    MOZ_ASSERT(mTarget->IsOnCurrentThread());
    if (mState != WebTransportSessionProxyState::ACTIVE || !mListener) {
      return;
    }
    listener = mListener;
  }

  listener->OnResetReceived(aStreamId, aError);
}

NS_IMETHODIMP WebTransportSessionProxy::OnResetReceived(uint64_t aStreamId,
                                                        nsresult aError) {
  MOZ_ASSERT(OnSocketThread());

  {
    MutexAutoLock lock(mMutex);
    if (!mTarget->IsOnCurrentThread()) {
      return mTarget->Dispatch(NS_NewRunnableFunction(
          "WebTransportSessionProxy::OnResetReceived",
          [self = RefPtr{this}, aStreamId, aError] {
            self->OnResetReceivedInternal(aStreamId, aError);
          }));
    }
  }

  OnResetReceivedInternal(aStreamId, aError);
  return NS_OK;
}

}  // namespace mozilla::net
