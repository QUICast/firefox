/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "WebTransportParent.h"

#include "Http3WebTransportSession.h"
#include "mozilla/StaticPrefs_network.h"
#include "mozilla/TimeStamp.h"
#include "mozilla/dom/ClientInfo.h"
#include "mozilla/dom/WebTransportBinding.h"
#include "mozilla/dom/WebTransportLog.h"
#include "mozilla/ipc/BackgroundParent.h"
#include "mozilla/net/WebTransportHash.h"
#include "nsIEventTarget.h"
#include "nsIOService.h"
#include "nsIPrincipal.h"
#include "nsIWebTransport.h"
#include "nsIWebTransportStream.h"
#include "nsStreamUtils.h"

using IPCResult = mozilla::ipc::IPCResult;

namespace mozilla::dom {

NS_IMPL_ISUPPORTS(WebTransportParent, WebTransportSessionEventListener);

using CreateWebTransportPromise =
    MozPromise<WebTransportReliabilityMode, nsresult, true>;
WebTransportParent::~WebTransportParent() {
  LOG(("Destroying WebTransportParent %p", this));
}

void WebTransportParent::Create(
    const nsAString& aURL, nsIPrincipal* aPrincipal,
    const uint64_t& aBrowsingContextID, const IPCClientInfo& aClientInfo,
    const bool& aDedicated, const net::WebTransportMulticastPolicy& aMulticast,
    const bool& aRequireUnreliable, const uint32_t& aCongestionControl,
    nsTArray<WebTransportHash>&& aServerCertHashes,
    Endpoint<PWebTransportParent>&& aParentEndpoint,
    std::function<void(std::tuple<const nsresult&, const uint8_t&>)>&&
        aResolver) {
  LOG(("Created WebTransportParent %p %s %s %s congestion=%s", this,
       NS_ConvertUTF16toUTF8(aURL).get(),
       aDedicated ? "Dedicated" : "AllowPooling",
       aRequireUnreliable ? "RequireUnreliable" : "",
       aCongestionControl ==
               (uint32_t)dom::WebTransportCongestionControl::Throughput
           ? "ThroughPut"
           : (aCongestionControl ==
                      (uint32_t)dom::WebTransportCongestionControl::Low_latency
                  ? "Low-Latency"
                  : "Default")));

  if (!aParentEndpoint.IsValid()) {
    aResolver(ResolveType(
        NS_ERROR_INVALID_ARG,
        static_cast<uint8_t>(WebTransportReliabilityMode::Pending)));
    return;
  }

  MOZ_DIAGNOSTIC_ASSERT(mozilla::net::gIOService);
  nsresult rv =
      mozilla::net::gIOService->NewWebTransport(getter_AddRefs(mWebTransport));
  if (NS_FAILED(rv)) {
    aResolver(ResolveType(
        rv, static_cast<uint8_t>(WebTransportReliabilityMode::Pending)));
    return;
  }

  mOwningEventTarget = GetCurrentSerialEventTarget();
  MOZ_ASSERT(aPrincipal);
  nsCOMPtr<nsIURI> uri;
  rv = NS_NewURI(getter_AddRefs(uri), aURL);
  if (NS_FAILED(rv)) {
    aResolver(ResolveType(
        NS_ERROR_INVALID_ARG,
        static_cast<uint8_t>(WebTransportReliabilityMode::Pending)));
    return;
  }

  nsTArray<RefPtr<nsIWebTransportHash>> nsServerCertHashes;
  for (const auto& hash : aServerCertHashes) {
    nsCString alg = hash.algorithm();
    nsServerCertHashes.AppendElement(
        new net::WebTransportHash(alg, hash.value()));
  }

  nsCOMPtr<nsIRunnable> r = NS_NewRunnableFunction(
      "WebTransport AsyncConnect",
      [self = RefPtr{this}, uri = std::move(uri),
       dedicated = true /* aDedicated, see BUG 1915735.*/,
       multicast = aMulticast, operationId = nsID::GenerateUUID(),
       nsServerCertHashes = std::move(nsServerCertHashes),
       principal = RefPtr{aPrincipal}, browsingContextID = aBrowsingContextID,
       flags = nsILoadInfo::SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL,
       clientInfo = ClientInfo{aClientInfo}] {
        LOG(("WebTransport %p AsyncConnect", self.get()));
        nsCOMPtr<nsIWebTransport> webTransport;
        {
          MutexAutoLock lock(self->mMutex);
          if (self->mLifecycle != Lifecycle::ConnectQueued) {
            return;
          }
          self->mLifecycle = Lifecycle::Negotiating;
          webTransport = self->mWebTransport;
        }
        auto operationPolicy = net::CreateWebTransportOperationPolicy(
            principal, uri, Some(clientInfo), browsingContextID, multicast,
            operationId);
        if (operationPolicy.isErr()) {
          self->OnSessionClosed(false, 0, ""_ns);
          return;
        }
        nsresult rv = webTransport->AsyncConnectWithClient(
            uri, dedicated, std::move(nsServerCertHashes), principal,
            browsingContextID, flags, self, Some(clientInfo),
            operationPolicy.unwrap(), nsIWebTransport::HTTPVersion::h3);
        if (NS_FAILED(rv)) {
          LOG(("AsyncConnect failed rv=0x%08" PRIx32,
               static_cast<uint32_t>(rv)));
          (void)self->OnSessionClosed(false, 0, ""_ns);
        }
      });

  // Bind to SocketThread for IPC - connection creation/destruction must
  // hit MainThread, but keep all other traffic on SocketThread.  Note that
  // we must call aResolver() on this (PBackground) thread.
  mSocketThread = do_GetService(NS_SOCKETTRANSPORTSERVICE_CONTRACTID, &rv);
  MOZ_ASSERT(NS_SUCCEEDED(rv));
  {
    MutexAutoLock lock(mMutex);
    mResolver = std::move(aResolver);
  }

  InvokeAsync(
      mSocketThread, __func__,
      [parentEndpoint = std::move(aParentEndpoint), runnable = r,
       p = RefPtr{this}]() mutable {
        LOG(("Binding parent endpoint"));
        if (!parentEndpoint.Bind(p)) {
          return CreateWebTransportPromise::CreateAndReject(NS_ERROR_FAILURE,
                                                            __func__);
        }
        {
          MutexAutoLock lock(p->mMutex);
          if (p->mLifecycle != Lifecycle::Init) {
            return CreateWebTransportPromise::CreateAndReject(NS_ERROR_ABORT,
                                                              __func__);
          }
          p->mLifecycle = Lifecycle::ConnectQueued;
        }
        // IPC now holds a ref to parent
        // Send connection to the server via MainThread
        nsresult rv = NS_DispatchToMainThread(runnable, NS_DISPATCH_NORMAL);
        if (NS_FAILED(rv)) {
          return CreateWebTransportPromise::CreateAndReject(rv, __func__);
        }

        return CreateWebTransportPromise::CreateAndResolve(
            WebTransportReliabilityMode::Supports_unreliable, __func__);
      })
      ->Then(
          GetCurrentSerialEventTarget(), __func__,
          [p = RefPtr{this}](
              const CreateWebTransportPromise::ResolveOrRejectValue& aValue) {
            if (aValue.IsReject()) {
              p->CompleteCreate(
                  aValue.RejectValue(),
                  static_cast<uint8_t>(WebTransportReliabilityMode::Pending));
            }
          });
}

void WebTransportParent::CompleteCreate(nsresult aResult,
                                        uint8_t aReliability) {
  MOZ_ASSERT(mOwningEventTarget);
  MOZ_ASSERT(mOwningEventTarget->IsOnCurrentThread());

  Maybe<RemoteCloseInfo> remoteClose;
  std::function<void(ResolveType)> resolver;
  {
    MutexAutoLock lock(mMutex);
    if (!mResolver) {
      return;
    }

    if (NS_SUCCEEDED(aResult)) {
      if (mLifecycle != Lifecycle::ReadyPending &&
          mLifecycle != Lifecycle::RemoteClosedPending) {
        return;
      }
    } else if (mLifecycle == Lifecycle::Active ||
               mLifecycle == Lifecycle::RemoteClosed ||
               mLifecycle == Lifecycle::Closing ||
               mLifecycle == Lifecycle::Closed) {
      return;
    }

    resolver = std::move(mResolver);
    if (NS_FAILED(aResult)) {
      mRemoteClose.reset();
      mLifecycle = Lifecycle::Closed;
    } else if (mLifecycle == Lifecycle::RemoteClosedPending) {
      remoteClose = std::move(mRemoteClose);
      mLifecycle = Lifecycle::RemoteClosed;
    } else {
      mLifecycle = Lifecycle::Active;
    }
  }

  // The IPDL resolver can synchronously run teardown code. Publish the
  // lifecycle transition under the mutex, then invoke external code unlocked.
  resolver(ResolveType(aResult, aReliability));

  if (remoteClose) {
    NotifyRemoteClosed(remoteClose->mCleanly, remoteClose->mErrorCode,
                       remoteClose->mReason);
  }
}

nsresult WebTransportParent::DispatchCreateResult(nsresult aResult,
                                                  uint8_t aReliability) {
  MOZ_ASSERT(mOwningEventTarget);
  if (mOwningEventTarget->IsOnCurrentThread()) {
    CompleteCreate(aResult, aReliability);
    return NS_OK;
  }

  nsresult rv = mOwningEventTarget->Dispatch(
      NS_NewRunnableFunction("WebTransportParent::CompleteCreate",
                             [self = RefPtr{this}, aResult, aReliability] {
                               self->CompleteCreate(aResult, aReliability);
                             }));
  if (NS_FAILED(rv)) {
    LOG(
        ("WebTransportParent %p failed to dispatch create result "
         "rv=0x%08" PRIx32,
         this, static_cast<uint32_t>(rv)));
    nsresult closeRv = Shutdown(0, ""_ns);
    if (NS_FAILED(closeRv)) {
      LOG(
          ("WebTransportParent %p cleanup after dispatch failure failed "
           "rv=0x%08" PRIx32,
           this, static_cast<uint32_t>(closeRv)));
    }
  }
  return rv;
}

nsresult WebTransportParent::Shutdown(uint32_t aCode,
                                      const nsACString& aReason) {
  nsCOMPtr<nsIWebTransport> webTransport;
  {
    MutexAutoLock lock(mMutex);
    if (mLifecycle == Lifecycle::Closing || mLifecycle == Lifecycle::Closed) {
      return NS_OK;
    }
    mLifecycle = Lifecycle::Closing;
    mResolver = nullptr;
    mRemoteClose.reset();
    webTransport = mWebTransport;
  }

  nsresult rv =
      webTransport ? webTransport->CloseSession(aCode, aReason) : NS_OK;
  {
    MutexAutoLock lock(mMutex);
    mLifecycle = Lifecycle::Closed;
  }
  return rv;
}

void WebTransportParent::ActorDestroy(ActorDestroyReason aWhy) {
  LOG(("ActorDestroy WebTransportParent %d", aWhy));
  nsresult rv = Shutdown(0, ""_ns);
  if (NS_FAILED(rv)) {
    LOG(("WebTransportParent %p ActorDestroy cleanup failed rv=0x%08" PRIx32,
         this, static_cast<uint32_t>(rv)));
  }
}

// We may not receive this response if the child side is destroyed without
// `Close` or `Shutdown` being explicitly called.
IPCResult WebTransportParent::RecvClose(const uint32_t& aCode,
                                        const nsACString& aReason) {
  LOG(("Close for %p received, code = %u, reason = %s", this, aCode,
       PromiseFlatCString(aReason).get()));
  nsresult rv = Shutdown(aCode, aReason);
  if (NS_FAILED(rv)) {
    LOG(("WebTransportParent %p RecvClose cleanup failed rv=0x%08" PRIx32, this,
         static_cast<uint32_t>(rv)));
  }
  Close();
  return IPC_OK();
}

class BidiReceiveStream : public nsIWebTransportStreamCallback {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIWEBTRANSPORTSTREAMCALLBACK

  BidiReceiveStream(
      WebTransportParent::CreateBidirectionalStreamResolver&& aResolver,
      std::function<
          void(uint64_t, WebTransportParent::OnResetOrStopSendingCallback&&,
               nsIWebTransportBidirectionalStream* aStream)>&& aStreamCallback,
      Maybe<int64_t> aSendOrder, nsCOMPtr<nsISerialEventTarget>& aSocketThread)
      : mResolver(aResolver),
        mStreamCallback(std::move(aStreamCallback)),
        mSendOrder(aSendOrder),
        mSocketThread(aSocketThread) {}

 private:
  virtual ~BidiReceiveStream() = default;
  WebTransportParent::CreateBidirectionalStreamResolver mResolver;
  std::function<void(uint64_t,
                     WebTransportParent::OnResetOrStopSendingCallback&&,
                     nsIWebTransportBidirectionalStream* aStream)>
      mStreamCallback;
  Maybe<int64_t> mSendOrder;
  nsCOMPtr<nsISerialEventTarget> mSocketThread;
};

class UniReceiveStream : public nsIWebTransportStreamCallback {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_NSIWEBTRANSPORTSTREAMCALLBACK

  UniReceiveStream(
      WebTransportParent::CreateUnidirectionalStreamResolver&& aResolver,
      std::function<void(uint64_t,
                         WebTransportParent::OnResetOrStopSendingCallback&&,
                         nsIWebTransportSendStream* aStream)>&& aStreamCallback,
      Maybe<int64_t> aSendOrder, nsCOMPtr<nsISerialEventTarget>& aSocketThread)
      : mResolver(aResolver),
        mStreamCallback(std::move(aStreamCallback)),
        mSendOrder(aSendOrder),
        mSocketThread(aSocketThread) {}

 private:
  virtual ~UniReceiveStream() = default;
  WebTransportParent::CreateUnidirectionalStreamResolver mResolver;
  std::function<void(uint64_t,
                     WebTransportParent::OnResetOrStopSendingCallback&&,
                     nsIWebTransportSendStream* aStream)>
      mStreamCallback;
  Maybe<int64_t> mSendOrder;
  nsCOMPtr<nsISerialEventTarget> mSocketThread;
};

NS_IMPL_ISUPPORTS(BidiReceiveStream, nsIWebTransportStreamCallback)
NS_IMPL_ISUPPORTS(UniReceiveStream, nsIWebTransportStreamCallback)

// nsIWebTransportStreamCallback:
NS_IMETHODIMP BidiReceiveStream::OnBidirectionalStreamReady(
    nsIWebTransportBidirectionalStream* aStream) {
  LOG(("Bidirectional stream ready!"));
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());

  aStream->SetSendOrder(mSendOrder);

  RefPtr<mozilla::ipc::DataPipeSender> inputsender;
  RefPtr<mozilla::ipc::DataPipeReceiver> inputreceiver;
  nsresult rv =
      NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                  getter_AddRefs(inputsender), getter_AddRefs(inputreceiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  uint64_t id;
  (void)aStream->GetStreamId(&id);
  nsCOMPtr<nsIAsyncInputStream> inputStream;
  aStream->GetInputStream(getter_AddRefs(inputStream));
  MOZ_ASSERT(inputStream);
  nsCOMPtr<nsISupports> inputCopyContext;
  rv = NS_AsyncCopy(inputStream, inputsender, mSocketThread,
                    NS_ASYNCCOPY_VIA_WRITESEGMENTS,  // can we use READSEGMENTS?
                    mozilla::ipc::kDefaultDataPipeCapacity, nullptr, nullptr,
                    true, true, getter_AddRefs(inputCopyContext));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  RefPtr<mozilla::ipc::DataPipeSender> outputsender;
  RefPtr<mozilla::ipc::DataPipeReceiver> outputreceiver;
  rv =
      NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                  getter_AddRefs(outputsender), getter_AddRefs(outputreceiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  nsCOMPtr<nsIAsyncOutputStream> outputStream;
  aStream->GetOutputStream(getter_AddRefs(outputStream));
  MOZ_ASSERT(outputStream);
  nsCOMPtr<nsISupports> outputCopyContext;
  rv = NS_AsyncCopy(outputreceiver, outputStream, mSocketThread,
                    NS_ASYNCCOPY_VIA_READSEGMENTS,
                    mozilla::ipc::kDefaultDataPipeCapacity, nullptr, nullptr,
                    true, true, getter_AddRefs(outputCopyContext));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  LOG(("Returning BidirectionalStream pipe to content"));
  mResolver(BidirectionalStream(id, inputreceiver, outputsender));

  auto onResetOrStopSending =
      [inputCopyContext(inputCopyContext), outputCopyContext(outputCopyContext),
       inputsender(inputsender),
       outputreceiver(outputreceiver)](nsresult aError) {
        LOG(("onResetOrStopSending err=%x", static_cast<uint32_t>(aError)));
        NS_CancelAsyncCopy(inputCopyContext, aError);
        inputsender->CloseWithStatus(aError);
        NS_CancelAsyncCopy(outputCopyContext, aError);
        outputreceiver->CloseWithStatus(aError);
      };

  // Store onResetOrStopSending in WebTransportParent::mBidiStreamCallbackMap
  // and onResetOrStopSending will be called when a stream receives STOP_SENDING
  // or RESET.
  mStreamCallback(id,
                  WebTransportParent::OnResetOrStopSendingCallback(
                      std::move(onResetOrStopSending)),
                  aStream);
  return NS_OK;
}

NS_IMETHODIMP UniReceiveStream::OnBidirectionalStreamReady(
    nsIWebTransportBidirectionalStream* aStream) {
  return NS_ERROR_FAILURE;
}

NS_IMETHODIMP
UniReceiveStream::OnUnidirectionalStreamReady(
    nsIWebTransportSendStream* aStream) {
  LOG(("Unidirectional stream ready!"));
  // We should be on the Socket Thread
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());

  aStream->SetSendOrder(mSendOrder);

  RefPtr<::mozilla::ipc::DataPipeSender> sender;
  RefPtr<::mozilla::ipc::DataPipeReceiver> receiver;
  nsresult rv = NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                            getter_AddRefs(sender), getter_AddRefs(receiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  uint64_t id;
  (void)aStream->GetStreamId(&id);
  nsCOMPtr<nsIAsyncOutputStream> outputStream;
  aStream->GetOutputStream(getter_AddRefs(outputStream));
  MOZ_ASSERT(outputStream);
  nsCOMPtr<nsISupports> copyContext;
  rv = NS_AsyncCopy(receiver, outputStream, mSocketThread,
                    NS_ASYNCCOPY_VIA_READSEGMENTS,
                    mozilla::ipc::kDefaultDataPipeCapacity, nullptr, nullptr,
                    true, true, getter_AddRefs(copyContext));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    mResolver(rv);
    return rv;
  }

  LOG(("Returning UnidirectionalStream pipe to content"));
  // pass the DataPipeSender to the content process
  mResolver(UnidirectionalStream(id, sender));

  auto onResetOrStopSending = [copyContext(copyContext),
                               receiver(receiver)](nsresult aError) {
    LOG(("onResetOrStopSending err=%x", static_cast<uint32_t>(aError)));
    NS_CancelAsyncCopy(copyContext, aError);
    receiver->CloseWithStatus(aError);
  };

  // Store onResetOrStopSending in WebTransportParent::mStreamCallbackMap and
  // onResetOrStopSending will be called when a stream receives STOP_SENDING.
  mStreamCallback(id,
                  WebTransportParent::OnResetOrStopSendingCallback(
                      std::move(onResetOrStopSending)),
                  aStream);

  return NS_OK;
}

NS_IMETHODIMP
BidiReceiveStream::OnUnidirectionalStreamReady(
    nsIWebTransportSendStream* aStream) {
  return NS_ERROR_FAILURE;
}

JS_HAZ_CAN_RUN_SCRIPT NS_IMETHODIMP UniReceiveStream::OnError(uint8_t aError) {
  nsresult rv = aError == nsIWebTransport::INVALID_STATE_ERROR
                    ? NS_ERROR_DOM_INVALID_STATE_ERR
                    : NS_ERROR_FAILURE;
  LOG(("CreateStream OnError: %u", aError));
  mResolver(rv);
  return NS_OK;
}

JS_HAZ_CAN_RUN_SCRIPT NS_IMETHODIMP BidiReceiveStream::OnError(uint8_t aError) {
  nsresult rv = aError == nsIWebTransport::INVALID_STATE_ERROR
                    ? NS_ERROR_DOM_INVALID_STATE_ERR
                    : NS_ERROR_FAILURE;
  LOG(("CreateStream OnError: %u", aError));
  mResolver(rv);
  return NS_OK;
}

IPCResult WebTransportParent::RecvSetSendOrder(uint64_t aStreamId,
                                               Maybe<int64_t> aSendOrder) {
  if (aSendOrder) {
    LOG(("Set sendOrder=%" PRIi64 " for streamId %" PRIu64, aSendOrder.value(),
         aStreamId));
  } else {
    LOG(("Set sendOrder=null for streamId %" PRIu64, aStreamId));
  }
  if (auto entry = mUniStreamCallbackMap.Lookup(aStreamId)) {
    entry->mStream->SetSendOrder(aSendOrder);
  } else if (auto entry = mBidiStreamCallbackMap.Lookup(aStreamId)) {
    entry->mStream->SetSendOrder(aSendOrder);
  }
  return IPC_OK();
}

IPCResult WebTransportParent::RecvCreateUnidirectionalStream(
    Maybe<int64_t> aSendOrder, CreateUnidirectionalStreamResolver&& aResolver) {
  LOG(("%s for %p received, useSendOrder=%d, sendOrder=%" PRIi64, __func__,
       this, aSendOrder.isSome(),
       aSendOrder.isSome() ? aSendOrder.value() : 0));

  auto streamCb =
      [self = RefPtr{this}](
          uint64_t aStreamId,
          WebTransportParent::OnResetOrStopSendingCallback&& aCallback,
          nsIWebTransportSendStream* aStream) {
        self->mUniStreamCallbackMap.InsertOrUpdate(
            aStreamId, StreamHash<nsIWebTransportSendStream>{
                           std::move(aCallback), aStream});
      };
  RefPtr<UniReceiveStream> callback = new UniReceiveStream(
      std::move(aResolver), std::move(streamCb), aSendOrder, mSocketThread);
  nsresult rv;
  rv = mWebTransport->CreateOutgoingUnidirectionalStream(callback);
  if (NS_FAILED(rv)) {
    callback->OnError(0);  // XXX
  }
  return IPC_OK();
}

IPCResult WebTransportParent::RecvCreateBidirectionalStream(
    Maybe<int64_t> aSendOrder, CreateBidirectionalStreamResolver&& aResolver) {
  LOG(("%s for %p received, useSendOrder=%d, sendOrder=%" PRIi64, __func__,
       this, aSendOrder.isSome(),
       aSendOrder.isSome() ? aSendOrder.value() : 0));

  auto streamCb =
      [self = RefPtr{this}](
          uint64_t aStreamId,
          WebTransportParent::OnResetOrStopSendingCallback&& aCallback,
          nsIWebTransportBidirectionalStream* aStream) {
        self->mBidiStreamCallbackMap.InsertOrUpdate(
            aStreamId, StreamHash<nsIWebTransportBidirectionalStream>{
                           std::move(aCallback), aStream});
      };
  RefPtr<BidiReceiveStream> callback = new BidiReceiveStream(
      std::move(aResolver), std::move(streamCb), aSendOrder, mSocketThread);
  nsresult rv;
  rv = mWebTransport->CreateOutgoingBidirectionalStream(callback);
  if (NS_FAILED(rv)) {
    callback->OnError(0);  // XXX
  }
  return IPC_OK();
}

// We recieve this notification from the WebTransportSessionProxy if session was
// successfully created at the end of
// WebTransportSessionProxy::OnStopRequest
NS_IMETHODIMP
WebTransportParent::OnSessionReady(uint64_t aSessionId) {
  MOZ_ASSERT(mOwningEventTarget);
  MOZ_ASSERT(!mOwningEventTarget->IsOnCurrentThread());

  LOG(("Created web transport session, sessionID = %" PRIu64 ", for %p",
       aSessionId, this));

  nsCOMPtr<nsIWebTransport> webTransport;
  nsresult rv;
  {
    // Retarget while holding the lifecycle lock so teardown cannot infer
    // socket-thread ownership until the target switch has completed.
    MutexAutoLock lock(mMutex);
    if (mLifecycle != Lifecycle::Negotiating) {
      return NS_OK;
    }
    mLifecycle = Lifecycle::Retargeting;
    webTransport = mWebTransport;
    rv = webTransport->RetargetTo(mSocketThread);
    mLifecycle =
        NS_SUCCEEDED(rv) ? Lifecycle::ReadyPending : Lifecycle::CreateFailed;
  }
  if (NS_FAILED(rv)) {
    nsresult closeRv = webTransport->CloseSession(0, ""_ns);
    if (NS_FAILED(closeRv)) {
      LOG(("WebTransportParent %p retarget cleanup failed rv=0x%08" PRIx32,
           this, static_cast<uint32_t>(closeRv)));
    }
    return DispatchCreateResult(
        rv,
        static_cast<uint8_t>(WebTransportReliabilityMode::Supports_unreliable));
  }

  return DispatchCreateResult(
      NS_OK,
      static_cast<uint8_t>(WebTransportReliabilityMode::Supports_unreliable));
}

// We receive this notification from the WebTransportSessionProxy if session
// creation was unsuccessful at the end of
// WebTransportSessionProxy::OnStopRequest
NS_IMETHODIMP
WebTransportParent::OnSessionClosed(const bool aCleanly,
                                    const uint32_t aErrorCode,
                                    const nsACString& aReason) {
  MOZ_ASSERT(mOwningEventTarget);
  MOZ_ASSERT(!mOwningEventTarget->IsOnCurrentThread());

  // currently we just know if session was closed gracefully or not.
  // we need better error propagation from lower-levels of http3
  // webtransport session and it's subsequent error mapping to DOM.
  // XXX See Bug 1806834
  bool creationFailed = false;
  bool notifyRemoteClose = false;
  {
    MutexAutoLock lock(mMutex);
    switch (mLifecycle) {
      case Lifecycle::ReadyPending:
        mLifecycle = Lifecycle::RemoteClosedPending;
        mRemoteClose =
            Some(RemoteCloseInfo{aCleanly, aErrorCode, nsCString{aReason}});
        return NS_OK;
      case Lifecycle::Active:
        mLifecycle = Lifecycle::RemoteClosed;
        notifyRemoteClose = true;
        break;
      case Lifecycle::Init:
      case Lifecycle::ConnectQueued:
      case Lifecycle::Negotiating:
      case Lifecycle::Retargeting:
        mLifecycle = Lifecycle::CreateFailed;
        creationFailed = true;
        break;
      case Lifecycle::RemoteClosedPending:
      case Lifecycle::RemoteClosed:
      case Lifecycle::CreateFailed:
      case Lifecycle::Closing:
      case Lifecycle::Closed:
        return NS_OK;
    }
  }

  if (creationFailed) {
    // this is an unclean close (we never got to ready)
    LOG(("webtransport %p session creation failed code= %u, reason= %s", this,
         aErrorCode, PromiseFlatCString(aReason).get()));
    // we know we haven't gone Ready yet
    return DispatchCreateResult(
        NS_ERROR_FAILURE,
        static_cast<uint8_t>(WebTransportReliabilityMode::Supports_unreliable));
  }

  if (notifyRemoteClose) {
    // https://w3c.github.io/webtransport/#web-transport-termination
    // Step 1: Let cleanly be a boolean representing whether the HTTP/3
    // stream associated with the CONNECT request that initiated
    // transport.[[Session]] is in the "Data Recvd" state. [QUIC]
    // XXX not calculated yet
    NotifyRemoteClosed(aCleanly, aErrorCode, aReason);
  }

  return NS_OK;
}

NS_IMETHODIMP WebTransportParent::OnStopSending(uint64_t aStreamId,
                                                nsresult aError) {
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  LOG(("WebTransportParent::OnStopSending %p stream id=%" PRIx64, this,
       aStreamId));
  if (auto entry = mUniStreamCallbackMap.Lookup(aStreamId)) {
    entry->mCallback.OnResetOrStopSending(aError);
    mUniStreamCallbackMap.Remove(aStreamId);
  } else if (auto entry = mBidiStreamCallbackMap.Lookup(aStreamId)) {
    entry->mCallback.OnResetOrStopSending(aError);
    mBidiStreamCallbackMap.Remove(aStreamId);
  }
  if (CanSend()) {
    (void)SendOnStreamResetOrStopSending(aStreamId, StopSendingError(aError));
  }
  return NS_OK;
}

NS_IMETHODIMP WebTransportParent::OnResetReceived(uint64_t aStreamId,
                                                  nsresult aError) {
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  LOG(("WebTransportParent::OnResetReceived %p stream id=%" PRIx64, this,
       aStreamId));
  if (auto entry = mUniStreamCallbackMap.Lookup(aStreamId)) {
    entry->mCallback.OnResetOrStopSending(aError);
    mUniStreamCallbackMap.Remove(aStreamId);
  } else if (auto entry = mBidiStreamCallbackMap.Lookup(aStreamId)) {
    entry->mCallback.OnResetOrStopSending(aError);
    mBidiStreamCallbackMap.Remove(aStreamId);
  }
  if (CanSend()) {
    (void)SendOnStreamResetOrStopSending(aStreamId, ResetError(aError));
  }
  return NS_OK;
}

void WebTransportParent::NotifyRemoteClosed(bool aCleanly, uint32_t aErrorCode,
                                            const nsACString& aReason) {
  LOG(("webtransport %p session remote closed cleanly=%d code= %u, reason= %s",
       this, aCleanly, aErrorCode, PromiseFlatCString(aReason).get()));
  nsresult rv = mSocketThread->Dispatch(NS_NewRunnableFunction(
      __func__, [self = RefPtr{this}, aErrorCode, reason = nsCString{aReason},
                 aCleanly]() {
        {
          MutexAutoLock lock(self->mMutex);
          if (self->mLifecycle != Lifecycle::RemoteClosed || !self->CanSend()) {
            return;
          }
        }
        // Tell the content side we were closed by the server
        (void)self->SendRemoteClosed(aCleanly, aErrorCode, reason);
        // Let the other end shut down the IPC channel after RecvClose()
      }));
  if (NS_FAILED(rv)) {
    LOG((
        "WebTransportParent %p failed to dispatch remote close rv=0x%08" PRIx32,
        this, static_cast<uint32_t>(rv)));
    nsresult closeRv = Shutdown(0, ""_ns);
    if (NS_FAILED(closeRv)) {
      LOG(("WebTransportParent %p remote-close cleanup failed rv=0x%08" PRIx32,
           this, static_cast<uint32_t>(closeRv)));
    }
  }
}

NS_IMETHODIMP
WebTransportParent::OnIncomingUnidirectionalStreamAvailable(
    nsIWebTransportReceiveStream* aStream) {
  // Note: we need to hold a reference to the stream if we want to get stats,
  // etc
  LOG(("%p IncomingUnidirectonalStream available", this));

  // We must be on the Socket Thread
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());

  RefPtr<DataPipeSender> sender;
  RefPtr<DataPipeReceiver> receiver;
  nsresult rv = NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                            getter_AddRefs(sender), getter_AddRefs(receiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  nsCOMPtr<nsIAsyncInputStream> inputStream;
  aStream->GetInputStream(getter_AddRefs(inputStream));
  MOZ_ASSERT(inputStream);
  rv = NS_AsyncCopy(inputStream, sender, mSocketThread,
                    NS_ASYNCCOPY_VIA_WRITESEGMENTS,
                    mozilla::ipc::kDefaultDataPipeCapacity);
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  LOG(("%p Sending UnidirectionalStream pipe to content", this));
  // pass the DataPipeReceiver to the content process
  uint64_t id;
  (void)aStream->GetStreamId(&id);
  (void)SendIncomingUnidirectionalStream(id, receiver);

  return NS_OK;
}

NS_IMETHODIMP
WebTransportParent::OnIncomingBidirectionalStreamAvailable(
    nsIWebTransportBidirectionalStream* aStream) {
  // Note: we need to hold a reference to the stream if we want to get stats,
  // etc
  LOG(("%p IncomingBidirectonalStream available", this));

  // We must be on the Socket Thread
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());

  RefPtr<DataPipeSender> inputSender;
  RefPtr<DataPipeReceiver> inputReceiver;
  nsresult rv =
      NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                  getter_AddRefs(inputSender), getter_AddRefs(inputReceiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  nsCOMPtr<nsIAsyncInputStream> inputStream;
  aStream->GetInputStream(getter_AddRefs(inputStream));
  MOZ_ASSERT(inputStream);
  rv = NS_AsyncCopy(inputStream, inputSender, mSocketThread,
                    NS_ASYNCCOPY_VIA_WRITESEGMENTS,
                    mozilla::ipc::kDefaultDataPipeCapacity);
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  RefPtr<DataPipeSender> outputSender;
  RefPtr<DataPipeReceiver> outputReceiver;
  rv =
      NewDataPipe(mozilla::ipc::kDefaultDataPipeCapacity,
                  getter_AddRefs(outputSender), getter_AddRefs(outputReceiver));
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  nsCOMPtr<nsIAsyncOutputStream> outputStream;
  aStream->GetOutputStream(getter_AddRefs(outputStream));
  MOZ_ASSERT(outputStream);
  rv = NS_AsyncCopy(outputReceiver, outputStream, mSocketThread,
                    NS_ASYNCCOPY_VIA_READSEGMENTS,
                    mozilla::ipc::kDefaultDataPipeCapacity);
  if (NS_WARN_IF(NS_FAILED(rv))) {
    return rv;
  }

  LOG(("%p Sending BidirectionalStream pipe to content", this));
  // pass the DataPipeSender to the content process
  uint64_t id;
  (void)aStream->GetStreamId(&id);
  (void)SendIncomingBidirectionalStream(id, inputReceiver, outputSender);
  return NS_OK;
}

::mozilla::ipc::IPCResult WebTransportParent::RecvGetMaxDatagramSize(
    GetMaxDatagramSizeResolver&& aResolver) {
  LOG(("WebTransportParent RecvGetMaxDatagramSize"));
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  MOZ_ASSERT(mWebTransport);
  MOZ_ASSERT(!mMaxDatagramSizeResolver);

  mMaxDatagramSizeResolver = std::move(aResolver);
  // maximum datagram size for the session is returned from network stack
  // synchronously via WebTransportSessionEventListener::OnMaxDatagramSize
  // interface
  mWebTransport->GetMaxDatagramSize();
  return IPC_OK();
}

::mozilla::ipc::IPCResult WebTransportParent::RecvGetHttpChannelID(
    GetHttpChannelIDResolver&& aResolver) {
  LOG(("WebTransportParent Channel ID"));
  MOZ_ASSERT(mWebTransport);
  uint64_t aHttpChannelId;
  mWebTransport->GetHttpChannelID(&aHttpChannelId);
  aResolver(aHttpChannelId);
  return IPC_OK();
}

// The promise sent in this request will be resolved
// in OnOutgoingDatagramOutCome which is called synchronously from
// WebTransportSessionProxy::SendDatagram
::mozilla::ipc::IPCResult WebTransportParent::RecvOutgoingDatagram(
    nsTArray<uint8_t>&& aData, const TimeStamp& aExpirationTime,
    OutgoingDatagramResolver&& aResolver) {
  LOG(("WebTransportParent sending datagram"));
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  MOZ_ASSERT(mWebTransport);

  (void)aExpirationTime;

  MOZ_ASSERT(!mOutgoingDatagramResolver);
  mOutgoingDatagramResolver = std::move(aResolver);
  // XXX we need to forward the timestamps to the necko stack
  // timestamp should be checked in the necko for expiry
  // See Bug 1818300
  // currently this calls OnOutgoingDatagramOutCome synchronously
  // Neqo won't call us back if the id == 0!
  // We don't use the ID for anything currently; rework of the stack
  // to implement proper HighWatermark buffering will require
  // changes here anyways.
  static uint64_t sDatagramId = 1;
  LOG_VERBOSE(("Sending datagram %" PRIu64 ", length %zu", sDatagramId,
               aData.Length()));
  (void)mWebTransport->SendDatagram(aData, sDatagramId++);

  return IPC_OK();
}

NS_IMETHODIMP WebTransportParent::OnDatagramReceived(
    const nsTArray<uint8_t>& aData) {
  // We must be on the Socket Thread
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());

  LOG(("WebTransportParent received datagram length = %zu", aData.Length()));

  TimeStamp ts = TimeStamp::Now();
  (void)SendIncomingDatagram(aData, ts);

  return NS_OK;
}

NS_IMETHODIMP
WebTransportParent::OnOutgoingDatagramOutCome(
    uint64_t aId, WebTransportSessionEventListener::DatagramOutcome aOutCome) {
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  // XXX - do we need better error mappings for failures?
  nsresult result = NS_ERROR_FAILURE;
  (void)result;
  (void)aId;

  if (aOutCome == WebTransportSessionEventListener::DatagramOutcome::SENT) {
    result = NS_OK;
    LOG(("Sent datagram id= %" PRIu64, aId));
  } else {
    LOG(("Didn't send datagram id= %" PRIu64, aId));
  }

  // This assumes the stack is calling us back synchronously!
  MOZ_ASSERT(mOutgoingDatagramResolver);
  mOutgoingDatagramResolver(result);
  mOutgoingDatagramResolver = nullptr;

  return NS_OK;
}

NS_IMETHODIMP WebTransportParent::OnMaxDatagramSize(uint64_t aSize) {
  LOG(("Max datagram size is %" PRIu64, aSize));
  MOZ_ASSERT(mSocketThread->IsOnCurrentThread());
  MOZ_ASSERT(mMaxDatagramSizeResolver);
  mMaxDatagramSizeResolver(aSize);
  mMaxDatagramSizeResolver = nullptr;
  return NS_OK;
}
}  // namespace mozilla::dom
