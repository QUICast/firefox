/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "WebTransportParent.h"
#include "WebTransportSessionBase.h"
#include "WebTransportSessionProxy.h"
#include "WebTransportStreamBase.h"
#include "gtest/gtest.h"
#include "mozilla/RefPtr.h"
#include "nsSocketTransportService2.h"
#include "nsThreadUtils.h"

using namespace mozilla;
using namespace mozilla::literals;

namespace mozilla::dom {

class WebTransportParentLifecycleTestPeer {
 public:
  enum class Stage : uint8_t {
    ConnectQueued,
    Negotiating,
    Retargeting,
    ReadyPending,
  };

  static void Prepare(WebTransportParent* aParent, Stage aStage) {
    aParent->mOwningEventTarget = GetCurrentSerialEventTarget();
    MutexAutoLock lock(aParent->mMutex);
    switch (aStage) {
      case Stage::ConnectQueued:
        aParent->mLifecycle = WebTransportParent::Lifecycle::ConnectQueued;
        break;
      case Stage::Negotiating:
        aParent->mLifecycle = WebTransportParent::Lifecycle::Negotiating;
        break;
      case Stage::Retargeting:
        aParent->mLifecycle = WebTransportParent::Lifecycle::Retargeting;
        break;
      case Stage::ReadyPending:
        aParent->mLifecycle = WebTransportParent::Lifecycle::ReadyPending;
        break;
    }
  }

  static void DestroyBehindBarrier(WebTransportParent* aParent) {
    std::mutex startedMutex;
    std::condition_variable startedCondition;
    bool started = false;
    std::atomic<bool> finished = false;
    std::thread destroyThread;
    {
      MutexAutoLock barrier(aParent->mMutex);
      destroyThread = std::thread([parent = RefPtr{aParent}, &startedMutex,
                                   &startedCondition, &started, &finished] {
        {
          std::lock_guard lock(startedMutex);
          started = true;
        }
        startedCondition.notify_one();
        parent->ActorDestroy(mozilla::ipc::IProtocol::Deletion);
        finished = true;
      });
      std::unique_lock startedLock(startedMutex);
      startedCondition.wait(startedLock, [&] { return started; });
      EXPECT_FALSE(finished.load());
    }
    destroyThread.join();
    EXPECT_TRUE(finished.load());
    MutexAutoLock lock(aParent->mMutex);
    EXPECT_EQ(aParent->mLifecycle, WebTransportParent::Lifecycle::Closed);
  }

  static bool DeliverCreateResultAfterClose(WebTransportParent* aParent) {
    uint32_t resolverCalls = 0;
    {
      MutexAutoLock lock(aParent->mMutex);
      aParent->mLifecycle = WebTransportParent::Lifecycle::Closed;
      aParent->mResolver = [&resolverCalls](WebTransportParent::ResolveType) {
        ++resolverCalls;
      };
    }
    aParent->CompleteCreate(NS_OK, 0);
    return resolverCalls != 0;
  }

  static bool IsClosed(WebTransportParent* aParent) {
    MutexAutoLock lock(aParent->mMutex);
    return aParent->mLifecycle == WebTransportParent::Lifecycle::Closed;
  }
};

}  // namespace mozilla::dom

namespace mozilla::net {

class CountingWebTransportSession final : public WebTransportSessionBase {
 public:
  NS_INLINE_DECL_THREADSAFE_REFCOUNTING(CountingWebTransportSession, override)

  uint64_t GetStreamId() const override { return 7; }

  void CloseSession(uint32_t, const nsACString&) override { ++mCloseCalls; }

  void RevokeMulticast() override { ++mRevokeCalls; }

  void GetMaxDatagramSize() override {}

  void SendDatagram(nsTArray<uint8_t>&&, uint64_t) override {}

  void CreateOutgoingBidirectionalStream(
      std::function<void(Result<RefPtr<WebTransportStreamBase>, nsresult>&&)>&&
          aCallback) override {
    aCallback(Err(NS_ERROR_ABORT));
  }

  void CreateOutgoingUnidirectionalStream(
      std::function<void(Result<RefPtr<WebTransportStreamBase>, nsresult>&&)>&&
          aCallback) override {
    aCallback(Err(NS_ERROR_ABORT));
  }

  uint32_t mCloseCalls = 0;
  uint32_t mRevokeCalls = 0;

 private:
  ~CountingWebTransportSession() override = default;
};

class CountingWebTransportListener final
    : public WebTransportSessionEventListener {
 public:
  NS_DECL_THREADSAFE_ISUPPORTS
  NS_DECL_WEBTRANSPORTSESSIONEVENTLISTENER

  Atomic<uint32_t> mCloseCalls{0};

 private:
  ~CountingWebTransportListener() = default;
};

NS_IMPL_ISUPPORTS(CountingWebTransportListener,
                  WebTransportSessionEventListener)

NS_IMETHODIMP CountingWebTransportListener::OnSessionReady(uint64_t) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnSessionClosed(bool, uint32_t,
                                                            const nsACString&) {
  ++mCloseCalls;
  return NS_OK;
}

NS_IMETHODIMP
CountingWebTransportListener::OnIncomingBidirectionalStreamAvailable(
    nsIWebTransportBidirectionalStream*) {
  return NS_OK;
}

NS_IMETHODIMP
CountingWebTransportListener::OnIncomingUnidirectionalStreamAvailable(
    nsIWebTransportReceiveStream*) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnStopSending(uint64_t, nsresult) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnResetReceived(uint64_t,
                                                            nsresult) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnDatagramReceived(
    const nsTArray<uint8_t>&) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnMaxDatagramSize(uint64_t) {
  return NS_OK;
}

NS_IMETHODIMP CountingWebTransportListener::OnOutgoingDatagramOutCome(
    uint64_t, WebTransportSessionEventListener::DatagramOutcome) {
  return NS_OK;
}

class WebTransportSessionProxyLifecycleTestPeer {
 public:
  static void SetDone(WebTransportSessionProxy* aProxy) {
    MutexAutoLock lock(aProxy->mMutex);
    aProxy->mState = WebTransportSessionProxy::DONE;
  }

  static void InjectDelayedCloseCallback(
      WebTransportSessionProxy* aProxy,
      WebTransportSessionEventListener* aListener) {
    {
      MutexAutoLock lock(aProxy->mMutex);
      aProxy->mState = WebTransportSessionProxy::DONE;
      aProxy->mListener = aListener;
      aProxy->mCloseCallbackTarget = GetCurrentSerialEventTarget();
    }
    aProxy->CallOnSessionClosedLocked();
  }

  static bool IsDone(WebTransportSessionProxy* aProxy) {
    MutexAutoLock lock(aProxy->mMutex);
    return aProxy->mState == WebTransportSessionProxy::DONE;
  }
};

TEST(TestWebTransportLifecycle, ActorDestroySerializesEveryTransition)
{
  using Stage = dom::WebTransportParentLifecycleTestPeer::Stage;
  for (Stage stage : {Stage::ConnectQueued, Stage::Negotiating,
                      Stage::Retargeting, Stage::ReadyPending}) {
    RefPtr<dom::WebTransportParent> parent = new dom::WebTransportParent();
    dom::WebTransportParentLifecycleTestPeer::Prepare(parent, stage);
    dom::WebTransportParentLifecycleTestPeer::DestroyBehindBarrier(parent);
  }
}

TEST(TestWebTransportLifecycle, StaleParentCallbacksCannotReactivate)
{
  RefPtr<dom::WebTransportParent> parent = new dom::WebTransportParent();
  dom::WebTransportParentLifecycleTestPeer::Prepare(
      parent, dom::WebTransportParentLifecycleTestPeer::Stage::ReadyPending);
  parent->ActorDestroy(mozilla::ipc::IProtocol::Deletion);

  EXPECT_FALSE(
      dom::WebTransportParentLifecycleTestPeer::DeliverCreateResultAfterClose(
          parent));

  ASSERT_TRUE(gSocketTransportService);
  NS_DispatchAndSpinEventLoopUntilComplete(
      "TestWebTransportLifecycle::StaleParentCallbacksCannotReactivate"_ns,
      gSocketTransportService,
      NS_NewRunnableFunction(
          "TestWebTransportLifecycle::StaleParentCallbacksCannotReactivate",
          [parent] {
            EXPECT_EQ(parent->OnSessionReady(7), NS_OK);
            EXPECT_EQ(parent->OnSessionClosed(false, 1, "late"_ns), NS_OK);
          }));

  EXPECT_TRUE(dom::WebTransportParentLifecycleTestPeer::IsClosed(parent));
}

TEST(TestWebTransportLifecycle, LateNativeSessionIsRevokedAndClosed)
{
  RefPtr<WebTransportSessionProxy> proxy = new WebTransportSessionProxy();
  WebTransportSessionProxyLifecycleTestPeer::SetDone(proxy);
  RefPtr<CountingWebTransportSession> lateSession =
      new CountingWebTransportSession();

  ASSERT_TRUE(gSocketTransportService);
  NS_DispatchAndSpinEventLoopUntilComplete(
      "TestWebTransportLifecycle::LateNativeSessionIsRevokedAndClosed"_ns,
      gSocketTransportService,
      NS_NewRunnableFunction(
          "TestWebTransportLifecycle::LateNativeSessionIsRevokedAndClosed",
          [proxy, lateSession] {
            EXPECT_EQ(proxy->OnSessionReadyInternal(lateSession),
                      NS_ERROR_ABORT);
          }));

  EXPECT_EQ(lateSession->mRevokeCalls, 1U);
  EXPECT_EQ(lateSession->mCloseCalls, 1U);
  EXPECT_TRUE(WebTransportSessionProxyLifecycleTestPeer::IsDone(proxy));
}

TEST(TestWebTransportLifecycle, DelayedCloseCallbackIsHarmlessAfterClose)
{
  RefPtr<WebTransportSessionProxy> proxy = new WebTransportSessionProxy();
  RefPtr<CountingWebTransportListener> listener =
      new CountingWebTransportListener();

  WebTransportSessionProxyLifecycleTestPeer::InjectDelayedCloseCallback(
      proxy, listener);

  EXPECT_EQ(listener->mCloseCalls, 0U);
  EXPECT_TRUE(WebTransportSessionProxyLifecycleTestPeer::IsDone(proxy));
}

}  // namespace mozilla::net
