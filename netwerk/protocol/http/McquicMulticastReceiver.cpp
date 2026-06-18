/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "HttpLog.h"

#include <inttypes.h>

#include "McquicMulticastReceiver.h"

#include "mozilla/StaticPrefs_network.h"
#include "nsSocketTransportService2.h"

namespace mozilla::net {

McquicMulticastReceiver::~McquicMulticastReceiver() {
  if (mReceiver) {
    neqo_mcquic_mcrx_receiver_free(mReceiver);
    mReceiver = nullptr;
  }
}

bool McquicMulticastReceiver::Enabled() {
  return StaticPrefs::network_http_http3_mcquic_native_moq_demo_enabled();
}

nsresult McquicMulticastReceiver::EnsureReady() const {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  if (!Enabled()) {
    return NS_ERROR_NOT_AVAILABLE;
  }

  if (!mReceiver) {
    return NS_ERROR_NOT_INITIALIZED;
  }

  return NS_OK;
}

nsresult McquicMulticastReceiver::Init() {
  MOZ_ASSERT(OnSocketThread(), "not on socket thread");

  if (!Enabled()) {
    LOG(("MCQUIC mcrx receiver disabled by pref"));
    return NS_ERROR_NOT_AVAILABLE;
  }

  if (mReceiver) {
    return NS_OK;
  }

  nsresult rv = neqo_mcquic_mcrx_receiver_new(&mReceiver);
  if (NS_FAILED(rv)) {
    LOG(("MCQUIC mcrx receiver init failed [rv=0x%08" PRIx32 "]",
         static_cast<uint32_t>(rv)));
    return rv;
  }

  LOG(("MCQUIC mcrx receiver initialized"));
  return NS_OK;
}

nsresult McquicMulticastReceiver::AddSsmSubscription(
    const nsACString& aSource, const nsACString& aGroup, uint16_t aPort,
    const nsACString& aInterface, Maybe<uint32_t> aInterfaceIndex,
    uint64_t* aSubscriptionId) {
  nsresult rv = EnsureReady();
  if (NS_FAILED(rv)) {
    return rv;
  }

  if (!aSubscriptionId) {
    return NS_ERROR_INVALID_ARG;
  }

  rv = neqo_mcquic_mcrx_receiver_add_ssm_subscription(
      mReceiver, &aSource, &aGroup, aPort, &aInterface,
      aInterfaceIndex.isSome(), aInterfaceIndex.valueOr(0), aSubscriptionId);
  if (NS_FAILED(rv)) {
    LOG(
        ("MCQUIC mcrx add SSM subscription failed [source=%s group=%s port=%u "
         "interface=%s rv=0x%08" PRIx32 "]",
         PromiseFlatCString(aSource).get(), PromiseFlatCString(aGroup).get(),
         aPort, PromiseFlatCString(aInterface).get(),
         static_cast<uint32_t>(rv)));
    return rv;
  }

  LOG(("MCQUIC mcrx added SSM subscription [id=%" PRIu64 " source=%s group=%s "
       "port=%u interface=%s]",
       *aSubscriptionId, PromiseFlatCString(aSource).get(),
       PromiseFlatCString(aGroup).get(), aPort,
       PromiseFlatCString(aInterface).get()));
  return NS_OK;
}

nsresult McquicMulticastReceiver::Join(uint64_t aSubscriptionId) {
  nsresult rv = EnsureReady();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = neqo_mcquic_mcrx_receiver_join(mReceiver, aSubscriptionId);
  if (NS_FAILED(rv)) {
    LOG(("MCQUIC mcrx join failed [id=%" PRIu64 " rv=0x%08" PRIx32 "]",
         aSubscriptionId, static_cast<uint32_t>(rv)));
    return rv;
  }

  LOG(("MCQUIC mcrx joined subscription [id=%" PRIu64 "]", aSubscriptionId));
  return NS_OK;
}

nsresult McquicMulticastReceiver::Leave(uint64_t aSubscriptionId) {
  nsresult rv = EnsureReady();
  if (NS_FAILED(rv)) {
    return rv;
  }

  return neqo_mcquic_mcrx_receiver_leave(mReceiver, aSubscriptionId);
}

nsresult McquicMulticastReceiver::Remove(uint64_t aSubscriptionId) {
  nsresult rv = EnsureReady();
  if (NS_FAILED(rv)) {
    return rv;
  }

  return neqo_mcquic_mcrx_receiver_remove(mReceiver, aSubscriptionId);
}

nsresult McquicMulticastReceiver::Poll(McquicMcrxPacket& aPacket) {
  nsresult rv = EnsureReady();
  if (NS_FAILED(rv)) {
    return rv;
  }

  rv = neqo_mcquic_mcrx_receiver_poll(mReceiver, &aPacket);
  if (rv == NS_BASE_STREAM_WOULD_BLOCK) {
    return rv;
  }
  if (NS_FAILED(rv)) {
    LOG(("MCQUIC mcrx poll failed [rv=0x%08" PRIx32 "]",
         static_cast<uint32_t>(rv)));
    return rv;
  }

  LOG(("MCQUIC mcrx packet [id=%" PRIu64 " source=%s:%u group=%s port=%u "
       "len=%zu]",
       aPacket.subscription_id, aPacket.source_ip.get(), aPacket.source_port,
       aPacket.group_ip.get(), aPacket.dst_port, aPacket.payload.Length()));
  return NS_OK;
}

}  // namespace mozilla::net
