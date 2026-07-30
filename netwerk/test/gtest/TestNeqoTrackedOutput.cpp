/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "DNS.h"
#include "gtest/gtest.h"
#include "mozilla/RefPtr.h"
#include "mozilla/net/NeqoHttp3Conn.h"
#include "nsString.h"
#include "prnetdb.h"

using namespace mozilla;
using namespace mozilla::net;
using namespace mozilla::literals;

namespace {

RefPtr<NeqoHttp3Conn> NewTrackedOutputConnection() {
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

NeqoGlueTestSendResult PrimeWouldBlock(NeqoHttp3Conn* conn) {
  auto result = neqo_glue_test_process_output_and_send(
      conn, NeqoGlueTestSendOutcome::WouldBlock, 0, 8, true);
  EXPECT_EQ(result.result, NS_BASE_STREAM_WOULD_BLOCK);
  EXPECT_EQ(result.bytes_written, 0U);
  EXPECT_EQ(result.send_calls, 1U);
  EXPECT_TRUE(result.output_pending);
  EXPECT_TRUE(neqo_glue_test_has_pending_output(conn));
  return result;
}

void ExpectUnblocked(NeqoHttp3Conn* conn) {
  EXPECT_FALSE(neqo_glue_test_has_pending_output(conn));
  auto result = neqo_glue_test_process_output_and_send(
      conn, NeqoGlueTestSendOutcome::Transient, 0, 8, true);
  EXPECT_NE(result.result, NS_ERROR_UNEXPECTED);
  EXPECT_FALSE(result.output_pending);
}

void ExpectSameCommittedStats(const NeqoGlueTestCommittedStats& aLeft,
                              const NeqoGlueTestCommittedStats& aRight) {
  EXPECT_TRUE(aLeft.available);
  EXPECT_TRUE(aRight.available);
  EXPECT_EQ(aLeft.packets_tx, aRight.packets_tx);
  EXPECT_EQ(aLeft.pmtud_tx, aRight.pmtud_tx);
  EXPECT_EQ(aLeft.frames_tx, aRight.frames_tx);
  EXPECT_EQ(aLeft.ecn_tx, aRight.ecn_tx);
  EXPECT_EQ(aLeft.ecn_path_validation, aRight.ecn_path_validation);
}

void ExpectFinalGleanStats(RefPtr<NeqoHttp3Conn>& aConn,
                           const NeqoGlueTestCommittedStats& aExpected,
                           uint8_t aExpectedDropResult) {
  neqo_glue_test_arm_drop_abandon_observer(aConn);
  aConn = nullptr;
  EXPECT_EQ(neqo_glue_test_take_drop_abandon_result(), aExpectedDropResult);
  auto finalStats = neqo_glue_test_take_drop_glean_stats();
  ExpectSameCommittedStats(finalStats, aExpected);
}

}  // namespace

TEST(TestNeqoTrackedOutput, InjectedSocketOutcomes)
{
  auto full = NewTrackedOutputConnection();
  ASSERT_TRUE(full);
  auto result = neqo_glue_test_process_output_and_send(
      full, NeqoGlueTestSendOutcome::Full, 0, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  EXPECT_GT(result.bytes_written, 0U);
  EXPECT_GT(result.send_calls, 0U);
  EXPECT_FALSE(result.output_pending);

  auto partial = NewTrackedOutputConnection();
  ASSERT_TRUE(partial);
  result = neqo_glue_test_process_output_and_send(
      partial, NeqoGlueTestSendOutcome::Prefix, 1, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  EXPECT_GT(result.first_segment_count, 1U);
  EXPECT_GT(result.send_calls, 1U);
  EXPECT_FALSE(result.output_pending);

  auto unsupported = NewTrackedOutputConnection();
  ASSERT_TRUE(unsupported);
  result = neqo_glue_test_process_output_and_send(
      unsupported, NeqoGlueTestSendOutcome::UnsupportedGso, 0, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  EXPECT_GT(result.first_segment_count, 1U);
  EXPECT_GT(result.send_calls, 1U);
  EXPECT_FALSE(result.output_pending);

  auto transient = NewTrackedOutputConnection();
  ASSERT_TRUE(transient);
  result = neqo_glue_test_process_output_and_send(
      transient, NeqoGlueTestSendOutcome::Transient, 0, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  EXPECT_EQ(result.timer, 1U);
  EXPECT_FALSE(result.output_pending);

  auto fatal = NewTrackedOutputConnection();
  ASSERT_TRUE(fatal);
  result = neqo_glue_test_process_output_and_send(
      fatal, NeqoGlueTestSendOutcome::Fatal, 0, 8, true);
  EXPECT_TRUE(NS_FAILED(result.result));
  EXPECT_FALSE(result.output_pending);

  auto overlong = NewTrackedOutputConnection();
  ASSERT_TRUE(overlong);
  result = neqo_glue_test_process_output_and_send(
      overlong, NeqoGlueTestSendOutcome::Overlong, 0, 8, true);
  EXPECT_EQ(result.result, NS_ERROR_UNEXPECTED);
  EXPECT_FALSE(result.output_pending);
}

TEST(TestNeqoTrackedOutput, WouldBlockMutationGates)
{
  NetAddr remote;
  remote.inet.family = AF_INET;
  remote.inet.port = PR_htons(4434);
  remote.inet.ip = PR_htonl(0xc0000202);

  auto input = NewTrackedOutputConnection();
  ASSERT_TRUE(input);
  PrimeWouldBlock(input);
  nsTArray<uint8_t> packet{0};
  EXPECT_EQ(input->ProcessInputUseNSPRForIO(remote, packet), NS_OK);
  ExpectUnblocked(input);

  auto output = NewTrackedOutputConnection();
  ASSERT_TRUE(output);
  PrimeWouldBlock(output);
  auto result = neqo_glue_test_process_output_and_send(
      output, NeqoGlueTestSendOutcome::Full, 0, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  EXPECT_FALSE(result.output_pending);

  auto events = NewTrackedOutputConnection();
  ASSERT_TRUE(events);
  PrimeWouldBlock(events);
  Http3Event event{};
  event.tag = Http3Event::Tag::NoEvent;
  nsTArray<uint8_t> data;
  EXPECT_EQ(events->GetEvent(&event, data), NS_OK);
  ExpectUnblocked(events);

  auto revoked = NewTrackedOutputConnection();
  ASSERT_TRUE(revoked);
  PrimeWouldBlock(revoked);
  EXPECT_EQ(revoked->McquicRevokeOperation(), NS_OK);
  EXPECT_TRUE(neqo_glue_test_mcquic_revoked_clean(revoked));
  ExpectUnblocked(revoked);

  auto closed = NewTrackedOutputConnection();
  ASSERT_TRUE(closed);
  PrimeWouldBlock(closed);
  closed->Close(0);
  ExpectUnblocked(closed);

  auto destroyed = NewTrackedOutputConnection();
  ASSERT_TRUE(destroyed);
  PrimeWouldBlock(destroyed);
  neqo_glue_test_arm_drop_abandon_observer(destroyed);
  destroyed = nullptr;
  EXPECT_EQ(neqo_glue_test_take_drop_abandon_result(), 2U);
}

TEST(TestNeqoTrackedOutput, StatisticsAreCommittedOnly)
{
  auto conn = NewTrackedOutputConnection();
  ASSERT_TRUE(conn);
  Http3Stats before{};
  conn->GetStats(&before);

  PrimeWouldBlock(conn);
  EXPECT_GT(neqo_glue_test_tentative_packets_tx(conn), before.packets_tx);
  Http3Stats pending{};
  conn->GetStats(&pending);
  EXPECT_EQ(pending.packets_tx, before.packets_tx);

  EXPECT_EQ(conn->AbandonOutput(), NS_OK);
  Http3Stats abandoned{};
  conn->GetStats(&abandoned);
  EXPECT_EQ(abandoned.packets_tx, before.packets_tx);

  auto result = neqo_glue_test_process_output_and_send(
      conn, NeqoGlueTestSendOutcome::Full, 0, 8, true);
  EXPECT_EQ(result.result, NS_OK);
  Http3Stats committed{};
  conn->GetStats(&committed);
  EXPECT_GT(committed.packets_tx, before.packets_tx);
}

TEST(TestNeqoTrackedOutput, FinalGleanUsesOnlyCommittedStatistics)
{
  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    auto result = neqo_glue_test_process_output_and_send(
        conn, NeqoGlueTestSendOutcome::Full, 0, 8, true);
    ASSERT_EQ(result.result, NS_OK);
    auto committed = neqo_glue_test_committed_stats(conn);
    EXPECT_GT(committed.packets_tx, before.packets_tx);
    EXPECT_GT(committed.frames_tx, before.frames_tx);
    ExpectFinalGleanStats(conn, committed, 1);
  }

  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    auto result = neqo_glue_test_process_output_and_send(
        conn, NeqoGlueTestSendOutcome::Prefix, 1, 8, true);
    ASSERT_EQ(result.result, NS_OK);
    ASSERT_GT(result.first_segment_count, 1U);
    ASSERT_EQ(result.send_calls, 2U);
    auto committed = neqo_glue_test_committed_stats(conn);
    EXPECT_GT(committed.packets_tx, before.packets_tx);
    EXPECT_GT(committed.frames_tx, before.frames_tx);
    ExpectFinalGleanStats(conn, committed, 1);
  }

  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    auto result = neqo_glue_test_process_output_and_send(
        conn, NeqoGlueTestSendOutcome::Prefix, 0, 8, true);
    ASSERT_EQ(result.result, NS_OK);
    ASSERT_EQ(result.bytes_written, 0U);
    ASSERT_EQ(result.send_calls, 1U);
    auto committed = neqo_glue_test_committed_stats(conn);
    ExpectSameCommittedStats(committed, before);
    ExpectFinalGleanStats(conn, committed, 1);
  }

  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    PrimeWouldBlock(conn);
    ASSERT_EQ(conn->AbandonOutput(), NS_OK);
    auto committed = neqo_glue_test_committed_stats(conn);
    ExpectSameCommittedStats(committed, before);
    ExpectFinalGleanStats(conn, committed, 1);
  }

  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    auto result = neqo_glue_test_process_output_and_send(
        conn, NeqoGlueTestSendOutcome::Fatal, 0, 8, true);
    ASSERT_TRUE(NS_FAILED(result.result));
    auto committed = neqo_glue_test_committed_stats(conn);
    ExpectSameCommittedStats(committed, before);
    ExpectFinalGleanStats(conn, committed, 1);
  }

  {
    auto conn = NewTrackedOutputConnection();
    ASSERT_TRUE(conn);
    auto before = neqo_glue_test_committed_stats(conn);
    PrimeWouldBlock(conn);
    ExpectFinalGleanStats(conn, before, 2);
  }
}

TEST(TestNeqoTrackedOutput, InvalidTokensFailClosed)
{
  auto first = NewTrackedOutputConnection();
  auto second = NewTrackedOutputConnection();
  ASSERT_TRUE(first);
  ASSERT_TRUE(second);

  auto result = neqo_glue_test_output_token_rejections(first, second);
  EXPECT_TRUE(result.overlong_rejected);
  EXPECT_TRUE(result.foreign_rejected);
  EXPECT_TRUE(result.duplicate_rejected);
  EXPECT_FALSE(neqo_glue_test_has_pending_output(first));
  EXPECT_FALSE(neqo_glue_test_has_pending_output(second));
}
