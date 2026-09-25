#include <unity.h>

#include <cstring>

#include "review_screens.h"

using namespace btcseed;

void setUp(void) {}
void tearDown(void) {}

static void test_format_address_grouped(void) {
  char out[64];
  TEST_ASSERT_TRUE(format_address_grouped("bc1qcr8te4kr609gcawu", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("bc1q cr8t e4kr 609g cawu", out);
}

static void test_format_address_grouped_short(void) {
  char out[16];
  TEST_ASSERT_TRUE(format_address_grouped("abc", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("abc", out);

  TEST_ASSERT_TRUE(format_address_grouped("", out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("", out);
}

static void test_format_address_grouped_respects_capacity(void) {
  char tiny[4];
  TEST_ASSERT_FALSE(format_address_grouped("bc1qcr8te4kr609gcawu", tiny, sizeof(tiny)));
}

static void test_format_btc(void) {
  char out[24];
  TEST_ASSERT_TRUE(format_btc(50000, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("0.00050000 BTC", out);

  TEST_ASSERT_TRUE(format_btc(100000000, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("1.00000000 BTC", out);

  TEST_ASSERT_TRUE(format_btc(0, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("0.00000000 BTC", out);
}

static void test_format_sats(void) {
  char out[24];
  TEST_ASSERT_TRUE(format_sats(1234, out, sizeof(out)));
  TEST_ASSERT_EQUAL_STRING("1234 sats", out);
}

static void test_estimate_vbytes(void) {
  // 1 input + 2 outputs P2WPKH: 10.5 + 68 + 62 = 140.5
  // TEST_ASSERT_EQUAL_DOUBLE exige Unity compilado com UNITY_INCLUDE_DOUBLE
  // (nao habilitado por padrao em builds embarcados) — usa float aqui.
  TEST_ASSERT_FLOAT_WITHIN(0.001f, 140.5f,
                          static_cast<float>(estimate_vbytes(1, 2)));
}

static void test_build_output_review(void) {
  OutputInfo info;
  strncpy(info.address, "bc1qcr8te4kr609gcawu", sizeof(info.address) - 1);
  info.amount_sats = 50000;
  info.is_change = false;
  info.claimed_change_invalid = false;

  OutputReviewText text;
  build_output_review(info, &text);

  TEST_ASSERT_EQUAL_STRING("bc1q cr8t e4kr 609g cawu", text.address_grouped);
  TEST_ASSERT_EQUAL_STRING("0.00050000 BTC", text.amount_btc);
  TEST_ASSERT_EQUAL_STRING("50000 sats", text.amount_sats);
  TEST_ASSERT_FALSE(text.is_change);
  TEST_ASSERT_FALSE(text.claimed_change_invalid);
}

static void test_build_output_review_flags_forged_change(void) {
  OutputInfo info;
  strncpy(info.address, "bc1qbogus", sizeof(info.address) - 1);
  info.amount_sats = 1000;
  info.is_change = false;
  info.claimed_change_invalid = true;

  OutputReviewText text;
  build_output_review(info, &text);
  TEST_ASSERT_TRUE(text.claimed_change_invalid);
  TEST_ASSERT_FALSE(text.is_change);
}

static void test_build_fee_review(void) {
  PsbtSummary summary{};
  summary.num_inputs = 1;
  summary.num_outputs = 2;
  summary.fee_sats = 1000;
  summary.high_fee_warning = false;

  FeeReviewText text;
  build_fee_review(summary, &text);

  TEST_ASSERT_EQUAL_STRING("1000 sats", text.fee_sats);
  // 1000 / 140.5 = 7.117... -> "~7.1 sat/vB"
  TEST_ASSERT_EQUAL_STRING("~7.1 sat/vB", text.fee_rate);
  TEST_ASSERT_FALSE(text.high_fee_warning);
}

static void test_build_fee_review_propagates_high_fee_warning(void) {
  PsbtSummary summary{};
  summary.num_inputs = 1;
  summary.num_outputs = 1;
  summary.fee_sats = 200000;
  summary.high_fee_warning = true;

  FeeReviewText text;
  build_fee_review(summary, &text);
  TEST_ASSERT_TRUE(text.high_fee_warning);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_format_address_grouped);
  RUN_TEST(test_format_address_grouped_short);
  RUN_TEST(test_format_address_grouped_respects_capacity);
  RUN_TEST(test_format_btc);
  RUN_TEST(test_format_sats);
  RUN_TEST(test_estimate_vbytes);
  RUN_TEST(test_build_output_review);
  RUN_TEST(test_build_output_review_flags_forged_change);
  RUN_TEST(test_build_fee_review);
  RUN_TEST(test_build_fee_review_propagates_high_fee_warning);
  return UNITY_END();
}
