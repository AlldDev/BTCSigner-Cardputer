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

// Quebra `text` em linhas de ate max_chars, confere que nenhuma passa do
// limite e que, sem os espacos, as linhas reproduzem `expected` inteiro.
static int wrap_and_check(const char *text, size_t max_chars, const char *expected) {
  char joined[160] = {0};
  size_t j = 0;
  size_t pos = 0, start = 0, n = 0;
  int lines = 0;
  while (wrap_next_line(text, &pos, max_chars, &start, &n)) {
    TEST_ASSERT_TRUE(n <= max_chars);
    TEST_ASSERT_TRUE(n > 0);
    for (size_t i = 0; i < n; i++) {
      if (text[start + i] != ' ') joined[j++] = text[start + i];
    }
    lines++;
  }
  joined[j] = '\0';
  TEST_ASSERT_EQUAL_STRING(expected, joined);
  return lines;
}

static void test_wrap_never_drops_address_chars(void) {
  const char *p2wpkh = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";            // 42
  const char *p2tr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"; // 62
  const char *p2pkh = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";                      // 34
  char grouped[100];

  // 29 chars/linha = fonte 8x16 na tela; 38 = fonte 6x8.
  TEST_ASSERT_TRUE(format_address_grouped(p2wpkh, grouped, sizeof(grouped)));
  TEST_ASSERT_EQUAL_INT(2, wrap_and_check(grouped, 29, p2wpkh));
  TEST_ASSERT_EQUAL_INT(2, wrap_and_check(grouped, 38, p2wpkh));

  TEST_ASSERT_TRUE(format_address_grouped(p2tr, grouped, sizeof(grouped)));
  TEST_ASSERT_EQUAL_INT(3, wrap_and_check(grouped, 29, p2tr));
  TEST_ASSERT_EQUAL_INT(3, wrap_and_check(grouped, 38, p2tr));

  TEST_ASSERT_TRUE(format_address_grouped(p2pkh, grouped, sizeof(grouped)));
  TEST_ASSERT_EQUAL_INT(2, wrap_and_check(grouped, 29, p2pkh));
}

static void test_wrap_hard_breaks_text_without_spaces(void) {
  // zpub: 111 chars sem espaco -> corte duro, nada perdido.
  const char *zpub =
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
  TEST_ASSERT_EQUAL_INT(4, wrap_and_check(zpub, 29, zpub));
  TEST_ASSERT_EQUAL_INT(0, wrap_and_check("   ", 29, ""));
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

static void test_build_output_review_propagates_change_index(void) {
  OutputInfo info;
  strncpy(info.address, "bc1qchange", sizeof(info.address) - 1);
  info.is_change = true;
  info.change_index = 5000;
  info.change_index_high = true;

  OutputReviewText text;
  build_output_review(info, &text);
  TEST_ASSERT_TRUE(text.is_change);
  TEST_ASSERT_EQUAL_UINT32(5000, text.change_index);
  TEST_ASSERT_TRUE(text.change_index_high);
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
  RUN_TEST(test_wrap_never_drops_address_chars);
  RUN_TEST(test_wrap_hard_breaks_text_without_spaces);
  RUN_TEST(test_format_btc);
  RUN_TEST(test_format_sats);
  RUN_TEST(test_estimate_vbytes);
  RUN_TEST(test_build_output_review);
  RUN_TEST(test_build_output_review_flags_forged_change);
  RUN_TEST(test_build_output_review_propagates_change_index);
  RUN_TEST(test_build_fee_review);
  RUN_TEST(test_build_fee_review_propagates_high_fee_warning);
  return UNITY_END();
}
