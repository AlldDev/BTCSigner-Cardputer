// Formato/cripto do backup no cartao RFID. Os vetores kGolden/kBad* foram
// gerados por uma implementacao independente (Python: hashlib + cryptography)
// com o mesmo RNG de contador usado aqui, para travar o formato.
#include <unity.h>

#include <cstring>

#include "config.h"
#include "rfid_seed_card.h"

extern "C" {
#include "bip39.h"
}

using namespace btcseed;

namespace {

constexpr char kPw[] = "correct horse battery staple";
constexpr size_t kPwLen = sizeof(kPw) - 1;
constexpr uint32_t kIters = 1000;

constexpr char kMnemonic12[] =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";
constexpr char kMnemonic24[] =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd "
    "amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";

const uint8_t kGoldenUsed[112] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x97, 0x35, 0xb1, 0xdc, 0x22, 0x65, 0xfa, 0x63, 0xd9, 0xa0, 0x4a, 0x4a, 0xf5, 0x62, 0x0c, 0xee, 0xc2, 0xa3, 0x7e, 0x63, 0xaf, 0xe6, 0x23, 0xa5, 0x9f, 0x09, 0x54, 0xc4, 0xa2, 0x2b, 0x5b, 0x0f, 0xad, 0x1e, 0xb3, 0x3d, 0xea, 0x40, 0x6d, 0xa5, 0x43, 0x4a, 0xf0, 0xcd, 0x0d, 0xb0, 0x46, 0x62, 0x31, 0x9b, 0xc7, 0xa4, 0x1c, 0x5b, 0x2e, 0x95, 0xc9, 0x49, 0x72, 0xcb, 0x74, 0x27, 0x44, 0x57, 0x8d, 0x4c, 0x66, 0xc2, 0x33, 0xf1, 0xc4, 0x64, 0x22, 0x1a, 0xe6, 0x40, 0x94, 0x80, 0x13, 0xbb};
// MAC valido, versao 2 no texto plano.
const uint8_t kBadVersionUsed[112] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x92, 0xa3, 0xac, 0x60, 0x54, 0x10, 0x9a, 0x90, 0x62, 0xdc, 0x57, 0xa8, 0xe8, 0x1d, 0x99, 0xc6, 0x12, 0x5d, 0xb0, 0x5b, 0xba, 0xa3, 0xd3, 0x42, 0xe9, 0x06, 0x14, 0x85, 0x84, 0x14, 0x95, 0xfd, 0x85, 0xf3, 0x47, 0x9d, 0x5d, 0x0a, 0x54, 0xa7, 0xfb, 0x23, 0x1b, 0x72, 0x5b, 0x1d, 0x84, 0x1d, 0xac, 0x39, 0x70, 0x07, 0x33, 0x06, 0x0a, 0xdb, 0x0a, 0x50, 0xf4, 0xb9, 0x1c, 0xb4, 0xc8, 0x86, 0x96, 0x1d, 0xa6, 0xb9, 0x9d, 0x73, 0x12, 0x4c, 0x0b, 0xdc, 0x7b, 0x3d, 0xd8, 0x55, 0x1e, 0xd1};
// MAC valido, 18 palavras (nao suportado).
const uint8_t kBadWordsUsed[112] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x66, 0x07, 0x6c, 0x06, 0xbb, 0x6a, 0x73, 0x5b, 0xe7, 0x33, 0x24, 0x1f, 0xad, 0x9a, 0x60, 0xb1, 0x09, 0x04, 0xf7, 0x21, 0x99, 0x47, 0xd3, 0xfe, 0xa6, 0x7a, 0x9e, 0x75, 0x22, 0x26, 0x57, 0x74, 0x42, 0x97, 0x21, 0xff, 0x19, 0xce, 0x25, 0x27, 0x12, 0xba, 0x7e, 0x25, 0xfe, 0xbb, 0xf6, 0x88, 0x22, 0xdd, 0xe3, 0x25, 0xc6, 0x53, 0xca, 0x54, 0xae, 0x10, 0x6f, 0x64, 0x87, 0x63, 0xf0, 0x95, 0x05, 0x10, 0xe0, 0x9b, 0x08, 0x92, 0xb0, 0x9c, 0xb7, 0xd6, 0x78, 0x76, 0x1f, 0xae, 0xbb, 0x1e};

uint8_t g_counter = 0;
void counter_rng(uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) buf[i] = g_counter++;
}

void make_card(const uint8_t used[kRfidUsedLen], uint8_t card[kMifareUsableBytes]) {
  for (size_t i = 0; i < kMifareUsableBytes; i++) {
    card[i] = i < kRfidUsedLen ? used[i] : static_cast<uint8_t>(i % 256);
  }
}

uint8_t g_card[kMifareUsableBytes];
uint8_t g_card2[kMifareUsableBytes];
char g_out[BIP39_MAX_MNEMONIC_LEN + 1];

bool all_zero(const void *p, size_t n) {
  const uint8_t *b = static_cast<const uint8_t *>(p);
  for (size_t i = 0; i < n; i++) {
    if (b[i] != 0) return false;
  }
  return true;
}

bool contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle, size_t needle_len) {
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, needle_len) == 0) return true;
  }
  return false;
}

} // namespace

void setUp(void) {
  g_counter = 0;
  memset(g_out, 'X', sizeof(g_out));
}
void tearDown(void) {}

static void test_block_mapping_never_hits_trailer_or_manufacturer(void) {
  int prev = 0;
  for (int i = 0; i < kMifareUsableBlocks; i++) {
    int b = mifare_physical_block_for_index(i);
    TEST_ASSERT_TRUE(b > prev); // monotonico e distinto
    TEST_ASSERT_NOT_EQUAL(0, b);
    TEST_ASSERT_NOT_EQUAL(3, b % 4);
    TEST_ASSERT_TRUE(b < kMifareSectors * 4);
    prev = b;
  }
  TEST_ASSERT_EQUAL_INT(1, mifare_physical_block_for_index(0));
  TEST_ASSERT_EQUAL_INT(4, mifare_physical_block_for_index(2));
  TEST_ASSERT_EQUAL_INT(62, mifare_physical_block_for_index(46));
  TEST_ASSERT_EQUAL_INT(-1, mifare_physical_block_for_index(-1));
  TEST_ASSERT_EQUAL_INT(-1, mifare_physical_block_for_index(kMifareUsableBlocks));
}

static void test_golden_vector_matches_independent_implementation(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card, counter_rng));
  TEST_ASSERT_EQUAL_HEX8_ARRAY(kGoldenUsed, g_card, kRfidUsedLen);
  for (size_t i = kRfidUsedLen; i < kMifareUsableBytes; i++) {
    TEST_ASSERT_EQUAL_HEX8(static_cast<uint8_t>(i % 256), g_card[i]);
  }
}

static void test_decodes_independent_golden_vector(void) {
  make_card(kGoldenUsed, g_card);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_EQUAL_STRING(kMnemonic12, g_out);
}

static void check_roundtrip(const char *mnemonic) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, mnemonic, kIters, g_card));
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_EQUAL_STRING(mnemonic, g_out);
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
}

static void test_roundtrip_12_words(void) { check_roundtrip(kMnemonic12); }
static void test_roundtrip_24_words(void) { check_roundtrip(kMnemonic24); }

static void test_roundtrip_with_production_iterations(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic24, kRfidPbkdf2Iterations, g_card));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card,
                                                            kRfidPbkdf2Iterations, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_EQUAL_STRING(kMnemonic24, g_out);
}

static void expect_auth_failed(const char *pw, size_t pw_len, uint32_t iters) {
  memset(g_out, 'X', sizeof(g_out));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kAuthFailed),
                        static_cast<int>(rfid_decode_backup(pw, pw_len, g_card, iters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_TRUE(all_zero(g_out, sizeof(g_out)));
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
}

static void test_wrong_password_fails_and_leaves_nothing(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  expect_auth_failed("correct horse battery stapla", kPwLen, kIters);
  expect_auth_failed(kPw, kPwLen - 1, kIters); // prefixo da senha
  expect_auth_failed("", 0, kIters);
}

static void test_different_iterations_fail(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  expect_auth_failed(kPw, kPwLen, kIters + 1);
}

static void test_any_tampered_byte_in_authenticated_region_fails(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  // salt, iv, ciphertext (inicio/fim) e tag
  const size_t offsets[] = {0, 15, 16, 31, 32, 79, 80, 111};
  for (size_t off : offsets) {
    g_card[off] ^= 0x01;
    expect_auth_failed(kPw, kPwLen, kIters);
    g_card[off] ^= 0x01;
  }
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
}

static void test_filler_region_is_not_authenticated_payload(void) {
  // [112,752) e so preenchimento aleatorio: altera-lo nao muda o conteudo.
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  g_card[kRfidUsedLen] ^= 0xFF;
  g_card[kMifareUsableBytes - 1] ^= 0xFF;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_EQUAL_STRING(kMnemonic12, g_out);
}

static void test_blank_cards(void) {
  memset(g_card, 0x00, sizeof(g_card));
  TEST_ASSERT_TRUE(rfid_card_is_blank(g_card));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kBlank),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_TRUE(all_zero(g_out, sizeof(g_out)));
  memset(g_card, 0xFF, sizeof(g_card));
  TEST_ASSERT_TRUE(rfid_card_is_blank(g_card));
  g_card[500] = 0x00;
  TEST_ASSERT_FALSE(rfid_card_is_blank(g_card));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kAuthFailed),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
}

static void test_valid_mac_but_invalid_content_is_malformed(void) {
  make_card(kBadVersionUsed, g_card);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kMalformed),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_TRUE(all_zero(g_out, sizeof(g_out)));
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  make_card(kBadWordsUsed, g_card);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kMalformed),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, g_out,
                                                            sizeof(g_out))));
  TEST_ASSERT_TRUE(all_zero(g_out, sizeof(g_out)));
}

static void test_encode_rejects_invalid_input_and_zeroes_output(void) {
  const char *bad[] = {
      // checksum errado
      "legal winner thank year wave sausage worth useful legal winner thank thank",
      // palavra fora da wordlist
      "legal winner thank year wave sausage worth useful legal winner thank yellowx",
      // 18 palavras (valido em BIP39, nao suportado aqui)
      "gravity machine north sort system female filter attitude volume fold club stay "
      "feature office ecology stable narrow fog",
      "",
  };
  for (const char *m : bad) {
    memset(g_card, 0xAA, sizeof(g_card));
    TEST_ASSERT_FALSE(rfid_encode_backup(kPw, kPwLen, m, kIters, g_card));
    TEST_ASSERT_TRUE(all_zero(g_card, sizeof(g_card)));
    TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  }
  TEST_ASSERT_FALSE(rfid_encode_backup("", 0, kMnemonic12, kIters, g_card));
  TEST_ASSERT_FALSE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, 0, g_card));
  TEST_ASSERT_FALSE(rfid_encode_backup(nullptr, 3, kMnemonic12, kIters, g_card));
}

static void test_decode_rejects_small_output_buffer(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic24, kIters, g_card));
  char small[64];
  memset(small, 'X', sizeof(small));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kMalformed),
                        static_cast<int>(rfid_decode_backup(kPw, kPwLen, g_card, kIters, small,
                                                            sizeof(small))));
  TEST_ASSERT_TRUE(all_zero(small, sizeof(small)));
}

static void test_two_backups_share_nothing(void) {
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card2));
  // salt, iv, ciphertext, tag e preenchimento todos diferentes
  const size_t regions[][2] = {{0, 16}, {16, 32}, {32, 80}, {80, 112}, {112, 752}};
  for (const auto &r : regions) {
    TEST_ASSERT_TRUE(memcmp(g_card + r[0], g_card2 + r[0], r[1] - r[0]) != 0);
  }
}

static void test_card_leaks_no_plaintext(void) {
  // "legal winner..." tem entropia 0x7f repetida: nenhum trecho dela, nem das
  // palavras em ASCII, pode aparecer no cartao.
  TEST_ASSERT_TRUE(rfid_encode_backup(kPw, kPwLen, kMnemonic12, kIters, g_card));
  const uint8_t ent[6] = {0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f};
  TEST_ASSERT_FALSE(contains(g_card, sizeof(g_card), ent, sizeof(ent)));
  const char *words[] = {"legal", "winner", "thank", "yellow", "wave"};
  for (const char *w : words) {
    TEST_ASSERT_FALSE(contains(g_card, sizeof(g_card), reinterpret_cast<const uint8_t *>(w),
                               strlen(w)));
  }
  TEST_ASSERT_FALSE(contains(g_card, sizeof(g_card), reinterpret_cast<const uint8_t *>("BSR"), 3));
}

static void expect_pw(RfidPasswordIssue expected, const char *pw) {
  TEST_ASSERT_EQUAL_INT_MESSAGE(static_cast<int>(expected),
                                static_cast<int>(rfid_check_password(pw, strlen(pw))), pw);
}

static void test_password_policy(void) {
  expect_pw(RfidPasswordIssue::kTooShort, "");
  expect_pw(RfidPasswordIssue::kTooShort, "abcdefghijk"); // 11
  expect_pw(RfidPasswordIssue::kOnlyDigits, "123456789012");
  expect_pw(RfidPasswordIssue::kOnlyDigits, "000000000000000000");
  expect_pw(RfidPasswordIssue::kTooFewDistinct, "aaaaaaaaaaaa");
  expect_pw(RfidPasswordIssue::kTooFewDistinct, "abababababab");
  expect_pw(RfidPasswordIssue::kTooFewDistinct, "abcabcabcabcabc");
  expect_pw(RfidPasswordIssue::kOk, "correct horse battery staple");
  expect_pw(RfidPasswordIssue::kOk, "abcdefgh1234");
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidPasswordIssue::kTooShort),
                        static_cast<int>(rfid_check_password(nullptr, 20)));
}

static void test_wipe_scratch(void) {
  rfid_wipe_scratch();
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_block_mapping_never_hits_trailer_or_manufacturer);
  RUN_TEST(test_golden_vector_matches_independent_implementation);
  RUN_TEST(test_decodes_independent_golden_vector);
  RUN_TEST(test_roundtrip_12_words);
  RUN_TEST(test_roundtrip_24_words);
  RUN_TEST(test_roundtrip_with_production_iterations);
  RUN_TEST(test_wrong_password_fails_and_leaves_nothing);
  RUN_TEST(test_different_iterations_fail);
  RUN_TEST(test_any_tampered_byte_in_authenticated_region_fails);
  RUN_TEST(test_filler_region_is_not_authenticated_payload);
  RUN_TEST(test_blank_cards);
  RUN_TEST(test_valid_mac_but_invalid_content_is_malformed);
  RUN_TEST(test_encode_rejects_invalid_input_and_zeroes_output);
  RUN_TEST(test_decode_rejects_small_output_buffer);
  RUN_TEST(test_two_backups_share_nothing);
  RUN_TEST(test_card_leaks_no_plaintext);
  RUN_TEST(test_password_policy);
  RUN_TEST(test_wipe_scratch);
  return UNITY_END();
}
