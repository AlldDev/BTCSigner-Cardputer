// Vetores oficiais de BIP39, extraidos de
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
// (idioma ingles), que usa passphrase "TREZOR" para gerar os seeds — exatamente
// o caso exigido pela secao 5.3 da spec. Roda no host via `pio test -e native`.
#include <unity.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
#include "bip39.h"
}

namespace {

void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  for (size_t i = 0; i < out_len; i++) {
    unsigned int byte;
    sscanf(hex + i * 2, "%2x", &byte);
    out[i] = static_cast<uint8_t>(byte);
  }
}

struct Vector {
  const char *mnemonic;
  const char *seed_hex; // 64 bytes / 128 hex chars, passphrase "TREZOR"
};

// clang-format off
const Vector kVectors[] = {
    {"abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon about",
     "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f0"
     "9a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
    {"legal winner thank year wave sausage worth useful legal winner "
     "thank yellow",
     "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa45"
     "7fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"},
    {"letter advice cage absurd amount doctor acoustic avoid letter "
     "advice cage above",
     "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa2"
     "80f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8"},
    {"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
     "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332"
     "572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069"},
    {"abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon art",
     "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170"
     "af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
    {"legal winner thank year wave sausage worth useful legal winner "
     "thank year wave sausage worth useful legal winner thank year wave "
     "sausage worth title",
     "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b"
     "146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"},
    {"letter advice cage absurd amount doctor acoustic avoid letter "
     "advice cage absurd amount doctor acoustic avoid letter advice cage "
     "absurd amount doctor acoustic bless",
     "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2e"
     "f61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"},
    {"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
     "zoo zoo zoo zoo zoo zoo vote",
     "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e16139"
     "12f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"},
};
// clang-format on

} // namespace

void setUp(void) {}
void tearDown(void) {}

static void test_checksum_valid_for_all_vectors(void) {
  for (const Vector &v : kVectors) {
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, mnemonic_check(v.mnemonic), v.mnemonic);
  }
}

static void test_seed_matches_official_vector_with_trezor_passphrase(void) {
  for (const Vector &v : kVectors) {
    uint8_t expected[64];
    hex_to_bytes(v.seed_hex, expected, sizeof(expected));

    uint8_t seed[64];
    mnemonic_to_seed(v.mnemonic, "TREZOR", seed, nullptr);

    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, seed, sizeof(seed),
                                          v.mnemonic);
  }
}

static void test_checksum_rejects_corrupted_mnemonic(void) {
  // Troca a ultima palavra de um mnemonico valido: o checksum deve falhar.
  const char *corrupted =
      "abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon";
  TEST_ASSERT_EQUAL_INT(0, mnemonic_check(corrupted));
}

static void test_autocomplete_mask_rejects_invalid_prefix(void) {
  // "zz" nao e prefixo de nenhuma palavra da wordlist BIP39.
  TEST_ASSERT_EQUAL_UINT32(0, mnemonic_word_completion_mask("zz", 2));
  // "aband" so continua com "abandon".
  uint32_t mask = mnemonic_word_completion_mask("aband", 5);
  TEST_ASSERT_EQUAL_UINT32(1u << ('o' - 'a'), mask);
}

static void test_autocomplete_finds_unique_word_by_prefix(void) {
  const char *word = mnemonic_complete_word("abando", 6);
  TEST_ASSERT_NOT_NULL(word);
  TEST_ASSERT_EQUAL_STRING("abandon", word);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_checksum_valid_for_all_vectors);
  RUN_TEST(test_seed_matches_official_vector_with_trezor_passphrase);
  RUN_TEST(test_checksum_rejects_corrupted_mnemonic);
  RUN_TEST(test_autocomplete_mask_rejects_invalid_prefix);
  RUN_TEST(test_autocomplete_finds_unique_word_by_prefix);
  return UNITY_END();
}
