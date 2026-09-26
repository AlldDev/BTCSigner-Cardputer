// Vetor oficial de BIP84 (bip-0084.mediawiki): mnemonico "abandon...about",
// passphrase vazia, mainnet. Exercita a pilha completa deste firmware
// (mnemonic -> seed -> m/84'/0'/0' -> zpub/enderecos) atraves de keys.h,
// nao apenas o trezor-crypto cru — e o teste mais proximo de um "vetor de
// integracao" que temos sem hardware.
#include <unity.h>

#include <cstring>

#include "keys.h"

extern "C" {
#include "ecdsa.h"
}

using btcseed::derive_address;
using btcseed::derive_master_key;
using btcseed::MasterKey;
using btcseed::Network;
using btcseed::serialize_account_xpub;
using btcseed::wipe;

namespace {
const char *kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";
}

void setUp(void) {}
void tearDown(void) {}

static void test_account_xpub_matches_bip84_vector(void) {
  MasterKey mk;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &mk));
  TEST_ASSERT_TRUE(mk.valid);

  char xpub[XPUB_MAXLEN];
  TEST_ASSERT_TRUE(serialize_account_xpub(mk, xpub, sizeof(xpub)));
  TEST_ASSERT_EQUAL_STRING(
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqt"
      "fSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
      xpub);

  wipe(&mk);
}

static void test_receive_and_change_addresses_match_bip84_vector(void) {
  MasterKey mk;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &mk));

  char addr[74];

  TEST_ASSERT_TRUE(derive_address(mk, 0, 0, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", addr);

  TEST_ASSERT_TRUE(derive_address(mk, 0, 1, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", addr);

  TEST_ASSERT_TRUE(derive_address(mk, 1, 0, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", addr);

  wipe(&mk);
}

static void test_descriptor_checksum_matches_bip380_vector(void) {
  char sum[9];
  TEST_ASSERT_TRUE(btcseed::descriptor_checksum("raw(deadbeef)", sum));
  TEST_ASSERT_EQUAL_STRING("89f8spxm", sum);
  TEST_ASSERT_FALSE(btcseed::descriptor_checksum("raw(\x01)", sum)); // fora do charset
}

static void test_descriptor_for_bip84_vector(void) {
  MasterKey mk;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &mk));

  char desc[200];
  TEST_ASSERT_TRUE(btcseed::build_descriptor(mk, btcseed::kChangeExternal, desc, sizeof(desc)));
  // xpub padrao da conta m/84'/0'/0' do mnemonic "abandon ... about" — mesma
  // chave do zpub oficial do BIP84, so com a versao BIP32 padrao.
  TEST_ASSERT_EQUAL_STRING_LEN(
      "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3Xy"
      "uvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#",
      desc, strlen(desc) - 8);

  const char *hash = strchr(desc, '#');
  TEST_ASSERT_NOT_NULL(hash);
  char body[200];
  memcpy(body, desc, hash - desc);
  body[hash - desc] = '\0';
  char sum[9];
  TEST_ASSERT_TRUE(btcseed::descriptor_checksum(body, sum));
  TEST_ASSERT_EQUAL_STRING(sum, hash + 1);

  // Buffer pequeno demais: falha em vez de truncar.
  TEST_ASSERT_FALSE(btcseed::build_descriptor(mk, btcseed::kChangeInternal, desc, 100));
  wipe(&mk);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_account_xpub_matches_bip84_vector);
  RUN_TEST(test_receive_and_change_addresses_match_bip84_vector);
  RUN_TEST(test_descriptor_checksum_matches_bip380_vector);
  RUN_TEST(test_descriptor_for_bip84_vector);
  return UNITY_END();
}
