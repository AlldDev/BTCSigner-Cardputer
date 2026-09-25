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

static void test_change_detection_finds_own_change_output(void) {
  MasterKey mk;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &mk));

  // hash160 do endereco de troco m/84'/0'/0'/1/0 (bc1q8c6fshw2dl...), obtido
  // decodificando o proprio endereco esperado do vetor oficial acima.
  HDNode change_node;
  TEST_ASSERT_TRUE(btcseed::derive_child_node(mk, 1, 0, &change_node));

  uint32_t found_index = 0xffffffff;
  uint8_t pubkeyhash[20];
  // Reconstroi o hash160 via derive_address + segwit_addr_decode round-trip
  // seria redundante; em vez disso reusa find_change_index com o proprio
  // hash160 derivado (equivalente ao que psbt.cpp fara a partir do PSBT).
  TEST_ASSERT_EQUAL_INT(0, hdnode_fill_public_key(&change_node));
  ecdsa_get_pubkeyhash(change_node.public_key, change_node.curve->hasher_pubkey,
                       pubkeyhash);
  btcseed::wipe_node(&change_node);

  TEST_ASSERT_TRUE(
      btcseed::find_change_index(mk, pubkeyhash, 5, &found_index));
  TEST_ASSERT_EQUAL_UINT32(0, found_index);

  // Um hash160 que nao pertence a esta seed nao deve ser encontrado.
  uint8_t bogus[20];
  memset(bogus, 0xAB, sizeof(bogus));
  TEST_ASSERT_FALSE(btcseed::find_change_index(mk, bogus, 5, &found_index));

  wipe(&mk);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_account_xpub_matches_bip84_vector);
  RUN_TEST(test_receive_and_change_addresses_match_bip84_vector);
  RUN_TEST(test_change_detection_finds_own_change_output);
  return UNITY_END();
}
