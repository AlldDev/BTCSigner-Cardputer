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
using btcseed::same_account;
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

// TOOLS > Testar backup: so a mesma seed + passphrase + rede conferem.
static void test_same_account(void) {
  MasterKey a, b;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senha", Network::kTestnet, &a));
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senha", Network::kTestnet, &b));
  TEST_ASSERT_TRUE(same_account(a, b));

  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senhA", Network::kTestnet, &b));
  TEST_ASSERT_FALSE(same_account(a, b)); // outra passphrase
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senha", Network::kMainnet, &b));
  TEST_ASSERT_FALSE(same_account(a, b)); // outra rede
  TEST_ASSERT_TRUE(derive_master_key(
      "legal winner thank year wave sausage worth useful legal winner thank yellow", "senha",
      Network::kTestnet, &b));
  TEST_ASSERT_FALSE(same_account(a, b)); // outra seed

  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senha", Network::kTestnet, &b));
  wipe(&b);
  TEST_ASSERT_FALSE(same_account(a, b)); // invalida
  TEST_ASSERT_FALSE(same_account(b, b));
  wipe(&a);
}

// derive_master_key_for(kP2wpkh) e exatamente o BIP84 de derive_master_key.
static void test_derive_master_key_for_p2wpkh(void) {
  MasterKey a, b;
  TEST_ASSERT_TRUE(btcseed::derive_master_key_for(btcseed::WalletScript::kP2wpkh, kMnemonic, "",
                                                  Network::kMainnet, &a));
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &b));
  TEST_ASSERT_TRUE(same_account(a, b));

  char xpub[XPUB_MAXLEN];
  TEST_ASSERT_TRUE(serialize_account_xpub(a, xpub, sizeof(xpub)));
  TEST_ASSERT_EQUAL_STRING(
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqt"
      "fSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
      xpub);

  // Valor fora do enum (Taproot ainda nao existe): falha fechada.
  TEST_ASSERT_FALSE(btcseed::derive_master_key_for(static_cast<btcseed::WalletScript>(1),
                                                   kMnemonic, "", Network::kMainnet, &a));
  TEST_ASSERT_FALSE(a.valid);
  wipe(&a);
  wipe(&b);
}

static void test_parse_receive_index(void) {
  using btcseed::parse_receive_index;
  uint32_t v = 12345;
  TEST_ASSERT_TRUE(parse_receive_index("0", &v));
  TEST_ASSERT_EQUAL_UINT32(0, v);
  TEST_ASSERT_TRUE(parse_receive_index("7", &v));
  TEST_ASSERT_EQUAL_UINT32(7, v);
  TEST_ASSERT_TRUE(parse_receive_index("007", &v));
  TEST_ASSERT_EQUAL_UINT32(7, v);
  TEST_ASSERT_TRUE(parse_receive_index("999", &v));
  TEST_ASSERT_EQUAL_UINT32(999, v);

  v = 42;
  TEST_ASSERT_FALSE(parse_receive_index("", &v));
  TEST_ASSERT_FALSE(parse_receive_index("1000", &v));
  TEST_ASSERT_FALSE(parse_receive_index("9999", &v));
  TEST_ASSERT_FALSE(parse_receive_index("12a", &v));
  TEST_ASSERT_FALSE(parse_receive_index("-1", &v));
  TEST_ASSERT_FALSE(parse_receive_index(" 1", &v));
  TEST_ASSERT_FALSE(parse_receive_index("1 ", &v));
  TEST_ASSERT_FALSE(parse_receive_index("2147483648", &v));
  TEST_ASSERT_FALSE(parse_receive_index(nullptr, &v));
  TEST_ASSERT_EQUAL_UINT32(42, v); // falha nao escreve
}

// Vetores independentes do firmware: gerados com embit (Python, implementacao
// propria de BIP32/bech32), m/84'/c'/0'/0/i do mnemonic "abandon ... about".
// Os indices 0 e 1 da mainnet sao tambem os vetores oficiais do BIP84.
static void test_receive_address_checked_matches_independent_vectors(void) {
  struct Vec {
    Network net;
    uint32_t index;
    const char *addr;
  };
  const Vec vecs[] = {
      {Network::kMainnet, 0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"},
      {Network::kMainnet, 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"},
      {Network::kMainnet, 999, "bc1q372mpzsck73z60gxytq8x6m8tlu2t95lm7r5qe"},
      {Network::kTestnet, 0, "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl"},
      {Network::kTestnet, 1, "tb1qd7spv5q28348xl4myc8zmh983w5jx32cjhkn97"},
      {Network::kTestnet, 999, "tb1qghvx7p5rkcl4354pfe0lrdygv3d0lttm9wfl9h"},
  };
  for (const Vec &v : vecs) {
    MasterKey mk;
    TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", v.net, &mk));
    char addr[74];
    TEST_ASSERT_TRUE(btcseed::derive_receive_address_checked(mk, v.index, addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_STRING(v.addr, addr);
    wipe(&mk);
  }
}

// Caminho privado e caminho publico (zpub) concordam em toda a faixa 0..999.
static void test_receive_address_checked_full_range(void) {
  const Network nets[] = {Network::kMainnet, Network::kTestnet};
  for (Network net : nets) {
    MasterKey mk;
    TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "senha", net, &mk));
    for (uint32_t i = 0; i <= btcseed::kMaxReceiveIndex; i++) {
      char checked[74];
      char plain[74];
      TEST_ASSERT_TRUE(btcseed::derive_receive_address_checked(mk, i, checked, sizeof(checked)));
      TEST_ASSERT_TRUE(derive_address(mk, btcseed::kChangeExternal, i, plain, sizeof(plain)));
      TEST_ASSERT_EQUAL_STRING(plain, checked);
    }
    wipe(&mk);
  }
}

static void test_receive_address_checked_rejects(void) {
  MasterKey mk;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &mk));
  char addr[74];

  memcpy(addr, "x", 2);
  TEST_ASSERT_FALSE(btcseed::derive_receive_address_checked(mk, 1000, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("", addr);
  memcpy(addr, "x", 2);
  TEST_ASSERT_FALSE(btcseed::derive_receive_address_checked(mk, 0x80000000u, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("", addr);
  TEST_ASSERT_FALSE(btcseed::derive_receive_address_checked(mk, 0, addr, 73)); // buffer curto

  wipe(&mk);
  memcpy(addr, "x", 2);
  TEST_ASSERT_FALSE(btcseed::derive_receive_address_checked(mk, 0, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("", addr);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_account_xpub_matches_bip84_vector);
  RUN_TEST(test_receive_and_change_addresses_match_bip84_vector);
  RUN_TEST(test_descriptor_checksum_matches_bip380_vector);
  RUN_TEST(test_descriptor_for_bip84_vector);
  RUN_TEST(test_same_account);
  RUN_TEST(test_derive_master_key_for_p2wpkh);
  RUN_TEST(test_parse_receive_index);
  RUN_TEST(test_receive_address_checked_matches_independent_vectors);
  RUN_TEST(test_receive_address_checked_full_range);
  RUN_TEST(test_receive_address_checked_rejects);
  return UNITY_END();
}
