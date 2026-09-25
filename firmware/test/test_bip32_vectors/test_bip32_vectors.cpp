// Vetores oficiais de BIP32 (bip-0032.mediawiki, Test vector 1 e 2).
// Exercita derivacao privada com indices normais, hardened e grandes
// (2147483647' = 0x7FFFFFFF | 0x80000000), e a serializacao xpub/xprv.
#include <unity.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" {
#include "bip32.h"
#include "curves.h"
#include "memzero.h"
}

namespace {

constexpr uint32_t kVersionPublic = 0x0488b21e;  // "xpub"
constexpr uint32_t kVersionPrivate = 0x0488ade4; // "xprv"
constexpr uint32_t kHardened = 0x80000000u;

void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  for (size_t i = 0; i < out_len; i++) {
    unsigned int byte;
    sscanf(hex + i * 2, "%2x", &byte);
    out[i] = static_cast<uint8_t>(byte);
  }
}

void expect_serialization(HDNode *node, uint32_t fingerprint,
                          const char *expected_xpub,
                          const char *expected_xprv) {
  char buf[XPUB_MAXLEN];

  HDNode pub_node = *node;
  TEST_ASSERT_EQUAL_INT(0, hdnode_fill_public_key(&pub_node));
  hdnode_serialize_public(&pub_node, fingerprint, kVersionPublic, buf,
                          sizeof(buf));
  TEST_ASSERT_EQUAL_STRING(expected_xpub, buf);

  hdnode_serialize_private(node, fingerprint, kVersionPrivate, buf,
                           sizeof(buf));
  TEST_ASSERT_EQUAL_STRING(expected_xprv, buf);
}

} // namespace

void setUp(void) {}
void tearDown(void) {}

static void test_vector1(void) {
  uint8_t seed[16];
  hex_to_bytes("000102030405060708090a0b0c0d0e0f", seed, sizeof(seed));

  HDNode node;
  TEST_ASSERT_EQUAL_INT(1,
                        hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME,
                                         &node));

  // Chain m
  expect_serialization(
      &node, 0,
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJo"
      "Cu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmP"
      "GJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

  // Chain m/0'
  uint32_t fp = hdnode_fingerprint(&node);
  TEST_ASSERT_EQUAL_INT(1, hdnode_private_ckd(&node, 0 | kHardened));
  expect_serialization(
      &node, fp,
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK"
      "1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6"
      "KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

  // Chain m/0'/1
  fp = hdnode_fingerprint(&node);
  TEST_ASSERT_EQUAL_INT(1, hdnode_private_ckd(&node, 1));
  expect_serialization(
      &node, fp,
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiG"
      "j7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1Um"
      "YPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");

  // Chain m/0'/1/2'
  fp = hdnode_fingerprint(&node);
  TEST_ASSERT_EQUAL_INT(1, hdnode_private_ckd(&node, 2 | kHardened));
  expect_serialization(
      &node, fp,
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2"
      "dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG"
      "3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");

  memzero(&node, sizeof(node));
}

static void test_vector2_large_index_and_non_hardened(void) {
  uint8_t seed[64];
  hex_to_bytes(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c9996"
      "93908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      seed, sizeof(seed));

  HDNode node;
  TEST_ASSERT_EQUAL_INT(1,
                        hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME,
                                         &node));

  // Chain m
  expect_serialization(
      &node, 0,
      "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oD"
      "MSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
      "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssr"
      "dK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");

  // Chain m/0 (nao-hardened)
  uint32_t fp = hdnode_fingerprint(&node);
  TEST_ASSERT_EQUAL_INT(1, hdnode_private_ckd(&node, 0));
  expect_serialization(
      &node, fp,
      "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7E"
      "RfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
      "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih"
      "2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");

  // Chain m/0/2147483647' (indice hardened maximo)
  fp = hdnode_fingerprint(&node);
  TEST_ASSERT_EQUAL_INT(1, hdnode_private_ckd(&node, 2147483647u | kHardened));
  expect_serialization(
      &node, fp,
      "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiL"
      "DBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
      "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTA"
      "wCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");

  memzero(&node, sizeof(node));
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_vector1);
  RUN_TEST(test_vector2_large_index_and_non_hardened);
  return UNITY_END();
}
