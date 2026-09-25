// Testes do parser/validador/assinador de PSBT: um PSBT valido minimo
// (construido a mao, byte a byte, contra a nossa propria MasterKey) e os
// casos maliciosos/malformados da secao 14 do spec.
#include <unity.h>

#include <cstring>

#include "keys.h"
#include "psbt.h"

extern "C" {
#include "ecdsa.h"
#include "hasher.h"
#include "memzero.h"
}

using namespace btcseed;

namespace {

const char *kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";

// --- construtor de PSBT de teste, byte a byte -------------------------------

class Builder {
public:
  void u8(uint8_t v) { push(&v, 1); }
  void bytes(const uint8_t *data, size_t len) { push(data, len); }
  void u32le(uint32_t v) {
    uint8_t b[4] = {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8),
                    static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 24)};
    push(b, 4);
  }
  void u64le(uint64_t v) {
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = static_cast<uint8_t>(v >> (8 * i));
    push(b, 8);
  }
  void fingerprint_be(uint32_t fp) {
    uint8_t b[4] = {static_cast<uint8_t>(fp >> 24), static_cast<uint8_t>(fp >> 16),
                    static_cast<uint8_t>(fp >> 8), static_cast<uint8_t>(fp)};
    push(b, 4);
  }
  void varint(uint64_t v) {
    if (v < 0xfd) {
      u8(static_cast<uint8_t>(v));
    } else if (v <= 0xffff) {
      u8(0xfd);
      u32le(static_cast<uint32_t>(v)); // escreve 4, mas so os 2 primeiros importam aqui
      len_ -= 2;                       // corrige: queremos so 2 bytes
    } else {
      TEST_FAIL_MESSAGE("varint grande demais para os testes");
    }
  }
  // separador de fim de mapa
  void end_map() { u8(0x00); }

  const uint8_t *data() const { return buf_; }
  size_t size() const { return len_; }

private:
  void push(const uint8_t *data, size_t n) {
    TEST_ASSERT_TRUE_MESSAGE(len_ + n <= sizeof(buf_), "builder overflow");
    memcpy(buf_ + len_, data, n);
    len_ += n;
  }
  uint8_t buf_[4096];
  size_t len_ = 0;
};

struct Fixture {
  MasterKey mk;
  uint8_t recv_hash[20];   // hash160 de m/84'/0'/0'/0/0 (input)
  uint8_t recv_pubkey[33];
  uint8_t change_hash[20]; // hash160 de m/84'/0'/0'/1/0 (troco)
  uint8_t change_pubkey[33];
};

void derive_hash_and_pubkey(const MasterKey &mk, uint32_t change, uint32_t index,
                           uint8_t out_pubkey[33], uint8_t out_hash[20]) {
  HDNode node;
  TEST_ASSERT_TRUE(derive_child_node(mk, change, index, &node));
  TEST_ASSERT_EQUAL_INT(0, hdnode_fill_public_key(&node));
  memcpy(out_pubkey, node.public_key, 33);
  ecdsa_get_pubkeyhash(node.public_key, node.curve->hasher_pubkey, out_hash);
  wipe_node(&node);
}

Fixture make_fixture() {
  Fixture f;
  TEST_ASSERT_TRUE(derive_master_key(kMnemonic, "", Network::kMainnet, &f.mk));
  derive_hash_and_pubkey(f.mk, 0, 0, f.recv_pubkey, f.recv_hash);
  derive_hash_and_pubkey(f.mk, 1, 0, f.change_pubkey, f.change_hash);
  return f;
}

// Constroi um PSBT binario com 1 input (nosso, witness_utxo=100000 sats) e
// 2 outputs: externo (50000 sats, hash arbitrario) e troco de verdade
// (49000 sats, m/84'/0'/0'/1/0) — fee = 1000 sats.
//
// `bip32_fp`: fingerprint escrito no PSBT_IN_BIP32_DERIVATION do input (para
// os testes de fingerprint errado). `sighash_value`: se >=0, escreve
// PSBT_IN_SIGHASH_TYPE com esse valor. `corrupt_change_hash`: se true, o
// output de troco alega ser m/84'/0'/0'/1/0 mas o script de fato aponta para
// outro hash (simula troco falsificado).
void build_psbt(const Fixture &f, Builder *b, uint32_t bip32_fp = 0,
               int64_t sighash_value = -1, bool corrupt_change_hash = false,
               bool use_real_fp = true) {
  uint32_t fingerprint = use_real_fp ? f.mk.master_fingerprint : bip32_fp;

  // --- unsigned tx ---
  Builder tx;
  tx.u32le(1); // version
  tx.varint(1); // 1 input
  uint8_t txid[32];
  memset(txid, 0x11, sizeof(txid));
  tx.bytes(txid, sizeof(txid));
  tx.u32le(0);       // vout
  tx.varint(0);      // scriptSig vazio
  tx.u32le(0xffffffff); // sequence
  tx.varint(2); // 2 outputs
  // output 0: externo
  tx.u64le(50000);
  tx.varint(22);
  tx.u8(0x00);
  tx.u8(0x14);
  uint8_t external_hash[20];
  memset(external_hash, 0xaa, sizeof(external_hash));
  tx.bytes(external_hash, sizeof(external_hash));
  // output 1: troco
  tx.u64le(49000);
  tx.varint(22);
  tx.u8(0x00);
  tx.u8(0x14);
  if (corrupt_change_hash) {
    uint8_t bogus[20];
    memset(bogus, 0xbb, sizeof(bogus));
    tx.bytes(bogus, sizeof(bogus));
  } else {
    tx.bytes(f.change_hash, sizeof(f.change_hash));
  }
  tx.u32le(0); // locktime

  // --- magic + global map ---
  b->bytes((const uint8_t[]){0x70, 0x73, 0x62, 0x74, 0xff}, 5);
  b->varint(1);
  b->u8(0x00); // PSBT_GLOBAL_UNSIGNED_TX
  b->varint(tx.size());
  b->bytes(tx.data(), tx.size());
  b->end_map();

  // --- input map (1 input) ---
  // PSBT_IN_WITNESS_UTXO
  b->varint(1);
  b->u8(0x01);
  Builder utxo;
  utxo.u64le(100000);
  utxo.varint(22);
  utxo.u8(0x00);
  utxo.u8(0x14);
  utxo.bytes(f.recv_hash, sizeof(f.recv_hash));
  b->varint(utxo.size());
  b->bytes(utxo.data(), utxo.size());
  // PSBT_IN_BIP32_DERIVATION
  b->varint(1 + 33);
  b->u8(0x06);
  b->bytes(f.recv_pubkey, sizeof(f.recv_pubkey));
  b->varint(4 + 5 * 4);
  b->fingerprint_be(fingerprint);
  b->u32le(kPurposeBip84);
  b->u32le(kCoinTypeMainnet);
  b->u32le(kAccountHardened);
  b->u32le(kChangeExternal);
  b->u32le(0);
  if (sighash_value >= 0) {
    b->varint(1);
    b->u8(0x03);
    b->varint(4);
    b->u32le(static_cast<uint32_t>(sighash_value));
  }
  b->end_map();

  // --- output maps ---
  // output 0 (externo): sem metadados
  b->end_map();
  // output 1 (troco): PSBT_OUT_BIP32_DERIVATION alegando m/84'/0'/0'/1/0
  b->varint(1 + 33);
  b->u8(0x02);
  b->bytes(f.change_pubkey, sizeof(f.change_pubkey));
  b->varint(4 + 5 * 4);
  b->fingerprint_be(f.mk.master_fingerprint);
  b->u32le(kPurposeBip84);
  b->u32le(kCoinTypeMainnet);
  b->u32le(kAccountHardened);
  b->u32le(kChangeInternal);
  b->u32le(0);
  b->end_map();
}

// Recalcula, de forma totalmente independente de psbt.cpp, o sighash BIP143
// da fixture construida por build_psbt() (1 input nosso, 2 outputs fixos).
// Serve para cross-validar build_sighash() por reimplementacao, nao por
// reflexao do proprio codigo testado.
void compute_expected_sighash(const uint8_t recv_hash[20],
                             const uint8_t change_hash[20], uint8_t out[32]) {
  uint8_t txid[32];
  memset(txid, 0x11, sizeof(txid));
  uint8_t outpoint[36];
  memcpy(outpoint, txid, 32);
  memset(outpoint + 32, 0, 4); // vout = 0

  uint8_t sequence[4] = {0xff, 0xff, 0xff, 0xff};

  uint8_t hash_prevouts[32];
  hasher_Raw(HASHER_SHA2D, outpoint, sizeof(outpoint), hash_prevouts);
  uint8_t hash_sequence[32];
  hasher_Raw(HASHER_SHA2D, sequence, sizeof(sequence), hash_sequence);

  uint8_t external_hash[20];
  memset(external_hash, 0xaa, sizeof(external_hash));
  Builder outputs;
  outputs.u64le(50000);
  outputs.varint(22);
  outputs.u8(0x00);
  outputs.u8(0x14);
  outputs.bytes(external_hash, sizeof(external_hash));
  outputs.u64le(49000);
  outputs.varint(22);
  outputs.u8(0x00);
  outputs.u8(0x14);
  outputs.bytes(change_hash, 20);
  uint8_t hash_outputs[32];
  hasher_Raw(HASHER_SHA2D, outputs.data(), outputs.size(), hash_outputs);

  uint8_t script_code[25] = {0x76, 0xa9, 0x14};
  memcpy(script_code + 3, recv_hash, 20);
  script_code[23] = 0x88;
  script_code[24] = 0xac;

  Builder preimage;
  preimage.u32le(1); // version
  preimage.bytes(hash_prevouts, 32);
  preimage.bytes(hash_sequence, 32);
  preimage.bytes(outpoint, 36);
  preimage.varint(25);
  preimage.bytes(script_code, 25);
  preimage.u64le(100000); // amount do witness_utxo do input
  preimage.bytes(sequence, 4);
  preimage.bytes(hash_outputs, 32);
  preimage.u32le(0); // locktime
  preimage.u32le(1); // sighash type ALL

  hasher_Raw(HASHER_SHA2D, preimage.data(), preimage.size(), out);
}

// Codec base64 local, so para preparar/inspecionar entradas e saidas nos
// testes — independente do codec privado dentro de psbt.cpp, para nao
// testar a implementacao contra ela mesma.
int8_t test_b64_val(uint8_t c) {
  if (c >= 'A' && c <= 'Z') return static_cast<int8_t>(c - 'A');
  if (c >= 'a' && c <= 'z') return static_cast<int8_t>(c - 'a' + 26);
  if (c >= '0' && c <= '9') return static_cast<int8_t>(c - '0' + 52);
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

void test_base64_encode(const uint8_t *in, size_t in_len, uint8_t *out,
                       size_t *out_len) {
  static const char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t o = 0, i = 0;
  for (; i + 3 <= in_len; i += 3) {
    uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = kTable[(n >> 6) & 0x3f];
    out[o++] = kTable[n & 0x3f];
  }
  size_t rem = in_len - i;
  if (rem == 1) {
    uint32_t n = static_cast<uint32_t>(in[i]) << 16;
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = '=';
    out[o++] = '=';
  } else if (rem == 2) {
    uint32_t n = (in[i] << 16) | (in[i + 1] << 8);
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = kTable[(n >> 6) & 0x3f];
    out[o++] = '=';
  }
  *out_len = o;
}

void test_base64_decode(const uint8_t *in, size_t in_len, uint8_t *out,
                       size_t *out_len) {
  size_t o = 0;
  for (size_t i = 0; i < in_len; i += 4) {
    bool pad2 = in[i + 2] == '=';
    bool pad3 = in[i + 3] == '=';
    int v0 = test_b64_val(in[i]);
    int v1 = test_b64_val(in[i + 1]);
    int v2 = pad2 ? 0 : test_b64_val(in[i + 2]);
    int v3 = pad3 ? 0 : test_b64_val(in[i + 3]);
    uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                (static_cast<uint32_t>(v1) << 12) |
                (static_cast<uint32_t>(v2) << 6) | static_cast<uint32_t>(v3);
    out[o++] = static_cast<uint8_t>((n >> 16) & 0xff);
    if (!pad2) out[o++] = static_cast<uint8_t>((n >> 8) & 0xff);
    if (!pad3) out[o++] = static_cast<uint8_t>(n & 0xff);
  }
  *out_len = o;
}

} // namespace

void setUp(void) {}
void tearDown(void) {}

static void test_valid_psbt_validates_and_summarizes(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b);

  Psbt psbt;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kNone),
                       static_cast<int>(psbt.load(b.data(), b.size())));
  TEST_ASSERT_FALSE(psbt.is_base64());
  TEST_ASSERT_EQUAL_INT(1, psbt.num_inputs());
  TEST_ASSERT_EQUAL_INT(2, psbt.num_outputs());

  PsbtSummary summary;
  PsbtError err = psbt.validate(f.mk, Network::kMainnet, &summary);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kNone), static_cast<int>(err));

  TEST_ASSERT_EQUAL_UINT64(100000, summary.total_input_sats);
  TEST_ASSERT_EQUAL_UINT64(99000, summary.total_output_sats);
  TEST_ASSERT_EQUAL_UINT64(1000, summary.fee_sats);
  TEST_ASSERT_FALSE(summary.high_fee_warning);

  TEST_ASSERT_FALSE(summary.outputs[0].is_change);
  TEST_ASSERT_EQUAL_UINT64(50000, summary.outputs[0].amount_sats);
  TEST_ASSERT_TRUE(summary.outputs[1].is_change);
  TEST_ASSERT_EQUAL_UINT32(0, summary.outputs[1].change_index);
  TEST_ASSERT_EQUAL_UINT64(49000, summary.outputs[1].amount_sats);
}

static void test_sign_and_serialize_roundtrip(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b);

  Psbt psbt;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt.load(b.data(), b.size())));
  PsbtSummary summary;
  TEST_ASSERT_EQUAL_INT(0,
                       static_cast<int>(psbt.validate(f.mk, Network::kMainnet, &summary)));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt.sign(f.mk)));

  uint8_t out[4096];
  size_t written = 0;
  TEST_ASSERT_TRUE(psbt.serialize_signed(out, sizeof(out), &written));

  // Nao recarregamos `out` via Psbt::load(): um PSBT ja assinado contem
  // PSBT_IN_PARTIAL_SIG, que este parser rejeita de proposito de volta na
  // entrada (kAlreadyHasSignature — o fluxo suportado e sempre PSBT->
  // assina->grava, nunca reprocessar o proprio PSBT ja assinado; multisig/
  // combiner estao fora do escopo). Em vez disso, inspecionamos os bytes
  // brutos da saida diretamente, como uma carteira watch-only faria.
  //
  // Procura o PSBT_IN_PARTIAL_SIG no binario serializado.
  const uint8_t *p = out;
  size_t found_at = 0;
  bool found = false;
  for (size_t i = 0; i + 1 < written; i++) {
    if (p[i] == 34 && p[i + 1] == 0x02) { // keylen=34, keytype=PARTIAL_SIG
      found = true;
      found_at = i;
      break;
    }
  }
  TEST_ASSERT_TRUE_MESSAGE(found, "PSBT_IN_PARTIAL_SIG nao encontrado na saida");

  const uint8_t *pubkey = p + found_at + 2;
  TEST_ASSERT_EQUAL_UINT8_ARRAY(f.recv_pubkey, pubkey, 33);

  size_t sig_len_pos = found_at + 2 + 33;
  uint8_t sig_len = p[sig_len_pos];
  const uint8_t *sig_and_type = p + sig_len_pos + 1;
  TEST_ASSERT_EQUAL_UINT8(0x01, sig_and_type[sig_len - 1]); // SIGHASH_ALL

  uint8_t sig64[64];
  TEST_ASSERT_EQUAL_INT(0, ecdsa_sig_from_der(sig_and_type, sig_len - 1, sig64));

  // Recalcula o sighash BIP143 de forma totalmente independente de
  // psbt.cpp (reimplementacao propria em compute_expected_sighash) e
  // verifica a assinatura contra ele — se build_sighash() tivesse um bug
  // (ordem de bytes errada, hash errado, etc.), a assinatura nao bateria
  // aqui mesmo que o parsing/serializacao parecessem corretos.
  uint8_t expected_digest[32];
  compute_expected_sighash(f.recv_hash, f.change_hash, expected_digest);

  HDNode node;
  TEST_ASSERT_TRUE(derive_child_node(f.mk, 0, 0, &node));
  TEST_ASSERT_EQUAL_INT(0, hdnode_fill_public_key(&node));
  TEST_ASSERT_EQUAL_INT(
      0, ecdsa_verify_digest(node.curve->params, node.public_key, sig64,
                            expected_digest));
  wipe_node(&node);
}

static void test_wrong_fingerprint_is_rejected(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b, /*bip32_fp=*/0xdeadbeef, -1, false, /*use_real_fp=*/false);

  Psbt psbt;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt.load(b.data(), b.size())));
  PsbtSummary summary;
  PsbtError err = psbt.validate(f.mk, Network::kMainnet, &summary);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kFingerprintMismatch),
                       static_cast<int>(err));
}

static void test_unsupported_sighash_is_rejected(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b, 0, /*sighash_value=*/0x02); // SIGHASH_NONE

  Psbt psbt;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt.load(b.data(), b.size())));
  PsbtSummary summary;
  PsbtError err = psbt.validate(f.mk, Network::kMainnet, &summary);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kUnsupportedSighash),
                       static_cast<int>(err));
}

static void test_forged_change_is_shown_as_external_with_warning(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b, 0, -1, /*corrupt_change_hash=*/true);

  Psbt psbt;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt.load(b.data(), b.size())));
  PsbtSummary summary;
  PsbtError err = psbt.validate(f.mk, Network::kMainnet, &summary);
  // A falsificacao de troco nao invalida o PSBT inteiro — so degrada aquele
  // output para "externo com aviso" (secao 9 do spec).
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kNone), static_cast<int>(err));
  TEST_ASSERT_FALSE(summary.outputs[1].is_change);
  TEST_ASSERT_TRUE(summary.outputs[1].claimed_change_invalid);
}

static void test_truncated_file_is_rejected(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b);

  Psbt psbt;
  PsbtError err = psbt.load(b.data(), b.size() - 5); // corta o final
  TEST_ASSERT_NOT_EQUAL(static_cast<int>(PsbtError::kNone), static_cast<int>(err));
}

static void test_bad_magic_is_rejected(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b);
  uint8_t corrupted[4096];
  memcpy(corrupted, b.data(), b.size());
  corrupted[0] = 0x00; // destroi o magic

  Psbt psbt;
  PsbtError err = psbt.load(corrupted, b.size());
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kBadEncoding),
                       static_cast<int>(err));
}

static void test_base64_roundtrip_matches_binary(void) {
  Fixture f = make_fixture();
  Builder b;
  build_psbt(f, &b);

  uint8_t b64[8192];
  size_t b64_len = 0;
  test_base64_encode(b.data(), b.size(), b64, &b64_len);
  TEST_ASSERT_EQUAL_INT(0, memcmp(b64, "cHNidP", 6));

  Psbt psbt_b64;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt_b64.load(b64, b64_len)));
  TEST_ASSERT_TRUE(psbt_b64.is_base64());

  PsbtSummary summary_b64;
  TEST_ASSERT_EQUAL_INT(
      0, static_cast<int>(psbt_b64.validate(f.mk, Network::kMainnet, &summary_b64)));
  TEST_ASSERT_EQUAL_UINT64(1000, summary_b64.fee_sats);
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt_b64.sign(f.mk)));

  uint8_t out_b64[8192];
  size_t out_b64_len = 0;
  TEST_ASSERT_TRUE(psbt_b64.serialize_signed(out_b64, sizeof(out_b64), &out_b64_len));
  TEST_ASSERT_EQUAL_INT(0, memcmp(out_b64, "cHNidP", 6));

  uint8_t decoded[8192];
  size_t decoded_len = 0;
  test_base64_decode(out_b64, out_b64_len, decoded, &decoded_len);

  // Assina a mesma fixture pelo caminho binario e confere que o binario
  // decodificado do base64 e byte-a-byte identico.
  Psbt psbt_bin;
  Builder b2;
  build_psbt(f, &b2);
  PsbtSummary summary_bin;
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt_bin.load(b2.data(), b2.size())));
  TEST_ASSERT_EQUAL_INT(
      0, static_cast<int>(psbt_bin.validate(f.mk, Network::kMainnet, &summary_bin)));
  TEST_ASSERT_EQUAL_INT(0, static_cast<int>(psbt_bin.sign(f.mk)));
  uint8_t out_bin[8192];
  size_t out_bin_len = 0;
  TEST_ASSERT_TRUE(psbt_bin.serialize_signed(out_bin, sizeof(out_bin), &out_bin_len));

  TEST_ASSERT_EQUAL_UINT32(out_bin_len, decoded_len);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(out_bin, decoded, out_bin_len);
}

static void test_nonempty_scriptsig_is_rejected(void) {
  // Constroi manualmente uma unsigned tx com scriptSig nao-vazio (invalido
  // por BIP174/9 do spec) e confere rejeicao.
  Builder tx;
  tx.u32le(1);
  tx.varint(1);
  uint8_t txid[32] = {0};
  tx.bytes(txid, sizeof(txid));
  tx.u32le(0);
  tx.varint(1); // scriptSig com 1 byte -> invalido para PSBT unsigned tx
  tx.u8(0x51);
  tx.u32le(0xffffffff);
  tx.varint(0); // 0 outputs
  tx.u32le(0);

  Builder b;
  b.bytes((const uint8_t[]){0x70, 0x73, 0x62, 0x74, 0xff}, 5);
  b.varint(1);
  b.u8(0x00);
  b.varint(tx.size());
  b.bytes(tx.data(), tx.size());
  b.end_map();

  Psbt psbt;
  PsbtError err = psbt.load(b.data(), b.size());
  TEST_ASSERT_EQUAL_INT(static_cast<int>(PsbtError::kNonEmptyScriptSig),
                       static_cast<int>(err));
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_valid_psbt_validates_and_summarizes);
  RUN_TEST(test_sign_and_serialize_roundtrip);
  RUN_TEST(test_wrong_fingerprint_is_rejected);
  RUN_TEST(test_unsupported_sighash_is_rejected);
  RUN_TEST(test_forged_change_is_shown_as_external_with_warning);
  RUN_TEST(test_truncated_file_is_rejected);
  RUN_TEST(test_bad_magic_is_rejected);
  RUN_TEST(test_base64_roundtrip_matches_binary);
  RUN_TEST(test_nonempty_scriptsig_is_rejected);
  return UNITY_END();
}
