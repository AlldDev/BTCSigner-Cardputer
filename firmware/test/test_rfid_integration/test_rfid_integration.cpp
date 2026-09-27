// Integracao ponta a ponta do backup RFID no host, com os mesmos modulos que
// main.cpp compoe: digitar a seed (MnemonicInput/PassphraseInput) -> derivar
// (keys) -> backup (rfid_seed_card) -> gravar num MIFARE Classic 1K simulado
// (mesmo percurso de blocos de rfid_io.cpp) -> wipe da sessao -> restaurar ->
// digitar a passphrase -> mesma MasterKey/zpub (vetor oficial BIP84).
#include <unity.h>

#include <cstring>

#include "config.h"
#include "keys.h"
#include "mnemonic_input.h"
#include "passphrase_input.h"
#include "rfid_seed_card.h"
#include "session.h"

extern "C" {
#include "bip39.h"
#include "memzero.h"
}

using namespace btcseed;

namespace {

constexpr char kMnemonic[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
constexpr char kBip84Zpub[] =
    "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
constexpr char kCardPassword[] = "cavalo bateria grampo correto";
constexpr char kPassphrase[] = "minha 25a palavra";
constexpr uint32_t kIters = 2000;

// --- MIFARE Classic 1K simulado: 64 blocos, bloco 0 e trailers de fabrica ---
constexpr int kBlocks = 64;
uint8_t g_mifare[kBlocks][kMifareBlockSize];
const uint8_t kManufacturer[16] = {0xde, 0xad, 0xbe, 0xef, 0x22, 0x08, 0x04, 0x00,
                                   0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};
const uint8_t kFactoryTrailer[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07,
                                     0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void mifare_factory_reset() {
  memset(g_mifare, 0, sizeof(g_mifare));
  memcpy(g_mifare[0], kManufacturer, 16);
  for (int s = 0; s < kMifareSectors; s++) memcpy(g_mifare[s * 4 + 3], kFactoryTrailer, 16);
}

// Mesmo percurso de rfid_write_all()/rfid_read_all(); `blocks` < 47 simula
// o cartao afastado no meio da gravacao.
void mifare_write(const uint8_t data[kMifareUsableBytes], int blocks = kMifareUsableBlocks) {
  for (int i = 0; i < blocks; i++) {
    memcpy(g_mifare[mifare_physical_block_for_index(i)], data + i * kMifareBlockSize, 16);
  }
}

void mifare_read(uint8_t out[kMifareUsableBytes]) {
  for (int i = 0; i < kMifareUsableBlocks; i++) {
    memcpy(out + i * kMifareBlockSize, g_mifare[mifare_physical_block_for_index(i)], 16);
  }
}

bool mifare_structure_intact() {
  if (memcmp(g_mifare[0], kManufacturer, 16) != 0) return false;
  for (int s = 0; s < kMifareSectors; s++) {
    if (memcmp(g_mifare[s * 4 + 3], kFactoryTrailer, 16) != 0) return false;
  }
  return true;
}

// --- estado equivalente ao de main.cpp (estatico, nunca na stack) -----------
MnemonicInput g_mnemonic(kMnemonicWordsShort);
char g_mnemonic_text[BIP39_MAX_MNEMONIC_LEN + 1];
PassphraseInput g_passphrase;
PassphraseInput g_card_pw;
uint8_t g_card_blob[kMifareUsableBytes];
uint8_t g_dump[kMifareUsableBytes];
MasterKey g_mk;

uint32_t g_now = 0;
uint32_t fake_millis() { return g_now; }
Session g_session(fake_millis);

void wipe_seed_material() {
  g_mnemonic.wipe();
  memzero(g_mnemonic_text, sizeof(g_mnemonic_text));
  g_passphrase.wipe();
  g_card_pw.wipe();
  memzero(g_card_blob, sizeof(g_card_blob));
  rfid_wipe_scratch();
  mnemonic_clear();
}

void type_text(PassphraseInput *in, const char *text) {
  for (const char *p = text; *p != '\0'; p++) TEST_ASSERT_TRUE(in->add_char(*p));
}

// Digita cada palavra letra a letra e escolhe o candidato exato, como na tela.
void type_mnemonic(const char *mnemonic) {
  g_mnemonic = MnemonicInput(kMnemonicWordsShort);
  char word[kMaxWordLen + 1];
  const char *p = mnemonic;
  while (*p != '\0') {
    size_t n = 0;
    while (p[n] != '\0' && p[n] != ' ') n++;
    memcpy(word, p, n);
    word[n] = '\0';
    for (size_t i = 0; i < n; i++) TEST_ASSERT_TRUE(g_mnemonic.try_add_letter(word[i]));
    while (strcmp(g_mnemonic.nth_candidate(g_mnemonic.selected_candidate_index()), word) != 0) {
      g_mnemonic.next_candidate();
    }
    TEST_ASSERT_TRUE(g_mnemonic.confirm_word());
    p += n;
    if (*p == ' ') p++;
  }
  TEST_ASSERT_TRUE(g_mnemonic.is_complete());
  TEST_ASSERT_TRUE(g_mnemonic.validate_checksum());
  TEST_ASSERT_TRUE(g_mnemonic.build_mnemonic(g_mnemonic_text, sizeof(g_mnemonic_text)));
}

bool contains(const uint8_t *hay, size_t hay_len, const void *needle, size_t needle_len) {
  for (size_t i = 0; i + needle_len <= hay_len; i++) {
    if (memcmp(hay + i, needle, needle_len) == 0) return true;
  }
  return false;
}

bool all_zero(const void *p, size_t n) {
  const uint8_t *b = static_cast<const uint8_t *>(p);
  for (size_t i = 0; i < n; i++) {
    if (b[i] != 0) return false;
  }
  return true;
}

void zpub_of(const MasterKey &mk, char out[XPUB_MAXLEN]) {
  TEST_ASSERT_TRUE(serialize_account_xpub(mk, out, XPUB_MAXLEN));
}

// Sessao original: digitar, derivar, fazer backup no cartao, encerrar.
void first_session_with_backup(const char *passphrase, char zpub_out[XPUB_MAXLEN],
                               uint32_t *fingerprint_out) {
  type_mnemonic(kMnemonic);
  g_passphrase.wipe();
  type_text(&g_passphrase, passphrase);
  TEST_ASSERT_TRUE(derive_master_key(g_mnemonic_text, g_passphrase.value(), Network::kMainnet,
                                     &g_mk));
  *fingerprint_out = g_mk.master_fingerprint;
  zpub_of(g_mk, zpub_out);

  g_card_pw.wipe();
  type_text(&g_card_pw, kCardPassword);
  TEST_ASSERT_TRUE(rfid_encode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()),
                                      g_mnemonic_text, kIters, g_card_blob));
  g_card_pw.wipe(); // main.cpp zera a senha logo apos cifrar
  mifare_write(g_card_blob);

  g_session.start(&g_mk); // confirm_fingerprint_and_start_session()
  wipe_seed_material();
  g_session.end();
}

// Sessao nova: ler o cartao, decifrar, digitar a passphrase, derivar.
RfidCardStatus restore_session(const char *card_password, const char *passphrase,
                               MasterKey *out) {
  mifare_read(g_card_blob);
  g_card_pw.wipe();
  type_text(&g_card_pw, card_password);
  RfidCardStatus st =
      rfid_decode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()), g_card_blob,
                         kIters, g_mnemonic_text, sizeof(g_mnemonic_text));
  g_card_pw.wipe();
  memzero(g_card_blob, sizeof(g_card_blob));
  if (st != RfidCardStatus::kOk) return st;
  g_passphrase.wipe();
  type_text(&g_passphrase, passphrase);
  TEST_ASSERT_TRUE(
      derive_master_key(g_mnemonic_text, g_passphrase.value(), Network::kMainnet, out));
  return st;
}

} // namespace

void setUp(void) {
  mifare_factory_reset();
  wipe_seed_material();
  wipe(&g_mk);
}
void tearDown(void) {}

static void test_end_to_end_backup_and_restore_matches_bip84_vector(void) {
  char zpub1[XPUB_MAXLEN];
  uint32_t fp1 = 0;
  first_session_with_backup("", zpub1, &fp1);
  TEST_ASSERT_EQUAL_STRING(kBip84Zpub, zpub1);
  TEST_ASSERT_TRUE(mifare_structure_intact());

  // Nada da primeira sessao sobrou na RAM.
  TEST_ASSERT_TRUE(all_zero(g_mnemonic_text, sizeof(g_mnemonic_text)));
  TEST_ASSERT_EQUAL_INT(0, g_passphrase.length());
  TEST_ASSERT_EQUAL_INT(0, g_card_pw.length());
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  TEST_ASSERT_FALSE(g_session.is_active());
  TEST_ASSERT_FALSE(g_session.master_key().valid);

  MasterKey mk2;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(restore_session(kCardPassword, "", &mk2)));
  TEST_ASSERT_EQUAL_STRING(kMnemonic, g_mnemonic_text);
  TEST_ASSERT_EQUAL_HEX32(fp1, mk2.master_fingerprint);
  char zpub2[XPUB_MAXLEN];
  zpub_of(mk2, zpub2);
  TEST_ASSERT_EQUAL_STRING(kBip84Zpub, zpub2);
  char addr[74];
  TEST_ASSERT_TRUE(derive_address(mk2, kChangeExternal, 0, addr, sizeof(addr)));
  TEST_ASSERT_EQUAL_STRING("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", addr);

  g_session.start(&mk2);
  wipe_seed_material();
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  g_session.end();
}

static void test_passphrase_is_not_on_card(void) {
  char zpub1[XPUB_MAXLEN];
  uint32_t fp1 = 0;
  first_session_with_backup(kPassphrase, zpub1, &fp1);

  // Restaurar com a passphrase certa: mesma carteira.
  MasterKey ok;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(restore_session(kCardPassword, kPassphrase, &ok)));
  TEST_ASSERT_EQUAL_HEX32(fp1, ok.master_fingerprint);
  wipe(&ok);
  wipe_seed_material();

  // Quem quebra a senha do cartao mas nao sabe a passphrase chega em outra carteira.
  MasterKey attacker;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(restore_session(kCardPassword, "", &attacker)));
  TEST_ASSERT_NOT_EQUAL(fp1, attacker.master_fingerprint);
  char zpub_attacker[XPUB_MAXLEN];
  zpub_of(attacker, zpub_attacker);
  TEST_ASSERT_TRUE(strcmp(zpub1, zpub_attacker) != 0);
  wipe(&attacker);

  // E a passphrase nao aparece em nenhum byte do cartao.
  mifare_read(g_dump);
  TEST_ASSERT_FALSE(contains(g_dump, sizeof(g_dump), kPassphrase, 5));
}

static void test_card_dump_reveals_nothing(void) {
  char zpub[XPUB_MAXLEN];
  uint32_t fp = 0;
  first_session_with_backup(kPassphrase, zpub, &fp);
  mifare_read(g_dump);

  const char *needles[] = {"abandon", "about", "cavalo", "bateria", "minha", "BTCSigner", "BSR"};
  for (const char *n : needles) TEST_ASSERT_FALSE(contains(g_dump, sizeof(g_dump), n, strlen(n)));
  const uint8_t zero_run[8] = {0}; // entropia de "abandon...about" e toda zero
  TEST_ASSERT_FALSE(contains(g_dump, sizeof(g_dump), zero_run, sizeof(zero_run)));

  // Parece aleatorio: 752 bytes uniformes tem ~242 valores distintos (dp ~3).
  bool seen[256] = {false};
  int distinct = 0;
  for (uint8_t b : g_dump) {
    if (!seen[b]) {
      seen[b] = true;
      distinct++;
    }
  }
  TEST_ASSERT_GREATER_THAN_INT(215, distinct);
}

static void test_wrong_password_restores_nothing(void) {
  char zpub[XPUB_MAXLEN];
  uint32_t fp = 0;
  first_session_with_backup("", zpub, &fp);
  MasterKey mk;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kAuthFailed),
                        static_cast<int>(restore_session("cavalo bateria grampo errado", "", &mk)));
  TEST_ASSERT_TRUE(all_zero(g_mnemonic_text, sizeof(g_mnemonic_text)));
  TEST_ASSERT_TRUE(rfid_scratch_is_clear());
  TEST_ASSERT_EQUAL_INT(0, g_card_pw.length());
}

static void test_blank_card_is_detected(void) {
  mifare_read(g_dump);
  TEST_ASSERT_TRUE(rfid_card_is_blank(g_dump));
  MasterKey mk;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kBlank),
                        static_cast<int>(restore_session(kCardPassword, "", &mk)));
}

static void test_interrupted_write_never_yields_a_seed(void) {
  // Backup antigo com uma senha antiga, depois gravacao nova interrompida.
  char zpub[XPUB_MAXLEN];
  uint32_t fp = 0;
  first_session_with_backup("", zpub, &fp);
  type_mnemonic(kMnemonic);
  type_text(&g_card_pw, "outra senha longa e diferente");
  TEST_ASSERT_TRUE(rfid_encode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()),
                                      g_mnemonic_text, kIters, g_card_blob));
  const char *new_pw = "outra senha longa e diferente";
  for (int blocks = 1; blocks < kMifareUsableBlocks; blocks += 5) {
    mifare_write(g_card_blob, blocks);
    TEST_ASSERT_TRUE(mifare_structure_intact());
    mifare_read(g_dump);
    // Com menos de 7 blocos novos (os 112 bytes autenticados), nenhuma senha abre.
    if (blocks < static_cast<int>(kRfidUsedLen / kMifareBlockSize)) {
      char out[BIP39_MAX_MNEMONIC_LEN + 1];
      TEST_ASSERT_NOT_EQUAL(static_cast<int>(RfidCardStatus::kOk),
                            static_cast<int>(rfid_decode_backup(kCardPassword, strlen(kCardPassword),
                                                                g_dump, kIters, out, sizeof(out))));
      TEST_ASSERT_NOT_EQUAL(static_cast<int>(RfidCardStatus::kOk),
                            static_cast<int>(rfid_decode_backup(new_pw, strlen(new_pw), g_dump,
                                                                kIters, out, sizeof(out))));
      TEST_ASSERT_TRUE(all_zero(out, sizeof(out)));
    }
  }
}

static void test_new_backup_leaves_nothing_of_the_old_one(void) {
  char zpub[XPUB_MAXLEN];
  uint32_t fp = 0;
  first_session_with_backup("", zpub, &fp);
  uint8_t old_card[kMifareUsableBytes];
  mifare_read(old_card);

  first_session_with_backup("", zpub, &fp); // regrava o mesmo cartao
  mifare_read(g_dump);
  for (int i = 0; i < kMifareUsableBlocks; i++) {
    TEST_ASSERT_FALSE(contains(g_dump, sizeof(g_dump), old_card + i * kMifareBlockSize, 16));
  }
  // A senha antiga (a mesma aqui) so abre o backup novo, nunca o antigo.
  MasterKey mk;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(restore_session(kCardPassword, "", &mk)));
  TEST_ASSERT_EQUAL_HEX32(fp, mk.master_fingerprint);
}

static void test_24_word_seed_roundtrip_through_card(void) {
  const char *m24 =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
      "abandon art";
  TEST_ASSERT_TRUE(mnemonic_check(m24));
  MasterKey typed;
  TEST_ASSERT_TRUE(derive_master_key(m24, kPassphrase, Network::kTestnet, &typed));
  TEST_ASSERT_TRUE(rfid_encode_backup(kCardPassword, strlen(kCardPassword), m24, kIters,
                                      g_card_blob));
  mifare_write(g_card_blob);
  mifare_read(g_dump);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(RfidCardStatus::kOk),
                        static_cast<int>(rfid_decode_backup(kCardPassword, strlen(kCardPassword),
                                                            g_dump, kIters, g_mnemonic_text,
                                                            sizeof(g_mnemonic_text))));
  TEST_ASSERT_EQUAL_STRING(m24, g_mnemonic_text);
  MasterKey restored;
  TEST_ASSERT_TRUE(derive_master_key(g_mnemonic_text, kPassphrase, Network::kTestnet, &restored));
  TEST_ASSERT_EQUAL_HEX32(typed.master_fingerprint, restored.master_fingerprint);
  TEST_ASSERT_EQUAL_MEMORY(typed.account_node.private_key, restored.account_node.private_key, 32);
  wipe(&typed);
  wipe(&restored);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  UNITY_BEGIN();
  RUN_TEST(test_end_to_end_backup_and_restore_matches_bip84_vector);
  RUN_TEST(test_passphrase_is_not_on_card);
  RUN_TEST(test_card_dump_reveals_nothing);
  RUN_TEST(test_wrong_password_restores_nothing);
  RUN_TEST(test_blank_card_is_detected);
  RUN_TEST(test_interrupted_write_never_yields_a_seed);
  RUN_TEST(test_new_backup_leaves_nothing_of_the_old_one);
  RUN_TEST(test_24_word_seed_roundtrip_through_card);
  return UNITY_END();
}
