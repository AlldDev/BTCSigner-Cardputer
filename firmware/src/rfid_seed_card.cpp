#include "rfid_seed_card.h"

#include <cstdlib>
#include <cstring>

#include "strong_random.h"

extern "C" {
#include "aes/aes.h"
#include "bip39.h"
#include "consteq.h"
#include "hmac.h"
#include "memzero.h"
#include "pbkdf2.h"
#include "sha2.h"
}

namespace btcseed {
namespace {

constexpr uint8_t kPlainVersion = 1;
constexpr size_t kKeyLen = 32;
constexpr size_t kOffSalt = 0;
constexpr size_t kOffIv = kOffSalt + kRfidSaltLen;
constexpr size_t kOffCiphertext = kOffIv + kRfidIvLen;
constexpr size_t kOffTag = kOffCiphertext + kRfidPlainLen;
constexpr size_t kPlainOffWords = 1;
constexpr size_t kPlainOffEntropy = 2;
constexpr size_t kEntropySlotLen = 32;

static_assert(kOffTag + kRfidTagLen == kRfidUsedLen, "layout do blob inconsistente");
static_assert(kPlainOffEntropy + kEntropySlotLen <= kRfidPlainLen, "slot de entropia nao cabe");
static_assert(kRfidPlainLen % 16 == 0, "texto plano precisa ser multiplo do bloco AES");

constexpr char kLabelEnc[] = "BTCSigner-RFID-v1-enc";
constexpr char kLabelMac[] = "BTCSigner-RFID-v1-mac";

// Todo material secreto vive aqui (nunca na stack) e e zerado de uma vez.
struct Scratch {
  PBKDF2_HMAC_SHA256_CTX pbkdf2;
  uint8_t master[kKeyLen];
  uint8_t aes_key[kKeyLen];
  uint8_t mac_key[kKeyLen];
  aes_encrypt_ctx enc;
  aes_decrypt_ctx dec;
  uint8_t iv[kRfidIvLen]; // copia: aes_cbc_* sobrescreve o IV recebido
  uint8_t plain[kRfidPlainLen];
  uint8_t bits[32 + 1]; // entropia + checksum de mnemonic_to_bits()
  uint8_t digest[32];   // checksum BIP39 / tag calculado
};
Scratch g_scratch;

// PBKDF2 gera um unico bloco de 32 bytes (o atacante nao economiza nada), e
// as duas chaves saem dele por HMAC com rotulos distintos. Usa a API
// Init/Update/Final porque o wrapper pbkdf2_hmac_sha256() deixa o digest na
// stack sem zerar.
void derive_keys(const char *password, size_t password_len, const uint8_t *salt,
                 uint32_t iterations) {
  pbkdf2_hmac_sha256_Init(&g_scratch.pbkdf2, reinterpret_cast<const uint8_t *>(password),
                          password_len, salt, kRfidSaltLen, 1);
  pbkdf2_hmac_sha256_Update(&g_scratch.pbkdf2, iterations);
  pbkdf2_hmac_sha256_Final(&g_scratch.pbkdf2, g_scratch.master);
  hmac_sha256(g_scratch.master, kKeyLen, reinterpret_cast<const uint8_t *>(kLabelEnc),
              sizeof(kLabelEnc) - 1, g_scratch.aes_key);
  hmac_sha256(g_scratch.master, kKeyLen, reinterpret_cast<const uint8_t *>(kLabelMac),
              sizeof(kLabelMac) - 1, g_scratch.mac_key);
  memzero(g_scratch.master, sizeof(g_scratch.master));
}

// aes_*_key256, aescrypt e sha256_Transform deixam round keys/estado na stack
// sem zerar (vendorizado, nao editavel). Sobrescreve essa regiao ao sair.
__attribute__((noinline)) void scrub_stack() {
  uint8_t pad[1536];
  memzero(pad, sizeof(pad));
}

size_t entropy_len_for_words(int words) { return static_cast<size_t>(words) * 4 / 3; }

bool valid_word_count(int words) { return words == 12 || words == 24; }

} // namespace

bool rfid_encode_backup(const char *password, size_t password_len, const char *mnemonic,
                        uint32_t iterations, uint8_t out[kMifareUsableBytes], RandomFn rng) {
  if (password == nullptr || password_len == 0 || mnemonic == nullptr || out == nullptr ||
      iterations == 0) {
    return false;
  }
  if (rng == nullptr) rng = strong_random_buffer;

  bool ok = false;
  size_t nbits = mnemonic_to_bits(mnemonic, g_scratch.bits);
  int words = static_cast<int>(nbits / 11);
  if (nbits % 11 == 0 && valid_word_count(words)) {
    size_t ent_len = entropy_len_for_words(words);
    sha256_Raw(g_scratch.bits, ent_len, g_scratch.digest);
    uint8_t mask = words == 12 ? 0xF0 : 0xFF;
    ok = (g_scratch.digest[0] & mask) == (g_scratch.bits[ent_len] & mask);

    if (ok) {
      // salt, iv e o preenchimento [112,752) de uma vez; o miolo e sobrescrito.
      rng(out, kMifareUsableBytes);
      rng(g_scratch.plain, sizeof(g_scratch.plain));
      g_scratch.plain[0] = kPlainVersion;
      g_scratch.plain[kPlainOffWords] = static_cast<uint8_t>(words);
      memcpy(g_scratch.plain + kPlainOffEntropy, g_scratch.bits, ent_len);

      derive_keys(password, password_len, out + kOffSalt, iterations);
      memcpy(g_scratch.iv, out + kOffIv, kRfidIvLen);
      ok = aes_encrypt_key256(g_scratch.aes_key, &g_scratch.enc) == EXIT_SUCCESS &&
           aes_cbc_encrypt(g_scratch.plain, out + kOffCiphertext,
                           static_cast<int>(kRfidPlainLen), g_scratch.iv,
                           &g_scratch.enc) == EXIT_SUCCESS;
      if (ok) {
        hmac_sha256(g_scratch.mac_key, kKeyLen, out, kOffTag, out + kOffTag);
      }
    }
  }
  if (!ok) memzero(out, kMifareUsableBytes);
  rfid_wipe_scratch();
  scrub_stack();
  return ok;
}

RfidCardStatus rfid_decode_backup(const char *password, size_t password_len,
                                  const uint8_t card[kMifareUsableBytes], uint32_t iterations,
                                  char *out_mnemonic, size_t out_cap) {
  if (out_mnemonic != nullptr && out_cap > 0) memzero(out_mnemonic, out_cap);
  if (card == nullptr || out_mnemonic == nullptr || out_cap < BIP39_MAX_MNEMONIC_LEN + 1) {
    return RfidCardStatus::kMalformed;
  }
  if (rfid_card_is_blank(card)) return RfidCardStatus::kBlank;
  if (password == nullptr || password_len == 0 || iterations == 0) {
    return RfidCardStatus::kAuthFailed;
  }

  derive_keys(password, password_len, card + kOffSalt, iterations);

  // MAC antes de qualquer decifragem.
  hmac_sha256(g_scratch.mac_key, kKeyLen, card, kOffTag, g_scratch.digest);
  if (!consteq(g_scratch.digest, card + kOffTag, kRfidTagLen)) {
    rfid_wipe_scratch();
    scrub_stack();
    return RfidCardStatus::kAuthFailed;
  }

  memcpy(g_scratch.iv, card + kOffIv, kRfidIvLen);
  bool ok = aes_decrypt_key256(g_scratch.aes_key, &g_scratch.dec) == EXIT_SUCCESS &&
            aes_cbc_decrypt(card + kOffCiphertext, g_scratch.plain,
                            static_cast<int>(kRfidPlainLen), g_scratch.iv,
                            &g_scratch.dec) == EXIT_SUCCESS;
  int words = g_scratch.plain[kPlainOffWords];
  ok = ok && g_scratch.plain[0] == kPlainVersion && valid_word_count(words);

  RfidCardStatus status = RfidCardStatus::kMalformed;
  if (ok) {
    // mnemonic_from_data() escreve num buffer estatico da lib: copiar e limpar ja.
    const char *m = mnemonic_from_data(g_scratch.plain + kPlainOffEntropy,
                                       entropy_len_for_words(words));
    if (m != nullptr) {
      size_t n = strlen(m);
      if (n + 1 <= out_cap) {
        memcpy(out_mnemonic, m, n + 1);
        status = RfidCardStatus::kOk;
      }
    }
    mnemonic_clear();
  }
  if (status != RfidCardStatus::kOk) memzero(out_mnemonic, out_cap);
  rfid_wipe_scratch();
  scrub_stack();
  return status;
}

RfidPasswordIssue rfid_check_password(const char *password, size_t len) {
  if (password == nullptr || len < static_cast<size_t>(kMinRfidPasswordLen)) {
    return RfidPasswordIssue::kTooShort;
  }
  bool seen[256] = {false};
  int distinct = 0;
  bool only_digits = true;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = static_cast<uint8_t>(password[i]);
    if (!seen[c]) {
      seen[c] = true;
      distinct++;
    }
    only_digits = only_digits && c >= '0' && c <= '9';
  }
  memzero(seen, sizeof(seen)); // histograma revela quais caracteres a senha tem
  if (only_digits) return RfidPasswordIssue::kOnlyDigits;
  if (distinct < kMinRfidPasswordDistinct) return RfidPasswordIssue::kTooFewDistinct;
  return RfidPasswordIssue::kOk;
}

bool rfid_card_is_blank(const uint8_t card[kMifareUsableBytes]) {
  if (card == nullptr) return false;
  bool all_zero = true;
  bool all_ff = true;
  for (size_t i = 0; i < kMifareUsableBytes; i++) {
    all_zero = all_zero && card[i] == 0x00;
    all_ff = all_ff && card[i] == 0xFF;
  }
  return all_zero || all_ff;
}

int mifare_physical_block_for_index(int data_block_index) {
  if (data_block_index < 0 || data_block_index >= kMifareUsableBlocks) return -1;
  if (data_block_index < 2) return data_block_index + 1; // setor 0: blocos 1 e 2
  int j = data_block_index - 2;
  int sector = 1 + j / 3;
  return sector * 4 + j % 3;
}

void rfid_wipe_scratch() { memzero(&g_scratch, sizeof(g_scratch)); }

bool rfid_scratch_is_clear() {
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&g_scratch);
  for (size_t i = 0; i < sizeof(g_scratch); i++) {
    if (p[i] != 0) return false;
  }
  return true;
}

} // namespace btcseed
