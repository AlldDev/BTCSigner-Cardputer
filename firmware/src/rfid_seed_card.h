// Formato e criptografia do backup opcional da seed num cartao MIFARE Classic.
// Logica pura (sem Arduino/leitor RFID): testada no host (`native`). A E/S no
// cartao fica em rfid_io.cpp.
//
// O cartao deve ser tratado como publico: qualquer leitor o copia. Os 752
// bytes gravados sao indistinguiveis de dados aleatorios e sempre do mesmo
// tamanho, qualquer que seja a seed:
//
//   [0,16)    salt  (PBKDF2)
//   [16,32)   iv    (AES-256-CBC)
//   [32,80)   ciphertext de 48 bytes fixos:
//               [0] versao (1)  [1] palavras (12|24)
//               [2,34) entropia BIP39 (12 palavras: 16 bytes + 16 aleatorios)
//               [34,48) aleatorio
//   [80,112)  HMAC-SHA256(mac_key, bytes [0,80))
//   [112,752) aleatorio (sobrescreve qualquer backup anterior)
//
// master  = PBKDF2-HMAC-SHA256(senha, salt, iteracoes), 32 bytes (1 bloco)
// aes_key = HMAC-SHA256(master, "BTCSigner-RFID-v1-enc")
// mac_key = HMAC-SHA256(master, "BTCSigner-RFID-v1-mac")
//
// A passphrase BIP39 nunca vai para o cartao: continua sendo digitada.
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace btcseed {

using RandomFn = void (*)(uint8_t *buf, size_t len);

// Monta os kMifareUsableBytes a gravar. `mnemonic` precisa ser um mnemonico
// BIP39 valido de 12 ou 24 palavras. `rng` so e trocado nos testes.
bool rfid_encode_backup(const char *password, size_t password_len, const char *mnemonic,
                        uint32_t iterations, uint8_t out[kMifareUsableBytes],
                        RandomFn rng = nullptr);

enum class RfidCardStatus {
  kOk,
  kBlank,      // cartao de fabrica (tudo 0x00 ou tudo 0xFF)
  kAuthFailed, // senha errada, cartao de outro formato ou corrompido
  kMalformed,  // MAC valido mas conteudo invalido (nao deveria acontecer)
};

// Em qualquer resultado diferente de kOk, `out_mnemonic` sai zerado.
// out_cap deve ser >= BIP39_MAX_MNEMONIC_LEN + 1.
RfidCardStatus rfid_decode_backup(const char *password, size_t password_len,
                                  const uint8_t card[kMifareUsableBytes], uint32_t iterations,
                                  char *out_mnemonic, size_t out_cap);

bool rfid_card_is_blank(const uint8_t card[kMifareUsableBytes]);

// Politica minima da senha do cartao. Nao mede forca de verdade: so barra o
// que cai rapido num ataque offline (curta, repetitiva, so digitos).
enum class RfidPasswordIssue { kOk, kTooShort, kTooFewDistinct, kOnlyDigits };
RfidPasswordIssue rfid_check_password(const char *password, size_t len);

// Indice de bloco de dados [0, kMifareUsableBlocks) -> bloco fisico do cartao,
// pulando o bloco 0 (fabricante) e os trailers. -1 se fora da faixa.
int mifare_physical_block_for_index(int data_block_index);

// Zera todos os buffers internos (chaves, contextos, texto plano). As funcoes
// acima ja fazem isso antes de retornar; exposto para wipe_seed_material().
void rfid_wipe_scratch();

// So para testes: true se todos os buffers internos estao zerados.
bool rfid_scratch_is_clear();

} // namespace btcseed
