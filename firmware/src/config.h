// Constantes de configuracao do firmware. Nenhum segredo deve ser
// definido aqui — apenas limites, timeouts e parametros de rede/derivacao.
#pragma once

#include <stdint.h>

namespace btcseed {

// --- Sessao ---
// Tempo de inatividade (ms) apos o qual a sessao e encerrada e todos os
// segredos sao zerados (BIP-11 do spec).
constexpr uint32_t kSessionTimeoutMs = 3 * 60 * 1000; // 3 minutos

// Quanto tempo Enter precisa ficar segurado para assinar uma PSBT.
constexpr uint32_t kHoldToSignMs = 1500;

// --- Mnemonico ---
constexpr int kMnemonicWordsShort = 12;
constexpr int kMnemonicWordsLong = 24;
constexpr int kMaxWordLen = 8;      // maior palavra da wordlist BIP39 e 8 letras
constexpr int kBip39WordlistSize = 2048;

// --- Passphrase (25a palavra) ---
// mnemonic_to_seed() (trezor-crypto) trunca em 256 caracteres.
constexpr int kMaxPassphraseLen = 256;

// --- Derivacao (BIP84, P2WPKH nativo) ---
enum class Network : uint8_t {
  kMainnet = 0,
  kTestnet = 1, // usado tambem para signet
};

// m/84'/coin'/0'
constexpr uint32_t kPurposeBip84 = 0x80000000u | 84u;
constexpr uint32_t kCoinTypeMainnet = 0x80000000u | 0u;
constexpr uint32_t kCoinTypeTestnet = 0x80000000u | 1u;
constexpr uint32_t kAccountHardened = 0x80000000u | 0u;
constexpr uint32_t kChangeExternal = 0;
constexpr uint32_t kChangeInternal = 1;

// --- Limites de PSBT (secao 9 do spec) ---
// O spec da 64 KB como exemplo ("ex: 64 KB"). Na pratica, uma PSBT P2WPKH
// com ate 20 inputs + 20 outputs (o proprio limite abaixo) fica bem abaixo
// de 16 KB (a conta cabe: ~1.5 KB de tx nao assinada + ~150B/input +
// ~100B/output = ~6.5 KB no pior caso). Reduzido de 64 KB para 16 KB
// porque o M5Stack Cardputer (ESP32-S3, 320 KB de RAM, sem PSRAM neste
// board) nao tem folga para os multiplos buffers do tamanho desse limite
// que main.cpp e psbt.cpp precisam manter em paralelo (build real medido:
// 64 KB deixava o firmware em 81% de uso de RAM; com 16 KB cai para ~30%).
// Subido para 32 KB (~46% de RAM) quando a tx anterior completa
// (non_witness_utxo) passou a ser obrigatoria: uma tx de origem grande
// (saque em lote de exchange) nao cabia em 16 KB. Cada KB aqui custa ~3.3 KB
// de RAM (buf_ do Psbt + scratch de serialize_signed + g_psbt_io_buf).
constexpr size_t kMaxPsbtFileSize = 32 * 1024; // 32 KB
constexpr int kMaxPsbtInputs = 20;
constexpr int kMaxPsbtOutputs = 20;
constexpr size_t kMaxFilenameLen = 64;

// Teto de valor do consenso (MAX_MONEY). Qualquer valor acima disso num
// PSBT e malformado — e garante que a soma de ate 20 valores nao estoura.
constexpr uint64_t kMaxMoneySats = 21000000ull * 100000000ull;

// Troco verificado com indice acima disso ganha aviso na revisao: uma
// carteira watch-only (gap limit ~20) nunca escanearia um indice absurdo e
// os fundos ficariam "escondidos". Ajustavel.
constexpr uint32_t kChangeIndexWarning = 1000;

// --- Aviso de taxa alta ---
constexpr double kHighFeeWarningPercent = 5.0; // % do valor enviado
constexpr uint64_t kHighFeeWarningAbsoluteSats = 100000; // 0.001 BTC, ajustavel

// --- Diretorios/arquivos no microSD ---
constexpr const char *kPsbtDir = "/psbt";
constexpr const char *kPsbtExtension = ".psbt";
constexpr const char *kSignedSuffix = "_signed";
constexpr const char *kXpubExportFile = "/wallet_export.txt";
constexpr int kMaxPsbtFilesListed = 32; // quantos .psbt cabem no menu
// Sem cartao montado, a aba ASSINAR tenta montar de novo a cada kSdPollMs.
constexpr uint32_t kSdPollMs = 2000;

// --- Backup opcional cifrado da seed em cartao MIFARE Classic (Unit RFID2) ---
// O cartao e legivel por qualquer um (chave de fabrica + Crypto1 quebrado):
// a unica protecao e senha x custo do KDF.
// FORMATO CONGELADO: o valor nao fica gravado no cartao, entao muda-lo torna
// ilegivel todo cartao ja gravado (o erro parece "senha errada"). O vetor
// golden de producao em test_rfid_seed_card trava este numero. Para mudar no
// futuro, a restauracao tem que continuar tentando os valores antigos.
constexpr uint32_t kRfidPbkdf2Iterations = 200000;
// Com o cartao copiado, a senha e atacada offline em GPU: PINs curtos caem em
// segundos. 12 caracteres e o piso; a tela recomenda 4-6 palavras aleatorias.
constexpr int kMinRfidPasswordLen = 12;
constexpr int kMinRfidPasswordDistinct = 8; // barra "aaaaaaaaaaaa", "121212121212"
constexpr uint32_t kRfidCardWaitTimeoutMs = 8000;
// Tela cheia de erro da restauracao antes de voltar sozinha ao inicio.
constexpr uint32_t kCardErrorShowMs = 3000;

// Layout de cada copia (rfid_seed_card.h): salt | iv | ciphertext | tag.
constexpr size_t kRfidSaltLen = 16;
constexpr size_t kRfidIvLen = 16;
constexpr size_t kRfidPlainLen = 48; // 3 blocos AES, tamanho fixo (sem padding)
constexpr size_t kRfidTagLen = 32;
constexpr size_t kRfidUsedLen = kRfidSaltLen + kRfidIvLen + kRfidPlainLen + kRfidTagLen; // 112
// Duas copias independentes (salt/iv/chaves proprios). A copia A e gravada por
// ultimo: uma gravacao interrompida sempre deixa o backup antigo (A intacto) ou
// o novo (B completo) legivel. Offsets alinhados a bloco de 16 bytes.
constexpr int kRfidSlotCount = 2;
constexpr size_t kRfidSlotOffsets[kRfidSlotCount] = {0, 384};

// MIFARE Classic 1K: 16 setores x 4 blocos de 16 bytes. Bloco 0 (fabricante)
// e o bloco 3 de cada setor (trailer) nunca sao escritos. Em cartoes 4K so os
// 16 primeiros setores (identicos aos do 1K) sao usados.
constexpr int kMifareBlockSize = 16;
constexpr int kMifareSectors = 16;
constexpr int kMifareUsableBlocks = 47;
constexpr size_t kMifareUsableBytes = kMifareUsableBlocks * kMifareBlockSize; // 752
// Chaves tentadas, em ordem. A de fabrica e a usual; 00..00 aparece em copias
// feitas por ferramentas que gravam o trailer como o dump mostra (Key A nao e
// legivel e sai zerada). Os trailers nunca sao escritos pelo firmware.
struct MifareKeyOption {
  bool key_b;
  uint8_t key[6];
};
constexpr MifareKeyOption kMifareKeys[] = {
    {false, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {false, {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {true, {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
};
constexpr int kMifareKeyCount = sizeof(kMifareKeys) / sizeof(kMifareKeys[0]);

static_assert(kRfidSlotOffsets[0] == 0, "copia A no inicio (gravada por ultimo)");
static_assert(kRfidSlotOffsets[0] + kRfidUsedLen <= kRfidSlotOffsets[1], "copias sobrepostas");
static_assert(kRfidSlotOffsets[1] % kMifareBlockSize == 0, "copia B fora do alinhamento");
static_assert(kRfidSlotOffsets[1] + kRfidUsedLen <= kMifareUsableBytes, "copia B nao cabe");
static_assert(kRfidUsedLen % kMifareBlockSize == 0, "copia nao ocupa blocos inteiros");

} // namespace btcseed
