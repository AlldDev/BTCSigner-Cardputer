// Constantes de configuracao do firmware. Nenhum segredo deve ser
// definido aqui — apenas limites, timeouts e parametros de rede/derivacao.
#pragma once

#include <stdint.h>

namespace btcseed {

// --- Sessao ---
// Tempo de inatividade (ms) apos o qual a sessao e encerrada e todos os
// segredos sao zerados (BIP-11 do spec).
constexpr uint32_t kSessionTimeoutMs = 3 * 60 * 1000; // 3 minutos

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
constexpr size_t kMaxPsbtFileSize = 16 * 1024; // 16 KB
constexpr int kMaxPsbtInputs = 20;
constexpr int kMaxPsbtOutputs = 20;
constexpr size_t kMaxFilenameLen = 64;

// --- Aviso de taxa alta ---
constexpr double kHighFeeWarningPercent = 5.0; // % do valor enviado
constexpr uint64_t kHighFeeWarningAbsoluteSats = 100000; // 0.001 BTC, ajustavel

// --- Diretorios/arquivos no microSD ---
constexpr const char *kPsbtDir = "/psbt";
constexpr const char *kPsbtExtension = ".psbt";
constexpr const char *kSignedSuffix = "_signed";
constexpr const char *kXpubExportFile = "/wallet_export.txt";
constexpr int kMaxPsbtFilesListed = 32; // quantos .psbt cabem no menu

} // namespace btcseed
