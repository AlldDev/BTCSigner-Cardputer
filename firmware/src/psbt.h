// Parser, validador e assinador de PSBT (BIP174), minimo e restrito ao
// subconjunto necessario (secao 9 da spec): PSBT versao 0, entradas P2WPKH
// unicas (BIP84), SIGHASH_ALL. Implementado do zero sobre trezor-crypto —
// a uBitcoin foi avaliada e descartada (ver README.md da raiz do projeto,
// secao "Revisao da uBitcoin").
//
// Qualquer campo do PSBT que este parser nao entende e preservado byte a
// byte (nunca modificado nem descartado) e reescrito verbatim ao assinar —
// e o comportamento exigido pelo proprio BIP174 para campos desconhecidos.
//
// IMPORTANTE: instancias de Psbt tem dezenas de KB de buffers internos
// (limitados por kMaxPsbtFileSize) e NÃO devem ser alocadas na stack de uma
// task do ESP32 (tipicamente 8-16 KB) — devem ser globais/estaticas ou
// alocadas explicitamente em PSRAM.
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"
#include "keys.h"

namespace btcseed {

enum class PsbtError {
  kNone = 0,
  kEmptyFile,
  kFileTooLarge,
  kBadEncoding,           // nem binario (magic psbt\xff) nem base64 (cHNidP...)
  kBadMagic,
  kTruncated,             // fim inesperado do buffer ao parsear
  kMalformed,             // varint nao minimo, tamanho de campo errado, etc.
  kMissingUnsignedTx,
  kUnsupportedVersion,    // PSBT_GLOBAL_VERSION != 0
  kTooManyInputs,
  kTooManyOutputs,
  kNonEmptyScriptSig,     // unsigned tx deveria ter scriptSig vazio (BIP174)
  kAlreadyHasSignature,   // PARTIAL_SIG/FINAL_* presentes: fluxo fora do escopo
  kMissingWitnessUtxo,
  kMissingBip32Derivation,
  kDuplicateField,
  kFingerprintMismatch,
  kDerivationPathMismatch, // fora de m/84'/coin'/0'/{0,1}/i da conta da sessao
  kPubkeyMismatch,         // pubkey do PSBT != pubkey derivado por nos mesmos
  kUnsupportedInputScript, // input a assinar nao e P2WPKH puro
  kUnsupportedSighash,
  kUnsupportedOutputScript,
  kNetworkMismatch,
  kAmountsDontBalance,     // soma dos inputs < soma dos outputs
  kNotValidated,           // sign() chamado antes de validate() ter sucesso
  kSignFailed,
  kBufferTooSmall,         // serialize_signed: buffer de saida pequeno demais
};

// Resumo de um output, para a tela de revisao (review_screens.cpp).
struct OutputInfo {
  char address[76] = {0};   // endereco formatado; vazio se script nao suportado
  uint64_t amount_sats = 0;
  bool is_change = false;          // derivacao E script batem com nossa seed
  uint32_t change_index = 0;       // valido apenas se is_change
  // O output alega (via PSBT_OUT_BIP32_DERIVATION) ser troco desta sessao,
  // mas a derivacao ou o hash nao batem — deve ser exibido como destino
  // EXTERNO com um aviso destacado (secao 9 do spec), nao como troco comum.
  bool claimed_change_invalid = false;
};

struct PsbtSummary {
  int num_inputs = 0;
  int num_outputs = 0;
  uint64_t total_input_sats = 0;
  uint64_t total_output_sats = 0;
  uint64_t fee_sats = 0;
  bool high_fee_warning = false;
  OutputInfo outputs[kMaxPsbtOutputs];
};

namespace internal {

struct ByteSpan {
  size_t offset = 0;
  size_t length = 0;
};

struct ParsedTxInput {
  ByteSpan outpoint; // 36 bytes: txid(32) + vout(4), formato de wire
  ByteSpan sequence; // 4 bytes LE
};

struct ParsedTxOutput {
  uint64_t value_sats = 0;
  ByteSpan script_pubkey;
};

struct InputMeta {
  ByteSpan raw_keypairs; // bytes originais do input map p/ passthrough verbatim

  bool has_witness_utxo = false;
  uint64_t witness_value_sats = 0;
  ByteSpan witness_script_pubkey; // scriptPubKey do UTXO sendo gasto

  bool has_bip32_derivation = false;
  uint8_t claimed_pubkey[33] = {0};
  uint32_t claimed_fingerprint = 0;
  uint32_t change = 0;
  uint32_t index = 0;

  bool sighash_present = false;
  uint32_t sighash_type = 0;

  // preenchido por sign():
  bool signed_ok = false;
  uint8_t sig_pubkey[33] = {0};
  uint8_t der_sig[73] = {0}; // DER (<=72 bytes) + 1 byte de sighash type
  uint8_t der_sig_len = 0;
};

struct OutputMeta {
  ByteSpan raw_keypairs; // passthrough verbatim

  bool has_bip32_derivation = false;
  uint32_t claimed_fingerprint = 0;
  uint32_t change = 0;
  uint32_t index = 0;
};

} // namespace internal

class Psbt {
public:
  Psbt() = default;

  // Detecta o formato (binario com magic `psbt\xff` ou base64 comecando
  // com `cHNidP`), decodifica e faz o parsing estrutural completo (mapas
  // BIP174 + transacao nao assinada). Nao faz nenhuma checagem semantica
  // que dependa da sessao (isso e validate()).
  PsbtError load(const uint8_t *data, size_t len);

  // O arquivo original estava em base64 (para regravar no mesmo formato).
  bool is_base64() const { return is_base64_; }

  int num_inputs() const { return tx_input_count_; }
  int num_outputs() const { return tx_output_count_; }

  // Valida tudo que a secao 9 do spec exige contra a MasterKey/rede da
  // sessao atual: fingerprint e caminho de derivacao de cada input, tipo de
  // script (P2WPKH), sighash (so ALL), saldo de entradas >= saidas, rede
  // dos outputs legados, e deteccao/verificacao de troco. `out_summary` e
  // obrigatorio (nao pode ser nullptr) e e escrito progressivamente durante
  // a validacao — so deve ser lido pelo chamador se o retorno for
  // PsbtError::kNone.
  PsbtError validate(const MasterKey &mk, Network network,
                    PsbtSummary *out_summary);

  // Assina todos os inputs. So pode ser chamado depois de validate() ter
  // retornado kNone e do usuario ter confirmado a revisao na tela. Zera a
  // chave privada de cada input imediatamente apos assinar aquele input.
  PsbtError sign(const MasterKey &mk);

  // Serializa o PSBT assinado de volta, no MESMO formato da entrada
  // (binario ou base64), em `out` (capacidade `out_len`). Todo campo que
  // este parser nao entendia e reescrito verbatim (byte a byte, sem
  // modificacao); o unico dado novo e o PSBT_IN_PARTIAL_SIG de cada input.
  bool serialize_signed(uint8_t *out, size_t out_len,
                       size_t *out_written) const;

private:
  PsbtError parse_structure();
  PsbtError parse_unsigned_tx(internal::ByteSpan tx_span);
  PsbtError parse_input_map(int index, size_t *cursor_pos);
  PsbtError parse_output_map(int index, size_t *cursor_pos);
  PsbtError cross_check_input(int index, const MasterKey &mk);
  void fill_output_info(int index, const MasterKey &mk, Network network,
                       OutputInfo *info) const;
  bool build_sighash(int index, uint8_t digest[32]) const;

  uint8_t buf_[kMaxPsbtFileSize];
  size_t buf_len_ = 0;
  bool is_base64_ = false;
  bool loaded_ = false;
  bool validated_ = false;

  internal::ByteSpan global_raw_keypairs_;
  internal::ByteSpan version_span_;   // 4 bytes LE, dentro de buf_
  internal::ByteSpan locktime_span_;  // 4 bytes LE, dentro de buf_
  internal::ByteSpan outputs_span_;   // bloco contiguo de todos os outputs

  int tx_input_count_ = 0;
  int tx_output_count_ = 0;
  internal::ParsedTxInput tx_inputs_[kMaxPsbtInputs];
  internal::ParsedTxOutput tx_outputs_[kMaxPsbtOutputs];

  internal::InputMeta inputs_[kMaxPsbtInputs];
  internal::OutputMeta outputs_[kMaxPsbtOutputs];
};

} // namespace btcseed
