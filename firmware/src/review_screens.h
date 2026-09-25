// Formatacao para a tela de revisao de PSBT (secao 9 do spec): quebra de
// endereco em grupos de 4 caracteres, valores em BTC/sats, taxa e aviso de
// taxa alta. So texto — nenhum desenho (isso e ui.cpp/main.cpp). Mantido
// separado de psbt.h para nao acoplar o parser a como os textos sao
// exibidos.
#pragma once

#include <cstddef>
#include <cstdint>

#include "psbt.h"

namespace btcseed {

// Insere um espaco a cada 4 caracteres de `address` (grupos de 4, secao 9:
// "endereco completo... em grupos de 4 caracteres"). `out` deve ter
// capacidade >= strlen(address) + strlen(address)/4 + 1.
bool format_address_grouped(const char *address, char *out, size_t out_len);

// "0.00050000 BTC" (8 casas decimais fixas, sempre).
bool format_btc(uint64_t sats, char *out, size_t out_len);

// "50000 sats".
bool format_sats(uint64_t sats, char *out, size_t out_len);

// Estimativa de tamanho em vbytes de uma transacao so com entradas/saidas
// P2WPKH (unica topologia que este firmware assina): ~10.5 vB fixos + ~68
// vB por input + ~31 vB por output. E uma aproximacao documentada, comum
// entre carteiras para esse caso, nao um calculo exato de weight/witness.
double estimate_vbytes(int num_inputs, int num_outputs);

// Texto pronto para exibir de UM output do PsbtSummary.
struct OutputReviewText {
  char address_grouped[100] = {0};
  char amount_btc[24] = {0};
  char amount_sats[24] = {0};
  bool is_change = false;
  bool claimed_change_invalid = false;
};
void build_output_review(const OutputInfo &output, OutputReviewText *out);

// Texto pronto para exibir do resumo de taxa da transacao inteira.
struct FeeReviewText {
  char fee_sats[24] = {0};
  char fee_rate[32] = {0}; // "~X.X sat/vB", vazio se num_inputs/outputs == 0
  bool high_fee_warning = false;
};
void build_fee_review(const PsbtSummary &summary, FeeReviewText *out);

} // namespace btcseed
