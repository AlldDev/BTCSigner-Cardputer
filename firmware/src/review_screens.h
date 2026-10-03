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

// Quebra de linha para exibir texto (enderecos agrupados, xpub) na tela.
// Pega a proxima linha de `text` a partir de *pos: pula espacos iniciais,
// usa ate `max_chars`, preferindo quebrar no ultimo espaco que cabe (corte
// duro se nao houver). Avanca *pos. Retorna false quando nao ha mais texto.
// Nunca descarta caractere que nao seja espaco.
bool wrap_next_line(const char *text, size_t *pos, size_t max_chars, size_t *line_start,
                    size_t *line_len);

// "0.00050000 BTC" (8 casas decimais fixas, sempre).
bool format_btc(uint64_t sats, char *out, size_t out_len);

// "50000 sats".
bool format_sats(uint64_t sats, char *out, size_t out_len);

// Estimativa de tamanho em vbytes da transacao: ~10.5 vB fixos + ~68 vB por
// input (sempre P2WPKH, unico tipo que este firmware assina) + o tamanho de
// cada output pelo tipo de script: P2WPKH 31, P2WSH 43, P2TR 43, P2PKH 34,
// P2SH 32 (kUnknown conta como P2WPKH). E uma aproximacao documentada, comum
// entre carteiras, nao um calculo exato de weight/witness.
double estimate_vbytes(const PsbtSummary &summary);

// Texto pronto para exibir de UM output do PsbtSummary.
struct OutputReviewText {
  char address_grouped[100] = {0};
  char amount_btc[24] = {0};
  char amount_sats[24] = {0};
  bool is_change = false;
  uint32_t change_chain = 0; // 0 = endereco de recebimento proprio, 1 = troco
  uint32_t change_index = 0;
  bool change_index_high = false;
  bool claimed_change_invalid = false;
};
void build_output_review(const OutputInfo &output, OutputReviewText *out);

// Texto pronto para exibir do resumo de taxa da transacao inteira.
struct FeeReviewText {
  char fee_sats[24] = {0};
  char fee_rate[32] = {0}; // "~X.X sat/vB" ("~0.XX" abaixo de 1), vazio se num_inputs/outputs == 0
  char spend_total[24] = {0}; // "0.01260000 BTC": externos + taxa
  char locktime[32] = {0};    // "bloco 850000" / "unix 1735689600"; vazio se 0
  bool rbf = false;
  bool high_fee_warning = false;
  bool low_fee_warning = false; // taxa estimada < kMinRelayFeeRateSatPerVb
};

// A tela DETALHES (RBF/locktime) so aparece quando ha algo a mostrar.
bool fee_review_has_details(const FeeReviewText &text);
void build_fee_review(const PsbtSummary &summary, FeeReviewText *out);

} // namespace btcseed
