#include "review_screens.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>

namespace btcseed {

bool format_address_grouped(const char *address, char *out, size_t out_len) {
  if (address == nullptr || out == nullptr) return false;
  size_t len = strlen(address);
  size_t needed = len + (len > 0 ? (len - 1) / 4 : 0) + 1;
  if (needed > out_len) return false;

  size_t o = 0;
  for (size_t i = 0; i < len; i++) {
    if (i > 0 && i % 4 == 0) out[o++] = ' ';
    out[o++] = address[i];
  }
  out[o] = '\0';
  return true;
}

bool wrap_next_line(const char *text, size_t *pos, size_t max_chars, size_t *line_start,
                    size_t *line_len) {
  if (text == nullptr || pos == nullptr || max_chars == 0) return false;
  size_t len = strlen(text);
  size_t p = *pos;
  while (p < len && text[p] == ' ') p++;
  if (p >= len) {
    *pos = len;
    return false;
  }
  size_t n = len - p;
  if (n > max_chars) {
    n = max_chars;
    size_t cut = n;
    while (cut > 0 && text[p + cut] != ' ') cut--;
    if (cut > 0) n = cut;
  }
  *line_start = p;
  *line_len = n;
  *pos = p + n;
  return true;
}

bool format_btc(uint64_t sats, char *out, size_t out_len) {
  if (out == nullptr) return false;
  uint64_t whole = sats / 100000000ull;
  uint64_t frac = sats % 100000000ull;
  int n = snprintf(out, out_len, "%" PRIu64 ".%08" PRIu64 " BTC", whole, frac);
  return n > 0 && static_cast<size_t>(n) < out_len;
}

bool format_sats(uint64_t sats, char *out, size_t out_len) {
  if (out == nullptr) return false;
  int n = snprintf(out, out_len, "%" PRIu64 " sats", sats);
  return n > 0 && static_cast<size_t>(n) < out_len;
}

namespace {

double output_vbytes(OutputScriptType type) {
  switch (type) {
    case OutputScriptType::kP2WSH: return 43.0;
    case OutputScriptType::kP2TR: return 43.0;
    case OutputScriptType::kP2PKH: return 34.0;
    case OutputScriptType::kP2SH: return 32.0;
    default: return 31.0; // P2WPKH (e kUnknown)
  }
}

} // namespace

double estimate_vbytes(const PsbtSummary &summary) {
  // Nao e um calculo exato de weight — documentado como estimativa na
  // tela (secao 9: "quando possivel, sat/vB estimado").
  double vb = 10.5 + 68.0 * summary.num_inputs;
  for (int i = 0; i < summary.num_outputs && i < kMaxPsbtOutputs; i++) {
    vb += output_vbytes(summary.outputs[i].script_type);
  }
  return vb;
}

void build_output_review(const OutputInfo &output, OutputReviewText *out) {
  if (out == nullptr) return;
  *out = OutputReviewText{};
  format_address_grouped(output.address, out->address_grouped,
                        sizeof(out->address_grouped));
  format_btc(output.amount_sats, out->amount_btc, sizeof(out->amount_btc));
  format_sats(output.amount_sats, out->amount_sats, sizeof(out->amount_sats));
  out->is_change = output.is_change;
  out->change_chain = output.change_chain;
  out->change_index = output.change_index;
  out->change_index_high = output.change_index_high;
  out->claimed_change_invalid = output.claimed_change_invalid;
}

void build_fee_review(const PsbtSummary &summary, FeeReviewText *out) {
  if (out == nullptr) return;
  *out = FeeReviewText{};
  format_sats(summary.fee_sats, out->fee_sats, sizeof(out->fee_sats));

  if (summary.num_inputs > 0 || summary.num_outputs > 0) {
    double vbytes = estimate_vbytes(summary);
    double rate = vbytes > 0 ? static_cast<double>(summary.fee_sats) / vbytes : 0.0;
    snprintf(out->fee_rate, sizeof(out->fee_rate), "~%.1f sat/vB", rate);
  }
  format_btc(summary.spend_total_sats, out->spend_total, sizeof(out->spend_total));
  // Consenso: nLockTime < 500000000 e altura de bloco; acima, timestamp unix.
  if (summary.locktime != 0) {
    snprintf(out->locktime, sizeof(out->locktime),
             summary.locktime < 500000000u ? "bloco %" PRIu32 : "unix %" PRIu32,
             summary.locktime);
  }
  out->rbf = summary.rbf;
  out->high_fee_warning = summary.high_fee_warning;
}

bool fee_review_has_details(const FeeReviewText &text) {
  return text.rbf || text.locktime[0] != '\0';
}

} // namespace btcseed
