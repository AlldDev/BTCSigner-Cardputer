// Maquina de estados das telas e loop principal (spec, secoes 6-11).
// Composicao pura dos modulos ja testados no host (session, keys,
// mnemonic_input, passphrase_input, psbt, review_screens, sd_io) com as
// primitivas de ui.cpp. Nao ha logica criptografica nem de parsing aqui —
// so orquestracao de tela/estado.
//
// AVISO: este arquivo depende do hardware (Arduino/M5Cardputer) e por isso
// nao pode ser compilado nem testado no ambiente `native`. Foi escrito com
// cuidado a partir dos modulos ja testados, mas o FLUXO DE TELAS em si
// (textos, paginacao, teclas exatas) ainda nao foi validado visualmente
// num Cardputer real — ver README.md.
#include <Arduino.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "config.h"
#include "keys.h"
#include "mnemonic_input.h"
#include "passphrase_input.h"
#include "psbt.h"
#include "review_screens.h"
#include "sd_io.h"
#include "session.h"
#include "ui.h"

extern "C" {
#include "bip39.h" // BIP39_MAX_MNEMONIC_LEN
#include "memzero.h"
}

using namespace btcseed;

namespace {

enum class State {
  kSelectWordCount,
  kSelectNetwork,
  kMnemonicEntry,
  kChecksumFailed,
  kPassphraseEntry,
  kFingerprintConfirm,
  kMainMenu,
  kPsbtList,
  kPsbtReviewOutput,
  kPsbtReviewFee,
  kPsbtDone,
  kXpubExport,
  kReceiveAddressEntry,
  kReceiveAddressShow,
};

// --- buffers "grandes" (nunca na stack) -------------------------------------
// Precisa caber o binario assinado (original + um PSBT_IN_PARTIAL_SIG por
// input) possivelmente codificado em base64 (~4/3 do tamanho binario).
constexpr size_t kPsbtIoBufSize =
    (kMaxPsbtFileSize + kMaxPsbtInputs * 128) * 4 / 3;
uint8_t g_psbt_io_buf[kPsbtIoBufSize];
Psbt g_psbt;
PsbtSummary g_summary;

// --- estado da sessao/telas --------------------------------------------------
uint32_t millis_fn() { return millis(); }
Session g_session(millis_fn);

State g_state = State::kSelectWordCount;

int g_word_count_choice = kMnemonicWordsLong;
Network g_network_choice = Network::kMainnet;

MnemonicInput g_mnemonic(kMnemonicWordsLong);
char g_mnemonic_text[BIP39_MAX_MNEMONIC_LEN + 1] = {0};
PassphraseInput g_passphrase;
MasterKey g_pending_mk;

int g_correction_index = 0; // usado em kChecksumFailed

int g_menu_index = 0;
constexpr const char *kMenuItems[] = {
    "Assinar PSBT",
    "Exportar xpub",
    "Ver endereco de recebimento",
    "Encerrar sessao",
};
constexpr int kMenuItemCount = 4;

PsbtFileEntry g_psbt_files[kMaxPsbtFilesListed];
int g_psbt_file_count = 0;
int g_psbt_file_selected = 0;
int g_psbt_output_index = 0;
OutputReviewText g_output_text;
FeeReviewText g_fee_text;
char g_status_line[80] = {0};

char g_index_entry[8] = {0}; // "Ver endereco de recebimento": indice digitado
int g_index_entry_len = 0;

// --- helpers de desenho ------------------------------------------------------

// Desenha `text` em uma ou mais linhas de ate `max_chars` caracteres,
// comecando em `*line` (que e incrementado a cada linha usada). ui.cpp nao
// quebra texto sozinho — telas com texto longo (enderecos) precisam disso.
void draw_wrapped(int *line, const char *text, TextStyle style = TextStyle::kNormal,
                  int max_chars = 38) {
  size_t len = strlen(text);
  size_t pos = 0;
  if (len == 0) {
    ui_draw_line((*line)++, "", style);
    return;
  }
  while (pos < len) {
    char chunk[64];
    size_t n = len - pos;
    if (n > static_cast<size_t>(max_chars)) n = static_cast<size_t>(max_chars);
    if (n >= sizeof(chunk)) n = sizeof(chunk) - 1;
    memcpy(chunk, text + pos, n);
    chunk[n] = '\0';
    ui_draw_line((*line)++, chunk, style);
    pos += n;
  }
}

void set_status(const char *text) {
  strncpy(g_status_line, text, sizeof(g_status_line) - 1);
  g_status_line[sizeof(g_status_line) - 1] = '\0';
}

void wipe_seed_material() {
  g_mnemonic.wipe();
  memzero(g_mnemonic_text, sizeof(g_mnemonic_text));
  g_passphrase.wipe();
  wipe(&g_pending_mk);
}

void go_to_start(const char *reason) {
  wipe_seed_material();
  g_session.end();
  set_status(reason != nullptr ? reason : "");
  g_word_count_choice = kMnemonicWordsLong;
  g_network_choice = Network::kMainnet;
  g_state = State::kSelectWordCount;
}

// --- render ------------------------------------------------------------------

void render();

void render_select_word_count() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "BTCSeed-Cardputer");
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Numero de palavras da seed:");
  ui_draw_line(line++,
              g_word_count_choice == kMnemonicWordsLong ? "> 24 (padrao)"
                                                        : "  24",
              g_word_count_choice == kMnemonicWordsLong ? TextStyle::kHighlighted
                                                        : TextStyle::kNormal);
  ui_draw_line(line++,
              g_word_count_choice == kMnemonicWordsShort ? "> 12" : "  12",
              g_word_count_choice == kMnemonicWordsShort ? TextStyle::kHighlighted
                                                          : TextStyle::kNormal);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Cima/Baixo: escolhe  Enter: ok", TextStyle::kMuted);
}

void render_select_network() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Rede desta sessao:");
  ui_draw_line(line++,
              g_network_choice == Network::kMainnet ? "> Mainnet" : "  Mainnet",
              g_network_choice == Network::kMainnet ? TextStyle::kHighlighted
                                                    : TextStyle::kNormal);
  ui_draw_line(line++,
              g_network_choice == Network::kTestnet ? "> Testnet/Signet"
                                                    : "  Testnet/Signet",
              g_network_choice == Network::kTestnet ? TextStyle::kHighlighted
                                                    : TextStyle::kNormal);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Cima/Baixo: escolhe  Enter: ok", TextStyle::kMuted);
}

void render_mnemonic_entry() {
  ui_clear();
  int line = 0;
  char header[32];
  snprintf(header, sizeof(header), "Palavra %d/%d",
          g_mnemonic.current_word_index() + 1, g_mnemonic.word_count());
  ui_draw_line(line++, header);

  char prefix_line[40];
  snprintf(prefix_line, sizeof(prefix_line), "> %s", g_mnemonic.current_prefix());
  ui_draw_line(line++, prefix_line);

  int count = g_mnemonic.count_candidates();
  if (count == 0) {
    ui_draw_line(line++, "(nenhuma palavra possivel)", TextStyle::kWarning);
  } else {
    int selected = g_mnemonic.selected_candidate_index();
    constexpr int kWindow = 5;
    int start = selected - 2;
    if (start < 0) start = 0;
    for (int i = 0; i < kWindow && start + i < count; i++) {
      int idx = start + i;
      const char *word = g_mnemonic.nth_candidate(idx);
      TextStyle style =
          (idx == selected) ? TextStyle::kHighlighted : TextStyle::kNormal;
      ui_draw_line(line++, word != nullptr ? word : "", style);
    }
  }
  ui_draw_line(ui_max_lines() - 1,
              "Enter=ok Bksp=apaga Setas=navega", TextStyle::kMuted);
}

void render_checksum_failed() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Checksum BIP39 invalido!", TextStyle::kWarning);
  ui_draw_line(line++, "");
  char msg[40];
  snprintf(msg, sizeof(msg), "Corrigir a partir da palavra: %d",
          g_correction_index + 1);
  ui_draw_line(line++, msg);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Esq/Dir muda, Enter corrige,", TextStyle::kMuted);
  ui_draw_line(line++, "^C recomeca do zero", TextStyle::kMuted);
}

void render_passphrase_entry() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Passphrase (25a palavra)");
  ui_draw_line(line++, "Pode ficar vazia. Enter confirma.", TextStyle::kMuted);
  ui_draw_line(line++, "");
  char display[kMaxPassphraseLen + 1];
  g_passphrase.render_display(display, sizeof(display));
  char line_buf[64];
  snprintf(line_buf, sizeof(line_buf), "> %s", display);
  ui_draw_line(line++, line_buf);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Tab: mostrar/ocultar", TextStyle::kMuted);
}

void render_fingerprint_confirm() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Confira o master fingerprint:");
  ui_draw_line(line++, "");
  char fp[9];
  format_fingerprint(g_pending_mk.master_fingerprint, fp);
  char fp_line[16];
  snprintf(fp_line, sizeof(fp_line), "  %s", fp);
  ui_draw_line(line++, fp_line, TextStyle::kHighlighted);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Bate com o anotado na geracao", TextStyle::kMuted);
  ui_draw_line(line++, "da seed? Enter=sim ^C=nao", TextStyle::kMuted);
}

void render_main_menu() {
  ui_clear();
  int line = 0;
  char fp[9];
  format_fingerprint(g_session.master_key().master_fingerprint, fp);
  char header[24];
  snprintf(header, sizeof(header), "Sessao ativa: %s", fp);
  ui_draw_line(line++, header, TextStyle::kMuted);
  ui_draw_line(line++, "");
  for (int i = 0; i < kMenuItemCount; i++) {
    char item[40];
    snprintf(item, sizeof(item), "%s%s", i == g_menu_index ? "> " : "  ",
            kMenuItems[i]);
    ui_draw_line(line++, item,
                i == g_menu_index ? TextStyle::kHighlighted : TextStyle::kNormal);
  }
  if (g_status_line[0] != '\0') {
    ui_draw_line(ui_max_lines() - 1, g_status_line, TextStyle::kMuted);
  }
}

void render_psbt_list() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Arquivos .psbt no cartao:");
  if (g_psbt_file_count == 0) {
    ui_draw_line(line++, "(nenhum encontrado)", TextStyle::kWarning);
  } else {
    for (int i = 0; i < g_psbt_file_count && line < ui_max_lines() - 1; i++) {
      char item[40];
      snprintf(item, sizeof(item), "%s%s", i == g_psbt_file_selected ? "> " : "  ",
              g_psbt_files[i].name);
      ui_draw_line(line++, item,
                  i == g_psbt_file_selected ? TextStyle::kHighlighted
                                            : TextStyle::kNormal);
    }
  }
  ui_draw_line(ui_max_lines() - 1, "Enter=abrir ^C=voltar", TextStyle::kMuted);
}

void render_psbt_review_output() {
  ui_clear();
  int line = 0;
  char header[32];
  snprintf(header, sizeof(header), "Output %d/%d", g_psbt_output_index + 1,
          g_summary.num_outputs);
  ui_draw_line(line++, header);

  if (g_output_text.claimed_change_invalid) {
    ui_draw_line(line++, "ALEGA SER TROCO MAS NAO BATE!", TextStyle::kWarning);
  } else if (g_output_text.is_change) {
    ui_draw_line(line++, "Troco (verificado)");
  } else {
    ui_draw_line(line++, "Destino externo");
  }
  draw_wrapped(&line, g_output_text.address_grouped);
  ui_draw_line(line++, g_output_text.amount_btc);
  ui_draw_line(line++, g_output_text.amount_sats, TextStyle::kMuted);

  ui_draw_line(ui_max_lines() - 1, "Enter=proximo ^C=cancelar", TextStyle::kMuted);
}

void render_psbt_review_fee() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Resumo da transacao");
  ui_draw_line(line++, "");
  char in_line[32];
  snprintf(in_line, sizeof(in_line), "Entradas: %d", g_summary.num_inputs);
  ui_draw_line(line++, in_line);
  char out_line[32];
  snprintf(out_line, sizeof(out_line), "Saidas: %d", g_summary.num_outputs);
  ui_draw_line(line++, out_line);
  ui_draw_line(line++, "");
  char fee_line[48];
  snprintf(fee_line, sizeof(fee_line), "Taxa: %s (%s)", g_fee_text.fee_sats,
          g_fee_text.fee_rate);
  ui_draw_line(line++, fee_line,
              g_fee_text.high_fee_warning ? TextStyle::kWarning : TextStyle::kNormal);
  if (g_fee_text.high_fee_warning) {
    ui_draw_line(line++, "AVISO: taxa alta!", TextStyle::kWarning);
  }
  ui_draw_line(line++, "");
  ui_draw_line(ui_max_lines() - 1, "Y/Enter=assinar ^C=cancela",
              TextStyle::kMuted);
}

void render_psbt_done() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "PSBT assinada e gravada:");
  draw_wrapped(&line, g_status_line);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Enter=voltar ao menu", TextStyle::kMuted);
}

void render_xpub_export() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, g_status_line[0] != '\0' ? g_status_line
                                                : "xpub exportado:");
  char fp[9];
  format_fingerprint(g_session.master_key().master_fingerprint, fp);
  char fp_line[16];
  snprintf(fp_line, sizeof(fp_line), "fp: %s", fp);
  ui_draw_line(line++, fp_line);

  char xpub[XPUB_MAXLEN];
  if (serialize_account_xpub(g_session.master_key(), xpub, sizeof(xpub))) {
    draw_wrapped(&line, xpub);
  }
  ui_draw_line(ui_max_lines() - 1, "Enter=voltar ao menu", TextStyle::kMuted);
}

void render_receive_address_entry() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, "Indice do endereco (0-999):");
  char idx_line[16];
  snprintf(idx_line, sizeof(idx_line), "> %s",
          g_index_entry_len > 0 ? g_index_entry : "0");
  ui_draw_line(line++, idx_line);
  ui_draw_line(line++, "");
  ui_draw_line(line++, "Digite numeros, Enter confirma", TextStyle::kMuted);
  ui_draw_line(line++, "^C volta ao menu", TextStyle::kMuted);
}

void render_receive_address_show() {
  ui_clear();
  int line = 0;
  ui_draw_line(line++, g_status_line);
  ui_draw_line(line++, "");
  uint32_t index = g_index_entry_len > 0 ? static_cast<uint32_t>(atoi(g_index_entry))
                                        : 0;
  char addr[74];
  if (derive_address(g_session.master_key(), kChangeExternal, index, addr,
                    sizeof(addr))) {
    char grouped[100];
    format_address_grouped(addr, grouped, sizeof(grouped));
    draw_wrapped(&line, grouped);
  } else {
    ui_draw_line(line++, "(falha ao derivar)", TextStyle::kWarning);
  }
  ui_draw_line(ui_max_lines() - 1, "Enter=voltar ao menu", TextStyle::kMuted);
}

void render() {
  switch (g_state) {
    case State::kSelectWordCount: render_select_word_count(); break;
    case State::kSelectNetwork: render_select_network(); break;
    case State::kMnemonicEntry: render_mnemonic_entry(); break;
    case State::kChecksumFailed: render_checksum_failed(); break;
    case State::kPassphraseEntry: render_passphrase_entry(); break;
    case State::kFingerprintConfirm: render_fingerprint_confirm(); break;
    case State::kMainMenu: render_main_menu(); break;
    case State::kPsbtList: render_psbt_list(); break;
    case State::kPsbtReviewOutput: render_psbt_review_output(); break;
    case State::kPsbtReviewFee: render_psbt_review_fee(); break;
    case State::kPsbtDone: render_psbt_done(); break;
    case State::kXpubExport: render_xpub_export(); break;
    case State::kReceiveAddressEntry: render_receive_address_entry(); break;
    case State::kReceiveAddressShow: render_receive_address_show(); break;
  }
}

// --- transicoes de estado / logica -------------------------------------------

void enter_mnemonic_entry() {
  g_mnemonic = MnemonicInput(g_word_count_choice);
  g_state = State::kMnemonicEntry;
}

void finish_mnemonic_entry() {
  if (!g_mnemonic.validate_checksum()) {
    g_correction_index = g_mnemonic.word_count() - 1;
    g_state = State::kChecksumFailed;
    return;
  }
  if (!g_mnemonic.build_mnemonic(g_mnemonic_text, sizeof(g_mnemonic_text))) {
    go_to_start("Erro interno ao montar mnemonico");
    return;
  }
  g_state = State::kPassphraseEntry;
}

void attempt_derive_and_show_fingerprint() {
  if (!derive_master_key(g_mnemonic_text, g_passphrase.value(),
                        g_network_choice, &g_pending_mk)) {
    set_status("Falha ao derivar chave");
    return;
  }
  g_state = State::kFingerprintConfirm;
}

void confirm_fingerprint_and_start_session() {
  g_session.start(&g_pending_mk); // move: g_pending_mk fica vazio depois
  wipe_seed_material();           // mnemonico e passphrase nao sao mais
                                  // necessarios: a MasterKey ja esta na sessao
  g_menu_index = 0;
  set_status("");
  g_state = State::kMainMenu;
}

void refresh_psbt_list() {
  g_psbt_file_count = list_psbt_files(g_psbt_files, kMaxPsbtFilesListed);
  g_psbt_file_selected = 0;
}

void start_psbt_review() {
  size_t len = 0;
  if (!read_psbt_file(g_psbt_files[g_psbt_file_selected].name, g_psbt_io_buf,
                      sizeof(g_psbt_io_buf), &len)) {
    set_status("Falha ao ler o arquivo");
    g_state = State::kMainMenu;
    return;
  }
  if (g_psbt.load(g_psbt_io_buf, len) != PsbtError::kNone) {
    set_status("PSBT invalida ou malformada");
    g_state = State::kMainMenu;
    return;
  }
  if (g_psbt.validate(g_session.master_key(), g_network_choice, &g_summary) !=
      PsbtError::kNone) {
    set_status("PSBT rejeitada na validacao");
    g_state = State::kMainMenu;
    return;
  }
  g_psbt_output_index = 0;
  build_output_review(g_summary.outputs[0], &g_output_text);
  g_state = State::kPsbtReviewOutput;
}

void sign_and_write_psbt() {
  if (g_psbt.sign(g_session.master_key()) != PsbtError::kNone) {
    set_status("Falha ao assinar");
    g_state = State::kMainMenu;
    return;
  }
  size_t written = 0;
  if (!g_psbt.serialize_signed(g_psbt_io_buf, sizeof(g_psbt_io_buf), &written)) {
    set_status("Falha ao serializar PSBT assinada");
    g_state = State::kMainMenu;
    return;
  }
  if (!write_signed_psbt(g_psbt_files[g_psbt_file_selected].name, g_psbt_io_buf,
                        written)) {
    set_status("Falha ao gravar no cartao (removido?)");
    g_state = State::kMainMenu;
    return;
  }
  char signed_name[kMaxFilenameLen + 1];
  build_signed_filename(g_psbt_files[g_psbt_file_selected].name, signed_name,
                        sizeof(signed_name));
  set_status(signed_name);
  g_state = State::kPsbtDone;
}

void do_xpub_export() {
  char xpub[XPUB_MAXLEN];
  if (!serialize_account_xpub(g_session.master_key(), xpub, sizeof(xpub))) {
    set_status("Falha ao gerar xpub");
    g_state = State::kMainMenu;
    return;
  }
  char fp[9];
  format_fingerprint(g_session.master_key().master_fingerprint, fp);
  char text[512];
  snprintf(text, sizeof(text),
          "Master Fingerprint: %s\r\n"
          "Derivation Path: m/84'/%d'/0'\r\n"
          "Extended Public Key: %s\r\n",
          fp, g_network_choice == Network::kMainnet ? 0 : 1, xpub);
  if (write_text_file(kXpubExportFile, text)) {
    set_status("Gravado em wallet_export.txt");
  } else {
    set_status("Falha ao gravar (cartao ausente?)");
  }
  g_state = State::kXpubExport;
}

// --- entrada de teclado por estado -------------------------------------------

void handle_key(const KeyEvent &key) {
  switch (g_state) {
    case State::kSelectWordCount:
      if ((key.ch == kKeyUp) || (key.ch == kKeyDown)) {
        g_word_count_choice = (g_word_count_choice == kMnemonicWordsLong)
                                  ? kMnemonicWordsShort
                                  : kMnemonicWordsLong;
      } else if (key.enter) {
        g_state = State::kSelectNetwork;
      }
      break;

    case State::kSelectNetwork:
      if ((key.ch == kKeyUp) || (key.ch == kKeyDown)) {
        g_network_choice = (g_network_choice == Network::kMainnet)
                              ? Network::kTestnet
                              : Network::kMainnet;
      } else if (key.enter) {
        enter_mnemonic_entry();
      } else if (key.esc) {
        g_state = State::kSelectWordCount;
      }
      break;

    case State::kMnemonicEntry: {
      if (key.esc) {
        go_to_start("");
        break;
      }
      if ((key.ch == kKeyUp) || (key.ch == kKeyLeft)) {
        g_mnemonic.prev_candidate();
      } else if ((key.ch == kKeyDown) || (key.ch == kKeyRight)) {
        g_mnemonic.next_candidate();
      } else if (key.backspace) {
        g_mnemonic.backspace();
      } else if (key.enter) {
        if (g_mnemonic.confirm_word() && g_mnemonic.is_complete()) {
          finish_mnemonic_entry();
        }
      } else if (key.ch != 0) {
        char c = key.ch;
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        g_mnemonic.try_add_letter(c);
      }
      break;
    }

    case State::kChecksumFailed:
      if (key.esc) {
        go_to_start("");
      } else if ((key.ch == kKeyLeft) && g_correction_index > 0) {
        g_correction_index--;
      } else if ((key.ch == kKeyRight) && g_correction_index < g_mnemonic.word_count() - 1) {
        g_correction_index++;
      } else if (key.enter) {
        g_mnemonic.restart_word(g_correction_index);
        g_state = State::kMnemonicEntry;
      }
      break;

    case State::kPassphraseEntry:
      if (key.esc) {
        go_to_start("");
      } else if (key.tab) {
        g_passphrase.toggle_visibility();
      } else if (key.backspace) {
        g_passphrase.backspace();
      } else if (key.enter) {
        attempt_derive_and_show_fingerprint();
      } else if (key.ch != 0) {
        g_passphrase.add_char(key.ch);
      }
      break;

    case State::kFingerprintConfirm:
      if (key.enter) {
        confirm_fingerprint_and_start_session();
      } else if (key.esc) {
        wipe(&g_pending_mk);
        g_passphrase.wipe();
        g_state = State::kPassphraseEntry;
      }
      break;

    case State::kMainMenu:
      if ((key.ch == kKeyUp)) {
        g_menu_index = (g_menu_index + kMenuItemCount - 1) % kMenuItemCount;
      } else if ((key.ch == kKeyDown)) {
        g_menu_index = (g_menu_index + 1) % kMenuItemCount;
      } else if (key.enter) {
        set_status("");
        switch (g_menu_index) {
          case 0:
            refresh_psbt_list();
            g_state = State::kPsbtList;
            break;
          case 1:
            do_xpub_export();
            break;
          case 2:
            g_index_entry[0] = '\0';
            g_index_entry_len = 0;
            g_state = State::kReceiveAddressEntry;
            break;
          case 3:
            go_to_start("Sessao encerrada");
            break;
        }
      }
      break;

    case State::kPsbtList:
      if (key.esc) {
        g_state = State::kMainMenu;
      } else if ((key.ch == kKeyUp) && g_psbt_file_count > 0) {
        g_psbt_file_selected =
            (g_psbt_file_selected + g_psbt_file_count - 1) % g_psbt_file_count;
      } else if ((key.ch == kKeyDown) && g_psbt_file_count > 0) {
        g_psbt_file_selected = (g_psbt_file_selected + 1) % g_psbt_file_count;
      } else if (key.enter && g_psbt_file_count > 0) {
        start_psbt_review();
      }
      break;

    case State::kPsbtReviewOutput:
      if (key.esc) {
        set_status("Cancelado pelo usuario");
        g_state = State::kMainMenu;
      } else if (key.enter) {
        g_psbt_output_index++;
        if (g_psbt_output_index >= g_summary.num_outputs) {
          build_fee_review(g_summary, &g_fee_text);
          g_state = State::kPsbtReviewFee;
        } else {
          build_output_review(g_summary.outputs[g_psbt_output_index],
                              &g_output_text);
        }
      }
      break;

    case State::kPsbtReviewFee:
      if (key.esc) {
        set_status("Cancelado pelo usuario");
        g_state = State::kMainMenu;
      } else if (key.enter || key.ch == 'y' || key.ch == 'Y') {
        sign_and_write_psbt();
      }
      break;

    case State::kPsbtDone:
      if (key.enter || key.esc) {
        set_status("");
        g_state = State::kMainMenu;
      }
      break;

    case State::kXpubExport:
      if (key.enter || key.esc) {
        set_status("");
        g_state = State::kMainMenu;
      }
      break;

    case State::kReceiveAddressEntry:
      if (key.esc) {
        g_state = State::kMainMenu;
      } else if (key.backspace) {
        if (g_index_entry_len > 0) g_index_entry[--g_index_entry_len] = '\0';
      } else if (key.enter) {
        g_state = State::kReceiveAddressShow;
      } else if (key.ch >= '0' && key.ch <= '9' &&
                static_cast<size_t>(g_index_entry_len) + 1 <
                    sizeof(g_index_entry)) {
        g_index_entry[g_index_entry_len++] = key.ch;
        g_index_entry[g_index_entry_len] = '\0';
      }
      break;

    case State::kReceiveAddressShow:
      if (key.enter || key.esc) {
        g_state = State::kMainMenu;
      }
      break;
  }
}

} // namespace

void setup() {
  ui_init();
  sd_init(); // se falhar, so as operacoes de PSBT/export falharao depois
  ui_set_persistent_banner(nullptr);
  render();
}

void loop() {
  ui_update();

  if (g_session.is_active() && g_session.is_expired()) {
    go_to_start("Sessao encerrada por inatividade");
    render();
    return;
  }

  KeyEvent key;
  if (!ui_poll_key(&key)) return;
  g_session.touch();

  // Faixa persistente "TESTNET": so existe depois que a rede foi escolhida.
  if (g_state != State::kSelectWordCount && g_state != State::kSelectNetwork) {
    ui_set_persistent_banner(g_network_choice == Network::kTestnet
                                ? "TESTNET/SIGNET"
                                : nullptr);
  }

  handle_key(key);
  render();
}
