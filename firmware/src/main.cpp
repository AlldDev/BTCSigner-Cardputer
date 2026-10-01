// Maquina de estados das telas e loop principal (spec, secoes 6-11).
// Composicao pura dos modulos ja testados no host (session, keys,
// mnemonic_input, passphrase_input, psbt, review_screens, sd_io) com as
// primitivas de ui.cpp. Nao ha logica criptografica nem de parsing aqui —
// so orquestracao de tela/estado. O visual segue o design "Cardputer PSBT
// Signer" (claude.ai/design), aplicado ao fluxo stateless deste firmware.
//
// AVISO: este arquivo depende do hardware (Arduino/M5Cardputer) e por isso
// nao pode ser compilado nem testado no ambiente `native`. O FLUXO DE TELAS
// em si (layout, paginacao, teclas exatas) ainda nao foi validado
// visualmente num Cardputer real — ver README.md.
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
#include "rfid_io.h"
#include "rfid_seed_card.h"
#include "sd_io.h"
#include "session.h"
#include "ui.h"

extern "C" {
#include "bip39.h" // BIP39_MAX_MNEMONIC_LEN, mnemonic_clear
#include "consteq.h"
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
  kBackupOffer,            // gravar backup cifrado no cartao RFID? (opt-in)
  kBackupPassword,         // senha do cartao
  kBackupPasswordConfirm,  // mesma senha de novo
  kBackupOverwriteConfirm, // cartao ja tem dados
  kBackupResult,
  kRestorePassword, // senha do cartao lido em "Restaurar do cartao"
  kCardError,       // erro na restauracao: tela cheia, volta sozinha ao inicio
  kHome,     // carrossel de areas ASSINAR / CARTEIRA / TOOLS / SESSAO
  kMainMenu, // lista da area g_tab
  kPsbtReviewOutput,
  kPsbtReviewFee,
  kPsbtConfirm, // segurar Enter para assinar
  kPsbtDone,
  kError,
  kXpubChoice,
  kXpubExport,
  kReceiveAddressEntry,
  kReceiveAddressShow,
  kToolVerifySource, // TOOLS > Testar backup: papel 12/24 ou cartao RFID
  kToolTestPassword, // TOOLS > Testar backup: senha do cartao lido
  kToolEraseConfirm, // TOOLS > Apagar backup: segurar Enter
  kToolResult,
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
bool g_sd_ok = false;
uint32_t g_sd_last_poll_ms = 0; // deteccao de cartao inserido na lista ASSINAR

int g_word_count_choice = kMnemonicWordsLong;
Network g_network_choice = Network::kMainnet;

MnemonicInput g_mnemonic(kMnemonicWordsLong);
char g_mnemonic_text[BIP39_MAX_MNEMONIC_LEN + 1] = {0};
PassphraseInput g_passphrase;
MasterKey g_pending_mk;
uint32_t g_last_key_ms = 0; // timeout das telas pre-sessao (ver loop())

int g_correction_index = 0; // usado em kChecksumFailed

// --- backup opcional no cartao RFID ------------------------------------------
enum StartRow { kStartRow24 = 0, kStartRow12, kStartRowRestore, kStartRowCount };
int g_start_row = kStartRow24;
bool g_restore_mode = false; // seed veio do cartao (pula a oferta de backup)
PassphraseInput g_card_pw;
PassphraseInput g_card_pw_confirm;
uint8_t g_rfid_card[kMifareUsableBytes] = {0}; // blob a gravar / lido do cartao
uint8_t g_rfid_scan[kMifareUsableBytes] = {0}; // conteudo anterior do cartao
bool g_backup_ok = false;
bool g_backup_skip_armed = false; // falha: primeiro ESC so avisa, o segundo pula
char g_backup_msg[32] = {0};
uint32_t g_kdf_ms = 0; // exibido no sucesso, para calibrar kRfidPbkdf2Iterations

// Menu principal: carrossel de areas (kHome) -> lista da area (kMainMenu).
enum Tab { kTabSign = 0, kTabWallet, kTabTools, kTabSession, kTabCount };
constexpr const char *kTabLabels[kTabCount] = {"ASSINAR", "CARTEIRA", "TOOLS", "SESSAO"};
constexpr MenuIcon kTabIcons[kTabCount] = {MenuIcon::kSign, MenuIcon::kWallet, MenuIcon::kTools,
                                           MenuIcon::kSession};
enum WalletRow { kRowFingerprint = 0, kRowNetwork, kRowScript, kRowXpub, kRowReceive,
                 kWalletRowCount };
enum SessionRow { kRowAutoLock = 0, kRowEndSession, kSessionRowCount };
enum ToolsRow { kRowTestBackup = 0, kRowEraseBackup, kRowBrightness, kToolsRowCount };
enum VerifySourceRow { kVerify12 = 0, kVerify24, kVerifyCard, kVerifySourceCount };
enum XpubChoiceRow { kXpubChoiceRaw = 0, kXpubChoiceDownload, kXpubChoiceCount };
constexpr int kMenuRowH = 20;
constexpr int kMenuVisibleRows = 5;
int g_tab = kTabSign;
int g_home_from = kTabSign; // area mostrada antes da tecla: o carrossel desliza dela ate g_tab
int g_row = 0;

constexpr uint8_t kBrightnessLevels[] = {77, 128, 179, 255};
constexpr int kBrightnessPct[] = {30, 50, 70, 100};
constexpr int kBrightnessCount = 4;
int g_brightness_idx = 2; // 70%, igual ao ui_init()

PsbtFileEntry g_psbt_files[kMaxPsbtFilesListed];
int g_psbt_file_count = 0;
int g_psbt_file_selected = 0;
int g_psbt_output_index = 0;
OutputReviewText g_output_text;
FeeReviewText g_fee_text;

// Segurar Enter em kPsbtConfirm. `armed` so vira true depois que Enter foi
// solto uma vez nesta tela — o Enter que veio do resumo nao conta.
bool g_hold_armed = false;
bool g_holding = false;
uint32_t g_hold_start_ms = 0;
int g_hold_pct = 0;

char g_status_line[80] = {0}; // mensagem transitoria: some na proxima tecla
char g_signed_name[kMaxFilenameLen + 1] = {0};
bool g_xpub_saved = false;
bool g_xpub_write_attempted = false; // true so quando veio de "Baixar arquivo"
char g_error_title[32] = {0};
char g_error_msg[48] = {0};
uint32_t g_card_error_since = 0; // kCardError

// TOOLS > Testar backup: com g_verify_mode, as telas de palavras/passphrase
// (as mesmas da entrada da seed) conferem contra a sessao em vez de abrir uma.
bool g_verify_mode = false;
int g_verify_slot = -1; // copia do cartao que abriu; -1 = digitado (papel)

// TOOLS: resultado de Testar/Apagar backup.
bool g_tool_ok = false;
char g_tool_title[24] = {0};
char g_tool_msg[40] = {0};
char g_tool_msg2[42] = {0};

char g_index_entry[8] = {0}; // "Endereco de recebimento": indice digitado
int g_index_entry_len = 0;

// --- helpers -----------------------------------------------------------------

void copy_str(char *dst, size_t dst_len, const char *src) {
  strncpy(dst, src != nullptr ? src : "", dst_len - 1);
  dst[dst_len - 1] = '\0';
}

void set_status(const char *text) { copy_str(g_status_line, sizeof(g_status_line), text); }

void show_error(const char *title, const char *msg) {
  copy_str(g_error_title, sizeof(g_error_title), title);
  copy_str(g_error_msg, sizeof(g_error_msg), msg);
  g_state = State::kError;
}

// "7a3fc21e" -> "7a3f c21e"
void format_fingerprint_spaced(uint32_t fingerprint, char out[10]) {
  char fp[9];
  format_fingerprint(fingerprint, fp);
  snprintf(out, 10, "%.4s %.4s", fp, fp + 4);
}

const char *psbt_error_message(PsbtError e) {
  switch (e) {
    case PsbtError::kFingerprintMismatch: return "outra seed ou passphrase?";
    case PsbtError::kDerivationPathMismatch:
    case PsbtError::kPubkeyMismatch: return "nenhuma chave desta carteira";
    case PsbtError::kNetworkMismatch: return "rede diferente da sessao";
    case PsbtError::kAlreadyHasSignature: return "PSBT ja tem assinatura";
    case PsbtError::kUnsupportedInputScript:
    case PsbtError::kUnsupportedOutputScript: return "script nao suportado";
    case PsbtError::kUnsupportedSighash: return "sighash nao suportado";
    case PsbtError::kAmountsDontBalance: return "saidas maiores que entradas";
    case PsbtError::kTooManyInputs:
    case PsbtError::kTooManyOutputs: return "entradas/saidas demais";
    case PsbtError::kFileTooLarge: return "arquivo grande demais";
    case PsbtError::kMissingWitnessUtxo:
    case PsbtError::kMissingBip32Derivation: return "PSBT sem dados de derivacao";
    case PsbtError::kMissingNonWitnessUtxo: return "PSBT sem tx anterior (non_witness)";
    case PsbtError::kPrevTxMismatch: return "valor/script do input nao confere";
    default: return "arquivo malformado";
  }
}

int menu_row_count() {
  switch (g_tab) {
    case kTabSign: return g_psbt_file_count;
    case kTabWallet: return kWalletRowCount;
    case kTabTools: return kToolsRowCount;
    default: return kSessionRowCount;
  }
}

void wipe_seed_material() {
  g_mnemonic.wipe();
  memzero(g_mnemonic_text, sizeof(g_mnemonic_text));
  g_passphrase.wipe();
  wipe(&g_pending_mk);
  g_card_pw.wipe();
  g_card_pw_confirm.wipe();
  memzero(g_rfid_card, sizeof(g_rfid_card));
  memzero(g_rfid_scan, sizeof(g_rfid_scan));
  rfid_wipe_scratch();
  mnemonic_clear(); // buffer estatico de mnemonic_from_data() (bip39.c)
}

void go_to_start(const char *reason) {
  wipe_seed_material();
  rfid_release_card();
  g_session.end();
  set_status(reason);
  g_start_row = kStartRow24;
  g_restore_mode = false;
  g_verify_mode = false;
  g_word_count_choice = kMnemonicWordsLong;
  g_network_choice = Network::kMainnet;
  g_state = State::kSelectWordCount;
}

// Erro na restauracao pelo cartao: limpa tudo ja (nada fica na RAM enquanto a
// tela aparece) e mostra em tela cheia; loop() volta ao inicio sozinho.
void show_card_error(const char *title, const char *msg) {
  go_to_start("");
  copy_str(g_error_title, sizeof(g_error_title), title);
  copy_str(g_error_msg, sizeof(g_error_msg), msg);
  g_card_error_since = millis();
  g_state = State::kCardError;
}

// Remonta sempre: o cartao pode ter sido inserido, removido ou trocado.
void refresh_psbt_list() {
  g_sd_ok = sd_remount();
  g_psbt_file_count = g_sd_ok ? list_psbt_files(g_psbt_files, kMaxPsbtFilesListed) : 0;
  g_psbt_file_selected = 0;
  g_sd_last_poll_ms = millis();
}

void go_to_menu(int tab) {
  g_tab = tab;
  g_row = 0;
  if (tab == kTabSign) refresh_psbt_list();
  g_state = State::kMainMenu;
}

void go_to_home(int tab) {
  g_tab = tab;
  g_home_from = tab;
  g_state = State::kHome;
}

// Sai de TOOLS > Testar backup no meio: zera o que foi digitado/lido, mas a
// sessao continua.
void abort_verify() {
  wipe_seed_material();
  wipe(&g_pending_mk);
  rfid_release_card();
  g_verify_mode = false;
  g_verify_slot = -1;
  go_to_menu(kTabTools);
}

// --- render ------------------------------------------------------------------

constexpr int kContentW = kScreenW - 2 * kMargin;

void kv_line(int y, const char *label, const char *value, uint16_t value_color = color::kText) {
  ui_text(kMargin, y, label, color::kMuted, Font::kBody);
  ui_text(kScreenW - kMargin, y, value, value_color, Font::kBody, Align::kRight);
}

// Endereco completo e agrupado em kBody. Se por algum motivo nao couber ate o
// rodape, cai para kSmall (38 chars/linha): nunca corta o endereco.
int draw_address(int y, const char *grouped) {
  int end = ui_text_wrapped(kMargin, y, kContentW, grouped, color::kText, Font::kBody, false);
  Font font = end <= kBodyBottom ? Font::kBody : Font::kSmall;
  return ui_text_wrapped(kMargin, y, kContentW, grouped, color::kText, font);
}

void render_select_word_count() {
  ui_begin_screen("SEED", "^v mover", "OK escolher");
  ui_text(kMargin, 18, "COMO CARREGAR A SEED", color::kMuted);
  ui_row(28, 22, "24 palavras", "padrao", g_start_row == kStartRow24);
  ui_row(51, 22, "12 palavras", nullptr, g_start_row == kStartRow12);
  ui_row(74, 22, "Restaurar do cartao", "RFID", g_start_row == kStartRowRestore);
  if (g_status_line[0] != '\0') ui_text(kMargin, 104, g_status_line, color::kOrange);
}

void render_select_network() {
  ui_begin_screen("REDE", "ESC voltar  ^v mover", "OK escolher");
  ui_text(kMargin, 20, "REDE DESTA SESSAO", color::kMuted);
  ui_row(31, 24, "Mainnet", "bc1...", g_network_choice == Network::kMainnet);
  ui_row(57, 24, "Testnet/Signet", "tb1...", g_network_choice == Network::kTestnet);
}

void render_mnemonic_entry() {
  char title[24];
  snprintf(title, sizeof(title), "PALAVRA %d/%d", g_mnemonic.current_word_index() + 1,
           g_mnemonic.word_count());
  ui_begin_screen(title, "ESC sair DEL apagar ^v", "OK confirmar");

  int count = g_mnemonic.count_candidates();
  ui_input_box(kMargin, 18, kContentW, g_mnemonic.current_prefix(), count == 0);
  if (count == 0) {
    ui_text(kMargin, 50, "sem palavra com esse prefixo", color::kError, Font::kBody);
    return;
  }
  constexpr int kWindow = 4;
  int selected = g_mnemonic.selected_candidate_index();
  int start = selected - 1;
  if (start < 0) start = 0;
  for (int i = 0; i < kWindow && start + i < count; i++) {
    int idx = start + i;
    const char *word = g_mnemonic.nth_candidate(idx);
    ui_row(45 + i * 19, 18, word != nullptr ? word : "", nullptr, idx == selected);
  }
}

void render_checksum_failed() {
  ui_begin_screen("ERRO", "ESC recomecar  <> palavra", "OK corrigir");
  ui_icon_error(kScreenW / 2, 36);
  ui_text(kScreenW / 2, 54, "Checksum invalido", color::kText, Font::kTitle, Align::kCenter);
  char msg[32];
  snprintf(msg, sizeof(msg), "Corrigir palavra < %d >", g_correction_index + 1);
  ui_text(kScreenW / 2, 78, msg, color::kMuted, Font::kBody, Align::kCenter);
}

void render_passphrase_entry() {
  ui_begin_screen("PASSPHRASE", "ESC sair  DEL apagar", "OK continuar");
  ui_text(kMargin, 19, g_verify_mode ? "PASSPHRASE DESTA SESSAO" : "PASSPHRASE (25a PALAVRA)",
          color::kMuted, Font::kBody);
  char display[kMaxPassphraseLen + 1];
  g_passphrase.render_display(display, sizeof(display));
  bool failed = g_status_line[0] != '\0';
  ui_input_box(kMargin, 37, kContentW, display, failed);
  memzero(display, sizeof(display)); // com Tab, e a passphrase em claro
  if (failed) {
    ui_text(kMargin, 67, g_status_line, color::kError);
  } else {
    ui_text(kMargin, 67, "Pode ficar vazia. Tab mostra/oculta.", color::kMuted);
  }
  ui_text(kMargin, 79, "Fn+` digita o caractere `", color::kMuted);
}

void render_fingerprint_confirm() {
  ui_begin_screen("FINGERPRINT", "ESC nao", "OK sim");
  ui_text(kScreenW / 2, 18, "MASTER FINGERPRINT", color::kMuted, Font::kSmall, Align::kCenter);
  char fp[10];
  format_fingerprint_spaced(g_pending_mk.master_fingerprint, fp);
  ui_text(kScreenW / 2, 28, fp, color::kOrange, Font::kBig, Align::kCenter);

  char label[40];
  snprintf(label, sizeof(label), "ENDERECO #0  m/84'/%d'/0'/0/0",
           g_network_choice == Network::kMainnet ? 0 : 1);
  ui_text(kMargin, 50, label, color::kMuted);
  char addr[74];
  if (derive_address(g_pending_mk, kChangeExternal, 0, addr, sizeof(addr))) {
    char grouped[100];
    format_address_grouped(addr, grouped, sizeof(grouped));
    draw_address(60, grouped);
  } else {
    ui_text(kMargin, 60, "(falha ao derivar)", color::kError, Font::kBody);
  }
  ui_text(kScreenW / 2, 100, "Confira com o anotado / Ian Coleman", color::kMuted,
          Font::kSmall, Align::kCenter);
}

// Tela de "aguarde" desenhada antes de uma operacao bloqueante (KDF, cartao).
void render_busy(const char *title, const char *line1, const char *line2) {
  ui_begin_screen(title, nullptr, "aguarde");
  ui_text(kScreenW / 2, 48, line1, color::kText, Font::kBody, Align::kCenter);
  if (line2 != nullptr) {
    ui_text(kScreenW / 2, 72, line2, color::kMuted, Font::kSmall, Align::kCenter);
  }
}

void render_backup_offer() {
  ui_begin_screen("BACKUP RFID", "ESC pular", "OK gravar");
  ui_text(kMargin, 20, "Gravar a seed cifrada num cartao?", color::kText);
  ui_text(kMargin, 34, "MIFARE Classic via Unit RFID2.", color::kMuted);
  ui_text(kMargin, 46, "A passphrase NAO vai para o cartao.", color::kMuted);
  ui_text(kMargin, 62, "Quem copiar o cartao pode testar", color::kOrange);
  ui_text(kMargin, 74, "senhas offline: use senha longa.", color::kOrange);
  ui_text(kMargin, 90, "Nao substitui o backup em papel.", color::kMuted);
}

void render_card_password(const char *title, const char *label, const PassphraseInput &pw,
                          const char *hint) {
  ui_begin_screen(title, "ESC voltar  DEL apagar", "OK continuar");
  ui_text(kMargin, 19, label, color::kMuted, Font::kBody);
  char display[kMaxPassphraseLen + 1];
  pw.render_display(display, sizeof(display));
  bool failed = g_status_line[0] != '\0';
  ui_input_box(kMargin, 37, kContentW, display, failed);
  memzero(display, sizeof(display));
  ui_text(kMargin, 67, failed ? g_status_line : hint, failed ? color::kError : color::kMuted);
  ui_text(kMargin, 79, "Tab mostra/oculta", color::kMuted);
}

void render_backup_overwrite_confirm() {
  ui_begin_screen("CARTAO EM USO", "ESC cancelar", "OK sobrescrever");
  ui_icon_error(kScreenW / 2, 34);
  ui_text(kScreenW / 2, 52, "Este cartao ja tem dados", color::kText, Font::kBody, Align::kCenter);
  ui_text(kScreenW / 2, 74, "Gravar por cima apaga tudo nele.", color::kMuted, Font::kSmall,
          Align::kCenter);
  ui_text(kScreenW / 2, 86, "Mantenha o mesmo cartao no leitor.", color::kMuted, Font::kSmall,
          Align::kCenter);
}

void render_backup_result() {
  if (g_backup_ok) {
    ui_begin_screen("BACKUP RFID", nullptr, "OK continuar");
    ui_icon_ok(kScreenW / 2, 36);
    ui_text(kScreenW / 2, 56, "Backup gravado", color::kText, Font::kTitle, Align::kCenter);
    ui_text(kScreenW / 2, 78, "gravado e conferido no cartao", color::kMuted, Font::kSmall,
            Align::kCenter);
    ui_text(kScreenW / 2, 90, "guarde a senha e o papel", color::kMuted, Font::kSmall,
            Align::kCenter);
    char kdf[32];
    snprintf(kdf, sizeof(kdf), "KDF %lu iter: %lu ms",
             static_cast<unsigned long>(kRfidPbkdf2Iterations),
             static_cast<unsigned long>(g_kdf_ms));
    ui_text(kScreenW / 2, 104, kdf, color::kTabIdle, Font::kSmall, Align::kCenter);
  } else {
    ui_begin_screen("BACKUP RFID", g_backup_skip_armed ? "ESC de novo: sem backup" : "ESC pular",
                    "OK tentar de novo");
    ui_icon_error(kScreenW / 2, 30);
    ui_text(kScreenW / 2, 48, "Backup nao gravado", color::kText, Font::kTitle, Align::kCenter);
    ui_text(kScreenW / 2, 68, g_backup_msg, color::kMuted, Font::kBody, Align::kCenter);
    // Copia A por ultimo: interrompido, o cartao fica com o backup antigo ou o novo.
    ui_text(kScreenW / 2, 90, "O cartao ficou com o backup antigo", color::kOrange, Font::kSmall,
            Align::kCenter);
    ui_text(kScreenW / 2, 102, "ou o novo: TOOLS > Testar backup", color::kOrange, Font::kSmall,
            Align::kCenter);
  }
}

struct MenuRow {
  const char *left;
  const char *right;
  uint16_t right_color;
};

void render_menu_rows(int y0, const MenuRow *rows, int n) {
  int start = g_row >= kMenuVisibleRows ? g_row - kMenuVisibleRows + 1 : 0;
  for (int i = 0; i < kMenuVisibleRows && start + i < n; i++) {
    int idx = start + i;
    ui_row(y0 + i * kMenuRowH, kMenuRowH - 1, rows[idx].left, rows[idx].right,
           idx == g_row, rows[idx].right_color);
  }
}

// Carrossel de areas. Numa troca de area (,/) so o corpo e redesenhado e a
// faixa de icones desliza; header e rodape ja estao na tela.
void render_home() {
  if (g_home_from == g_tab) ui_begin_screen("SIGNER", "<> navegar", "OK abrir");
  ui_menu_carousel(kTabIcons, kTabLabels, kTabCount, g_tab, g_home_from);
  g_home_from = g_tab;
}

void render_main_menu() {
  const char *hint = g_tab == kTabSign ? "ESC menu ^v R atualiza" : "ESC menu  ^v mover";
  ui_begin_screen(kTabLabels[g_tab], g_status_line[0] != '\0' ? g_status_line : hint,
                  "OK abrir");
  int y0 = kBodyTop + 3;

  if (g_tab == kTabSign) {
    if (g_psbt_file_count == 0) {
      ui_text(kScreenW / 2, 42, "nenhum .psbt no cartao", color::kMuted, Font::kBody,
              Align::kCenter);
      ui_text(kScreenW / 2, 64, g_sd_ok ? "coloque em /psbt ou na raiz" : "cartao SD nao montado",
              g_sd_ok ? color::kMuted : color::kError, Font::kSmall, Align::kCenter);
      ui_text(kScreenW / 2, 76, g_sd_ok ? "R atualiza a lista" : "insira o cartao: detecta sozinho",
              color::kMuted, Font::kSmall, Align::kCenter);
      return;
    }
    MenuRow rows[kMaxPsbtFilesListed];
    for (int i = 0; i < g_psbt_file_count; i++) {
      rows[i] = {g_psbt_files[i].name, nullptr, color::kMuted};
    }
    render_menu_rows(y0, rows, g_psbt_file_count);
  } else if (g_tab == kTabWallet) {
    char fp[10];
    format_fingerprint_spaced(g_session.master_key().master_fingerprint, fp);
    const MenuRow rows[kWalletRowCount] = {
        {"Fingerprint", fp, color::kMuted},
        {"Rede", g_network_choice == Network::kTestnet ? "testnet" : "mainnet",
         g_network_choice == Network::kTestnet ? color::kError : color::kMuted},
        {"Script", "P2WPKH m/84'", color::kMuted},
        {"Exportar xpub", ">", color::kMuted},
        {"Endereco de recebimento", ">", color::kMuted},
    };
    render_menu_rows(y0, rows, kWalletRowCount);
  } else if (g_tab == kTabTools) {
    char bright[8];
    snprintf(bright, sizeof(bright), "%d%%", kBrightnessPct[g_brightness_idx]);
    const MenuRow rows[kToolsRowCount] = {
        {"Testar backup", ">", color::kMuted},
        {"Apagar backup RFID", ">", color::kError},
        {"Brilho", bright, color::kMuted},
    };
    render_menu_rows(y0, rows, kToolsRowCount);
  } else {
    char lock[12];
    snprintf(lock, sizeof(lock), "%lu min",
             static_cast<unsigned long>(kSessionTimeoutMs / 60000));
    const MenuRow rows[kSessionRowCount] = {
        {"Bloqueio auto", lock, color::kMuted},
        {"Encerrar sessao", ">", color::kError},
    };
    render_menu_rows(y0, rows, kSessionRowCount);
  }
}

void render_psbt_review_output() {
  bool last = g_psbt_output_index + 1 >= g_summary.num_outputs;
  ui_begin_screen("REVISAR", "ESC cancelar", last ? "OK resumo" : "OK proxima");

  // Linha 1: "1/2 DESTINO" etc. (o nome do arquivo fica na lista e no "Concluido").
  char head[12];
  snprintf(head, sizeof(head), "%d/%d", g_psbt_output_index + 1, g_summary.num_outputs);
  ui_text(kMargin, 18, head, color::kMuted, Font::kBody);
  int label_x = kMargin + ui_text_width(head, Font::kBody) + 8;
  if (g_output_text.claimed_change_invalid) {
    ui_text(label_x, 18, "ALEGA TROCO: NAO BATE!", color::kError, Font::kBody);
  } else if (g_output_text.is_change) {
    char label[28];
    snprintf(label, sizeof(label),
             g_output_text.change_index_high ? "TROCO #%lu ALTO!" : "TROCO #%lu verif.",
             static_cast<unsigned long>(g_output_text.change_index));
    ui_text(label_x, 18, label, g_output_text.change_index_high ? color::kError : color::kOk,
            Font::kBody);
  } else {
    ui_text(label_x, 18, "DESTINO EXTERNO", color::kText, Font::kBody);
  }

  // amount_btc = "0.01250000 BTC": numero grande + unidade menor.
  char amount[sizeof(g_output_text.amount_btc)];
  copy_str(amount, sizeof(amount), g_output_text.amount_btc);
  char *unit = strchr(amount, ' ');
  if (unit != nullptr) *unit++ = '\0';
  ui_text(kMargin, 35, amount, color::kOrange, Font::kBig);
  if (unit != nullptr) {
    ui_text(kMargin + ui_text_width(amount, Font::kBig) + 6, 37, unit, color::kText, Font::kBody);
  }
  ui_text(kMargin, 54, g_output_text.amount_sats, color::kMuted, Font::kBody);

  draw_address(72, g_output_text.address_grouped);
}

void render_psbt_review_fee() {
  ui_begin_screen("RESUMO", "ESC cancelar", "OK continuar");
  char n[8];
  snprintf(n, sizeof(n), "%d", g_summary.num_inputs);
  kv_line(19, "Entradas", n);
  snprintf(n, sizeof(n), "%d", g_summary.num_outputs);
  kv_line(37, "Saidas", n);
  uint16_t fee_color = g_fee_text.high_fee_warning ? color::kError : color::kText;
  kv_line(55, "Taxa", g_fee_text.fee_sats, fee_color);
  kv_line(73, "Taxa estimada", g_fee_text.fee_rate, fee_color);
  if (g_fee_text.high_fee_warning) {
    ui_text(kScreenW / 2, 96, "AVISO: taxa alta!", color::kError, Font::kTitle, Align::kCenter);
  }
}

void draw_hold_bar() { ui_progress(16, 74, kScreenW - 32, 18, g_hold_pct, "SEGURE ENTER"); }

void render_psbt_confirm() {
  ui_begin_screen("CONFIRMAR", "ESC voltar", "segure OK");
  ui_text(kScreenW / 2, 26, "Assinar transacao?", color::kText, Font::kTitle, Align::kCenter);
  char sub[48];
  snprintf(sub, sizeof(sub), "%d saidas - taxa %s", g_summary.num_outputs, g_fee_text.fee_sats);
  ui_text(kScreenW / 2, 48, sub, color::kMuted, Font::kBody, Align::kCenter);
  draw_hold_bar();
}

void render_signing() {
  ui_begin_screen("ASSINANDO", nullptr, "nao desligue");
  ui_text(kScreenW / 2, 50, "Assinando...", color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 74, "calculando assinaturas", color::kMuted, Font::kSmall,
          Align::kCenter);
}

void render_psbt_done() {
  ui_begin_screen("CONCLUIDO", "arquivo no SD", "OK voltar");
  ui_icon_ok(kScreenW / 2, 38);
  ui_text(kScreenW / 2, 58, "Assinado e salvo", color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 82, g_signed_name, color::kMuted, Font::kSmall, Align::kCenter);
}

void render_card_error() {
  ui_begin_screen("ERRO", nullptr, "voltando...");
  ui_icon_error(kScreenW / 2, 38);
  ui_text(kScreenW / 2, 58, g_error_title, color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 80, g_error_msg, color::kMuted, Font::kBody, Align::kCenter);
}

void render_error() {
  ui_begin_screen("ERRO", "ESC voltar", "OK voltar");
  ui_icon_error(kScreenW / 2, 38);
  ui_text(kScreenW / 2, 58, g_error_title, color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 80, g_error_msg, color::kMuted, Font::kBody, Align::kCenter);
}

void render_xpub_choice() {
  ui_begin_screen("XPUB", "ESC voltar  ^v mover", "OK escolher");
  const MenuRow rows[kXpubChoiceCount] = {
      {"Ver RAW", nullptr, color::kMuted},
      {"Baixar arquivo", nullptr, color::kMuted},
  };
  render_menu_rows(kBodyTop + 4, rows, kXpubChoiceCount);
}

void render_xpub_export() {
  ui_begin_screen("XPUB", nullptr, "OK voltar");
  int y = 18;
  if (g_xpub_write_attempted) {
    ui_text(kMargin, y, g_xpub_saved ? "Gravado em wallet_export.txt"
                                      : "Falha ao gravar (cartao ausente?)",
            g_xpub_saved ? color::kOk : color::kError);
    y += 10;
  }
  char fp[10];
  format_fingerprint_spaced(g_session.master_key().master_fingerprint, fp);
  char info[40];
  snprintf(info, sizeof(info), "fp %s  m/84'/%d'/0'", fp,
           g_network_choice == Network::kMainnet ? 0 : 1);
  ui_text(kMargin, y, info, color::kMuted);
  y += 12;
  char xpub[XPUB_MAXLEN];
  if (serialize_account_xpub(g_session.master_key(), xpub, sizeof(xpub))) {
    draw_address(y, xpub);
  }
}

void render_receive_address_entry() {
  ui_begin_screen("RECEBER", "ESC voltar  DEL apagar", "OK mostrar");
  ui_text(kMargin, 24, "INDICE DO ENDERECO (0-999)", color::kMuted);
  ui_input_box(kMargin, 36, kContentW, g_index_entry, false);
  ui_text(kMargin, 66, "vazio = indice 0", color::kMuted);
}

void render_receive_address_show() {
  uint32_t index = g_index_entry_len > 0 ? static_cast<uint32_t>(atoi(g_index_entry)) : 0;
  char title[20];
  snprintf(title, sizeof(title), "RECEBER #%lu", static_cast<unsigned long>(index));
  ui_begin_screen(title, nullptr, "OK voltar");
  char path[32];
  snprintf(path, sizeof(path), "m/84'/%d'/0'/0/%lu",
           g_network_choice == Network::kMainnet ? 0 : 1, static_cast<unsigned long>(index));
  ui_text(kMargin, 20, path, color::kMuted);

  char addr[74];
  if (derive_address(g_session.master_key(), kChangeExternal, index, addr, sizeof(addr))) {
    char grouped[100];
    format_address_grouped(addr, grouped, sizeof(grouped));
    draw_address(34, grouped);
  } else {
    ui_text(kMargin, 34, "(falha ao derivar)", color::kError, Font::kBody);
  }
}

void render_tool_verify_source() {
  ui_begin_screen("TESTAR BACKUP", "ESC voltar  ^v mover", "OK escolher");
  ui_text(kMargin, 18, "CONFERIR COM ESTA SESSAO", color::kMuted);
  const MenuRow rows[kVerifySourceCount] = {
      {"Papel: 12 palavras", nullptr, color::kMuted},
      {"Papel: 24 palavras", nullptr, color::kMuted},
      {"Cartao RFID", nullptr, color::kMuted},
  };
  render_menu_rows(28, rows, kVerifySourceCount);
  ui_text(kMargin, 108, "A passphrase e pedida no fim", color::kMuted);
}

void render_tool_erase_confirm() {
  ui_begin_screen("APAGAR BACKUP", "ESC cancelar", "segure OK");
  ui_text(kScreenW / 2, 24, "Apagar o backup do cartao?", color::kText, Font::kBody,
          Align::kCenter);
  ui_text(kScreenW / 2, 44, "Nao ha como desfazer.", color::kError, Font::kSmall,
          Align::kCenter);
  ui_text(kScreenW / 2, 56, "Mantenha o mesmo cartao no leitor.", color::kMuted, Font::kSmall,
          Align::kCenter);
  draw_hold_bar();
}

void render_tool_result() {
  ui_begin_screen("TOOLS", nullptr, "OK voltar");
  if (g_tool_ok) {
    ui_icon_ok(kScreenW / 2, 34);
  } else {
    ui_icon_error(kScreenW / 2, 34);
  }
  ui_text(kScreenW / 2, 52, g_tool_title, color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 74, g_tool_msg, color::kMuted, Font::kBody, Align::kCenter);
  ui_text(kScreenW / 2, 94, g_tool_msg2, color::kMuted, Font::kSmall, Align::kCenter);
}

HeaderNet header_net() {
  if (g_state == State::kSelectWordCount || g_state == State::kSelectNetwork ||
      g_state == State::kCardError) {
    return HeaderNet::kNone;
  }
  return g_network_choice == Network::kTestnet ? HeaderNet::kTestnet : HeaderNet::kMainnet;
}

void render() {
  ui_set_header_status(header_net(), g_sd_ok);
  switch (g_state) {
    case State::kSelectWordCount: render_select_word_count(); break;
    case State::kSelectNetwork: render_select_network(); break;
    case State::kMnemonicEntry: render_mnemonic_entry(); break;
    case State::kChecksumFailed: render_checksum_failed(); break;
    case State::kPassphraseEntry: render_passphrase_entry(); break;
    case State::kFingerprintConfirm: render_fingerprint_confirm(); break;
    case State::kBackupOffer: render_backup_offer(); break;
    case State::kBackupPassword:
      render_card_password("SENHA CARTAO", "SENHA DO CARTAO (min 12)", g_card_pw,
                           "Ideal: 4 a 6 palavras aleatorias");
      break;
    case State::kBackupPasswordConfirm:
      render_card_password("SENHA CARTAO", "REPITA A SENHA", g_card_pw_confirm,
                           "Anote: sem ela o cartao e inutil");
      break;
    case State::kBackupOverwriteConfirm: render_backup_overwrite_confirm(); break;
    case State::kBackupResult: render_backup_result(); break;
    case State::kRestorePassword:
      render_card_password("RESTAURAR", "SENHA DO CARTAO", g_card_pw,
                           "A passphrase e pedida depois");
      break;
    case State::kHome: render_home(); break;
    case State::kMainMenu: render_main_menu(); break;
    case State::kPsbtReviewOutput: render_psbt_review_output(); break;
    case State::kPsbtReviewFee: render_psbt_review_fee(); break;
    case State::kPsbtConfirm: render_psbt_confirm(); break;
    case State::kPsbtDone: render_psbt_done(); break;
    case State::kError: render_error(); break;
    case State::kCardError: render_card_error(); break;
    case State::kXpubChoice: render_xpub_choice(); break;
    case State::kXpubExport: render_xpub_export(); break;
    case State::kReceiveAddressEntry: render_receive_address_entry(); break;
    case State::kReceiveAddressShow: render_receive_address_show(); break;
    case State::kToolVerifySource: render_tool_verify_source(); break;
    case State::kToolTestPassword:
      render_card_password("TESTAR BACKUP", "SENHA DO CARTAO", g_card_pw,
                           "Depois: a passphrase desta sessao");
      break;
    case State::kToolEraseConfirm: render_tool_erase_confirm(); break;
    case State::kToolResult: render_tool_result(); break;
  }
}

void render_boot(int pct) {
  ui_progress(kScreenW / 2 - 55, 100, 110, 2, pct, nullptr);
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
    if (g_verify_mode) {
      abort_verify();
    } else {
      go_to_start("Erro interno ao montar mnemonico");
    }
    return;
  }
  g_passphrase.wipe();
  g_state = State::kPassphraseEntry;
}

void attempt_derive_and_show_fingerprint() {
  if (!derive_master_key(g_mnemonic_text, g_passphrase.value(), g_network_choice,
                         &g_pending_mk)) {
    set_status("Falha ao derivar chave");
    return;
  }
  g_state = State::kFingerprintConfirm;
}

void confirm_fingerprint_and_start_session() {
  g_session.start(&g_pending_mk); // move: g_pending_mk fica vazio depois
  wipe_seed_material();           // mnemonico e passphrase nao sao mais
                                  // necessarios: a MasterKey ja esta na sessao
  go_to_home(kTabSign);
}

// --- backup/restauracao no cartao RFID ----------------------------------------

const char *rfid_io_message(RfidIoStatus st) {
  switch (st) {
    case RfidIoStatus::kNoReader: return "Unit RFID2 nao encontrada";
    case RfidIoStatus::kNoCard: return "Nenhum cartao encostado";
    case RfidIoStatus::kUnsupportedCard: return "Nao e MIFARE Classic";
    case RfidIoStatus::kAccessDenied: return "Chave do cartao desconhecida";
    case RfidIoStatus::kVerifyFailed: return "Conferencia falhou";
    case RfidIoStatus::kCardChanged: return "Outro cartao encostado";
    default: return "Cartao afastado no meio";
  }
}

bool same_secret(const PassphraseInput &a, const char *b) {
  size_t len = static_cast<size_t>(a.length());
  return len > 0 && strlen(b) == len && consteq(a.value(), b, len);
}

void finish_backup(bool ok, const char *msg) {
  rfid_release_card();
  memzero(g_rfid_card, sizeof(g_rfid_card));
  memzero(g_rfid_scan, sizeof(g_rfid_scan));
  g_backup_ok = ok;
  g_backup_skip_armed = false;
  copy_str(g_backup_msg, sizeof(g_backup_msg), msg);
  g_state = State::kBackupResult;
}

void write_backup_to_card() {
  render_busy("GRAVANDO", "Nao afaste o cartao", nullptr);
  RfidIoStatus st = rfid_write_all(g_rfid_card);
  if (st == RfidIoStatus::kOk) st = rfid_verify(g_rfid_card);
  finish_backup(st == RfidIoStatus::kOk, st == RfidIoStatus::kOk ? "" : rfid_io_message(st));
}

// Cifra primeiro (a senha sai da RAM antes de tocar no cartao), depois grava.
void start_backup() {
  render_busy("CIFRANDO", "Derivando chave da senha", "leva alguns segundos");
  uint32_t t0 = millis();
  bool encoded = rfid_encode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()),
                                    g_mnemonic_text, kRfidPbkdf2Iterations, g_rfid_card);
  g_kdf_ms = millis() - t0;
  g_card_pw.wipe();
  g_card_pw_confirm.wipe();
  if (!encoded) {
    finish_backup(false, "Falha ao cifrar");
    return;
  }
  RfidIoStatus st = rfid_init();
  if (st == RfidIoStatus::kOk) {
    render_busy("CARTAO", "Encoste o cartao no leitor", "Unit RFID2 no Grove");
    st = rfid_wait_for_card(kRfidCardWaitTimeoutMs);
  }
  if (st == RfidIoStatus::kOk) st = rfid_read_all(g_rfid_scan);
  if (st != RfidIoStatus::kOk) {
    finish_backup(false, rfid_io_message(st));
    return;
  }
  bool blank = rfid_card_is_blank(g_rfid_scan);
  memzero(g_rfid_scan, sizeof(g_rfid_scan));
  if (!blank) {
    // Antena desligada enquanto o usuario decide; a gravacao reseleciona o
    // cartao e exige o mesmo UID.
    rfid_release_card();
    g_state = State::kBackupOverwriteConfirm;
    return;
  }
  write_backup_to_card();
}

void start_restore() {
  RfidIoStatus st = rfid_init();
  if (st == RfidIoStatus::kOk) {
    render_busy("CARTAO", "Encoste o cartao no leitor", "Unit RFID2 no Grove");
    st = rfid_wait_for_card(kRfidCardWaitTimeoutMs);
  }
  if (st == RfidIoStatus::kOk) st = rfid_read_all(g_rfid_card);
  rfid_release_card();
  if (st != RfidIoStatus::kOk) {
    show_card_error("FALHA NA LEITURA", rfid_io_message(st));
    return;
  }
  if (rfid_card_is_blank(g_rfid_card)) {
    show_card_error("SEM BACKUP", "Cartao vazio, nada gravado");
    return;
  }
  g_card_pw.wipe();
  g_state = State::kRestorePassword;
}

void attempt_restore_decode() {
  render_busy("DECIFRANDO", "Derivando chave da senha", "senha errada leva o dobro (2 copias)");
  RfidCardStatus st = rfid_decode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()),
                                         g_rfid_card, kRfidPbkdf2Iterations, g_mnemonic_text,
                                         sizeof(g_mnemonic_text));
  g_card_pw.wipe();
  switch (st) {
    case RfidCardStatus::kOk:
      memzero(g_rfid_card, sizeof(g_rfid_card));
      g_passphrase.wipe();
      g_state = State::kPassphraseEntry; // mesmo caminho da digitacao a partir daqui
      break;
    case RfidCardStatus::kAuthFailed:
      // Indistinguiveis por design: senha errada, as duas copias danificadas,
      // cartao de outro formato/versao de kRfidPbkdf2Iterations.
      set_status("Senha errada ou backup incompleto");
      break;
    default:
      show_card_error("CORROMPIDO", "Conteudo do cartao invalido");
      break;
  }
}

// Tecla em uma tela de senha do cartao. Retorna true se foi Enter.
bool edit_card_password(PassphraseInput *pw, const KeyEvent &key) {
  if (key.tab) {
    pw->toggle_visibility();
  } else if (key.backspace) {
    pw->backspace();
  } else if (key.enter) {
    return true;
  } else if (key.ch != 0) {
    pw->add_char(key.ch);
  }
  return false;
}

// --- TOOLS: testar / apagar o backup no cartao ---------------------------------

void show_tool_result(bool ok, const char *title, const char *msg, const char *msg2) {
  rfid_release_card();
  memzero(g_rfid_card, sizeof(g_rfid_card));
  memzero(g_rfid_scan, sizeof(g_rfid_scan));
  g_card_pw.wipe();
  g_verify_mode = false;
  g_verify_slot = -1;
  g_tool_ok = ok;
  copy_str(g_tool_title, sizeof(g_tool_title), title);
  copy_str(g_tool_msg, sizeof(g_tool_msg), msg);
  copy_str(g_tool_msg2, sizeof(g_tool_msg2), msg2);
  g_state = State::kToolResult;
}

// Le o cartao inteiro em `out`. Mostra o erro e retorna false se falhar ou se
// o cartao estiver vazio. O cartao continua selecionado (para apagar).
bool tool_read_card(uint8_t out[kMifareUsableBytes]) {
  RfidIoStatus st = rfid_init();
  if (st == RfidIoStatus::kOk) {
    render_busy("CARTAO", "Encoste o cartao no leitor", "Unit RFID2 no Grove");
    st = rfid_wait_for_card(kRfidCardWaitTimeoutMs);
  }
  if (st == RfidIoStatus::kOk) st = rfid_read_all(out);
  if (st != RfidIoStatus::kOk) {
    show_tool_result(false, "Falha na leitura", rfid_io_message(st), "");
    return false;
  }
  if (rfid_card_is_blank(out)) {
    show_tool_result(false, "Sem backup", "Cartao vazio", "nada gravado nele");
    return false;
  }
  return true;
}

void start_tool_test() {
  if (!tool_read_card(g_rfid_card)) return;
  rfid_release_card();
  g_card_pw.wipe();
  g_verify_mode = true;
  g_verify_slot = -1;
  g_state = State::kToolTestPassword;
}

void start_tool_verify_paper(int words) {
  wipe_seed_material();
  g_verify_mode = true;
  g_verify_slot = -1;
  g_word_count_choice = words;
  enter_mnemonic_entry();
}

// Decifra o cartao; o mnemonico fica em g_mnemonic_text (nunca desenhado) ate
// a passphrase ser digitada e verify_against_session() conferir e zerar tudo.
void attempt_tool_test_decode() {
  render_busy("DECIFRANDO", "Derivando chave da senha", "senha errada leva o dobro (2 copias)");
  int slot = -1;
  RfidCardStatus st = rfid_decode_backup(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()),
                                         g_rfid_card, kRfidPbkdf2Iterations, g_mnemonic_text,
                                         sizeof(g_mnemonic_text), &slot);
  g_card_pw.wipe();
  if (st == RfidCardStatus::kAuthFailed) {
    set_status("Senha errada ou cartao danificado"); // cartao continua lido: tentar de novo
    return;
  }
  memzero(g_rfid_card, sizeof(g_rfid_card));
  if (st != RfidCardStatus::kOk) {
    g_verify_mode = false;
    show_tool_result(false, "Corrompido", "Conteudo do cartao invalido", "");
    return;
  }
  g_verify_slot = slot;
  g_passphrase.wipe();
  g_state = State::kPassphraseEntry; // g_verify_mode: Enter -> verify_against_session()
}

// Deriva a chave do backup (papel ou cartao) + passphrase e compara com a da
// sessao. Tudo, menos a sessao, e zerado antes do resultado aparecer.
void verify_against_session() {
  render_busy("CONFERINDO", "Derivando a chave", "comparando com a sessao");
  bool derived = derive_master_key(g_mnemonic_text, g_passphrase.value(), g_network_choice,
                                   &g_pending_mk);
  bool match = derived && same_account(g_pending_mk, g_session.master_key());
  char fp[10] = {0};
  if (derived) format_fingerprint_spaced(g_pending_mk.master_fingerprint, fp);
  int slot = g_verify_slot;
  wipe(&g_pending_mk);
  wipe_seed_material();
  g_verify_mode = false;
  g_verify_slot = -1;

  char msg[40];
  if (!derived) {
    show_tool_result(false, "Falha", "Falha ao derivar chave", "");
  } else if (match) {
    snprintf(msg, sizeof(msg), "fp %s", fp);
    const char *source = slot < 0    ? "backup em papel + passphrase"
                         : slot == 0 ? "cartao (copia A) + passphrase"
                                     : "copia A danificada: grave de novo";
    show_tool_result(true, "Confere com a sessao", msg, source);
  } else {
    snprintf(msg, sizeof(msg), "fp digitado %s", fp);
    show_tool_result(false, "NAO confere", msg, "palavras ou passphrase diferentes");
  }
}

void start_tool_erase() {
  if (!tool_read_card(g_rfid_scan)) return;
  memzero(g_rfid_scan, sizeof(g_rfid_scan));
  // Antena desligada enquanto o usuario decide; a gravacao reseleciona e
  // exige o mesmo UID.
  rfid_release_card();
  g_hold_armed = false;
  g_holding = false;
  g_hold_pct = 0;
  g_state = State::kToolEraseConfirm;
}

// Sem senha de proposito: o cartao usa a chave de fabrica, qualquer app NFC ja
// consegue apaga-lo, e exigir a senha impediria apagar um backup esquecido.
void erase_card_backup() {
  render_busy("APAGANDO", "Nao afaste o cartao", nullptr);
  rfid_blank_image(g_rfid_card);
  RfidIoStatus st = rfid_write_all(g_rfid_card);
  if (st == RfidIoStatus::kOk) st = rfid_verify(g_rfid_card);
  if (st == RfidIoStatus::kOk) {
    show_tool_result(true, "Backup apagado", "Cartao zerado e conferido", "");
  } else {
    // A copia A e zerada por ultimo: interrompido, o backup pode continuar la.
    show_tool_result(false, "Nao apagado", rfid_io_message(st), "o backup pode continuar no cartao");
  }
}

void start_psbt_review() {
  size_t len = 0;
  if (!read_psbt_file(g_psbt_files[g_psbt_file_selected].name, g_psbt_io_buf,
                      sizeof(g_psbt_io_buf), &len)) {
    show_error("Falha ao ler", "erro lendo o arquivo do SD");
    return;
  }
  PsbtError err = g_psbt.load(g_psbt_io_buf, len);
  if (err != PsbtError::kNone) {
    show_error("PSBT invalida", psbt_error_message(err));
    return;
  }
  err = g_psbt.validate(g_session.master_key(), g_network_choice, &g_summary);
  if (err != PsbtError::kNone) {
    show_error("PSBT rejeitada", psbt_error_message(err));
    return;
  }
  g_psbt_output_index = 0;
  build_output_review(g_summary.outputs[0], &g_output_text);
  g_state = State::kPsbtReviewOutput;
}

void enter_psbt_confirm() {
  g_hold_armed = false;
  g_holding = false;
  g_hold_pct = 0;
  g_state = State::kPsbtConfirm;
}

// Chamado ao terminar o "segure Enter" em kPsbtConfirm: assina e grava
// direto no SD como <nome>_signed.psbt.
void sign_and_save_psbt() {
  render_signing();
  if (g_psbt.sign(g_session.master_key()) != PsbtError::kNone) {
    show_error("Falha ao assinar", "nada foi gravado no SD");
    return;
  }
  size_t written = 0;
  if (!g_psbt.serialize_signed(g_psbt_io_buf, sizeof(g_psbt_io_buf), &written)) {
    show_error("Falha ao serializar", "PSBT assinada grande demais");
    return;
  }
  if (!write_signed_psbt(g_psbt_files[g_psbt_file_selected].name, g_psbt_io_buf, written)) {
    show_error("Falha ao gravar", "cartao SD removido?");
    return;
  }
  build_signed_filename(g_psbt_files[g_psbt_file_selected].name, g_signed_name,
                        sizeof(g_signed_name));
  g_state = State::kPsbtDone;
}

void do_xpub_export_raw() {
  g_xpub_write_attempted = false;
  g_state = State::kXpubExport;
}

void do_xpub_export_download() {
  g_sd_ok = sd_remount(); // cartao pode ter sido trocado desde a ultima montagem
  char xpub[XPUB_MAXLEN];
  if (!serialize_account_xpub(g_session.master_key(), xpub, sizeof(xpub))) {
    show_error("Falha no xpub", "erro ao serializar a conta");
    return;
  }
  char fp[9];
  format_fingerprint(g_session.master_key().master_fingerprint, fp);
  char receive_desc[200];
  char change_desc[200];
  if (!build_descriptor(g_session.master_key(), kChangeExternal, receive_desc,
                        sizeof(receive_desc)) ||
      !build_descriptor(g_session.master_key(), kChangeInternal, change_desc,
                        sizeof(change_desc))) {
    show_error("Falha no xpub", "erro ao montar descriptor");
    return;
  }
  char text[768];
  snprintf(text, sizeof(text),
           "Master Fingerprint: %s\r\n"
           "Derivation Path: m/84'/%d'/0'\r\n"
           "Extended Public Key: %s\r\n"
           "Receive Descriptor: %s\r\n"
           "Change Descriptor: %s\r\n",
           fp, g_network_choice == Network::kMainnet ? 0 : 1, xpub, receive_desc, change_desc);
  g_xpub_saved = write_text_file(kXpubExportFile, text);
  g_xpub_write_attempted = true;
  g_state = State::kXpubExport;
}

void activate_menu_row() {
  switch (g_tab) {
    case kTabSign:
      if (g_psbt_file_count > 0) {
        g_psbt_file_selected = g_row;
        start_psbt_review();
      }
      break;
    case kTabWallet:
      if (g_row == kRowXpub) {
        g_row = 0;
        g_state = State::kXpubChoice;
      } else if (g_row == kRowReceive) {
        g_index_entry[0] = '\0';
        g_index_entry_len = 0;
        g_state = State::kReceiveAddressEntry;
      }
      break;
    case kTabSession:
      if (g_row == kRowEndSession) go_to_start("Sessao encerrada");
      break;
    case kTabTools:
      if (g_row == kRowTestBackup) {
        g_row = 0;
        g_state = State::kToolVerifySource;
      } else if (g_row == kRowEraseBackup) {
        start_tool_erase();
      } else if (g_row == kRowBrightness) {
        g_brightness_idx = (g_brightness_idx + 1) % kBrightnessCount;
        ui_set_brightness(kBrightnessLevels[g_brightness_idx]);
      }
      break;
  }
}

// Chamado a cada iteracao do loop em kPsbtConfirm/kToolEraseConfirm. Retorna
// true se concluiu (assinou ou apagou; a tela ja mudou e precisa de render()).
bool update_hold() {
  if (!ui_enter_held()) {
    g_hold_armed = true;
    if (g_holding) {
      g_holding = false;
      g_hold_pct = 0;
      draw_hold_bar();
    }
    return false;
  }
  if (!g_hold_armed) return false;

  uint32_t now = millis();
  if (!g_holding) {
    g_holding = true;
    g_hold_start_ms = now;
  }
  g_session.touch();
  int pct = static_cast<int>((now - g_hold_start_ms) * 100 / kHoldToSignMs);
  if (pct > 100) pct = 100;
  if (pct != g_hold_pct) {
    g_hold_pct = pct;
    draw_hold_bar();
  }
  if (pct < 100) return false;
  g_holding = false;
  g_hold_armed = false;
  if (g_state == State::kToolEraseConfirm) {
    erase_card_backup();
  } else {
    sign_and_save_psbt();
  }
  return true;
}

// --- entrada de teclado por estado -------------------------------------------

void handle_key(const KeyEvent &key) {
  set_status("");
  switch (g_state) {
    case State::kSelectWordCount:
      if (key.ch == kKeyUp) {
        g_start_row = (g_start_row + kStartRowCount - 1) % kStartRowCount;
      } else if (key.ch == kKeyDown) {
        g_start_row = (g_start_row + 1) % kStartRowCount;
      } else if (key.enter) {
        g_restore_mode = g_start_row == kStartRowRestore;
        g_word_count_choice =
            g_start_row == kStartRow12 ? kMnemonicWordsShort : kMnemonicWordsLong;
        g_state = State::kSelectNetwork;
      }
      break;

    case State::kSelectNetwork:
      if ((key.ch == kKeyUp) || (key.ch == kKeyDown)) {
        g_network_choice = (g_network_choice == Network::kMainnet) ? Network::kTestnet
                                                                   : Network::kMainnet;
      } else if (key.enter) {
        if (g_restore_mode) {
          start_restore();
        } else {
          enter_mnemonic_entry();
        }
      } else if (key.esc) {
        g_restore_mode = false;
        g_state = State::kSelectWordCount;
      }
      break;

    case State::kMnemonicEntry: {
      if (key.esc) {
        if (g_verify_mode) {
          abort_verify();
        } else {
          go_to_start("");
        }
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
        if (g_verify_mode) {
          abort_verify();
        } else {
          go_to_start("");
        }
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
        if (g_verify_mode) {
          abort_verify();
        } else {
          go_to_start("");
        }
      } else if (key.tab) {
        g_passphrase.toggle_visibility();
      } else if (key.backspace) {
        g_passphrase.backspace();
      } else if (key.enter) {
        if (g_verify_mode) {
          verify_against_session();
        } else {
          attempt_derive_and_show_fingerprint();
        }
      } else if (key.ch != 0) {
        g_passphrase.add_char(key.ch);
      }
      break;

    case State::kFingerprintConfirm:
      if (key.enter) {
        // Unico ponto em que o mnemonico ainda esta na RAM antes do wipe.
        if (g_restore_mode) {
          confirm_fingerprint_and_start_session();
        } else {
          g_state = State::kBackupOffer;
        }
      } else if (key.esc) {
        wipe(&g_pending_mk);
        g_passphrase.wipe();
        g_state = State::kPassphraseEntry;
      }
      break;

    case State::kBackupOffer:
      if (key.enter) {
        g_card_pw.wipe();
        g_card_pw_confirm.wipe();
        g_state = State::kBackupPassword;
      } else if (key.esc) {
        confirm_fingerprint_and_start_session(); // comportamento sem backup
      }
      break;

    case State::kBackupPassword:
      if (key.esc) {
        g_card_pw.wipe();
        g_state = State::kBackupOffer;
      } else if (edit_card_password(&g_card_pw, key)) {
        RfidPasswordIssue issue =
            rfid_check_password(g_card_pw.value(), static_cast<size_t>(g_card_pw.length()));
        if (issue == RfidPasswordIssue::kTooShort) {
          set_status("Curta demais: minimo 12 caracteres");
        } else if (issue == RfidPasswordIssue::kOnlyDigits) {
          set_status("So digitos cai rapido: use palavras");
        } else if (issue == RfidPasswordIssue::kTooFewDistinct) {
          set_status("Repetitiva demais: use palavras");
        } else if (same_secret(g_card_pw, g_passphrase.value())) {
          set_status("Nao use a mesma senha da passphrase");
        } else {
          g_card_pw_confirm.wipe();
          g_state = State::kBackupPasswordConfirm;
        }
      }
      break;

    case State::kBackupPasswordConfirm:
      if (key.esc) {
        g_card_pw.wipe();
        g_card_pw_confirm.wipe();
        g_state = State::kBackupPassword;
      } else if (edit_card_password(&g_card_pw_confirm, key)) {
        if (same_secret(g_card_pw_confirm, g_card_pw.value())) {
          start_backup();
        } else {
          g_card_pw.wipe();
          g_card_pw_confirm.wipe();
          g_state = State::kBackupPassword;
          set_status("Senhas diferentes, digite de novo");
        }
      }
      break;

    case State::kBackupOverwriteConfirm:
      if (key.enter) {
        write_backup_to_card();
      } else if (key.esc) {
        finish_backup(false, "Gravacao cancelada");
      }
      break;

    case State::kBackupResult:
      if (key.enter && !g_backup_ok) {
        g_state = State::kBackupPassword; // nova tentativa: senha digitada de novo
      } else if (key.esc && !g_backup_ok && !g_backup_skip_armed) {
        g_backup_skip_armed = true; // depois de seguir, o mnemonico sai da RAM
      } else if (key.enter || key.esc) {
        confirm_fingerprint_and_start_session();
      }
      break;

    case State::kRestorePassword:
      if (key.esc) {
        go_to_start("Restauracao cancelada");
      } else if (edit_card_password(&g_card_pw, key) && g_card_pw.length() > 0) {
        attempt_restore_decode();
      }
      break;

    case State::kHome:
      if (key.ch == kKeyLeft || key.ch == kKeyRight) {
        g_home_from = g_tab;
        g_tab = (g_tab + (key.ch == kKeyRight ? 1 : kTabCount - 1)) % kTabCount;
      } else if (key.enter) {
        go_to_menu(g_tab);
      }
      break;

    case State::kMainMenu: {
      int n = menu_row_count();
      if (key.esc) {
        go_to_home(g_tab);
      } else if (key.ch == kKeyUp && n > 0) {
        g_row = (g_row + n - 1) % n;
      } else if (key.ch == kKeyDown && n > 0) {
        g_row = (g_row + 1) % n;
      } else if ((key.ch == 'r' || key.ch == 'R') && g_tab == kTabSign) {
        refresh_psbt_list();
        g_row = 0;
        set_status(g_sd_ok ? "Cartao SD atualizado" : "Cartao SD nao encontrado");
      } else if (key.enter) {
        activate_menu_row();
      }
      break;
    }

    case State::kPsbtReviewOutput:
      if (key.esc) {
        go_to_menu(kTabSign);
        set_status("Cancelado pelo usuario");
      } else if (key.enter) {
        g_psbt_output_index++;
        if (g_psbt_output_index >= g_summary.num_outputs) {
          build_fee_review(g_summary, &g_fee_text);
          g_state = State::kPsbtReviewFee;
        } else {
          build_output_review(g_summary.outputs[g_psbt_output_index], &g_output_text);
        }
      }
      break;

    case State::kPsbtReviewFee:
      if (key.esc) {
        go_to_menu(kTabSign);
        set_status("Cancelado pelo usuario");
      } else if (key.enter) {
        enter_psbt_confirm();
      }
      break;

    case State::kPsbtConfirm:
      // Enter e tratado por update_hold() no loop (precisa do estado "segurado").
      if (key.esc) g_state = State::kPsbtReviewFee;
      break;

    case State::kCardError:
      if (key.enter || key.esc) go_to_start("");
      break;

    case State::kPsbtDone:
    case State::kError:
      if (key.enter || key.esc) go_to_menu(kTabSign);
      break;

    case State::kXpubChoice:
      if (key.esc) {
        go_to_menu(kTabWallet);
      } else if (key.ch == kKeyUp) {
        g_row = (g_row + kXpubChoiceCount - 1) % kXpubChoiceCount;
      } else if (key.ch == kKeyDown) {
        g_row = (g_row + 1) % kXpubChoiceCount;
      } else if (key.enter) {
        switch (g_row) {
          case kXpubChoiceRaw: do_xpub_export_raw(); break;
          case kXpubChoiceDownload: do_xpub_export_download(); break;
        }
      }
      break;

    case State::kXpubExport:
      if (key.enter || key.esc) g_state = State::kXpubChoice;
      break;

    case State::kReceiveAddressEntry:
      if (key.esc) {
        go_to_menu(kTabWallet);
      } else if (key.backspace) {
        if (g_index_entry_len > 0) g_index_entry[--g_index_entry_len] = '\0';
      } else if (key.enter) {
        g_state = State::kReceiveAddressShow;
      } else if (key.ch >= '0' && key.ch <= '9' &&
                 static_cast<size_t>(g_index_entry_len) + 1 < sizeof(g_index_entry)) {
        g_index_entry[g_index_entry_len++] = key.ch;
        g_index_entry[g_index_entry_len] = '\0';
      }
      break;

    case State::kReceiveAddressShow:
      if (key.enter || key.esc) go_to_menu(kTabWallet);
      break;

    case State::kToolVerifySource:
      if (key.esc) {
        go_to_menu(kTabTools);
      } else if (key.ch == kKeyUp) {
        g_row = (g_row + kVerifySourceCount - 1) % kVerifySourceCount;
      } else if (key.ch == kKeyDown) {
        g_row = (g_row + 1) % kVerifySourceCount;
      } else if (key.enter) {
        switch (g_row) {
          case kVerify12: start_tool_verify_paper(kMnemonicWordsShort); break;
          case kVerify24: start_tool_verify_paper(kMnemonicWordsLong); break;
          case kVerifyCard: start_tool_test(); break;
        }
      }
      break;

    case State::kToolTestPassword:
      if (key.esc) {
        abort_verify();
      } else if (edit_card_password(&g_card_pw, key) && g_card_pw.length() > 0) {
        attempt_tool_test_decode();
      }
      break;

    case State::kToolEraseConfirm:
      // Enter e tratado por update_hold() no loop.
      if (key.esc) go_to_menu(kTabTools);
      break;

    case State::kToolResult:
      if (key.enter || key.esc) go_to_menu(kTabTools);
      break;
  }
}

} // namespace

void setup() {
  ui_init();
  ui_clear();
  ui_logo(kScreenW / 2, 36);
  ui_text(kScreenW / 2, 66, "BTC SIGNER", color::kText, Font::kTitle, Align::kCenter);
  ui_text(kScreenW / 2, 86, "PSBT - OFFLINE - AIR-GAPPED", color::kMuted, Font::kSmall,
          Align::kCenter);
  // O splash dura kBootSplashMs no total, contando o tempo do sd_init().
  uint32_t t0 = millis();
  render_boot(0);
  g_sd_ok = sd_init(); // se falhar, so as operacoes de PSBT/export falharao depois
  for (uint32_t el = millis() - t0; el < kBootSplashMs; el = millis() - t0) {
    render_boot(static_cast<int>(el * 100 / kBootSplashMs));
    delay(40);
  }
  render_boot(100);
  render();
}

void loop() {
  ui_update();

  // Antes da sessao existir o mnemonico (e depois g_pending_mk) ja esta na
  // RAM, entao o timeout vale tambem para essas telas.
  bool pre_session = g_state == State::kMnemonicEntry ||
                     g_state == State::kChecksumFailed ||
                     g_state == State::kPassphraseEntry ||
                     g_state == State::kFingerprintConfirm ||
                     g_state == State::kBackupOffer ||
                     g_state == State::kBackupPassword ||
                     g_state == State::kBackupPasswordConfirm ||
                     g_state == State::kBackupOverwriteConfirm ||
                     g_state == State::kBackupResult ||
                     g_state == State::kRestorePassword;
  if ((pre_session && millis() - g_last_key_ms >= kSessionTimeoutMs) ||
      (g_session.is_active() && g_session.is_expired())) {
    go_to_start("Sessao encerrada por inatividade");
    render();
    return;
  }

  // So sem cartao montado: com cartao, remontar a toda hora atrapalharia a leitura.
  if (g_state == State::kMainMenu && g_tab == kTabSign && !g_sd_ok &&
      millis() - g_sd_last_poll_ms >= kSdPollMs) {
    refresh_psbt_list();
    g_row = 0;
    render();
  }

  if (g_state == State::kCardError && millis() - g_card_error_since >= kCardErrorShowMs) {
    go_to_start("");
    render();
    return;
  }

  if ((g_state == State::kPsbtConfirm || g_state == State::kToolEraseConfirm) && update_hold()) {
    render();
    return;
  }

  KeyEvent key;
  if (!ui_poll_key(&key)) return;
  g_last_key_ms = millis();
  g_session.touch();
  handle_key(key);
  render();
}
