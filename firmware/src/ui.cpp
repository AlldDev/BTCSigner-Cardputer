// So compila no ambiente `cardputer`. API confirmada nos exemplos oficiais
// de m5stack/M5Cardputer (examples/Basic/keyboard/inputText,
// examples/Basic/keyboard/singlePress, examples/Basic/display) para a
// biblioteca M5Cardputer 1.1.1 — ver README.md, secao "ui.{h,cpp}", para o
// que foi e o que NAO foi verificado contra hardware real.
#include "ui.h"

#include <cstring>

#include <M5Cardputer.h>

namespace btcseed {
namespace {

constexpr int kScreenWidth = 240;
constexpr int kScreenHeight = 135;
constexpr int kLineHeightPx = 12;
constexpr int kBannerHeightPx = 12;

char g_banner[32] = {0};
bool g_has_banner = false;

uint32_t color_for_style(TextStyle style, bool *out_invert) {
  *out_invert = false;
  switch (style) {
    case TextStyle::kHighlighted:
      *out_invert = true;
      return TFT_WHITE;
    case TextStyle::kWarning:
      return TFT_RED;
    case TextStyle::kMuted:
      return TFT_DARKGREY;
    case TextStyle::kNormal:
    default:
      return TFT_WHITE;
  }
}

void draw_banner_now() {
  if (!g_has_banner) return;
  M5Cardputer.Display.fillRect(0, 0, kScreenWidth, kBannerHeightPx, TFT_RED);
  M5Cardputer.Display.setTextColor(TFT_WHITE, TFT_RED);
  M5Cardputer.Display.setCursor(2, 1);
  M5Cardputer.Display.print(g_banner);
}

} // namespace

void ui_init() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true); // true: inicializa o teclado
  M5Cardputer.Display.setRotation(1); // paisagem, teclado embaixo
  M5Cardputer.Display.setTextSize(1);
  M5Cardputer.Display.setTextColor(TFT_WHITE, TFT_BLACK);
  ui_clear();
}

void ui_update() { M5Cardputer.update(); }

bool ui_poll_key(KeyEvent *out) {
  if (out == nullptr) return false;
  *out = KeyEvent{};

  if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) {
    return false;
  }

  auto status = M5Cardputer.Keyboard.keysState();
  out->has_event = true;
  out->enter = status.enter;
  out->backspace = status.del; // essa lib so tem "del", nao "backspace"
  out->tab = status.tab;
  out->ctrl = status.ctrl;
  if (!status.word.empty()) {
    out->ch = status.word[0];
  }
  // "Esc" nao existe neste teclado: Ctrl+C e a convencao deste firmware
  // (ver KeyEvent, em ui.h, para o porque).
  for (char c : status.word) {
    if (status.ctrl && (c == 'c' || c == 'C')) {
      out->esc = true;
      break;
    }
  }
  return true;
}

void ui_set_persistent_banner(const char *text) {
  if (text == nullptr || text[0] == '\0') {
    g_has_banner = false;
    g_banner[0] = '\0';
    return;
  }
  strncpy(g_banner, text, sizeof(g_banner) - 1);
  g_banner[sizeof(g_banner) - 1] = '\0';
  g_has_banner = true;
}

void ui_clear() {
  M5Cardputer.Display.fillScreen(TFT_BLACK);
  draw_banner_now();
}

void ui_draw_line(int line, const char *text, TextStyle style) {
  if (text == nullptr || line < 0) return;

  bool invert = false;
  uint32_t fg = color_for_style(style, &invert);
  int y = (g_has_banner ? kBannerHeightPx : 0) + line * kLineHeightPx;
  if (y < 0 || y + kLineHeightPx > kScreenHeight) return; // fora da tela

  if (invert) {
    M5Cardputer.Display.fillRect(0, y, kScreenWidth, kLineHeightPx, fg);
    M5Cardputer.Display.setTextColor(TFT_BLACK, fg);
  } else {
    M5Cardputer.Display.fillRect(0, y, kScreenWidth, kLineHeightPx, TFT_BLACK);
    M5Cardputer.Display.setTextColor(fg, TFT_BLACK);
  }
  M5Cardputer.Display.setCursor(2, y + 1);
  M5Cardputer.Display.print(text);
}

int ui_width() { return kScreenWidth; }
int ui_height() { return kScreenHeight; }

int ui_max_lines() {
  int usable = kScreenHeight - (g_has_banner ? kBannerHeightPx : 0);
  return usable / kLineHeightPx;
}

} // namespace btcseed
