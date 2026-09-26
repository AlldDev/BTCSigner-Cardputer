// So compila no ambiente `cardputer`. Ver ui.h para a origem do visual.
#include "ui.h"

#include <cstring>

#include <M5Cardputer.h>

#include "review_screens.h" // wrap_next_line

namespace btcseed {
namespace {

constexpr int kHeaderH = 14;
constexpr int kFooterY = kBodyBottom; // linha divisoria do rodape
constexpr int kSmallCharW = 6;
constexpr int kSmallLineH = 10;
constexpr int kBodyCharW = 8;
constexpr int kBodyLineH = 16;

HeaderNet g_net = HeaderNet::kNone;
bool g_sd_ok = false;

M5GFX &D() { return M5Cardputer.Display; }

void set_font(Font font) {
  switch (font) {
    case Font::kBig: D().setFont(&fonts::FreeMonoBold12pt7b); break;
    case Font::kTitle: D().setFont(&fonts::FreeMonoBold9pt7b); break;
    case Font::kBody: D().setFont(&fonts::AsciiFont8x16); break;
    case Font::kSmall:
    default: D().setFont(&fonts::Font0); break;
  }
}

textdatum_t datum_for(Align align) {
  switch (align) {
    case Align::kCenter: return textdatum_t::top_center;
    case Align::kRight: return textdatum_t::top_right;
    case Align::kLeft:
    default: return textdatum_t::top_left;
  }
}

void draw_battery(int x, int y) {
  int32_t level = M5.Power.getBatteryLevel();
  if (level < 0) return; // sem leitura: nao inventa um valor
  if (level > 100) level = 100;
  D().drawRect(x, y, 14, 7, color::kMuted);
  D().fillRect(x + 14, y + 2, 1, 3, color::kMuted);
  uint16_t fill = level <= 20 ? color::kError : color::kOk;
  D().fillRect(x + 2, y + 2, (10 * level) / 100, 3, fill);
}

void draw_header(const char *title) {
  D().fillRect(0, 0, kScreenW, kHeaderH, color::kBg);
  D().fillCircle(8, 7, 3, color::kOrange);
  ui_text(15, 3, title != nullptr ? title : "", color::kText);

  int x = kScreenW - 5 - 15;
  draw_battery(x, 3);
  x -= 6;
  const char *sd = g_sd_ok ? "SD" : "SEM SD";
  x -= ui_text_width(sd);
  ui_text(x, 3, sd, g_sd_ok ? color::kMuted : color::kError);
  if (g_net != HeaderNet::kNone) {
    const char *net = g_net == HeaderNet::kTestnet ? "TESTNET" : "MAIN";
    x -= 6 + ui_text_width(net);
    ui_text(x, 3, net, g_net == HeaderNet::kTestnet ? color::kError : color::kOrange);
  }
  D().drawFastHLine(0, kHeaderH, kScreenW, color::kLine);
}

void draw_footer(const char *left, const char *right) {
  D().drawFastHLine(0, kFooterY, kScreenW, color::kLine);
  if (left != nullptr) ui_text(5, kFooterY + 3, left, color::kMuted);
  if (right != nullptr) {
    ui_text(kScreenW - 5, kFooterY + 3, right, color::kOrange, Font::kSmall,
            Align::kRight);
  }
}

} // namespace

void ui_init() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true); // true: inicializa o teclado
  D().setRotation(1);           // paisagem, teclado embaixo
  D().setTextSize(1);
  ui_set_brightness(179);       // 70%, o padrao do design
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
  // Tecla serigrafada "ESC" chega como '`'; Fn+` mantem o '`' literal.
  if (out->ch == '`' && !status.fn) {
    out->esc = true;
    out->ch = 0;
  }
  return true;
}

bool ui_enter_held() { return M5Cardputer.Keyboard.keysState().enter; }

void ui_set_brightness(uint8_t level) { D().setBrightness(level); }

void ui_set_header_status(HeaderNet net, bool sd_ok) {
  g_net = net;
  g_sd_ok = sd_ok;
}

void ui_begin_screen(const char *title, const char *foot_left, const char *foot_right) {
  D().fillScreen(color::kBg);
  draw_header(title);
  draw_footer(foot_left, foot_right);
}

void ui_clear() { D().fillScreen(color::kBg); }

void ui_fill(int x, int y, int w, int h, uint16_t c) { D().fillRect(x, y, w, h, c); }

void ui_text(int x, int y, const char *text, uint16_t c, Font font, Align align) {
  if (text == nullptr) return;
  set_font(font);
  D().setTextDatum(datum_for(align));
  D().setTextColor(c); // fundo transparente: quem chama ja pintou o fundo
  D().drawString(text, x, y);
}

int ui_text_width(const char *text, Font font) {
  if (text == nullptr) return 0;
  set_font(font);
  return D().textWidth(text);
}

int ui_text_wrapped(int x, int y, int w, const char *text, uint16_t c, Font font,
                    bool draw) {
  bool body = font == Font::kBody;
  size_t max_chars = static_cast<size_t>(w / (body ? kBodyCharW : kSmallCharW));
  int line_h = body ? kBodyLineH : kSmallLineH;
  char chunk[64];
  if (max_chars >= sizeof(chunk)) max_chars = sizeof(chunk) - 1;
  size_t pos = 0, start = 0, n = 0;
  while (wrap_next_line(text, &pos, max_chars, &start, &n)) {
    if (draw) {
      memcpy(chunk, text + start, n);
      chunk[n] = '\0';
      ui_text(x, y, chunk, c, body ? Font::kBody : Font::kSmall);
    }
    y += line_h;
  }
  return y;
}

void ui_row(int y, int h, const char *left, const char *right, bool selected,
            uint16_t right_color) {
  D().fillRoundRect(3, y, kScreenW - 6, h, 2, selected ? color::kOrange : color::kBg);
  int ty = y + (h - kBodyLineH) / 2;
  ui_text(8, ty, left, selected ? color::kBg : color::kText, Font::kBody);
  if (right != nullptr) {
    ui_text(kScreenW - 8, ty, right, selected ? color::kOnOrangeDim : right_color,
            Font::kBody, Align::kRight);
  }
}

void ui_tabs(int y, const char *const *labels, int n, int active) {
  if (n <= 0) return;
  int w = kScreenW / n;
  D().fillRect(0, y, kScreenW, kTabsH, color::kBg);
  for (int i = 0; i < n; i++) {
    bool on = i == active;
    ui_text(i * w + w / 2, y + 4, labels[i], on ? color::kOrange : color::kTabIdle,
            Font::kSmall, Align::kCenter);
    if (on) D().fillRect(i * w, y + kTabsH - 3, w, 2, color::kOrange);
  }
  D().drawFastHLine(0, y + kTabsH - 1, kScreenW, color::kLine);
}

void ui_input_box(int x, int y, int w, const char *text, bool error) {
  constexpr int kH = 24;
  D().fillRoundRect(x, y, w, kH, 3, color::kSurface);
  D().drawRoundRect(x, y, w, kH, 3, error ? color::kError : color::kOrange);
  const char *shown = text != nullptr ? text : "";
  size_t len = strlen(shown);
  size_t max_chars = static_cast<size_t>((w - 14 - kBodyCharW) / kBodyCharW);
  if (len > max_chars) shown += len - max_chars;
  ui_text(x + 7, y + 4, shown, color::kOrange, Font::kBody);
  int cursor_x = x + 7 + ui_text_width(shown, Font::kBody) + 1;
  D().fillRect(cursor_x, y + 5, kBodyCharW, 14, color::kOrange);
}

void ui_progress(int x, int y, int w, int h, int pct, const char *label) {
  if (pct < 0) pct = 0;
  if (pct > 100) pct = 100;
  int filled = (w * pct) / 100;
  if (label == nullptr) {
    D().fillRect(x, y, w, h, color::kLine);
    D().fillRect(x, y, filled, h, color::kOrange);
    return;
  }
  D().fillRect(x, y, w, h, color::kBg);
  D().fillRect(x, y, filled, h, color::kOrange);
  D().drawRoundRect(x, y, w, h, 3, color::kOrange);
  int ty = y + (h - 8) / 2;
  int cx = x + w / 2;
  if (filled < w) {
    D().setClipRect(x + filled, y, w - filled, h);
    ui_text(cx, ty, label, color::kOrange, Font::kSmall, Align::kCenter);
  }
  if (filled > 0) {
    D().setClipRect(x, y, filled, h);
    ui_text(cx, ty, label, color::kBg, Font::kSmall, Align::kCenter);
  }
  D().clearClipRect();
}

void ui_icon_ok(int cx, int cy) {
  D().fillCircle(cx, cy, 14, color::kOk);
  D().drawWideLine(cx - 6, cy + 1, cx - 2, cy + 5, 1.3f, color::kBg);
  D().drawWideLine(cx - 2, cy + 5, cx + 6, cy - 4, 1.3f, color::kBg);
}

void ui_icon_error(int cx, int cy) {
  D().fillCircle(cx, cy, 14, color::kError);
  ui_text(cx + 1, cy - 7, "!", color::kBg, Font::kTitle, Align::kCenter);
}

void ui_logo(int cx, int cy) {
  D().fillCircle(cx, cy, 23, color::kOrange);
  D().fillRect(cx - 5, cy - 18, 3, 6, TFT_WHITE);
  D().fillRect(cx + 1, cy - 18, 3, 6, TFT_WHITE);
  D().fillRect(cx - 5, cy + 12, 3, 6, TFT_WHITE);
  D().fillRect(cx + 1, cy + 12, 3, 6, TFT_WHITE);
  ui_text(cx, cy - 10, "B", TFT_WHITE, Font::kBig, Align::kCenter);
}

} // namespace btcseed
