// So compila no ambiente `cardputer`. Ver ui.h para a origem do visual.
#include "ui.h"

#include <cmath>
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

// --- carrossel do menu inicial (geometria do design, deslocada pelo header) ---
constexpr int kStripY = 21;   // faixa dos icones (desenhada num sprite)
constexpr int kStripH = 62;
constexpr int kTileW = 64;    // passo entre icones
constexpr int kCarouselLabelY = 88;
constexpr int kCarouselDotsY = 107;
constexpr uint32_t kSlideMs = 180;

// Icones do design (viewBox 24x24, traco 1.8), em escala `s` px centrada em
// (cx, cy). So primitivas do M5GFX: nao ha SVG no firmware.
struct IconPen {
  lgfx::LovyanGFX &g;
  float x0, y0, k, r;
  uint16_t c;
  float X(float x) const { return x0 + x * k; }
  float Y(float y) const { return y0 + y * k; }
  void line(float ax, float ay, float bx, float by) const {
    g.drawWideLine(X(ax), Y(ay), X(bx), Y(by), r, c);
  }
  void round_rect(float ax, float ay, float bx, float by, float rad) const {
    int x = static_cast<int>(X(ax) + 0.5f), y = static_cast<int>(Y(ay) + 0.5f);
    int w = static_cast<int>((bx - ax) * k + 0.5f), h = static_cast<int>((by - ay) * k + 0.5f);
    int rr = static_cast<int>(rad * k + 0.5f);
    g.drawRoundRect(x, y, w, h, rr, c);
    if (r >= 0.8f) g.drawRoundRect(x + 1, y + 1, w - 2, h - 2, rr > 0 ? rr - 1 : 0, c);
  }
};

void draw_menu_icon(lgfx::LovyanGFX &g, MenuIcon icon, int cx, int cy, int s, uint16_t c) {
  float k = s / 24.0f;
  IconPen p{g, cx - 12 * k, cy - 12 * k, k, 0.9f * k, c};
  switch (icon) {
    case MenuIcon::kSign: // lapis
      p.line(4, 20, 8, 20);
      p.line(8, 20, 19, 9);
      p.line(19, 9, 15, 5);
      p.line(15, 5, 4, 16);
      p.line(4, 16, 4, 20);
      p.line(13.5f, 6.5f, 17.5f, 10.5f);
      p.line(14, 20, 20, 20);
      break;
    case MenuIcon::kWallet: // carteira
      p.round_rect(3, 7, 20, 20, 2);
      p.line(3, 7, 15, 4);
      p.line(15, 4, 15, 7);
      p.line(16, 13.5f, 17, 13.5f);
      break;
    case MenuIcon::kTools: // engrenagem
      g.drawCircle(cx, cy, static_cast<int>(3 * k + 0.5f), c);
      g.drawCircle(cx, cy, static_cast<int>(3 * k + 0.5f) - 1, c);
      p.line(12, 2, 12, 5);
      p.line(12, 19, 12, 22);
      p.line(2, 12, 5, 12);
      p.line(19, 12, 22, 12);
      p.line(4.9f, 4.9f, 7, 7);
      p.line(17, 17, 19.1f, 19.1f);
      p.line(4.9f, 19.1f, 7, 17);
      p.line(17, 7, 19.1f, 4.9f);
      break;
    case MenuIcon::kSession: // cadeado
      p.round_rect(5, 11, 19, 21, 2);
      p.line(8, 11, 8, 7);
      p.line(16, 11, 16, 7);
      g.fillArc(static_cast<int>(p.X(12) + 0.5f), static_cast<int>(p.Y(7) + 0.5f),
                static_cast<int>(4 * k + p.r), static_cast<int>(4 * k - p.r), 180, 360, c);
      p.line(12, 15, 12, 17);
      break;
  }
}

// Faixa de icones em `g` (sprite ou a propria tela) com topo em `y0`. `center`
// fica no meio deslocado de `offset` px; os vizinhos se repetem dando a volta,
// entao o ultimo -> primeiro desliza como qualquer outro passo. Tamanho e cor
// de cada tile dependem da distancia ao meio, o que anima a troca de destaque.
void draw_strip(lgfx::LovyanGFX &g, int y0, const MenuIcon *icons, int n, int center,
                float offset) {
  g.fillRect(0, y0, kScreenW, kStripH, color::kBg);
  int cy = y0 + kStripH / 2;
  for (int rel = -3; rel <= 3; rel++) {
    float fx = kScreenW / 2 + rel * kTileW + offset;
    float d = fabsf(fx - kScreenW / 2) / kTileW;
    if (d > 1.0f) d = 1.0f;
    int size = static_cast<int>(54 - 14 * d + 0.5f);
    int icon = static_cast<int>(26 - 8 * d + 0.5f);
    bool on = d < 0.5f;
    int x = static_cast<int>(fx + 0.5f) - size / 2;
    if (x + size < 0 || x >= kScreenW) continue;
    int idx = ((center + rel) % n + n) % n;
    g.fillRoundRect(x, cy - size / 2, size, size, 10, on ? color::kOrange : color::kSurface);
    if (!on) g.drawRoundRect(x, cy - size / 2, size, size, 10, color::kLine);
    draw_menu_icon(g, icons[idx], x + size / 2, cy, icon, on ? color::kBg : color::kMuted);
  }
  // Setas: carrossel infinito, sempre ha vizinho dos dois lados.
  g.drawWideLine(8, cy - 4, 5, cy, 1.0f, color::kOrange);
  g.drawWideLine(5, cy, 8, cy + 4, 1.0f, color::kOrange);
  g.drawWideLine(kScreenW - 9, cy - 4, kScreenW - 6, cy, 1.0f, color::kOrange);
  g.drawWideLine(kScreenW - 6, cy, kScreenW - 9, cy + 4, 1.0f, color::kOrange);
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

void ui_menu_carousel(const MenuIcon *icons, const char *const *labels, int n, int active,
                      int from) {
  if (n <= 0) return;
  D().fillRect(0, kCarouselLabelY, kScreenW, kFooterY - kCarouselLabelY, color::kBg);
  ui_text(kScreenW / 2, kCarouselLabelY, labels[active], color::kText, Font::kTitle,
          Align::kCenter);
  int dots_w = 10 + (n - 1) * (3 + 3);
  int x = (kScreenW - dots_w) / 2;
  for (int i = 0; i < n; i++) {
    int w = i == active ? 10 : 3;
    D().fillRoundRect(x, kCarouselDotsY, w, 3, 1, i == active ? color::kOrange : color::kDotIdle);
    x += w + 3;
  }

  int dir = 0;
  if (from != active) {
    if ((from + 1) % n == active) dir = 1;
    else if ((from + n - 1) % n == active) dir = -1;
  }
  M5Canvas canvas(&D());
  canvas.setColorDepth(16);
  bool sprite = canvas.createSprite(kScreenW, kStripH) != nullptr;
  if (dir == 0) {
    if (sprite) {
      draw_strip(canvas, 0, icons, n, active, 0.0f);
      canvas.pushSprite(0, kStripY);
    } else {
      draw_strip(D(), kStripY, icons, n, active, 0.0f);
    }
  } else if (!sprite) {
    // Sem heap para o sprite: sem animacao (desenhar direto piscaria).
    draw_strip(D(), kStripY, icons, n, active, 0.0f);
  } else {
    // O deslocamento vai de 0 (centro em `from`) a 1 tile, com ease-out.
    uint32_t t0 = millis();
    for (;;) {
      uint32_t el = millis() - t0;
      float p = el >= kSlideMs ? 1.0f : static_cast<float>(el) / kSlideMs;
      float e = 1.0f - (1.0f - p) * (1.0f - p);
      draw_strip(canvas, 0, icons, n, from, -dir * e * kTileW);
      canvas.pushSprite(0, kStripY);
      if (p >= 1.0f) break;
    }
  }
  if (sprite) canvas.deleteSprite();
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
