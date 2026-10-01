// Primitivas de desenho e leitura do teclado do M5Cardputer. So isso —
// nenhuma logica de fluxo/estado das telas mora aqui (isso e main.cpp).
//
// So compila no ambiente `cardputer` (depende de M5Cardputer/M5GFX). O visual
// (paleta, header/rodape, carrossel, linhas de lista, caixa de entrada, barras,
// icones) segue o design "Bitcoin Signer IoT Interface" do claude.ai/design
// (Cardputer PSBT Signer.dc.html / Screen.dc.html), 240x135 px.
//
// Textos: so ASCII. A fonte 6x8 do M5GFX nao tem acentos nem setas.
#pragma once

#include <cstddef>
#include <cstdint>

namespace btcseed {

// Evento de teclado de uma iteracao do loop (ver ui_poll_key).
//
// A lib do Cardputer NAO expoe Esc nem setas como sinais proprios (a
// struct real so tem tab/fn/shift/ctrl/opt/alt/del/enter/space + os
// caracteres imprimiveis em `word` — confirmado lendo
// M5Cardputer/src/utility/Keyboard/Keyboard.h da versao pinada, nao supondo
// API). Duas convencoes deste firmware compensam isso:
//
//   - "Voltar/Cancelar" = tecla ESC (canto superior esquerdo, serigrafada
//     "ESC", que a lib entrega como '`'), detectada aqui para todas as
//     telas. Como '`' tambem e caractere valido de passphrase, Fn+` entrega
//     o '`' literal em `ch` em vez de Esc.
//   - "Setas" nao existem como sinal proprio: as teclas fisicas ; , . /
//     tem setas serigrafadas (uso pretendido pela propria M5Stack), mas
//     como sao caracteres imprimiveis validos (podem aparecer numa
//     passphrase), a decisao de trata-las como navegacao ou como texto
//     literal e do CHAMADOR (main.cpp), dependendo da tela atual — nunca
//     daqui.
struct KeyEvent {
  bool has_event = false; // houve alguma tecla pressionada nesta iteracao
  bool esc = false;       // tecla ESC ('`' sem Fn)
  bool enter = false;
  bool backspace = false; // "del" na API da lib (unica tecla de apagar)
  bool tab = false;
  bool ctrl = false;
  char ch = 0; // caractere imprimivel pressionado, ou 0 se nenhum
};

// Convencao deste firmware para as teclas ; , . / quando uma tela precisa
// de navegacao direcional (nunca use estes literais fora dessas telas —
// em entrada de texto livre, ch deve ser tratado como caractere normal).
constexpr char kKeyUp = ';';
constexpr char kKeyLeft = ',';
constexpr char kKeyDown = '.';
constexpr char kKeyRight = '/';

// Paleta do design, em RGB565.
namespace color {
constexpr uint16_t kOrange = 0xF483;     // #F7931A
constexpr uint16_t kBg = 0x0841;         // #0B0B0C
constexpr uint16_t kSurface = 0x1082;    // #121214
constexpr uint16_t kLine = 0x18E4;       // #1E1E22
constexpr uint16_t kText = 0xF79E;       // #F2F2F2
constexpr uint16_t kMuted = 0x8C52;      // #8A8A90
constexpr uint16_t kTabIdle = 0x6B4E;    // #6A6A70
constexpr uint16_t kOk = 0x3EF0;         // #3DDC84
constexpr uint16_t kError = 0xFA69;      // #FF4D4D
constexpr uint16_t kOnOrangeDim = 0x4940; // #4A2A05, texto secundario sobre laranja
constexpr uint16_t kDotIdle = 0x39C8;    // #3A3A40, pontinhos do carrossel
} // namespace color

enum class Font {
  kSmall, // 6x8 do M5GFX (header, rodape, rotulos secundarios)
  kBody,  // AsciiFont8x16, monoespacada (conteudo principal, enderecos)
  kBig,   // FreeMonoBold12pt7b (valor em BTC)
  kTitle, // FreeMonoBold9pt7b (titulos centrais)
};
enum class Align { kLeft, kCenter, kRight };
enum class HeaderNet { kNone, kMainnet, kTestnet };
enum class MenuIcon { kSign, kWallet, kTools, kSession };

// Geometria fixa: header 0..14, corpo kBodyTop..kBodyBottom, rodape abaixo.
constexpr int kScreenW = 240;
constexpr int kScreenH = 135;
constexpr int kBodyTop = 15;
constexpr int kBodyBottom = 122;
constexpr int kMargin = 4; // margem lateral do conteudo em kBody (29 chars/linha)

// --- ciclo de vida / teclado ---

// Inicializa M5Cardputer (tela + teclado). Chamar uma vez em setup().
void ui_init();

// Uma vez por iteracao do loop, antes de ui_poll_key()/ui_enter_held().
void ui_update();

// Preenche `out` com a tecla pressionada nesta iteracao. So reflete a borda
// de pressao (uma tecla segurada gera um evento, nao um por frame).
bool ui_poll_key(KeyEvent *out);

// Enter esta fisicamente pressionado AGORA (para "segure Enter").
bool ui_enter_held();

// 0-255.
void ui_set_brightness(uint8_t level);

// --- desenho ---

// Estado mostrado no header de toda tela com chrome. kTestnet aparece em
// vermelho e cumpre o indicador persistente de rede da secao 8 do spec.
void ui_set_header_status(HeaderNet net, bool sd_ok);

// Limpa a tela e desenha header (titulo) + rodape (dica a esquerda em cinza,
// acao a direita em laranja). nullptr = vazio.
// ponytail: redesenho direto na tela (pode piscar); trocar por um M5Canvas
// 240x135 se o flicker incomodar no hardware.
void ui_begin_screen(const char *title, const char *foot_left, const char *foot_right);

// Tela cheia sem header/rodape (boot).
void ui_clear();

void ui_fill(int x, int y, int w, int h, uint16_t c);
void ui_text(int x, int y, const char *text, uint16_t c, Font font = Font::kSmall,
             Align align = Align::kLeft);
int ui_text_width(const char *text, Font font = Font::kSmall);

// Quebra `text` em linhas de ate `w` px (wrap_next_line, preferindo espacos,
// nunca descarta caractere). Retorna o y logo abaixo da ultima linha. Com
// draw=false so mede. So kSmall/kBody (monoespacadas).
int ui_text_wrapped(int x, int y, int w, const char *text, uint16_t c,
                    Font font = Font::kSmall, bool draw = true);

// Linha de lista em kBody: fundo laranja + texto escuro quando selecionada.
void ui_row(int y, int h, const char *left, const char *right, bool selected,
            uint16_t right_color = color::kMuted);

// Carrossel infinito do menu inicial, no corpo da tela: fila de icones (o
// selecionado grande e laranja), setas, nome da area e pontinhos. Se `from`
// e vizinho de `active` (dando a volta), desliza de `from` ate `active`
// (bloqueia ~180 ms); senao desenha direto. Nao limpa header/rodape.
void ui_menu_carousel(const MenuIcon *icons, const char *const *labels, int n, int active,
                      int from);

// Caixa de entrada de 24 px com cursor em bloco. Se `text` nao cabe, mostra
// o final. Borda vermelha se `error`.
void ui_input_box(int x, int y, int w, const char *text, bool error);

// Barra de progresso 0-100. Com `label`: borda laranja e texto que inverte
// de cor na parte preenchida. Sem label: trilho cinza fino.
void ui_progress(int x, int y, int w, int h, int pct, const char *label);

void ui_icon_ok(int cx, int cy);
void ui_icon_error(int cx, int cy);
void ui_logo(int cx, int cy);

} // namespace btcseed
