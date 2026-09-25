// Primitivas de desenho e leitura do teclado do M5Cardputer. So isso —
// nenhuma logica de fluxo/estado das telas mora aqui (isso e main.cpp).
//
// So compila no ambiente `cardputer` (depende de M5Cardputer/M5GFX). API
// baseada nos exemplos oficiais de M5Cardputer 1.1.1 (M5Cardputer.begin,
// M5Cardputer.Keyboard.{isChange,isPressed,keysState}, M5Cardputer.Display).
// Ainda NAO compilado contra o hardware real nesta sessao — ver README.md.
#pragma once

#include <cstddef>

namespace btcseed {

// Evento de teclado de uma iteracao do loop (ver ui_poll_key).
//
// O teclado fisico do Cardputer NAO TEM tecla Esc nem setas dedicadas (a
// struct real da lib so expoe tab/fn/shift/ctrl/opt/alt/del/enter/space +
// os caracteres imprimiveis em `word` — confirmado lendo
// M5Cardputer/src/utility/Keyboard/Keyboard.h da versao pinada, nao supondo
// API). Duas convencoes deste firmware compensam isso:
//
//   - "Cancelar" = Ctrl+C, detectado aqui (universal, nao depende do
//     estado da tela) — nao conflita com a passphrase livre porque Ctrl
//     nunca e como alguem digitaria um 'C' de verdade (isso e Shift+c).
//   - "Setas" nao existem como sinal proprio: as teclas fisicas ; , . /
//     tem setas serigrafadas (uso pretendido pela propria M5Stack), mas
//     como sao caracteres imprimiveis validos (podem aparecer numa
//     passphrase), a decisao de trata-las como navegacao ou como texto
//     literal e do CHAMADOR (main.cpp), dependendo da tela atual — nunca
//     daqui.
struct KeyEvent {
  bool has_event = false; // houve alguma tecla pressionada nesta iteracao
  bool esc = false;       // Ctrl+C
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

enum class TextStyle {
  kNormal,
  kHighlighted, // selecao atual (ex: candidato de autocomplete, item de menu)
  kWarning,     // aviso destacado (taxa alta, troco nao verificado)
  kMuted,       // texto secundario
};

// --- ciclo de vida ---

// Inicializa M5Cardputer (tela + teclado) e configura a tela (rotacao
// paisagem, fonte, cores). Chamar uma vez em setup().
void ui_init();

// Deve ser chamado uma vez por iteracao do loop principal, antes de
// ui_poll_key().
void ui_update();

// Preenche `out` com o estado do teclado desta iteracao. Retorna
// out->has_event (conveniencia). So reflete mudancas de estado (uma tecla
// pressionada uma vez gera um evento, nao um por frame enquanto segurada).
bool ui_poll_key(KeyEvent *out);

// --- desenho ---

// Define o texto de uma faixa persistente no topo da tela (ex: "TESTNET",
// secao 8 do spec — deve ficar visivel a sessao toda). nullptr ou "" remove
// a faixa. ui_clear() sempre redesenha a faixa atual, se houver, para que
// nenhuma tela precise se lembrar de faz-lo.
void ui_set_persistent_banner(const char *text);

// Limpa a tela e redesenha a faixa persistente (se houver).
void ui_clear();

// Desenha uma "linha" de texto numa grade fixa de altura kLineHeightPx,
// numerada a partir de 0 logo abaixo da faixa persistente (se houver).
void ui_draw_line(int line, const char *text, TextStyle style = TextStyle::kNormal);

int ui_width();
int ui_height();
// Quantas linhas de texto cabem na tela (considerando a faixa persistente,
// se houver) — util para quem pagina listas longas (menu, PSBTs, outputs).
int ui_max_lines();

} // namespace btcseed
