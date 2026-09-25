// Entrada da passphrase BIP39 (25a palavra, secao 7 da spec). Entrada
// livre, mascarada por padrao, com opcao explicita de passphrase vazia.
// So o buffer/estado mora aqui — nenhum desenho de tela (isso e ui.cpp).
#pragma once

#include <cstddef>

#include "config.h"

namespace btcseed {

class PassphraseInput {
public:
  PassphraseInput() = default;

  // Aceita qualquer caractere ASCII imprimivel (0x20 a 0x7e — "qualquer
  // caractere que o teclado permita", secao 7.1). Retorna false se o
  // caractere for nao-imprimivel ou o buffer ja estiver cheio
  // (kMaxPassphraseLen, o limite de mnemonic_to_seed do trezor-crypto).
  bool add_char(char c);

  // Apaga o ultimo caractere digitado. Retorna false se ja estava vazio.
  bool backspace();

  // Alterna entre mascarado (padrao) e visivel, para conferencia (secao
  // 7.2). Comeca sempre mascarado.
  void toggle_visibility() { visible_ = !visible_; }
  bool is_visible() const { return visible_; }

  int length() const { return length_; }
  bool is_empty() const { return length_ == 0; }

  // Preenche `out` com o que a tela deve mostrar: o texto real se
  // is_visible(), ou uma sequencia de '*' do mesmo tamanho caso contrario.
  // NUNCA retorna o texto real quando mascarado.
  void render_display(char *out, size_t out_len) const;

  // O texto realmente digitado, para derive_master_key(). Nunca deve ser
  // usado para exibicao na tela (use render_display() para isso).
  const char *value() const { return buffer_; }

  // Zera o buffer da RAM. Chamar assim que a derivacao terminar (secao
  // 7.4) e ao encerrar/abortar a sessao.
  void wipe();

private:
  char buffer_[kMaxPassphraseLen + 1] = {0};
  int length_ = 0;
  bool visible_ = false;
};

} // namespace btcseed
