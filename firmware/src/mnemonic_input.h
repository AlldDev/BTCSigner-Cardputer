// Logica de entrada do mnemonico BIP39 com autocomplete (secao 6 da spec).
// So a maquina de estados/filtragem mora aqui — nenhum desenho de tela ou
// leitura de teclado (isso e ui.cpp). Isso permite testar toda a logica de
// autocomplete/validacao no host (native), sem hardware.
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace btcseed {

class MnemonicInput {
public:
  // word_count deve ser kMnemonicWordsShort (12) ou kMnemonicWordsLong (24).
  explicit MnemonicInput(int word_count);

  // Tenta adicionar uma letra ('a'-'z') ao prefixo da palavra atual.
  // Retorna false (e nao altera nada) se nenhuma palavra da wordlist BIP39
  // comeca com esse prefixo — a UI deve simplesmente ignorar a tecla.
  bool try_add_letter(char c);

  // Apaga a ultima letra do prefixo atual. Se o prefixo ja estiver vazio,
  // volta para a palavra anterior (permitindo corrigi-la) e retorna true;
  // se ja estiver na primeira palavra sem nada digitado, nao faz nada e
  // retorna false.
  bool backspace();

  // Confirma a palavra atual (Enter): exige que haja pelo menos um
  // candidato (unico ou escolhido via next/prev_candidate). Avanca para a
  // proxima palavra. Retorna false se nao havia candidato valido.
  bool confirm_word();

  // Navegacao entre candidatos quando ha mais de um com o prefixo atual.
  void next_candidate();
  void prev_candidate();

  // --- introspeccao para a UI ---
  int word_count() const { return word_count_; }
  int current_word_index() const { return current_index_; } // 0-based
  const char *current_prefix() const { return prefix_; }

  // Quantas palavras da wordlist casam com o prefixo atual.
  int count_candidates() const;
  // A n-esima (0-based) palavra que casa com o prefixo atual, ou nullptr.
  const char *nth_candidate(int n) const;
  // Indice (dentro dos candidatos filtrados) atualmente selecionado por
  // next_candidate()/prev_candidate().
  int selected_candidate_index() const { return selected_candidate_; }

  bool has_unique_candidate() const { return count_candidates() == 1; }
  const char *unique_candidate() const;

  // Todas as word_count() palavras ja foram confirmadas.
  bool is_complete() const { return current_index_ >= word_count_; }

  // Junta as palavras confirmadas separadas por espaco em `out`. Requer
  // is_complete(). `out_len` deve ser >= BIP39_MAX_MNEMONIC_LEN + 1.
  bool build_mnemonic(char *out, size_t out_len) const;

  // Roda mnemonic_check() (trezor-crypto) sobre o mnemonico montado.
  bool validate_checksum() const;

  // Volta o cursor para a palavra `index` (0-based) para o usuario corrigi-la,
  // sem mexer nas outras palavras ja confirmadas. Usado apos uma falha de
  // checksum (secao 6.3 da spec: corrigir palavra por palavra).
  void restart_word(int index);

  // Zera todo o buffer de palavras/prefixo digitado da RAM. Chamar ao final
  // da derivacao da seed e ao abortar/encerrar a sessao.
  void wipe();

private:
  int word_count_;
  int current_index_ = 0;
  int selected_candidate_ = 0;
  char prefix_[kMaxWordLen + 1] = {0};
  int prefix_len_ = 0;
  char words_[kMnemonicWordsLong][kMaxWordLen + 1] = {{0}};
};

} // namespace btcseed
