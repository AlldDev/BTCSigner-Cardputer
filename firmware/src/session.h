// Estado da sessao: guarda a MasterKey enquanto a sessao esta ativa, aplica
// o timeout de inatividade e garante que end()/timeout zerem tudo (secao 11
// da spec). Nenhuma logica de UI ou hardware mora aqui — a fonte de tempo e
// injetada para permitir testar a logica de timeout no host (native).
#pragma once

#include <cstdint>

#include "config.h"
#include "keys.h"

namespace btcseed {

class Session {
public:
  using MillisFn = uint32_t (*)();

  explicit Session(MillisFn millis_fn) : millis_fn_(millis_fn) {}

  // Chamado uma vez, apos mnemonico + passphrase terem sido validados e a
  // MasterKey derivada com sucesso. Assume posse: `mk` e movido para dentro
  // da sessao e o chamador nao deve mais usa-lo diretamente.
  void start(MasterKey *mk) {
    end(); // por seguranca, garante que nao havia sessao anterior residual
    master_key_ = *mk;
    *mk = MasterKey{}; // o chamador perde a copia; wipe() cuida do conteudo
    active_ = true;
    last_activity_ms_ = millis_fn_();
  }

  // Chamado a cada tecla pressionada / interacao valida, para resetar o
  // relogio de inatividade.
  void touch() {
    if (active_) {
      last_activity_ms_ = millis_fn_();
    }
  }

  // Deve ser checado no loop principal. Nao encerra a sessao sozinho —
  // quem chama decide o que fazer (normalmente: exibir aviso e end()).
  bool is_expired() const {
    if (!active_) {
      return false;
    }
    // Subtracao sem sinal: correta mesmo com overflow de millis() (~49 dias).
    uint32_t elapsed = millis_fn_() - last_activity_ms_;
    return elapsed >= kSessionTimeoutMs;
  }

  bool is_active() const { return active_; }

  const MasterKey &master_key() const { return master_key_; }

  // Zera todo material privado e marca a sessao como inativa. Seguro chamar
  // multiplas vezes (timeout, "Encerrar sessao", remocao do microSD durante
  // uma operacao, ou erro fatal podem todos chamar end()).
  void end() {
    wipe(&master_key_);
    active_ = false;
    last_activity_ms_ = 0;
  }

private:
  MillisFn millis_fn_;
  MasterKey master_key_{};
  uint32_t last_activity_ms_ = 0;
  bool active_ = false;
};

} // namespace btcseed
