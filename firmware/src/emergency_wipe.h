// Wipe de emergencia: chamado quando o firmware vai reiniciar por uma falha
// (tc_fault_handler do trezor-crypto ou panic do ESP-IDF). O callback e
// registrado pelo main.cpp, assim trezor_platform.cpp/panic_hooks.cpp nao
// dependem dele.
#pragma once

namespace btcseed {

// O callback roda em contexto de falha/panic: so memzero, sem alocar, sem
// I2C/SPI, sem desenhar e sem logar.
void set_emergency_wipe(void (*fn)());

// Chama o callback registrado, se houver. Idempotente; nunca loga.
void emergency_wipe();

} // namespace btcseed
