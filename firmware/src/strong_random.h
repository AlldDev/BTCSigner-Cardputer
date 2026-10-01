// Entropia real para material que precisa ser imprevisivel (salt/IV do backup
// no cartao RFID). Implementada em trezor_platform.cpp.
#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Sem WiFi/BT ligados, esp_random() (usado por random_buffer()) e so
// pseudoaleatorio. Esta funcao liga a fonte de ruido do SAR ADC
// (bootloader_random_enable) durante a geracao. Nao chamar enquanto algo le o
// ADC. No host (testes) usa getrandom().
void strong_random_buffer(uint8_t *buf, size_t len);

} // extern "C"
