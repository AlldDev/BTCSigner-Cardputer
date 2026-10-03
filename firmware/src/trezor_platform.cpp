// Pontos de integracao que o trezor-crypto espera da plataforma hospedeira.
// Nenhuma logica criptografica mora aqui — apenas ganchos que a lib declara
// mas nao implementa, porque sao inerentemente especificos da plataforma:
//
//  - tc_fault_handler(): chamado por consteq() quando uma comparacao em
//    tempo constante detecta uma anomalia (possivel fault injection). A
//    reacao correta e zerar os segredos e reiniciar imediatamente, sem
//    imprimir nada que possa vazar estado. No aparelho nao usa abort(): ele
//    passaria pelo panic do ESP-IDF (dump na serial, core dump).
//  - random_buffer(): fonte de entropia usada pelo trezor-crypto para
//    mascaramento contra side-channel durante a assinatura ECDSA (RFC6979 ja
//    torna o nonce deterministico; isso e so blinding adicional). NAO e a
//    origem da seed do usuario (essa vem do teclado). Com WiFi/BT desligados,
//    esp_random() e so pseudoaleatorio: qualquer uso que exija entropia real
//    (salt/IV) deve chamar strong_random_buffer().
#include <cstdint>
#include <cstdlib>

#include "emergency_wipe.h"
#include "strong_random.h"

#if defined(ARDUINO) || defined(ESP_PLATFORM)
#include <bootloader_random.h> // fonte de ruido do SAR ADC (entropia real sem RF)
#include <esp_system.h>        // esp_random()
#else
#include <cstddef>
#include <sys/random.h> // getrandom() — apenas para os testes no host
#endif

extern "C" {

void tc_fault_handler(const char *msg) {
  (void)msg; // nunca logar: pode ser dado sensivel no momento da falha
  btcseed::emergency_wipe();
#if defined(ARDUINO) || defined(ESP_PLATFORM)
  esp_restart();
#else
  abort();
#endif
}

void random_buffer(uint8_t *buf, size_t len) {
#if defined(ARDUINO) || defined(ESP_PLATFORM)
  for (size_t i = 0; i < len; i += 4) {
    uint32_t r = esp_random();
    size_t chunk = (len - i < 4) ? (len - i) : 4;
    for (size_t j = 0; j < chunk; j++) {
      buf[i + j] = static_cast<uint8_t>(r >> (8 * j));
    }
  }
#else
  size_t offset = 0;
  while (offset < len) {
    ssize_t n = getrandom(buf + offset, len - offset, 0);
    if (n <= 0) {
      continue;
    }
    offset += static_cast<size_t>(n);
  }
#endif
}

void strong_random_buffer(uint8_t *buf, size_t len) {
#if defined(ARDUINO) || defined(ESP_PLATFORM)
  bootloader_random_enable();
  random_buffer(buf, len);
  bootloader_random_disable();
#else
  random_buffer(buf, len);
#endif
}

} // extern "C"
