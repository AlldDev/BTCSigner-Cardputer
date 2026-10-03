// Ganchos do panic do ESP-IDF, so no aparelho. O sdkconfig pre-compilado do
// arduino-esp32 grava core dump na flash (CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH,
// particao coredump do default_8MB.csv) e imprime registradores/backtrace na
// UART0/USB em todo panic. O core dump leva as stacks das tasks, que podem ter
// resto de seed/chave, e ficaria persistido. Como nao da para mudar o
// sdkconfig sem trocar de framework, os simbolos sao interceptados via
// -Wl,--wrap no platformio.ini.
#include <esp_core_dump.h>
#include <esp_private/panic_internal.h>
#include <esp_private/system_internal.h>

#include "emergency_wipe.h"
#include "panic_hooks.h"

extern "C" {

// -Wl,--wrap=esp_core_dump_to_flash (todos os envs de aparelho): nunca grava.
void __wrap_esp_core_dump_to_flash(panic_info_t *info) { (void)info; }

#if BTCSEED_RELEASE
// -Wl,--wrap=esp_panic_handler (so release): zera os segredos e reinicia sem
// imprimir nada. O cardputer-debug mantem o dump na serial para desenvolver.
void __wrap_esp_panic_handler(panic_info_t *info) {
  (void)info;
  btcseed::emergency_wipe();
  esp_restart_noos();
}
#endif

} // extern "C"

namespace btcseed {

// Apaga um core dump deixado por uma versao antiga do firmware (ou por outra
// tabela de particoes, como a do M5Launcher). NOT_FOUND = sem particao;
// INVALID_SIZE = particao vazia. Qualquer outro resultado, inclusive dump
// truncado/com CRC invalido, apaga. So escreve na flash se houver algo.
void erase_stale_core_dump() {
  size_t addr = 0, size = 0;
  esp_err_t err = esp_core_dump_image_get(&addr, &size);
  if (err != ESP_ERR_NOT_FOUND && err != ESP_ERR_INVALID_SIZE) esp_core_dump_image_erase();
}

} // namespace btcseed
