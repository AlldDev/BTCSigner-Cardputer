#include "secure_wipe.h"

#include <cstddef>
#include <cstdint>

extern "C" {
#include "memzero.h"
}

#if defined(ARDUINO) || defined(ESP_PLATFORM)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

namespace btcseed {

__attribute__((noinline)) void scrub_stack() {
  uint8_t pad[1536];
  memzero(pad, sizeof(pad));
}

#if defined(ARDUINO) || defined(ESP_PLATFORM)

namespace {
// Fim da stack: canario 0xA5 do FreeRTOS (CHECK_STACKOVERFLOW_CANARY) e
// watchpoint de 32 B (WATCHPOINT_END_OF_STACK). Nunca escrever ali.
constexpr size_t kBottomGuard = 256;
// Acima: o proprio frame desta funcao e a area de spill de janelas do Xtensa.
constexpr size_t kTopGuard = 512;
// Mesmo byte com que o FreeRTOS preenche a stack, para que o canario e o
// uxTaskGetStackHighWaterMark continuem valendo.
constexpr uint8_t kFill = 0xA5;
} // namespace

__attribute__((noinline)) void scrub_free_stack() {
  uintptr_t lo = reinterpret_cast<uintptr_t>(pxTaskGetStackStart(nullptr)) + kBottomGuard;
  uintptr_t hi = reinterpret_cast<uintptr_t>(__builtin_frame_address(0)) - kTopGuard;
  if (hi <= lo) return;
  volatile uint8_t *p = reinterpret_cast<volatile uint8_t *>(lo);
  for (size_t i = 0, n = hi - lo; i < n; i++) p[i] = kFill;
}

#else

void scrub_free_stack() { scrub_stack(); }

#endif

} // namespace btcseed
