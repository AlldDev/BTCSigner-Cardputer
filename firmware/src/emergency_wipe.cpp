#include "emergency_wipe.h"

namespace btcseed {
namespace {
void (*g_wipe_fn)() = nullptr;
} // namespace

void set_emergency_wipe(void (*fn)()) { g_wipe_fn = fn; }

void emergency_wipe() {
  if (g_wipe_fn != nullptr) g_wipe_fn();
}

} // namespace btcseed
