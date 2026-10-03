// Ganchos do panic/core dump do ESP-IDF (so aparelho). Ver panic_hooks.cpp.
#pragma once

namespace btcseed {

// Chamar no inicio do setup().
void erase_stale_core_dump();

} // namespace btcseed
