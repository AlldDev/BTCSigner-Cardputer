#include "passphrase_input.h"

extern "C" {
#include "memzero.h"
}

namespace btcseed {

bool PassphraseInput::add_char(char c) {
  if (c < 0x20 || c > 0x7e) return false; // so ASCII imprimivel
  if (length_ >= kMaxPassphraseLen) return false;
  buffer_[length_++] = c;
  buffer_[length_] = '\0';
  return true;
}

bool PassphraseInput::backspace() {
  if (length_ == 0) return false;
  buffer_[--length_] = '\0';
  return true;
}

void PassphraseInput::render_display(char *out, size_t out_len) const {
  if (out == nullptr || out_len == 0) return;
  size_t n = static_cast<size_t>(length_);
  if (n > out_len - 1) n = out_len - 1;
  if (visible_) {
    for (size_t i = 0; i < n; i++) out[i] = buffer_[i];
  } else {
    for (size_t i = 0; i < n; i++) out[i] = '*';
  }
  out[n] = '\0';
}

void PassphraseInput::wipe() {
  memzero(buffer_, sizeof(buffer_));
  length_ = 0;
  visible_ = false;
}

} // namespace btcseed
