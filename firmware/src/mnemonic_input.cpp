#include "mnemonic_input.h"

#include <cstring>

extern "C" {
#include "bip39.h"
#include "memzero.h"
}

namespace btcseed {

MnemonicInput::MnemonicInput(int word_count) : word_count_(word_count) {}

bool MnemonicInput::try_add_letter(char c) {
  if (is_complete()) {
    return false;
  }
  if (c < 'a' || c > 'z') {
    return false;
  }
  if (prefix_len_ >= kMaxWordLen) {
    return false;
  }
  uint32_t mask = mnemonic_word_completion_mask(prefix_, prefix_len_);
  if ((mask & (1u << (c - 'a'))) == 0) {
    return false; // nenhuma palavra da wordlist continua com essa letra
  }
  prefix_[prefix_len_++] = c;
  prefix_[prefix_len_] = '\0';
  selected_candidate_ = 0;
  return true;
}

bool MnemonicInput::backspace() {
  if (prefix_len_ > 0) {
    prefix_[--prefix_len_] = '\0';
    selected_candidate_ = 0;
    return true;
  }
  if (current_index_ > 0) {
    current_index_--;
    memzero(words_[current_index_], sizeof(words_[current_index_]));
    prefix_len_ = 0;
    prefix_[0] = '\0';
    selected_candidate_ = 0;
    return true;
  }
  return false;
}

bool MnemonicInput::confirm_word() {
  if (is_complete()) {
    return false;
  }
  int count = count_candidates();
  if (count == 0) {
    return false;
  }
  int index = selected_candidate_;
  if (index >= count) {
    index = count - 1;
  }
  const char *word = nth_candidate(index);
  if (word == nullptr) {
    return false;
  }
  strncpy(words_[current_index_], word, kMaxWordLen);
  words_[current_index_][kMaxWordLen] = '\0';

  current_index_++;
  prefix_len_ = 0;
  prefix_[0] = '\0';
  selected_candidate_ = 0;
  return true;
}

void MnemonicInput::next_candidate() {
  int count = count_candidates();
  if (count > 0) {
    selected_candidate_ = (selected_candidate_ + 1) % count;
  }
}

void MnemonicInput::prev_candidate() {
  int count = count_candidates();
  if (count > 0) {
    selected_candidate_ = (selected_candidate_ - 1 + count) % count;
  }
}

int MnemonicInput::count_candidates() const {
  int count = 0;
  for (int i = 0; i < BIP39_WORD_COUNT; i++) {
    if (strncmp(BIP39_WORDLIST_ENGLISH[i], prefix_, prefix_len_) == 0) {
      count++;
    }
  }
  return count;
}

const char *MnemonicInput::nth_candidate(int n) const {
  if (n < 0) {
    return nullptr;
  }
  int count = 0;
  for (int i = 0; i < BIP39_WORD_COUNT; i++) {
    if (strncmp(BIP39_WORDLIST_ENGLISH[i], prefix_, prefix_len_) == 0) {
      if (count == n) {
        return BIP39_WORDLIST_ENGLISH[i];
      }
      count++;
    }
  }
  return nullptr;
}

const char *MnemonicInput::unique_candidate() const {
  return count_candidates() == 1 ? nth_candidate(0) : nullptr;
}

bool MnemonicInput::build_mnemonic(char *out, size_t out_len) const {
  if (!is_complete() || out == nullptr) {
    return false;
  }
  size_t pos = 0;
  for (int i = 0; i < word_count_; i++) {
    size_t len = strlen(words_[i]);
    if (pos + len + 1 >= out_len) { // +1 espaco/terminador
      return false;
    }
    if (i > 0) {
      out[pos++] = ' ';
    }
    memcpy(out + pos, words_[i], len);
    pos += len;
  }
  out[pos] = '\0';
  return true;
}

bool MnemonicInput::validate_checksum() const {
  char buf[BIP39_MAX_MNEMONIC_LEN + 1];
  if (!build_mnemonic(buf, sizeof(buf))) {
    return false;
  }
  bool ok = mnemonic_check(buf) == 1;
  memzero(buf, sizeof(buf));
  return ok;
}

void MnemonicInput::restart_word(int index) {
  if (index < 0 || index >= word_count_) {
    return;
  }
  current_index_ = index;
  prefix_len_ = 0;
  prefix_[0] = '\0';
  selected_candidate_ = 0;
}

void MnemonicInput::wipe() {
  memzero(prefix_, sizeof(prefix_));
  memzero(words_, sizeof(words_));
  prefix_len_ = 0;
  current_index_ = 0;
  selected_candidate_ = 0;
}

} // namespace btcseed
