// Logica pura de nomes/caminhos usada por sd_io.h — sem nenhum include do
// Arduino/SD, para poder rodar tambem no host (`pio test -e native`). A E/S
// de fato no cartao (que depende de hardware) mora em sd_io.cpp.
#include "sd_io.h"

#include <cstring>

namespace btcseed {

bool sanitize_filename(const char *name, char *out, size_t out_cap) {
  if (name == nullptr || out == nullptr) return false;
  size_t len = strlen(name);
  if (len == 0 || len > static_cast<size_t>(kMaxFilenameLen)) return false;
  if (out_cap < len + 1) return false;

  for (size_t i = 0; i < len; i++) {
    char c = name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
             c == ' ';
    if (!ok) return false;
    if (c == '.' && i + 1 < len && name[i + 1] == '.') {
      return false; // ".." em qualquer posicao: possivel path traversal
    }
  }

  memcpy(out, name, len + 1);
  return true;
}

bool has_extension(const char *name, const char *ext) {
  if (name == nullptr || ext == nullptr) return false;
  size_t name_len = strlen(name);
  size_t ext_len = strlen(ext);
  if (ext_len == 0 || ext_len > name_len) return false;

  const char *suffix = name + (name_len - ext_len);
  for (size_t i = 0; i < ext_len; i++) {
    char a = suffix[i];
    char b = ext[i];
    if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
    if (a != b) return false;
  }
  return true;
}

bool join_path(const char *dir, const char *name, char *out, size_t out_cap) {
  if (dir == nullptr || name == nullptr || out == nullptr) return false;
  size_t dir_len = strlen(dir);
  bool needs_slash = dir_len == 0 || dir[dir_len - 1] != '/';
  size_t name_len = strlen(name);
  size_t total = dir_len + (needs_slash ? 1 : 0) + name_len + 1;
  if (total > out_cap) return false;

  size_t pos = 0;
  memcpy(out + pos, dir, dir_len);
  pos += dir_len;
  if (needs_slash) out[pos++] = '/';
  memcpy(out + pos, name, name_len);
  pos += name_len;
  out[pos] = '\0';
  return true;
}

bool build_signed_filename(const char *name, char *out, size_t out_cap) {
  if (name == nullptr || out == nullptr) return false;
  size_t name_len = strlen(name);
  size_t ext_len = strlen(kPsbtExtension);
  size_t suffix_len = strlen(kSignedSuffix);

  bool has_ext = has_extension(name, kPsbtExtension);
  size_t stem_len = has_ext ? (name_len - ext_len) : name_len;

  size_t total = stem_len + suffix_len + (has_ext ? ext_len : 0) + 1;
  if (total > out_cap) return false;

  size_t pos = 0;
  memcpy(out + pos, name, stem_len);
  pos += stem_len;
  memcpy(out + pos, kSignedSuffix, suffix_len);
  pos += suffix_len;
  if (has_ext) {
    memcpy(out + pos, kPsbtExtension, ext_len);
    pos += ext_len;
  }
  out[pos] = '\0';
  return true;
}

} // namespace btcseed
