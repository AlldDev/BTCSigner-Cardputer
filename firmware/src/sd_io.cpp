// E/S de fato no microSD do M5Stack Cardputer. So compila no ambiente
// `cardputer` (precisa de Arduino/SD.h) — a logica pura de nomes/caminhos
// que roda tambem no host esta em sd_io_paths.cpp.
//
// Pinos do slot de microSD confirmados no exemplo oficial da M5Stack
// (m5stack/M5Cardputer, examples/Basic/sdcard/sdcard.ino). A biblioteca
// M5Unified/M5Cardputer nao expoe esses pinos via API propria — o proprio
// exemplo oficial os define como constantes locais, entao fazemos o mesmo.
#include "sd_io.h"

#include <cstring>

#include <SD.h>
#include <SPI.h>

namespace btcseed {
namespace {

constexpr int kSdSckPin = 40;
constexpr int kSdMisoPin = 39;
constexpr int kSdMosiPin = 14;
constexpr int kSdCsPin = 12;
constexpr uint32_t kSdSpiHz = 25000000;

bool g_sd_ready = false;
bool g_spi_started = false;
char g_psbt_dir[kMaxFilenameLen + 1] = {0};
bool g_psbt_dir_known = false;

bool directory_exists(const char *path) {
  File f = SD.open(path);
  if (!f) return false;
  bool is_dir = f.isDirectory();
  f.close();
  return is_dir;
}

// Resolve uma vez por montagem se os .psbt vivem em kPsbtDir ou na raiz —
// secao 9 do spec permite as duas opcoes. sd_remount() invalida (outro cartao).
const char *psbt_dir() {
  if (!g_psbt_dir_known) {
    strncpy(g_psbt_dir, directory_exists(kPsbtDir) ? kPsbtDir : "/", sizeof(g_psbt_dir) - 1);
    g_psbt_dir_known = true;
  }
  return g_psbt_dir;
}

bool mount() {
  g_psbt_dir_known = false;
  g_sd_ready = SD.begin(kSdCsPin, SPI, kSdSpiHz) && SD.cardType() != CARD_NONE;
  return g_sd_ready;
}

// Escreve em um arquivo temporario e so renomeia para `final_path` se a
// escrita completar por inteiro — se o cartao for removido no meio do
// caminho, nunca sobra um arquivo parcial com o nome final (secao 11).
bool write_file_atomic(const char *final_path, const uint8_t *data,
                       size_t len) {
  char tmp_path[kMaxFilenameLen * 2 + 8];
  int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);
  if (n <= 0 || static_cast<size_t>(n) >= sizeof(tmp_path)) return false;

  SD.remove(tmp_path); // limpa lixo de uma tentativa anterior interrompida

  File f = SD.open(tmp_path, FILE_WRITE);
  if (!f) return false;

  size_t written = f.write(data, len);
  f.flush();
  f.close();

  if (written != len) {
    SD.remove(tmp_path);
    return false;
  }

  SD.remove(final_path); // troca atomica: substitui uma versao anterior, se houver
  if (!SD.rename(tmp_path, final_path)) {
    SD.remove(tmp_path);
    return false;
  }
  return true;
}

} // namespace

bool sd_init() {
  if (!g_spi_started) {
    SPI.begin(kSdSckPin, kSdMisoPin, kSdMosiPin, kSdCsPin);
    g_spi_started = true;
  }
  return mount();
}

bool sd_remount() {
  if (!g_spi_started) return sd_init();
  // Desmonta sempre: com o cartao trocado, a FAT em cache seria a do anterior.
  SD.end();
  g_sd_ready = false;
  return mount();
}

int list_psbt_files(PsbtFileEntry *out, int max_files) {
  if (!g_sd_ready || out == nullptr || max_files <= 0) return 0;

  File dir = SD.open(psbt_dir());
  if (!dir || !dir.isDirectory()) return 0;

  int count = 0;
  for (File entry = dir.openNextFile(); entry && count < max_files;
      entry = dir.openNextFile()) {
    if (!entry.isDirectory()) {
      const char *name = entry.name();
      // Algumas versoes do core ESP32 retornam o caminho completo em
      // name(); ficamos so com o componente final do nome.
      const char *slash = strrchr(name, '/');
      const char *base = (slash != nullptr) ? slash + 1 : name;

      char sanitized[kMaxFilenameLen + 1];
      if (has_extension(base, kPsbtExtension) &&
          sanitize_filename(base, sanitized, sizeof(sanitized))) {
        memcpy(out[count].name, sanitized, sizeof(sanitized));
        count++;
      }
    }
    entry.close();
  }
  dir.close();
  return count;
}

bool read_psbt_file(const char *filename, uint8_t *buf, size_t buf_cap,
                    size_t *out_len) {
  if (!g_sd_ready || filename == nullptr || buf == nullptr ||
      out_len == nullptr) {
    return false;
  }
  char sanitized[kMaxFilenameLen + 1];
  if (!sanitize_filename(filename, sanitized, sizeof(sanitized))) return false;

  char path[kMaxFilenameLen * 2 + 4];
  if (!join_path(psbt_dir(), sanitized, path, sizeof(path))) return false;

  File f = SD.open(path, FILE_READ);
  if (!f) return false;

  size_t size = f.size();
  if (size == 0 || size > kMaxPsbtFileSize || size > buf_cap) {
    f.close();
    return false;
  }
  size_t read = f.read(buf, size);
  f.close();
  if (read != size) return false;

  *out_len = read;
  return true;
}

bool write_signed_psbt(const char *original_filename, const uint8_t *data,
                      size_t len) {
  if (!g_sd_ready || original_filename == nullptr || data == nullptr) {
    return false;
  }
  char sanitized[kMaxFilenameLen + 1];
  if (!sanitize_filename(original_filename, sanitized, sizeof(sanitized))) {
    return false;
  }
  char signed_name[kMaxFilenameLen + 1];
  if (!build_signed_filename(sanitized, signed_name, sizeof(signed_name))) {
    return false;
  }
  char path[kMaxFilenameLen * 2 + 4];
  if (!join_path(psbt_dir(), signed_name, path, sizeof(path))) return false;

  return write_file_atomic(path, data, len);
}

bool write_text_file(const char *path, const char *text) {
  if (!g_sd_ready || path == nullptr || text == nullptr) return false;
  return write_file_atomic(path, reinterpret_cast<const uint8_t *>(text),
                          strlen(text));
}

} // namespace btcseed
