#include "psbt.h"

#include <cstring>

extern "C" {
#include "ecdsa.h"
#include "hasher.h"
#include "base58.h"
#include "memzero.h"
#include "segwit_addr.h"
}

namespace btcseed {

using internal::ByteSpan;
using internal::InputMeta;
using internal::OutputMeta;
using internal::ParsedTxInput;
using internal::ParsedTxOutput;

namespace {

// --- Cursor: leitura sequencial com checagem de limites --------------------
// Todo ponteiro/indice que sai daqui e absoluto dentro do buffer original
// (buf_), nao relativo a sub-regioes — assim spans guardados podem ser
// reusados diretamente contra buf_ em qualquer lugar (sighash, passthrough).
class Cursor {
public:
  Cursor(const uint8_t *data, size_t len) : data_(data), len_(len) {}
  Cursor(const uint8_t *data, size_t len, size_t start_pos)
      : data_(data), len_(len), pos_(start_pos) {}

  size_t pos() const { return pos_; }
  size_t remaining() const { return pos_ <= len_ ? len_ - pos_ : 0; }

  bool read_u8(uint8_t *out) {
    if (remaining() < 1) return false;
    *out = data_[pos_++];
    return true;
  }

  bool read_u32_le(uint32_t *out) {
    if (remaining() < 4) return false;
    *out = static_cast<uint32_t>(data_[pos_]) |
          (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
          (static_cast<uint32_t>(data_[pos_ + 2]) << 16) |
          (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
    pos_ += 4;
    return true;
  }

  bool read_u64_le(uint64_t *out) {
    if (remaining() < 8) return false;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
      v = (v << 8) | data_[pos_ + i];
    }
    *out = v;
    pos_ += 8;
    return true;
  }

  bool read_bytes(size_t n, ByteSpan *out) {
    if (remaining() < n) return false;
    out->offset = pos_;
    out->length = n;
    pos_ += n;
    return true;
  }

  bool skip(size_t n) {
    if (remaining() < n) return false;
    pos_ += n;
    return true;
  }

  // CompactSize (varint) do protocolo Bitcoin/PSBT. Rejeita codificacao
  // nao-minima (defesa contra PSBTs malformadas/maliciosas — secao 14).
  bool read_varint(uint64_t *out) {
    uint8_t first;
    if (!read_u8(&first)) return false;
    if (first < 0xfd) {
      *out = first;
      return true;
    }
    if (first == 0xfd) {
      if (remaining() < 2) return false;
      uint32_t v = data_[pos_] | (static_cast<uint32_t>(data_[pos_ + 1]) << 8);
      pos_ += 2;
      if (v < 0xfd) return false; // nao-minimo
      *out = v;
      return true;
    }
    if (first == 0xfe) {
      uint32_t v;
      if (!read_u32_le(&v)) return false;
      if (v <= 0xffffu) return false; // nao-minimo
      *out = v;
      return true;
    }
    // first == 0xff
    uint64_t v;
    if (!read_u64_le(&v)) return false;
    if (v <= 0xffffffffull) return false; // nao-minimo
    *out = v;
    return true;
  }

  const uint8_t *data() const { return data_; }

private:
  const uint8_t *data_;
  size_t len_;
  size_t pos_ = 0;
};

// Le uma chave BIP174 (<keylen><keytype><keydata>). Retorna false em erro de
// formato. `is_separator` vira true quando keylen==0 (fim do mapa) — nesse
// caso keytype/keydata nao sao tocados.
bool read_key(Cursor *c, bool *is_separator, uint8_t *keytype,
             ByteSpan *keydata) {
  uint64_t keylen;
  if (!c->read_varint(&keylen)) return false;
  if (keylen == 0) {
    *is_separator = true;
    return true;
  }
  *is_separator = false;
  if (!c->read_u8(keytype)) return false;
  size_t keydata_len = static_cast<size_t>(keylen) - 1;
  if (keydata_len == 0) {
    keydata->offset = c->pos();
    keydata->length = 0;
    return true;
  }
  return c->read_bytes(keydata_len, keydata);
}

bool read_value(Cursor *c, ByteSpan *value) {
  uint64_t valuelen;
  if (!c->read_varint(&valuelen)) return false;
  return c->read_bytes(static_cast<size_t>(valuelen), value);
}

// --- base64 (nao e criptografia — apenas codificacao de texto) -------------

int8_t b64_val(uint8_t c) {
  if (c >= 'A' && c <= 'Z') return static_cast<int8_t>(c - 'A');
  if (c >= 'a' && c <= 'z') return static_cast<int8_t>(c - 'a' + 26);
  if (c >= '0' && c <= '9') return static_cast<int8_t>(c - '0' + 52);
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

bool base64_decode(const uint8_t *in, size_t in_len, uint8_t *out,
                   size_t out_cap, size_t *out_len) {
  if (in_len == 0 || (in_len % 4) != 0) return false;
  size_t o = 0;
  for (size_t i = 0; i < in_len; i += 4) {
    bool pad2 = (in[i + 2] == '=');
    bool pad3 = (in[i + 3] == '=');
    if (in[i] == '=' || in[i + 1] == '=') return false; // '=' nunca nos 2 primeiros
    if (pad2 && !pad3) return false;                    // "XX=Y" invalido
    if ((pad2 || pad3) && i + 4 != in_len) return false; // '=' so no ultimo grupo

    int v0 = b64_val(in[i]);
    int v1 = b64_val(in[i + 1]);
    int v2 = pad2 ? 0 : b64_val(in[i + 2]);
    int v3 = pad3 ? 0 : b64_val(in[i + 3]);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return false;

    uint32_t n = (static_cast<uint32_t>(v0) << 18) |
                (static_cast<uint32_t>(v1) << 12) |
                (static_cast<uint32_t>(v2) << 6) | static_cast<uint32_t>(v3);
    if (o >= out_cap) return false;
    out[o++] = static_cast<uint8_t>((n >> 16) & 0xff);
    if (!pad2) {
      if (o >= out_cap) return false;
      out[o++] = static_cast<uint8_t>((n >> 8) & 0xff);
    }
    if (!pad3) {
      if (o >= out_cap) return false;
      out[o++] = static_cast<uint8_t>(n & 0xff);
    }
  }
  *out_len = o;
  return true;
}

bool base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_cap,
                   size_t *out_len) {
  static const char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t needed = ((in_len + 2) / 3) * 4;
  if (needed + 1 > out_cap) return false;

  size_t o = 0;
  size_t i = 0;
  for (; i + 3 <= in_len; i += 3) {
    uint32_t n = (static_cast<uint32_t>(in[i]) << 16) |
                (static_cast<uint32_t>(in[i + 1]) << 8) | in[i + 2];
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = kTable[(n >> 6) & 0x3f];
    out[o++] = kTable[n & 0x3f];
  }
  size_t rem = in_len - i;
  if (rem == 1) {
    uint32_t n = static_cast<uint32_t>(in[i]) << 16;
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = '=';
    out[o++] = '=';
  } else if (rem == 2) {
    uint32_t n =
        (static_cast<uint32_t>(in[i]) << 16) | (static_cast<uint32_t>(in[i + 1]) << 8);
    out[o++] = kTable[(n >> 18) & 0x3f];
    out[o++] = kTable[(n >> 12) & 0x3f];
    out[o++] = kTable[(n >> 6) & 0x3f];
    out[o++] = '=';
  }
  out[o] = '\0';
  *out_len = o;
  return true;
}

constexpr uint8_t kPsbtMagic[5] = {0x70, 0x73, 0x62, 0x74, 0xff};

uint32_t coin_type_for(Network network) {
  return network == Network::kMainnet ? kCoinTypeMainnet : kCoinTypeTestnet;
}

bool is_p2wpkh(const uint8_t *script, size_t len, const uint8_t **hash20) {
  if (len != 22 || script[0] != 0x00 || script[1] != 0x14) return false;
  *hash20 = script + 2;
  return true;
}

// Versoes de endereco legado (base58check) por rede — usadas so para exibir
// outputs externos P2PKH/P2SH na tela de revisao, nunca para os nossos
// proprios enderecos (que sao sempre P2WPKH/BIP84).
struct LegacyVersions {
  uint8_t p2pkh;
  uint8_t p2sh;
};
constexpr LegacyVersions kMainnetLegacy{0x00, 0x05};
constexpr LegacyVersions kTestnetLegacy{0x6f, 0xc4};

} // namespace

PsbtError Psbt::load(const uint8_t *data, size_t len) {
  loaded_ = false;
  validated_ = false;
  if (data == nullptr || len == 0) return PsbtError::kEmptyFile;
  if (len > kMaxPsbtFileSize) return PsbtError::kFileTooLarge;

  if (len >= 5 && memcmp(data, kPsbtMagic, 5) == 0) {
    is_base64_ = false;
    memcpy(buf_, data, len);
    buf_len_ = len;
  } else if (len >= 6 && memcmp(data, "cHNidP", 6) == 0) {
    is_base64_ = true;
    size_t decoded_len = 0;
    if (!base64_decode(data, len, buf_, sizeof(buf_), &decoded_len)) {
      return PsbtError::kBadEncoding;
    }
    buf_len_ = decoded_len;
    if (buf_len_ < 5 || memcmp(buf_, kPsbtMagic, 5) != 0) {
      return PsbtError::kBadMagic;
    }
  } else {
    return PsbtError::kBadEncoding;
  }

  PsbtError err = parse_structure();
  loaded_ = (err == PsbtError::kNone);
  return err;
}

PsbtError Psbt::parse_structure() {
  Cursor c(buf_, buf_len_, 5); // pula o magic

  bool seen_tx = false;
  bool seen_version = false;
  ByteSpan unsigned_tx_value{};
  size_t global_start = c.pos();

  for (;;) {
    bool is_sep = false;
    uint8_t keytype = 0;
    ByteSpan keydata{};
    if (!read_key(&c, &is_sep, &keytype, &keydata)) return PsbtError::kTruncated;
    if (is_sep) break;
    ByteSpan value{};
    if (!read_value(&c, &value)) return PsbtError::kTruncated;

    if (keytype == 0x00) { // PSBT_GLOBAL_UNSIGNED_TX
      if (seen_tx) return PsbtError::kDuplicateField;
      seen_tx = true;
      unsigned_tx_value = value;
    } else if (keytype == 0xfb) { // PSBT_GLOBAL_VERSION
      if (seen_version) return PsbtError::kDuplicateField;
      seen_version = true;
      if (value.length != 4) return PsbtError::kMalformed;
      uint32_t version = static_cast<uint32_t>(buf_[value.offset]) |
                         (static_cast<uint32_t>(buf_[value.offset + 1]) << 8) |
                         (static_cast<uint32_t>(buf_[value.offset + 2]) << 16) |
                         (static_cast<uint32_t>(buf_[value.offset + 3]) << 24);
      if (version != 0) return PsbtError::kUnsupportedVersion;
    }
    // demais keytypes (XPUB, PROPRIETARY, desconhecidos): ignorados aqui de
    // proposito — o span bruto abaixo os preserva verbatim.
  }
  global_raw_keypairs_.offset = global_start;
  global_raw_keypairs_.length = (c.pos() - 1) - global_start; // -1: o 0x00 final

  if (!seen_tx) return PsbtError::kMissingUnsignedTx;

  PsbtError err = parse_unsigned_tx(unsigned_tx_value);
  if (err != PsbtError::kNone) return err;

  if (tx_input_count_ > kMaxPsbtInputs) return PsbtError::kTooManyInputs;
  if (tx_output_count_ > kMaxPsbtOutputs) return PsbtError::kTooManyOutputs;

  size_t pos = c.pos();
  for (int i = 0; i < tx_input_count_; i++) {
    err = parse_input_map(i, &pos);
    if (err != PsbtError::kNone) return err;
  }
  for (int i = 0; i < tx_output_count_; i++) {
    err = parse_output_map(i, &pos);
    if (err != PsbtError::kNone) return err;
  }

  return PsbtError::kNone;
}

PsbtError Psbt::parse_unsigned_tx(ByteSpan tx_span) {
  size_t tx_end = tx_span.offset + tx_span.length;
  Cursor c(buf_, tx_end, tx_span.offset);

  if (!c.read_bytes(4, &version_span_)) return PsbtError::kTruncated;

  uint64_t in_count;
  if (!c.read_varint(&in_count)) return PsbtError::kTruncated;
  if (in_count > static_cast<uint64_t>(kMaxPsbtInputs)) {
    return PsbtError::kTooManyInputs;
  }
  tx_input_count_ = static_cast<int>(in_count);
  for (int i = 0; i < tx_input_count_; i++) {
    if (!c.read_bytes(36, &tx_inputs_[i].outpoint)) return PsbtError::kTruncated;
    uint64_t script_sig_len;
    if (!c.read_varint(&script_sig_len)) return PsbtError::kTruncated;
    if (script_sig_len != 0) return PsbtError::kNonEmptyScriptSig;
    if (!c.read_bytes(4, &tx_inputs_[i].sequence)) return PsbtError::kTruncated;
  }

  uint64_t out_count;
  if (!c.read_varint(&out_count)) return PsbtError::kTruncated;
  if (out_count > static_cast<uint64_t>(kMaxPsbtOutputs)) {
    return PsbtError::kTooManyOutputs;
  }
  tx_output_count_ = static_cast<int>(out_count);
  size_t outputs_start = c.pos();
  for (int i = 0; i < tx_output_count_; i++) {
    uint64_t value;
    if (!c.read_u64_le(&value)) return PsbtError::kTruncated;
    tx_outputs_[i].value_sats = value;
    uint64_t script_len;
    if (!c.read_varint(&script_len)) return PsbtError::kTruncated;
    if (!c.read_bytes(static_cast<size_t>(script_len),
                      &tx_outputs_[i].script_pubkey)) {
      return PsbtError::kTruncated;
    }
  }
  outputs_span_.offset = outputs_start;
  outputs_span_.length = c.pos() - outputs_start;

  if (!c.read_bytes(4, &locktime_span_)) return PsbtError::kTruncated;

  if (c.pos() != tx_end) return PsbtError::kMalformed; // lixo apos locktime

  return PsbtError::kNone;
}

PsbtError Psbt::parse_input_map(int index, size_t *cursor_pos) {
  Cursor c(buf_, buf_len_, *cursor_pos);
  InputMeta &m = inputs_[index];
  m = InputMeta{};
  size_t start = c.pos();

  for (;;) {
    bool is_sep = false;
    uint8_t keytype = 0;
    ByteSpan keydata{};
    if (!read_key(&c, &is_sep, &keytype, &keydata)) return PsbtError::kTruncated;
    if (is_sep) break;
    ByteSpan value{};
    if (!read_value(&c, &value)) return PsbtError::kTruncated;

    switch (keytype) {
      case 0x00: // PSBT_IN_NON_WITNESS_UTXO — conferido em verify_prev_tx()
        if (m.has_non_witness_utxo) return PsbtError::kDuplicateField;
        if (keydata.length != 0) return PsbtError::kMalformed;
        m.has_non_witness_utxo = true;
        m.non_witness_utxo = value;
        break;
      case 0x01: { // PSBT_IN_WITNESS_UTXO
        if (m.has_witness_utxo) return PsbtError::kDuplicateField;
        Cursor vc(buf_, value.offset + value.length, value.offset);
        uint64_t amount;
        if (!vc.read_u64_le(&amount)) return PsbtError::kMalformed;
        uint64_t script_len;
        ByteSpan script{};
        if (!vc.read_varint(&script_len) ||
            !vc.read_bytes(static_cast<size_t>(script_len), &script)) {
          return PsbtError::kMalformed;
        }
        if (vc.pos() != value.offset + value.length) return PsbtError::kMalformed;
        m.has_witness_utxo = true;
        m.witness_value_sats = amount;
        m.witness_script_pubkey = script;
        break;
      }
      case 0x02: // PSBT_IN_PARTIAL_SIG
      case 0x07: // PSBT_IN_FINAL_SCRIPTSIG
      case 0x08: // PSBT_IN_FINAL_SCRIPTWITNESS
        return PsbtError::kAlreadyHasSignature;
      case 0x03: { // PSBT_IN_SIGHASH_TYPE
        if (m.sighash_present) return PsbtError::kDuplicateField;
        if (value.length != 4) return PsbtError::kMalformed;
        m.sighash_present = true;
        m.sighash_type = static_cast<uint32_t>(buf_[value.offset]) |
                        (static_cast<uint32_t>(buf_[value.offset + 1]) << 8) |
                        (static_cast<uint32_t>(buf_[value.offset + 2]) << 16) |
                        (static_cast<uint32_t>(buf_[value.offset + 3]) << 24);
        break;
      }
      case 0x04: // PSBT_IN_REDEEM_SCRIPT — P2SH (embutido), fora do escopo
        return PsbtError::kUnsupportedInputScript;
      case 0x05: // PSBT_IN_WITNESS_SCRIPT — P2WSH, fora do escopo
        return PsbtError::kUnsupportedInputScript;
      case 0x06: { // PSBT_IN_BIP32_DERIVATION
        if (m.has_bip32_derivation) return PsbtError::kDuplicateField;
        if (keydata.length != 33) return PsbtError::kMalformed;
        if (value.length != 4 + 5 * 4) return PsbtError::kDerivationPathMismatch;
        memcpy(m.claimed_pubkey, buf_ + keydata.offset, 33);
        m.claimed_fingerprint =
            (static_cast<uint32_t>(buf_[value.offset]) << 24) |
            (static_cast<uint32_t>(buf_[value.offset + 1]) << 16) |
            (static_cast<uint32_t>(buf_[value.offset + 2]) << 8) |
            static_cast<uint32_t>(buf_[value.offset + 3]);
        uint32_t path[5];
        for (int p = 0; p < 5; p++) {
          size_t o = value.offset + 4 + p * 4;
          path[p] = static_cast<uint32_t>(buf_[o]) |
                    (static_cast<uint32_t>(buf_[o + 1]) << 8) |
                    (static_cast<uint32_t>(buf_[o + 2]) << 16) |
                    (static_cast<uint32_t>(buf_[o + 3]) << 24);
        }
        if (path[0] != kPurposeBip84 || path[2] != kAccountHardened) {
          return PsbtError::kDerivationPathMismatch;
        }
        if (path[1] != kCoinTypeMainnet && path[1] != kCoinTypeTestnet) {
          return PsbtError::kDerivationPathMismatch;
        }
        if ((path[3] & 0x80000000u) || (path[4] & 0x80000000u)) {
          return PsbtError::kDerivationPathMismatch; // change/index nao devem ser hardened
        }
        if (path[3] != kChangeExternal && path[3] != kChangeInternal) {
          return PsbtError::kDerivationPathMismatch;
        }
        m.has_bip32_derivation = true;
        m.coin_type = path[1];
        m.change = path[3];
        m.index = path[4];
        break;
      }
      default:
        break; // desconhecido/nao usado: ignorado, preservado no span bruto
    }
  }

  m.raw_keypairs.offset = start;
  m.raw_keypairs.length = (c.pos() - 1) - start;
  *cursor_pos = c.pos();
  return PsbtError::kNone;
}

PsbtError Psbt::parse_output_map(int index, size_t *cursor_pos) {
  Cursor c(buf_, buf_len_, *cursor_pos);
  OutputMeta &m = outputs_[index];
  m = OutputMeta{};
  size_t start = c.pos();

  for (;;) {
    bool is_sep = false;
    uint8_t keytype = 0;
    ByteSpan keydata{};
    if (!read_key(&c, &is_sep, &keytype, &keydata)) return PsbtError::kTruncated;
    if (is_sep) break;
    ByteSpan value{};
    if (!read_value(&c, &value)) return PsbtError::kTruncated;

    if (keytype == 0x02) { // PSBT_OUT_BIP32_DERIVATION
      if (m.has_bip32_derivation) return PsbtError::kDuplicateField;
      if (keydata.length == 33 && value.length == 4 + 5 * 4) {
        uint32_t fingerprint =
            (static_cast<uint32_t>(buf_[value.offset]) << 24) |
            (static_cast<uint32_t>(buf_[value.offset + 1]) << 16) |
            (static_cast<uint32_t>(buf_[value.offset + 2]) << 8) |
            static_cast<uint32_t>(buf_[value.offset + 3]);
        uint32_t path[5];
        for (int p = 0; p < 5; p++) {
          size_t o = value.offset + 4 + p * 4;
          path[p] = static_cast<uint32_t>(buf_[o]) |
                    (static_cast<uint32_t>(buf_[o + 1]) << 8) |
                    (static_cast<uint32_t>(buf_[o + 2]) << 16) |
                    (static_cast<uint32_t>(buf_[o + 3]) << 24);
        }
        bool shape_ok = path[0] == kPurposeBip84 && path[2] == kAccountHardened &&
                       (path[1] == kCoinTypeMainnet || path[1] == kCoinTypeTestnet) &&
                       (path[3] == kChangeExternal || path[3] == kChangeInternal) &&
                       !(path[4] & 0x80000000u);
        if (shape_ok) {
          m.has_bip32_derivation = true;
          m.claimed_fingerprint = fingerprint;
          m.coin_type = path[1];
          m.change = path[3];
          m.index = path[4];
        }
        // formato reconhecido mas fora da forma esperada: nao trata como
        // candidato a troco, mas tambem nao rejeita o PSBT inteiro por
        // causa disso (o output so sera exibido como externo comum).
      }
      // keydata/value com tamanho errado: idem, so nao vira candidato a troco.
    }
    // demais keytypes: ignorados aqui, preservados no span bruto.
  }

  m.raw_keypairs.offset = start;
  m.raw_keypairs.length = (c.pos() - 1) - start;
  *cursor_pos = c.pos();
  return PsbtError::kNone;
}

// Prova o witness_utxo do input `index` pela tx anterior completa: o txid
// (double-SHA256 da serializacao sem witness) tem que ser o do outpoint, e o
// output `vout` dela tem que ter o mesmo valor e scriptPubKey.
PsbtError Psbt::verify_prev_tx(int index) const {
  const InputMeta &m = inputs_[index];
  const ByteSpan &prev = m.non_witness_utxo;
  size_t prev_end = prev.offset + prev.length;
  Cursor c(buf_, prev_end, prev.offset);

  Hasher h;
  hasher_Init(&h, HASHER_SHA2D);

  ByteSpan version{};
  if (!c.read_bytes(4, &version)) return PsbtError::kMalformed;
  hasher_Update(&h, buf_ + version.offset, 4);

  // Marker 0x00 + flag 0x01 (BIP144): fora do txid. Uma tx com 0 inputs
  // seria ambigua aqui, mas e invalida de qualquer jeito.
  bool segwit = c.remaining() >= 2 && buf_[c.pos()] == 0x00 &&
                buf_[c.pos() + 1] == 0x01;
  if (segwit) c.skip(2);

  size_t body_start = c.pos();
  uint64_t in_count;
  if (!c.read_varint(&in_count) || in_count == 0) return PsbtError::kMalformed;
  for (uint64_t i = 0; i < in_count; i++) {
    uint64_t script_len;
    if (!c.skip(36) || !c.read_varint(&script_len) || script_len > c.remaining() ||
        !c.skip(static_cast<size_t>(script_len)) || !c.skip(4)) {
      return PsbtError::kMalformed;
    }
  }

  const uint8_t *outpoint = buf_ + tx_inputs_[index].outpoint.offset;
  uint32_t vout = static_cast<uint32_t>(outpoint[32]) |
                  (static_cast<uint32_t>(outpoint[33]) << 8) |
                  (static_cast<uint32_t>(outpoint[34]) << 16) |
                  (static_cast<uint32_t>(outpoint[35]) << 24);
  uint64_t out_count;
  if (!c.read_varint(&out_count)) return PsbtError::kMalformed;
  bool found = false;
  uint64_t value = 0;
  ByteSpan script{};
  for (uint64_t i = 0; i < out_count; i++) {
    uint64_t v;
    uint64_t script_len;
    ByteSpan s{};
    if (!c.read_u64_le(&v) || !c.read_varint(&script_len) ||
        script_len > c.remaining() ||
        !c.read_bytes(static_cast<size_t>(script_len), &s)) {
      return PsbtError::kMalformed;
    }
    if (i == vout) {
      found = true;
      value = v;
      script = s;
    }
  }
  hasher_Update(&h, buf_ + body_start, c.pos() - body_start);

  if (segwit) {
    for (uint64_t i = 0; i < in_count; i++) {
      uint64_t items;
      if (!c.read_varint(&items)) return PsbtError::kMalformed;
      for (uint64_t k = 0; k < items; k++) {
        uint64_t item_len;
        if (!c.read_varint(&item_len) || item_len > c.remaining() ||
            !c.skip(static_cast<size_t>(item_len))) {
          return PsbtError::kMalformed;
        }
      }
    }
  }

  ByteSpan locktime{};
  if (!c.read_bytes(4, &locktime)) return PsbtError::kMalformed;
  if (c.pos() != prev_end) return PsbtError::kMalformed; // lixo apos locktime
  hasher_Update(&h, buf_ + locktime.offset, 4);

  uint8_t txid[32];
  hasher_Final(&h, txid);

  if (!found || memcmp(txid, outpoint, 32) != 0) return PsbtError::kPrevTxMismatch;
  if (value != m.witness_value_sats) return PsbtError::kPrevTxMismatch;
  if (script.length != m.witness_script_pubkey.length ||
      memcmp(buf_ + script.offset, buf_ + m.witness_script_pubkey.offset,
             script.length) != 0) {
    return PsbtError::kPrevTxMismatch;
  }
  return PsbtError::kNone;
}

PsbtError Psbt::cross_check_input(int index, const MasterKey &mk) {
  InputMeta &m = inputs_[index];

  if (!m.has_witness_utxo) return PsbtError::kMissingWitnessUtxo;
  if (!m.has_non_witness_utxo) return PsbtError::kMissingNonWitnessUtxo;
  PsbtError prev_err = verify_prev_tx(index);
  if (prev_err != PsbtError::kNone) return prev_err;
  if (!m.has_bip32_derivation) return PsbtError::kMissingBip32Derivation;
  if (m.sighash_present && m.sighash_type != 0x00000001u) {
    return PsbtError::kUnsupportedSighash;
  }
  if (m.claimed_fingerprint != mk.master_fingerprint) {
    return PsbtError::kFingerprintMismatch;
  }
  if (m.coin_type != coin_type_for(mk.network)) return PsbtError::kNetworkMismatch;

  const uint8_t *hash20 = nullptr;
  if (!is_p2wpkh(buf_ + m.witness_script_pubkey.offset,
                m.witness_script_pubkey.length, &hash20)) {
    return PsbtError::kUnsupportedInputScript;
  }

  HDNode node;
  if (!derive_child_node(mk, m.change, m.index, &node)) {
    return PsbtError::kDerivationPathMismatch;
  }
  if (hdnode_fill_public_key(&node) != 0) {
    wipe_node(&node);
    return PsbtError::kDerivationPathMismatch;
  }
  bool pubkey_ok = memcmp(node.public_key, m.claimed_pubkey, 33) == 0;
  uint8_t derived_hash[20];
  ecdsa_get_pubkeyhash(node.public_key, node.curve->hasher_pubkey, derived_hash);
  wipe_node(&node);

  if (!pubkey_ok) return PsbtError::kPubkeyMismatch;
  if (memcmp(derived_hash, hash20, 20) != 0) return PsbtError::kPubkeyMismatch;

  return PsbtError::kNone;
}

void Psbt::fill_output_info(int index, const MasterKey &mk, Network network,
                           OutputInfo *info) const {
  *info = OutputInfo{};
  info->amount_sats = tx_outputs_[index].value_sats;

  const ByteSpan &spk = tx_outputs_[index].script_pubkey;
  const uint8_t *script = buf_ + spk.offset;
  const char *hrp = (network == Network::kMainnet) ? "bc" : "tb";
  const LegacyVersions &legacy =
      (network == Network::kMainnet) ? kMainnetLegacy : kTestnetLegacy;

  bool addr_ok = false;
  const uint8_t *hash20 = nullptr;
  if (is_p2wpkh(script, spk.length, &hash20)) {
    addr_ok = segwit_addr_encode(info->address, hrp, 0, hash20, 20) == 1;
  } else if (spk.length == 34 && script[0] == 0x00 && script[1] == 0x20) {
    // P2WSH: bech32 v0, 32 bytes. So exibido (nao pode ser nosso troco).
    addr_ok = segwit_addr_encode(info->address, hrp, 0, script + 2, 32) == 1;
  } else if (spk.length == 34 && script[0] == 0x51 && script[1] == 0x20) {
    // P2TR: bech32m v1, 32 bytes. Fora do escopo de carteira, so exibicao.
    addr_ok = segwit_addr_encode(info->address, hrp, 1, script + 2, 32) == 1;
  } else if (spk.length == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
            script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
    // P2PKH classico
    uint8_t payload[21];
    payload[0] = legacy.p2pkh;
    memcpy(payload + 1, script + 3, 20);
    addr_ok = base58_encode_check(payload, sizeof(payload), HASHER_SHA2D,
                                 info->address, sizeof(info->address)) > 0;
    memzero(payload, sizeof(payload));
  } else if (spk.length == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
            script[22] == 0x87) {
    // P2SH classico
    uint8_t payload[21];
    payload[0] = legacy.p2sh;
    memcpy(payload + 1, script + 2, 20);
    addr_ok = base58_encode_check(payload, sizeof(payload), HASHER_SHA2D,
                                 info->address, sizeof(info->address)) > 0;
    memzero(payload, sizeof(payload));
  }

  if (!addr_ok) {
    info->address[0] = '\0'; // sinaliza script nao suportado ao chamador
  }

  const OutputMeta &om = outputs_[index];
  bool candidate_change = om.has_bip32_derivation &&
                          om.claimed_fingerprint == mk.master_fingerprint;
  if (candidate_change) {
    HDNode node;
    bool matched = false;
    // Coin type de outra rede: alegacao falsa, mesmo que o hash batesse.
    if (om.coin_type == coin_type_for(mk.network) &&
        derive_child_node(mk, om.change, om.index, &node)) {
      if (hdnode_fill_public_key(&node) == 0) {
        uint8_t derived_hash[20];
        ecdsa_get_pubkeyhash(node.public_key, node.curve->hasher_pubkey,
                             derived_hash);
        matched = hash20 != nullptr && memcmp(derived_hash, hash20, 20) == 0;
      }
      wipe_node(&node);
    }
    if (matched) {
      info->is_change = true;
      info->change_index = om.index;
      info->change_index_high = om.index > kChangeIndexWarning;
    } else {
      info->claimed_change_invalid = true;
    }
  }
}

PsbtError Psbt::validate(const MasterKey &mk, Network network,
                        PsbtSummary *out_summary) {
  validated_ = false;
  if (!loaded_) return PsbtError::kEmptyFile;
  if (out_summary == nullptr) return PsbtError::kMalformed;
  if (tx_input_count_ == 0 || tx_output_count_ == 0) return PsbtError::kMalformed;

  // Escreve direto em *out_summary (em vez de montar uma copia local) para
  // nao duplicar ~2 KB de OutputInfo[] na stack desta funcao.
  *out_summary = PsbtSummary{};
  out_summary->num_inputs = tx_input_count_;
  out_summary->num_outputs = tx_output_count_;

  uint64_t total_in = 0;
  for (int i = 0; i < tx_input_count_; i++) {
    PsbtError err = cross_check_input(i, mk);
    if (err != PsbtError::kNone) return err;
    if (inputs_[i].witness_value_sats > kMaxMoneySats) return PsbtError::kMalformed;
    total_in += inputs_[i].witness_value_sats;
  }

  uint64_t total_out = 0;
  uint64_t external_out = 0;
  for (int i = 0; i < tx_output_count_; i++) {
    OutputInfo &info = out_summary->outputs[i];
    fill_output_info(i, mk, network, &info);
    if (info.address[0] == '\0') return PsbtError::kUnsupportedOutputScript;
    if (info.amount_sats > kMaxMoneySats) return PsbtError::kMalformed;

    total_out += info.amount_sats;
    if (!info.is_change) {
      external_out += info.amount_sats;
    }
  }
  // Nota sobre rede (secao 9 do spec, "rede dos enderecos compativel"): uma
  // scriptPubKey Bitcoin NAO carrega nenhum byte de rede (bc1/tb1 etc. e so
  // formatacao da STRING de endereco). O unico sinal de rede no PSBT e o
  // coin type alegado na derivacao (84'/0' vs 84'/1'), cruzado com a sessao
  // em cross_check_input(); fill_output_info() formata tudo com a rede da
  // sessao.

  if (total_in > kMaxMoneySats || total_out > kMaxMoneySats) return PsbtError::kMalformed;
  if (total_in < total_out) return PsbtError::kAmountsDontBalance;

  out_summary->total_input_sats = total_in;
  out_summary->total_output_sats = total_out;
  out_summary->fee_sats = total_in - total_out;
  bool over_absolute = out_summary->fee_sats > kHighFeeWarningAbsoluteSats;
  bool over_percent =
      external_out > 0 &&
      static_cast<double>(out_summary->fee_sats) >
          (kHighFeeWarningPercent / 100.0) * static_cast<double>(external_out);
  out_summary->high_fee_warning = over_absolute || over_percent;

  validated_ = true;
  return PsbtError::kNone;
}

bool Psbt::build_sighash(int index, uint8_t digest[32]) const {
  uint8_t hash_prevouts[32];
  uint8_t hash_sequence[32];
  uint8_t hash_outputs[32];
  {
    uint8_t prevouts[kMaxPsbtInputs * 36];
    uint8_t sequences[kMaxPsbtInputs * 4];
    for (int i = 0; i < tx_input_count_; i++) {
      memcpy(prevouts + i * 36, buf_ + tx_inputs_[i].outpoint.offset, 36);
      memcpy(sequences + i * 4, buf_ + tx_inputs_[i].sequence.offset, 4);
    }
    hasher_Raw(HASHER_SHA2D, prevouts, tx_input_count_ * 36, hash_prevouts);
    hasher_Raw(HASHER_SHA2D, sequences, tx_input_count_ * 4, hash_sequence);
  }
  hasher_Raw(HASHER_SHA2D, buf_ + outputs_span_.offset, outputs_span_.length,
            hash_outputs);

  const InputMeta &m = inputs_[index];
  const uint8_t *hash20 = nullptr;
  if (!is_p2wpkh(buf_ + m.witness_script_pubkey.offset,
                m.witness_script_pubkey.length, &hash20)) {
    return false;
  }
  // OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG (BIP143:
  // scriptCode do P2WPKH e o script P2PKH equivalente ao seu witness
  // program). Indices atribuidos explicitamente — um initializer-list
  // posicional aqui e facil de contar errado (ja aconteceu: um zero a
  // menos deslocava OP_EQUALVERIFY/OP_CHECKSIG e corrompia o sighash).
  uint8_t script_code[25];
  script_code[0] = 0x76; // OP_DUP
  script_code[1] = 0xa9; // OP_HASH160
  script_code[2] = 0x14; // push 20 bytes
  memcpy(script_code + 3, hash20, 20);
  script_code[23] = 0x88; // OP_EQUALVERIFY
  script_code[24] = 0xac; // OP_CHECKSIG

  uint8_t preimage[4 + 32 + 32 + 36 + 1 + 25 + 8 + 4 + 32 + 4 + 4];
  size_t pos = 0;
  memcpy(preimage + pos, buf_ + version_span_.offset, 4);
  pos += 4;
  memcpy(preimage + pos, hash_prevouts, 32);
  pos += 32;
  memcpy(preimage + pos, hash_sequence, 32);
  pos += 32;
  memcpy(preimage + pos, buf_ + tx_inputs_[index].outpoint.offset, 36);
  pos += 36;
  preimage[pos++] = 0x19; // compact size 25
  memcpy(preimage + pos, script_code, 25);
  pos += 25;
  uint64_t amount = m.witness_value_sats;
  for (int i = 0; i < 8; i++) {
    preimage[pos++] = static_cast<uint8_t>(amount >> (8 * i));
  }
  memcpy(preimage + pos, buf_ + tx_inputs_[index].sequence.offset, 4);
  pos += 4;
  memcpy(preimage + pos, hash_outputs, 32);
  pos += 32;
  memcpy(preimage + pos, buf_ + locktime_span_.offset, 4);
  pos += 4;
  preimage[pos++] = 0x01; // SIGHASH_ALL, 4 bytes LE
  preimage[pos++] = 0x00;
  preimage[pos++] = 0x00;
  preimage[pos++] = 0x00;

  hasher_Raw(HASHER_SHA2D, preimage, pos, digest);
  memzero(preimage, sizeof(preimage));
  return true;
}

PsbtError Psbt::sign(const MasterKey &mk) {
  if (!validated_) return PsbtError::kNotValidated;

  for (int i = 0; i < tx_input_count_; i++) {
    InputMeta &m = inputs_[i];

    uint8_t digest[32];
    if (!build_sighash(i, digest)) return PsbtError::kSignFailed;

    HDNode node;
    if (!derive_child_node(mk, m.change, m.index, &node)) {
      memzero(digest, sizeof(digest));
      return PsbtError::kSignFailed;
    }
    if (hdnode_fill_public_key(&node) != 0) {
      wipe_node(&node);
      memzero(digest, sizeof(digest));
      return PsbtError::kSignFailed;
    }

    uint8_t sig64[64];
    uint8_t pby;
    int rc = hdnode_sign_digest(&node, digest, sig64, &pby, nullptr);
    memcpy(m.sig_pubkey, node.public_key, 33);
    wipe_node(&node);
    memzero(digest, sizeof(digest));

    if (rc != 0) {
      memzero(sig64, sizeof(sig64));
      return PsbtError::kSignFailed;
    }

    uint8_t der[72];
    int der_len = ecdsa_sig_to_der(sig64, der);
    memzero(sig64, sizeof(sig64));
    if (der_len <= 0 || static_cast<size_t>(der_len) + 1 > sizeof(m.der_sig)) {
      return PsbtError::kSignFailed;
    }
    memcpy(m.der_sig, der, static_cast<size_t>(der_len));
    m.der_sig[der_len] = 0x01; // SIGHASH_ALL
    m.der_sig_len = static_cast<uint8_t>(der_len + 1);
    m.signed_ok = true;
  }
  return PsbtError::kNone;
}

namespace {

// Escreve um CompactSize (varint) minimamente codificado.
size_t write_varint(uint8_t *out, uint64_t v) {
  if (v < 0xfd) {
    out[0] = static_cast<uint8_t>(v);
    return 1;
  }
  if (v <= 0xffff) {
    out[0] = 0xfd;
    out[1] = static_cast<uint8_t>(v);
    out[2] = static_cast<uint8_t>(v >> 8);
    return 3;
  }
  if (v <= 0xffffffffull) {
    out[0] = 0xfe;
    for (int i = 0; i < 4; i++) out[1 + i] = static_cast<uint8_t>(v >> (8 * i));
    return 5;
  }
  out[0] = 0xff;
  for (int i = 0; i < 8; i++) out[1 + i] = static_cast<uint8_t>(v >> (8 * i));
  return 9;
}

} // namespace

bool Psbt::serialize_signed(uint8_t *out, size_t out_len,
                           size_t *out_written) const {
  if (out == nullptr || out_written == nullptr) return false;

  // Buffer binario intermediario: PSBT original + um PSBT_IN_PARTIAL_SIG
  // novo por input (pubkey 33B + DER<=72B + 1B sighash + overhead de
  // varints, generosamente arredondado). `static` para nao empilhar mais
  // ~68 KB na stack — isso torna serialize_signed() nao-reentrante, o que
  // e aceitavel porque o firmware so assina um PSBT por vez.
  static constexpr size_t kScratchSize = kMaxPsbtFileSize + kMaxPsbtInputs * 128;
  static uint8_t scratch[kScratchSize];
  size_t pos = 0;

  auto put = [&](const uint8_t *data, size_t len) {
    if (pos + len > kScratchSize) return false;
    memcpy(scratch + pos, data, len);
    pos += len;
    return true;
  };

  if (!put(kPsbtMagic, sizeof(kPsbtMagic))) return false;
  if (!put(buf_ + global_raw_keypairs_.offset, global_raw_keypairs_.length)) {
    return false;
  }
  uint8_t zero = 0x00;
  if (!put(&zero, 1)) return false;

  for (int i = 0; i < tx_input_count_; i++) {
    const InputMeta &m = inputs_[i];
    if (!m.signed_ok) return false;
    if (!put(buf_ + m.raw_keypairs.offset, m.raw_keypairs.length)) return false;

    uint8_t key_hdr[2];
    key_hdr[0] = 34; // keylen: 1 (keytype) + 33 (pubkey)
    key_hdr[1] = 0x02; // PSBT_IN_PARTIAL_SIG
    if (!put(key_hdr, 2)) return false;
    if (!put(m.sig_pubkey, 33)) return false;

    uint8_t val_len[9];
    size_t val_len_bytes = write_varint(val_len, m.der_sig_len);
    if (!put(val_len, val_len_bytes)) return false;
    if (!put(m.der_sig, m.der_sig_len)) return false;

    if (!put(&zero, 1)) return false;
  }

  for (int i = 0; i < tx_output_count_; i++) {
    const OutputMeta &m = outputs_[i];
    if (!put(buf_ + m.raw_keypairs.offset, m.raw_keypairs.length)) return false;
    if (!put(&zero, 1)) return false;
  }

  if (is_base64_) {
    size_t encoded_len = 0;
    if (!base64_encode(scratch, pos, reinterpret_cast<char *>(out), out_len,
                       &encoded_len)) {
      return false;
    }
    *out_written = encoded_len;
  } else {
    if (pos > out_len) return false;
    memcpy(out, scratch, pos);
    *out_written = pos;
  }
  return true;
}

} // namespace btcseed
