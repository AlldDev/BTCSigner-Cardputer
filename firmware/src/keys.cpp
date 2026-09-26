#include "keys.h"

#include <cstdio>
#include <cstring>

extern "C" {
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "memzero.h"
#include "options.h"
#include "segwit_addr.h"
}

// mnemonic_to_seed() com cache copiaria mnemonico/passphrase/seed para um
// buffer estatico que wipe_seed_material()/Session::end() nao alcancam.
static_assert(USE_BIP39_CACHE == 0, "compile com -DUSE_BIP39_CACHE=0 (platformio.ini)");

namespace btcseed {
namespace {

// Versoes estendidas SLIP-132 para BIP84 (P2WPKH nativo).
constexpr uint32_t kZpubVersionMainnet = 0x04b24746;
constexpr uint32_t kVpubVersionTestnet = 0x045f1cf6;
// Versoes BIP32 padrao, exigidas dentro de output descriptors.
constexpr uint32_t kXpubVersionMainnet = 0x0488b21e;
constexpr uint32_t kTpubVersionTestnet = 0x043587cf;

const char *hrp_for_network(Network network) {
  return network == Network::kMainnet ? "bc" : "tb";
}

uint32_t coin_type_for_network(Network network) {
  return network == Network::kMainnet ? kCoinTypeMainnet : kCoinTypeTestnet;
}

uint32_t xpub_version_for_network(Network network) {
  return network == Network::kMainnet ? kZpubVersionMainnet
                                      : kVpubVersionTestnet;
}

} // namespace

bool derive_master_key(const char *mnemonic, const char *passphrase,
                       Network network, MasterKey *out) {
  if (mnemonic == nullptr || passphrase == nullptr || out == nullptr) {
    return false;
  }
  *out = MasterKey{};

  uint8_t seed[64];
  mnemonic_to_seed(mnemonic, passphrase, seed, nullptr);

  HDNode node;
  bool ok = hdnode_from_seed(seed, sizeof(seed), SECP256K1_NAME, &node) == 1;
  memzero(seed, sizeof(seed));
  if (!ok) {
    return false;
  }

  uint32_t master_fingerprint = hdnode_fingerprint(&node);

  ok = ok && hdnode_private_ckd(&node, kPurposeBip84) == 1;
  ok = ok && hdnode_private_ckd(&node, coin_type_for_network(network)) == 1;
  if (!ok) {
    wipe_node(&node);
    return false;
  }
  uint32_t account_parent_fingerprint = hdnode_fingerprint(&node);

  ok = hdnode_private_ckd(&node, kAccountHardened) == 1;
  if (!ok) {
    wipe_node(&node);
    return false;
  }

  out->account_node = node;
  out->master_fingerprint = master_fingerprint;
  out->account_parent_fingerprint = account_parent_fingerprint;
  out->network = network;
  out->valid = true;

  memzero(&node, sizeof(node));
  return true;
}

bool derive_child_node(const MasterKey &mk, uint32_t change, uint32_t index,
                       HDNode *out_node) {
  if (!mk.valid || out_node == nullptr) {
    return false;
  }
  HDNode node = mk.account_node;
  bool ok = hdnode_private_ckd(&node, change) == 1 &&
            hdnode_private_ckd(&node, index) == 1;
  if (!ok) {
    wipe_node(&node);
    return false;
  }
  *out_node = node;
  memzero(&node, sizeof(node));
  return true;
}

bool derive_address(const MasterKey &mk, uint32_t change, uint32_t index,
                    char *out_addr, size_t out_len) {
  if (out_addr == nullptr || out_len == 0) {
    return false;
  }
  HDNode node;
  if (!derive_child_node(mk, change, index, &node)) {
    return false;
  }
  if (hdnode_fill_public_key(&node) != 0) {
    wipe_node(&node);
    return false;
  }
  uint8_t pubkeyhash[20];
  ecdsa_get_pubkeyhash(node.public_key, node.curve->hasher_pubkey,
                       pubkeyhash);
  wipe_node(&node);

  bool ok = segwit_addr_encode(out_addr, hrp_for_network(mk.network), 0,
                               pubkeyhash, sizeof(pubkeyhash)) == 1;
  memzero(pubkeyhash, sizeof(pubkeyhash));
  if (!ok) {
    out_addr[0] = '\0';
  }
  (void)out_len; // segwit_addr_encode exige buffer >= 73 + strlen(hrp); ver keys.h
  return ok;
}

namespace {

bool serialize_account_pub(const MasterKey &mk, uint32_t version, char *out, size_t out_len) {
  if (!mk.valid || out == nullptr) {
    return false;
  }
  HDNode node = mk.account_node;
  if (hdnode_fill_public_key(&node) != 0) {
    memzero(&node, sizeof(node));
    return false;
  }
  size_t written =
      hdnode_serialize_public(&node, mk.account_parent_fingerprint, version, out, out_len);
  memzero(&node, sizeof(node));
  return written > 0;
}

uint64_t descriptor_polymod(uint64_t c, int val) {
  uint8_t c0 = static_cast<uint8_t>(c >> 35);
  c = ((c & 0x7ffffffffull) << 5) ^ static_cast<uint64_t>(val);
  if (c0 & 1) c ^= 0xf5dee51989ull;
  if (c0 & 2) c ^= 0xa9fdca3312ull;
  if (c0 & 4) c ^= 0x1bab10e32dull;
  if (c0 & 8) c ^= 0x3706b1677aull;
  if (c0 & 16) c ^= 0x644d626ffdull;
  return c;
}

} // namespace

bool serialize_account_xpub(const MasterKey &mk, char *out, size_t out_len) {
  return serialize_account_pub(mk, xpub_version_for_network(mk.network), out, out_len);
}

// Algoritmo de referencia do BIP380 (DescriptorChecksum do Bitcoin Core).
bool descriptor_checksum(const char *desc, char out[9]) {
  static const char kInputCharset[] =
      "0123456789()[],'/*abcdefgh@:$%{}"
      "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
      "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
  static const char kChecksumCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  if (desc == nullptr || out == nullptr) return false;

  uint64_t c = 1;
  int cls = 0;
  int cls_count = 0;
  for (const char *p = desc; *p != '\0'; p++) {
    const char *hit = strchr(kInputCharset, *p);
    if (hit == nullptr) return false;
    int pos = static_cast<int>(hit - kInputCharset);
    c = descriptor_polymod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    if (++cls_count == 3) {
      c = descriptor_polymod(c, cls);
      cls = 0;
      cls_count = 0;
    }
  }
  if (cls_count > 0) c = descriptor_polymod(c, cls);
  for (int j = 0; j < 8; j++) c = descriptor_polymod(c, 0);
  c ^= 1;
  for (int j = 0; j < 8; j++) out[j] = kChecksumCharset[(c >> (5 * (7 - j))) & 31];
  out[8] = '\0';
  return true;
}

bool build_descriptor(const MasterKey &mk, uint32_t change, char *out, size_t out_len) {
  if (out == nullptr) return false;
  char xpub[XPUB_MAXLEN];
  uint32_t version =
      mk.network == Network::kMainnet ? kXpubVersionMainnet : kTpubVersionTestnet;
  if (!serialize_account_pub(mk, version, xpub, sizeof(xpub))) return false;
  char fp[9];
  format_fingerprint(mk.master_fingerprint, fp);
  int n = snprintf(out, out_len, "wpkh([%s/84h/%dh/0h]%s/%lu/*)", fp,
                   mk.network == Network::kMainnet ? 0 : 1, xpub,
                   static_cast<unsigned long>(change));
  if (n <= 0 || static_cast<size_t>(n) + 9 >= out_len) return false; // + "#" + 8 chars
  char sum[9];
  if (!descriptor_checksum(out, sum)) return false;
  snprintf(out + n, out_len - n, "#%s", sum);
  return true;
}

void wipe_node(HDNode *node) {
  if (node != nullptr) {
    memzero(node, sizeof(HDNode));
  }
}

void wipe(MasterKey *mk) {
  if (mk != nullptr) {
    wipe_node(&mk->account_node);
    mk->master_fingerprint = 0;
    mk->account_parent_fingerprint = 0;
    mk->valid = false;
  }
}

void format_fingerprint(uint32_t fingerprint, char out[9]) {
  static const char kHex[] = "0123456789abcdef";
  for (int i = 0; i < 8; i++) {
    int shift = (7 - i) * 4;
    out[i] = kHex[(fingerprint >> shift) & 0xf];
  }
  out[8] = '\0';
}

} // namespace btcseed
