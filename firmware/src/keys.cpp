#include "keys.h"

#include <cstring>

extern "C" {
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "memzero.h"
#include "segwit_addr.h"
}

namespace btcseed {
namespace {

// Versoes estendidas SLIP-132 para BIP84 (P2WPKH nativo).
constexpr uint32_t kZpubVersionMainnet = 0x04b24746;
constexpr uint32_t kVpubVersionTestnet = 0x045f1cf6;

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

bool serialize_account_xpub(const MasterKey &mk, char *out, size_t out_len) {
  if (!mk.valid || out == nullptr) {
    return false;
  }
  HDNode node = mk.account_node;
  if (hdnode_fill_public_key(&node) != 0) {
    memzero(&node, sizeof(node));
    return false;
  }
  size_t written = hdnode_serialize_public(
      &node, mk.account_parent_fingerprint,
      xpub_version_for_network(mk.network), out, out_len);
  memzero(&node, sizeof(node));
  return written > 0;
}

bool find_change_index(const MasterKey &mk, const uint8_t pubkeyhash[20],
                       uint32_t scan_limit, uint32_t *out_index) {
  if (!mk.valid || pubkeyhash == nullptr || out_index == nullptr) {
    return false;
  }
  for (uint32_t index = 0; index < scan_limit; index++) {
    HDNode node;
    if (!derive_child_node(mk, kChangeInternal, index, &node)) {
      continue;
    }
    if (hdnode_fill_public_key(&node) != 0) {
      wipe_node(&node);
      continue;
    }
    uint8_t candidate[20];
    ecdsa_get_pubkeyhash(node.public_key, node.curve->hasher_pubkey,
                         candidate);
    wipe_node(&node);

    bool match = memcmp(candidate, pubkeyhash, sizeof(candidate)) == 0;
    memzero(candidate, sizeof(candidate));
    if (match) {
      *out_index = index;
      return true;
    }
  }
  return false;
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
