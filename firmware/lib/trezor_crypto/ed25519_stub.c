// Stub deliberado — ver lib/trezor_crypto/README.md, secao "ed25519_stub.c".
//
// bip32.c (trezor-firmware) referencia estes dois simbolos em um branch de
// hdnode_sign() que so e alcancado quando node->curve->params == NULL (curvas
// ed25519). Este firmware so usa secp256k1_info (params != NULL), entao esse
// branch e inalcancavel aqui. Em vez de vendorizar toda a ed25519-donna so
// para satisfazer o linker, os simbolos sao definidos como stubs inofensivos.
#include <stddef.h>
#include <stdint.h>

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];
typedef unsigned char curve25519_key[32];

void ed25519_sign(const unsigned char *m, size_t mlen,
                   const ed25519_secret_key sk, ed25519_signature RS) {
  (void)m;
  (void)mlen;
  (void)sk;
  for (size_t i = 0; i < sizeof(ed25519_signature); i++) {
    RS[i] = 0;
  }
}

void ed25519_sign_sha3(const unsigned char *m, size_t mlen,
                        const ed25519_secret_key sk, ed25519_signature RS) {
  (void)m;
  (void)mlen;
  (void)sk;
  for (size_t i = 0; i < sizeof(ed25519_signature); i++) {
    RS[i] = 0;
  }
}

// Idem, para o branch `#if USE_KECCAK` de hdnode_sign() (curva
// ed25519-keccak, usada por outras moedas — nunca por este firmware).
void ed25519_sign_keccak(const unsigned char *m, size_t mlen,
                         const ed25519_secret_key sk, ed25519_signature RS) {
  (void)m;
  (void)mlen;
  (void)sk;
  for (size_t i = 0; i < sizeof(ed25519_signature); i++) {
    RS[i] = 0;
  }
}

// Idem, para hdnode_get_shared_key() (ECDH sobre curve25519, so alcancavel
// quando node->curve->params == NULL — nunca o caso aqui).
void curve25519_scalarmult(curve25519_key mypublic, const curve25519_key secret,
                           const curve25519_key basepoint) {
  (void)secret;
  (void)basepoint;
  for (size_t i = 0; i < sizeof(curve25519_key); i++) {
    mypublic[i] = 0;
  }
}
