// Wrapper fino sobre trezor-crypto (BIP32/BIP39/BIP84) para secp256k1.
//
// Nenhuma aritmetica de curva, hash ou HMAC e implementada aqui — tudo vem
// de lib/trezor_crypto (trezor-firmware/crypto). Este arquivo so organiza a
// derivacao de conta/endereco/troco conforme BIP84 e cuida da limpeza de
// memoria de cada estrutura que carrega material privado.
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"

extern "C" {
#include "bip32.h"
}

namespace btcseed {

// Chave mestra da sessao, derivada uma unica vez a partir do seed BIP39.
// `account_node` e o node em m/84'/coin'/0' (ja com a chave privada da
// conta) — os enderecos individuais sao derivados sob demanda a partir dele.
struct MasterKey {
  HDNode account_node{};             // m/84'/coin'/0'
  uint32_t master_fingerprint = 0;   // fingerprint de m (raiz), para PSBT/UI
  uint32_t account_parent_fingerprint = 0; // fingerprint de m/84'/coin', p/ zpub
  Network network = Network::kMainnet;
  bool valid = false;
};

// Deriva o seed BIP39 (PBKDF2) a partir do mnemonico + passphrase, e a
// partir dele a MasterKey em m/84'/coin'/0'. `mnemonic` deve ja ter passado
// por mnemonic_check() antes de chamar esta funcao. O buffer de seed
// intermediario e sempre zerado antes de retornar, sucesso ou falha.
bool derive_master_key(const char *mnemonic, const char *passphrase,
                       Network network, MasterKey *out);

// Deriva o node privado completo em m/84'/coin'/0'/change/index a partir da
// MasterKey (que ja e a subarvore da conta). O chamador e responsavel por
// chamar wipe_node() no resultado assim que terminar de usa-lo.
bool derive_child_node(const MasterKey &mk, uint32_t change, uint32_t index,
                       HDNode *out_node);

// Endereco P2WPKH (bech32) de m/84'/coin'/0'/change/index.
// out_addr deve ter pelo menos 74 bytes.
bool derive_address(const MasterKey &mk, uint32_t change, uint32_t index,
                    char *out_addr, size_t out_len);

// zpub (mainnet) / vpub (testnet) da conta, formato SLIP-132.
// out deve ter pelo menos XPUB_MAXLEN bytes.
bool serialize_account_xpub(const MasterKey &mk, char *out, size_t out_len);

// Verifica se (change, index) produz o hash160 fornecido — usado para
// confirmar que um output de troco realmente pertence a esta seed antes de
// exibi-lo como "Troco (verificado)" (secao 9 do spec). Testa apenas
// change=1 (troco interno) nos primeiros `scan_limit` indices.
bool find_change_index(const MasterKey &mk, const uint8_t pubkeyhash[20],
                       uint32_t scan_limit, uint32_t *out_index);

// Zera todo material privado das estruturas (private_key, chain_code,
// private_key_extension, fingerprint). Seguro para chamar mais de uma vez.
void wipe_node(HDNode *node);
void wipe(MasterKey *mk);

// Formata um fingerprint BIP32 como 8 digitos hex minusculos + terminador
// nulo (out deve ter pelo menos 9 bytes). Usado para o usuario conferir o
// master fingerprint contra o anotado na geracao da seed (secao 7 do spec).
void format_fingerprint(uint32_t fingerprint, char out[9]);

} // namespace btcseed
