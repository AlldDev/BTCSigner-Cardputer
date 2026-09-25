# trezor_crypto (vendoring por "trampolim")

Este diretorio NAO contem codigo criptografico proprio. Cada arquivo `*.c`
aqui e um trampolim de uma linha:

```c
#include "../trezor-firmware/crypto/<arquivo>.c"
```

que inclui, textualmente e sem nenhuma modificacao, o arquivo `.c` original
do submodulo `firmware/lib/trezor-firmware` (pinado em um commit especifico,
ver raiz do repositorio para o hash). Isso existe por um motivo de build,
nao de auditoria de codigo:

- `firmware/lib/trezor-firmware/crypto/` e o diretorio `crypto/` completo do
  monorepo trezor-firmware, que inclui suporte a Ethereum, NEM, Monero,
  Cardano, SLIP-39, testes, fuzzers e ferramentas com `main()` proprio. Se o
  PlatformIO compilasse esse diretorio inteiro como uma biblioteca, o build
  quebraria (multiplos `main`, dependencias externas como libsecp256k1-zkp
  ausentes) e traria uma superficie de codigo enorme e irrelevante para este
  firmware.
- Este diretorio (`trezor_crypto/`) e a lista explicita e auditavel de QUAIS
  arquivos do trezor-crypto este firmware realmente usa. Qualquer arquivo do
  submodulo que nao tenha um trampolim aqui simplesmente nunca e compilado.
- Nenhum arquivo do submodulo e editado. Para conferir que o codigo
  compilado e byte-a-byte o codigo upstream, basta olhar o alvo do
  `#include` e comparar com o commit pinado do submodulo.

## Arquivos incluidos e por que

| Trampolim | Motivo |
|---|---|
| `memzero.c` | zerar buffers de segredo (seed, chaves, PSBT parcial) |
| `rand.c` | fonte de aleatoriedade exigida pela API do trezor-crypto (a entropia real da seed vem do usuario, nao deste RNG) |
| `consteq.c` | comparacao em tempo constante usada pelo bip39.c |
| `sha2.c` | SHA-256/SHA-512 (PBKDF2, hashes de PSBT, checksum BIP39) |
| `ripemd160.c` | HASH160 para enderecos P2WPKH |
| `hmac.c` | HMAC-SHA512 (BIP32) |
| `pbkdf2.c` | PBKDF2-HMAC-SHA512 (mnemonic -> seed BIP39) |
| `bignum.c` | aritmetica de bignum usada pelo secp256k1.c |
| `curves.c` | tabela de curvas (usada por bip32.c) |
| `nist256p1.c` | referenciado por bip32.c (tabela de curvas); a curva P-256 em si nao e usada por este firmware |
| `secp256k1.c` | aritmetica da curva secp256k1 (Bitcoin) |
| `ecdsa.c` | assinatura/verificacao ECDSA sobre secp256k1 |
| `base58.c` | Base58Check (nao usado para enderecos P2WPKH, mas e dependencia de bip32.c) |
| `segwit_addr.c` | codificacao bech32 dos enderecos P2WPKH (bc1.../tb1...) |
| `bip39.c` | mnemonico -> seed (PBKDF2), validacao de checksum |
| `bip39_english.c` | wordlist BIP39 em ingles (2048 palavras), usada pelo autocomplete |
| `bip32.c` | derivacao hierarquica de chaves (BIP32/BIP84) |
| `address.c` | `address_prefix_bytes_len`/`address_write_prefix_bytes`/`address_check_prefix`, usados por funcoes de endereco legado dentro de `ecdsa.c` (nao usamos essas funcoes, mas `ecdsa.c` as define no mesmo arquivo, entao precisam linkar) |
| `rfc6979.c` | nonce deterministico (RFC6979) para ECDSA — caminho realmente usado na assinatura |
| `hmac_drbg.c` | dependencia de `rfc6979.c` |
| `hasher.c` | dispatcher de hash generico usado por `hdnode_fingerprint`/`hdnode_serialize*` |
| `blake256.c`, `blake2b.c`, `groestl.c`, `sha3.c` | outras familias de hash que o `switch` de `hasher.c` referencia para OUTRAS moedas — nunca exercitadas com `secp256k1_info` (que so usa SHA-256/RIPEMD-160), mas precisam linkar porque fazem parte do mesmo `switch` |

Todos os arquivos acima sao auto-contidos (sem dependencia de bibliotecas
externas ao trezor-firmware, ao contrario de `zkp_*.c`, que precisaria da
libsecp256k1-zkp vendorizada em outro lugar do monorepo e por isso nao e
usada — ver `ecdsa.c`, que so chama `zkp_ecdsa_*` quando
`USE_SECP256K1_ZKP_ECDSA` esta definido, o que nunca fazemos aqui).

## `ed25519_stub.c`

Este arquivo NAO e um trampolim — e codigo escrito para este projeto.
`bip32.c` e um arquivo generico multi-moeda com varios branches de fallback
para curvas que nao sao ECDSA (`node->curve->params == NULL`): ed25519,
ed25519-sha3, ed25519-keccak e curve25519. Esses branches chamam
`ed25519_sign()`, `ed25519_sign_sha3()`, `ed25519_sign_keccak()` (em
`hdnode_sign()`) e `curve25519_scalarmult()` (em `hdnode_get_shared_key()`).
Todos sao codigo morto para este firmware, porque toda `HDNode` aqui sempre
usa `secp256k1_info` (`params != NULL`), tomando sempre o branch ECDSA logo
acima de cada um. Ainda assim, o linker exige que os simbolos existam. Em
vez de vendorizar toda a implementacao ed25519-donna/curve25519-donna (varios
arquivos, mais Keccak/SHA3) so para satisfazer branches inalcancaveis,
`ed25519_stub.c` implementa esses quatro simbolos como stubs que preenchem a
saida com zeros. Isso e seguro porque:

1. Este firmware so cria `HDNode` com `&secp256k1_info` (ver `keys.cpp`).
2. Esses branches so sao alcancados se `node->curve->params == NULL`, o que
   nunca acontece aqui.
3. Os testes de vetores oficiais (BIP32/BIP39/BIP84) exercitam exatamente o
   caminho ECDSA/secp256k1, nunca os stubs.

Commit pinado do submodulo: `148e530180937bdf9aa5f5744862b909a90a1c70`
(trezor/trezor-firmware, diretorio `crypto/`).
