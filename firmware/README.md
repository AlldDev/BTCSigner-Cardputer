# BTCSigner Cardputer — firmware

Documentação técnica do firmware. Para a visão geral do projeto, ver o
[README principal](../README.md).

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#módulos">Módulos</a> ·
  <a href="#parser-de-psbt">Parser de PSBT</a> ·
  <a href="#microsd">microSD</a> ·
  <a href="#telas-e-teclado">Telas e teclado</a> ·
  <a href="#build">Build</a> ·
  <a href="#testes">Testes</a> ·
  <a href="#ausência-de-rádio">Ausência de rádio</a> ·
  <a href="#dependências-e-vendoring">Dependências</a> ·
  <a href="#modelo-de-ameaça">Modelo de ameaça</a>
</p>

---

## Status

**Validado em testnet num Cardputer real, ainda não usado em mainnet.** O núcleo criptográfico e o
parser de PSBT estão testados contra vetores oficiais e casos maliciosos no host. O fluxo de telas,
o teclado e a E/S no microSD rodam no aparelho físico: entrada de seed, aba CARTEIRA, listagem de
`.psbt` e assinatura gravando `*_signed.psbt` no cartão, tudo em testnet. O firmware **não deve
ser usado com fundos reais** antes do primeiro uso em mainnet com valores pequenos (ver
[O que falta](#o-que-falta)).

---

## Módulos

`src/` é plano. A divisão é entre **lógica pura testável no host** e **cola com o hardware**
(excluída do ambiente `native`).

| Módulo | Arquivo | Status |
|---|---|---|
| Config/constantes | `src/config.h` | feito |
| Derivação BIP32/BIP39/BIP84 | `src/keys.{h,cpp}` | feito, testado |
| Sessão (timeout, wipe) | `src/session.h` | feito, testado |
| Entrada de mnemônico + autocomplete | `src/mnemonic_input.{h,cpp}` | feito, testado |
| Passphrase (25ª palavra) | `src/passphrase_input.{h,cpp}` | feito, testado |
| Parser/validador/assinador de PSBT | `src/psbt.{h,cpp}` | feito, testado |
| Formatação da tela de revisão | `src/review_screens.{h,cpp}` | feito, testado |
| E/S no microSD (nomes/caminhos) | `src/sd_io_paths.cpp` (via `sd_io.h`) | feito, testado |
| E/S no microSD (hardware) | `src/sd_io.cpp` | feito, validado no aparelho |
| Primitivas de tela/teclado | `src/ui.{h,cpp}` | feito, validado no aparelho |
| Máquina de estados / loop principal | `src/main.cpp` | feito, validado no aparelho (testnet) |
| Hooks de plataforma do trezor-crypto | `src/trezor_platform.cpp` | feito |
| Vendoring do trezor-crypto | `lib/trezor_crypto/`, `lib/trezor-firmware/` (submódulo) | feito |

`session.h` não tem `.cpp`: a lógica inteira (timeout + wipe) cabe em métodos inline.

---

## Parser de PSBT

`src/psbt.{h,cpp}` é um parser BIP174 mínimo, escrito do zero sobre trezor-crypto (não usa a
uBitcoin — ver [Revisão da uBitcoin](#revisão-da-ubitcoin)). Suporta só PSBT versão 0, entradas
P2WPKH únicas (BIP84, sem P2SH-embutido nem P2WSH/multisig) e `SIGHASH_ALL`. Todo campo que o
parser não entende é preservado byte a byte e reescrito verbatim (exigência do BIP174 para campos
desconhecidos). Decisões de escopo:

- **Todo input da PSBT deve ser nosso**: cada input precisa ter `PSBT_IN_WITNESS_UTXO` e
  `PSBT_IN_BIP32_DERIVATION` com o fingerprint da sessão e caminho `m/84'/coin'/0'/{0,1}/i`. Não há
  suporte a PSBTs multi-signatário/coinjoin — um input que não seja nosso é rejeitado
  (fail-closed), nunca ignorado silenciosamente.
- **Tx anterior obrigatória**: cada input também precisa de `PSBT_IN_NON_WITNESS_UTXO`. O firmware
  confere que o txid dela é o do outpoint e que o output gasto tem o mesmo valor/script do
  `witness_utxo` — sem isso, duas PSBTs com valores falsos diferentes combinam numa tx com taxa
  inflada (CVE-2020-14199). Sparrow, Bitcoin Core e Electrum já incluem o campo; tx anteriores muito
  grandes podem estourar o limite de 32 KB.
- **Verificação dupla do input**: além do fingerprint/caminho reivindicado, o firmware deriva a
  chave e confere que o pubkey e o hash160 batem byte a byte com a PSBT — uma PSBT poderia alegar
  caminho/fingerprint corretos mas apontar para um UTXO de outra chave.
- **Outputs externos**: P2WPKH/P2WSH/P2TR/P2PKH/P2SH são reconhecidos e exibidos com endereço
  decodificado; um script não reconhecido (ex: `OP_RETURN`, multisig bruto) faz o parser REJEITAR a
  PSBT inteira, em vez de assinar algo que não pode ser mostrado com clareza.
- **Troco falsificado não invalida a PSBT inteira**: um output que alega
  (`PSBT_OUT_BIP32_DERIVATION`) ser troco desta sessão mas cujo hash160 não bate com a derivação é
  marcado `claimed_change_invalid` e exibido como destino externo, com aviso.
- **"Rede compatível"**: uma scriptPubKey não carrega nenhum byte de rede (isso é só convenção da
  STRING de endereço) — não há o que cruzar a partir da PSBT. O firmware sempre formata endereços
  usando a rede da sessão; ver o comentário em `psbt.cpp::validate()`.
- **Limites** (`config.h`): 32 KB por arquivo, 20 inputs, 20 outputs. Avisos de taxa alta acima de
  5% do valor enviado ou 100.000 sats, e de índice de troco acima de 1000.
- Instâncias de `Psbt` têm dezenas de KB de buffers internos e devem ser **estáticas/globais, nunca
  alocadas na stack** (stacks de task do ESP32 têm 8–16 KB).

---

## microSD

Dividido por testabilidade: `sd_io_paths.cpp` tem a lógica pura de nomes/caminhos (sanitização,
junção de caminho, nome `_signed`), sem include de Arduino — roda e é testada no host. `sd_io.cpp`
tem a E/S de fato (Arduino `SD.h`/`SPI.h`) e só compila no ambiente `cardputer`.

- **Pinos** (SCK=40, MISO=39, MOSI=14, CS=12, SPI a 25 MHz): confirmados no exemplo oficial
  `examples/Basic/sdcard/sdcard.ino` do repositório `m5stack/M5Cardputer`. A lib M5Cardputer não
  expõe esses pinos via API própria — hardcodá-los é o padrão da própria M5Stack.
- **Escrita atômica**: toda gravação (PSBT assinada, `wallet_export.txt`) vai primeiro para um
  `.tmp` e só é renomeada se completar por inteiro; se o cartão sair no meio, o `.tmp` é removido e
  a função retorna false — nunca fica um arquivo parcial com o nome final.
- **Nomes de arquivo**: só letras, dígitos, `-`, `_`, `.` e espaço; `..`, barras ou qualquer coisa
  fora desse conjunto é rejeitada (path traversal). Ao listar, arquivos fora do padrão são omitidos
  do menu.
- **Layout no cartão**: PSBTs em `/psbt/*.psbt` (até 32 listadas), assinadas gravadas como
  `<nome>_signed.psbt`, export em `/wallet_export.txt`.

---

## Telas e teclado

`ui.cpp` só tem primitivas (tela + leitura de teclado); toda a máquina de estados das telas
(entrada de seed, passphrase, confirmação de fingerprint, menu, revisão de PSBT, export de xpub,
endereço de recebimento) mora em `main.cpp`, compondo os módulos testados no host.

**O teclado do Cardputer não tem Esc nem setas.** Isso só foi descoberto lendo o header/`.cpp`
reais da versão instalada da lib (`M5Cardputer/src/utility/Keyboard/Keyboard.h`) — uma pesquisa
inicial tinha encontrado uma API com booleanos `esc`/`up`/`down`/… que **não existe** na versão
1.1.1 publicada; o build pegou o erro na hora (`'struct KeysState' has no member named 'esc'`). A
struct real só tem `tab/fn/shift/ctrl/opt/alt/del/enter/space` + os caracteres em `word`. Duas
convenções cobrem a lacuna (documentadas em `ui.h`):

- **Voltar/Cancelar = tecla ESC** (canto superior esquerdo, entregue pela lib como `` ` ``). Como
  `` ` `` também é caractere válido de passphrase, **Fn+`** digita o literal.
- **Navegação = `;` `,` `.` `/`** (que têm setas serigrafadas no teclado). Como são caracteres
  imprimíveis, tratá-las como direção ou texto é decisão de `main.cpp` por tela (na passphrase, por
  exemplo, são só caracteres).

**Visual.** Paleta escura com laranja BTC (tokens RGB565 em `ui.h`), header com título + rede + SD
+ bateria, rodapé com dica/ação, splash de boot e telas de sucesso/erro com ícone. Textos só em
ASCII (a fonte 6x8 do M5GFX não tem acentos).

- **Menu em abas**: `,` `/` trocam de aba, `;` `.` movem, Enter abre. ASSINAR = lista de `.psbt`
  do SD; CARTEIRA = fingerprint, rede, script, exportar xpub, endereço de recebimento; SESSAO =
  brilho (Enter cicla 30/50/70/100%, não persiste), bloqueio automático (informativo) e encerrar
  sessão.
- **Fontes**: conteúdo em `AsciiFont8x16` (29 caracteres/linha com margem de 4 px),
  header/rodapé/rótulos em 6x8. Endereços sempre completos: P2WPKH ocupa 2 linhas, P2WSH/P2TR 3. Se
  não couber, `draw_address` cai para 6x8 em vez de cortar. A quebra (`wrap_next_line`) é testada
  em `test_review_screens`.
- **Tela de fingerprint** mostra também o endereço #0 (`m/84'/coin'/0'/0/0`) completo. O Ian
  Coleman não exibe master fingerprint, mas esse endereço tem que bater com a 1ª linha de *Derived
  Addresses* da aba BIP84 (com a mesma passphrase). O zpub em CARTEIRA → Exportar xpub tem que
  bater com *Account Extended Public Key*. "Baixar arquivo" grava também os output descriptors
  BIP380 (`wpkh([fp/84h/0h/0h]xpub/0/*)#checksum` e `/1/*`), importáveis direto no Sparrow/Core.
- **TESTNET** aparece em vermelho no header de toda tela depois que a rede foi escolhida.
- **Revisão**: cada saída é mostrada uma a uma com o endereço COMPLETO, depois o resumo de taxa e,
  por fim, **segurar Enter por `kHoldToSignMs` (1,5 s)** para assinar. Soltar antes zera a barra, e
  o Enter vindo da tela anterior não conta: é preciso soltar e segurar de novo.
- **Sessão** expira após `kSessionTimeoutMs` (3 min) sem uso, apagando a chave da RAM.

---

## Build

Pré-requisitos: Python 3 + PlatformIO (`pip install --user platformio`) e, para os testes nativos,
um compilador C++ no host (`gcc-c++`/`g++`).

**Antes do primeiro build**, inicialize o submódulo `lib/trezor-firmware` — ele vem vazio num clone
normal e é de onde vêm `bip32.h`/`bip39.c`/etc.:

```sh
git submodule update --init --recursive
```

Sem isso o build falha com `fatal error: bip32.h: No such file or directory`.

Três ambientes em `platformio.ini`, todos rodados de dentro de `firmware/`:

```sh
pio run -e cardputer          # release para o hardware (Serial/USB-CDC desligados)
pio run -e cardputer-debug    # mesmo, com CORE_DEBUG_LEVEL=3 e Serial ligado
pio test -e native            # só host, para os testes
```

O build de release gera `.pio/build/cardputer/firmware.bin`.

**RAM é a restrição que manda** (ESP32-S3, 320 KB, sem PSRAM). O build inicial com
`kMaxPsbtFileSize = 64 KB` media 81% de RAM; reduzido para 16 KB caiu para ~29%; depois subido para
32 KB (~46%) para caber a tx anterior completa (`non_witness_utxo`), agora obrigatória. Cada KB de
limite custa ~3,3 KB de RAM.

### Merge bin para o M5Launcher

O M5Launcher instala a partir de um binário mesclado (bootloader + partition table + app), não do
`firmware.bin` isolado. Depois de um `pio run -e cardputer`, a partir da raiz do repositório:

```sh
esptool.py --chip esp32s3 merge_bin -o firmware/.pio/build/cardputer/merged.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     firmware/.pio/build/cardputer/bootloader.bin \
  0x8000  firmware/.pio/build/cardputer/partitions.bin \
  0x10000 firmware/.pio/build/cardputer/firmware.bin
```

(Offsets padrão do target `m5stack-stamps3`/ESP32-S3 com bootloader clássico; confirme com
`pio run -e cardputer -v` se a placa usar offsets diferentes.) Copie o **`merged.bin`** para o
microSD e instale pelo M5Launcher.

---

## Testes

```sh
pio test -e native                           # todas as suítes
pio test -e native -f test_review_screens    # uma suíte, pelo nome do diretório
```

Cada diretório em `test/` é um binário Unity independente rodando no host: `test_bip32_vectors`,
`test_bip39_vectors`, `test_bip84_vectors`, `test_mnemonic_input`, `test_passphrase_input`,
`test_psbt_parse`, `test_review_screens`, `test_sd_io_paths`, `test_session`. `ui.cpp`, `main.cpp`
e `sd_io.cpp` dependem de hardware e ficam de fora do `native`.

Vetores e casos cobertos:

- **BIP39**: vetores oficiais (12, 18 e 24 palavras) com passphrase `TREZOR`, de
  `trezor/python-mnemonic/vectors.json`.
- **BIP32**: Test vector 1 (derivação hardened em profundidade) e Test vector 2 (índice hardened
  máximo `2147483647'` e derivação não-hardened), de `bip-0032.mediawiki`.
- **BIP84**: vetor oficial de `bip-0084.mediawiki` (zpub da conta + endereços de recebimento/troco),
  exercitando a pilha completa deste firmware (mnemonic → seed → conta → zpub/endereços), não só o
  trezor-crypto cru.
- **PSBT**: uma PSBT válida construída à mão (input nosso + output externo + troco verdadeiro) —
  valida, calcula taxa/aviso, assina, e a assinatura é conferida com `ecdsa_verify_digest` contra um
  sighash BIP143 recalculado de forma independente do código de produção (pegou um bug real: um
  array de scriptCode com um elemento a menos, que deslocava `OP_EQUALVERIFY`/`OP_CHECKSIG`). Casos
  maliciosos/malformados: fingerprint errado, sighash ≠ ALL, troco falsificado, arquivo truncado,
  magic corrompido, scriptSig não-vazio na unsigned tx, round-trip binário/base64, entre outros.

---

## Ausência de rádio

Nenhum arquivo deste repositório inclui `WiFi.h`, `BLEDevice.h`, `esp_wifi.h` ou `esp_bt.h`. Como
"nenhum arquivo nosso inclui" não prova que uma dependência não puxe rádio por baixo, o binário
final (`pio run -e cardputer`) foi inspecionado com `xtensa-esp32s3-elf-nm firmware.elf`: não há
`esp_wifi_init`, `esp_bt_controller_init` nem símbolos bluedroid/nimble de código (só limites de
seção de memória que o linker script do chip sempre declara). O único símbolo relacionado a BT é
`esp_bt_controller_mem_release`, que o boilerplate do arduino-esp32 chama para LIBERAR a RAM
reservada ao controlador — o oposto de inicializá-lo.

**`hmac_sha256` colide com a stack WiFi.** O arduino-esp32 sempre linka `libwpa_supplicant.a`
(mesmo sem chamar nenhuma API de rádio), que define sua própria `hmac_sha256`, colidindo com a de
`hmac.c` do trezor-crypto ("multiple definition"). Resolvido com uma flag em `platformio.ini`
(`-Dhmac_sha256=btcseed_tc_hmac_sha256`, um `#define` de renomeação, não um patch no vendorizado).
Essa função específica (o wrapper one-shot, não Init/Update/Final) não é chamada por nada que este
firmware usa.

---

## Dependências e vendoring

Toda a criptografia vem do diretório `crypto/` do monorepo
[`trezor/trezor-firmware`](https://github.com/trezor/trezor-firmware), adicionado como submódulo em
`lib/trezor-firmware/`, pinado no commit `148e530180937bdf9aa5f5744862b909a90a1c70`. O repositório
standalone `trezor/trezor-crypto` está arquivado desde 2019 e não deve ser usado. A libsecp256k1 do
Bitcoin Core **não** é usada; o `secp256k1.c` do trezor-crypto, sim.

O submódulo usa `sparse-checkout` para trazer só `crypto/`. Nem todo arquivo é compilado:
`lib/trezor_crypto/` contém a lista explícita e auditável dos `.c` usados (trampolins `#include`,
sem modificar o upstream) — ver [`lib/trezor_crypto/README.md`](./lib/trezor_crypto/README.md) para
a lista e a justificativa de cada um, incluindo os dois casos de código próprio: stubs para símbolos
inalcançáveis (`ed25519_stub.c`) e os hooks de plataforma em `src/trezor_platform.cpp`
(`tc_fault_handler` e `random_buffer` — RNG de hardware no aparelho, `getrandom()` no host, usado
só para blinding de ECDSA, nunca como fonte da seed).

**Auditoria**: este projeto não implementa curva elíptica, hash, HMAC, PBKDF2 nem derivação
BIP32/39. As únicas linhas "sensíveis" próprias são os wrappers finos em `src/keys.cpp` (orquestra
chamadas ao trezor-crypto) e os dois hooks de plataforma.

### Revisão da uBitcoin

**Decisão: não usar a uBitcoin.** Revisão de `github.com/micro-bitcoin/uBitcoin` feita em
2026-09-23:

1. **Manutenção estagnada**: último push de código em 2023-03-26; 13 issues abertas sem resposta,
   incluindo compatibilidade com ESP-IDF/ESP32 recentes (#33, #38).
2. **Bug conhecido na área de PSBT**: issue #19, "PSBT double-signing creates invalid output"
   (2022-08-03, sem fix) — exatamente a superfície que este firmware dependeria.
3. **Positivo**: a aritmética de curva delega para trezor-crypto, mas o parsing/serialização BIP174
   em volta é código próprio da uBitcoin, e é ali que está o bug.
4. **Colisões de símbolo** sem correção: issues #28/#33 (`hmac_sha256`, `Network`) em builds ESP32
   recentes.

Como toda a criptografia já vem do trezor-crypto, o único ganho seria o parser BIP174 — justamente
onde há um bug conhecido. Daí o parser próprio, mínimo e com testes dedicados.

---

## Modelo de ameaça

- **Sem secure element**: nenhuma proteção contra ataques físicos avançados (glitching, power
  analysis, dump de RAM com o aparelho ligado e a seed carregada). Mitigado só pela posse física
  durante a sessão e pelo timeout de inatividade.
- **Sem câmera**: não há QR code; toda entrada/saída passa pelo microSD.
- **A segurança da seed depende da geração externa**: o firmware só valida o checksum BIP39, não
  como a seed foi gerada.

### Geração da seed fora do aparelho

Este firmware **nunca gera a seed**:

1. Baixe o HTML standalone do [Ian Coleman BIP39 Tool](https://github.com/iancoleman/bip39/releases)
   do release oficial e verifique o hash/assinatura.
2. Rode num computador offline, de preferência um live USB (ex: Tails), sem rede o tempo todo.
3. Use entropia física (ex: 99 lançamentos de dado de 6 faces para 256 bits) no campo de entropia,
   em vez de confiar só no gerador do navegador.
4. Anote as palavras à mão (papel ou metal) e o master fingerprint. Feche o navegador e desligue a
   máquina. Sem prints, arquivos ou área de transferência.
5. Digite as palavras no Cardputer a cada sessão e confira que o fingerprint exibido bate com o
   anotado.

---

## O que falta

- **Primeiro uso em mainnet** com valores pequenos.
- Tela opcional de revisão do mnemônico em grupos pequenos — não implementada, explicitamente
  opcional.
