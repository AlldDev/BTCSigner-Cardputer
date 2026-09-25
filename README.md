# BTCSeed-Cardputer

Firmware para o M5Stack Cardputer (ESP32-S3) que funciona como signer Bitcoin
stateless e air-gapped: a seed BIP39 e digitada a cada sessao, nada secreto e
persistido, e o dispositivo assina PSBTs via microSD. Ver `spec.md` para a
especificacao completa.

**Status: builda para o hardware, ainda nao validado em uma tela/teclado
reais.** Todos os modulos da secao 13 do spec existem e `pio run -e
cardputer` gera `firmware.bin` com sucesso (RAM ~29%, Flash ~17%). O nucleo
criptografico e o parser de PSBT estao testados contra vetores oficiais e
casos maliciosos no host. O que falta e validacao com o dispositivo fisico
em maos: o FLUXO de telas (textos, paginacao, teclas) foi escrito com
cuidado a partir da API real da lib instalada, mas nunca foi visto
acendendo numa tela de verdade. Este firmware **ainda nao foi usado para
assinar uma transacao real** e nao deve ser usado com fundos reais antes do
checklist da secao 14 do spec estar completo (ver "O que falta" abaixo).

## O que ja existe

| Modulo | Arquivo | Status |
|---|---|---|
| Derivacao BIP32/BIP39/BIP84 | `firmware/src/keys.{h,cpp}` | feito, testado |
| Entrada de mnemonico + autocomplete | `firmware/src/mnemonic_input.{h,cpp}` | feito, testado |
| Sessao (timeout, wipe) | `firmware/src/session.h` | feito, testado |
| Parser/validador/assinador de PSBT | `firmware/src/psbt.{h,cpp}` | feito, testado |
| E/S no microSD (nomes/caminhos) | `firmware/src/sd_io_paths.cpp` (via `sd_io.h`) | feito, testado |
| E/S no microSD (hardware) | `firmware/src/sd_io.cpp` | feito, **nao compilado contra hardware ainda** |
| Vetores oficiais BIP32/39/84 | `firmware/test/test_bip{32,39,84}_vectors` | passando (24 casos) |
| PSBT valido + malicioso/malformado | `firmware/test/test_psbt_parse` | passando (9 casos) |
| Nomes de arquivo sanitizados | `firmware/test/test_sd_io_paths` | passando (11 casos) |
| Config/constantes | `firmware/src/config.h` | feito |
| Vendoring do trezor-crypto | `firmware/lib/trezor_crypto/`, `firmware/lib/trezor-firmware/` (submodulo) | feito |
| Passphrase (25a palavra) | `firmware/src/passphrase_input.{h,cpp}` | feito, testado |
| Formatacao da tela de revisao | `firmware/src/review_screens.{h,cpp}` | feito, testado |
| Primitivas de tela/teclado | `firmware/src/ui.{h,cpp}` | feito, builda para o hardware |
| Maquina de estados / loop principal | `firmware/src/main.cpp` | feito, builda para o hardware |
| Passphrase | `firmware/test/test_passphrase_input` | passando (7 casos) |
| Formatacao de revisao | `firmware/test/test_review_screens` | passando (10 casos) |

## `psbt.{h,cpp}` — o que faz e limitacoes assumidas

Parser BIP174 minimo, escrito do zero sobre trezor-crypto (nao usa a
uBitcoin — ver "Revisao da uBitcoin" abaixo). Suporta so o subconjunto da
secao 9 do spec: PSBT versao 0, entradas P2WPKH unicas (BIP84, sem
P2SH-embutido nem P2WSH/multisig), SIGHASH_ALL. Todo campo do PSBT que o
parser nao entende e preservado byte a byte e reescrito verbatim (exigencia
do proprio BIP174 para campos desconhecidos). Decisoes de escopo explicitas:

- **Todo input da PSBT deve ser nosso**: cada input precisa ter
  `PSBT_IN_WITNESS_UTXO` e `PSBT_IN_BIP32_DERIVATION` com o fingerprint da
  sessao e caminho `m/84'/coin'/0'/{0,1}/i`. Nao ha suporte a PSBTs
  multi-signatario/coinjoin nesta v1 — um input que nao seja nosso e
  rejeitado (fail-closed), nunca ignorado silenciosamente.
- **Verificacao dupla do input**: alem de conferir o fingerprint/caminho
  reivindicado, o firmware deriva a chave correspondente e confere que o
  pubkey e o hash160 batem byte a byte com o que esta na PSBT — uma PSBT
  poderia alegar um caminho/fingerprint corretos mas apontar para um UTXO
  que na verdade nao corresponde aquela chave.
- **Outputs externos**: qualquer tipo de script (P2WPKH/P2WSH/P2TR/P2PKH/
  P2SH) reconhecido e exibido com endereco decodificado; um script nao
  reconhecido (ex: `OP_RETURN`, multisig bruto) faz o parser REJEITAR a PSBT
  inteira, em vez de arriscar assinar algo que nao pode ser mostrado ao
  usuario com clareza (confirmacao humana obrigatoria, secao 3 do spec).
- **Troco falsificado nao invalida a PSBT inteira**: um output que alega
  (`PSBT_OUT_BIP32_DERIVATION`) ser troco desta sessao mas cujo hash160 nao
  bate com a derivacao reivindicada e marcado `claimed_change_invalid` e
  exibido como destino externo com aviso — exatamente o comportamento
  pedido na secao 9 do spec.
- **"Rede compativel"**: uma scriptPubKey Bitcoin nao carrega nenhum byte
  de rede (isso e so uma convencao de como a STRING de endereco e
  formatada) — nao ha o que cruzar a partir do proprio PSBT. O firmware
  sempre formata qualquer endereco que exibe usando a rede da sessao; ver o
  comentario em `psbt.cpp::validate()` para o detalhe.
- Instancias de `Psbt` tem dezenas de KB de buffers internos e devem ser
  estaticas/globais, nunca alocadas na stack.

## `sd_io.{h,cpp}` — o que faz e limitacoes assumidas

Dividido em duas partes por testabilidade: `sd_io_paths.cpp` tem a logica
pura de nomes/caminhos (sanitizacao, juncao de caminho, nome `_signed`),
sem nenhum include de Arduino — roda e e testada no host. `sd_io.cpp` tem a
E/S de fato (Arduino `SD.h`/`SPI.h`), so compila no ambiente `cardputer`.

- **Pinos do slot de microSD** (SCK=40, MISO=39, MOSI=14, CS=12, SPI a 25
  MHz): confirmados no exemplo oficial `examples/Basic/sdcard/sdcard.ino` do
  repositorio `m5stack/M5Cardputer`. A biblioteca M5Unified/M5Cardputer nao
  expoe esses pinos via API propria (nem o exemplo oficial usa uma) —
  hardcoda-los como constantes nomeadas e o padrao usado pela propria
  M5Stack, nao um desvio.
- **Escrita atomica**: toda gravacao (PSBT assinada, `wallet_export.txt`) vai
  primeiro para um arquivo `.tmp` e so e renomeada para o nome final se
  completar por inteiro; se o cartao for removido no meio do caminho, o
  `.tmp` e removido e a funcao retorna false — nunca fica um arquivo parcial
  com o nome final (secao 11 do spec).
- **Nomes de arquivo**: so letras, digitos, `-`, `_`, `.` e espaco; nomes com
  `..`, barras, ou fora desse conjunto sao rejeitados (path traversal). Ao
  listar, um arquivo com nome fora desse padrao e simplesmente omitido do
  menu — nunca usado nem exibido.
- **Compila contra o hardware real** (`pio run -e cardputer` — ver "Build"
  abaixo) usando a API oficial do `SD.h` do core arduino-esp32. Ainda falta
  testar fisicamente ler/gravar num cartao de verdade.

## `ui.{h,cpp}` e `main.cpp` — o que faz e o que a pesquisa revelou

`ui.cpp` so tem primitivas (tela + leitura de teclado); toda a maquina de
estados das telas (secoes 6-11 do spec: entrada de seed, passphrase,
confirmacao de fingerprint, menu, revisao de PSBT, export de xpub, endereco
de recebimento) mora em `main.cpp`, compondo os modulos ja testados no host.

**O teclado fisico do Cardputer nao tem tecla Esc nem setas dedicadas.**
Isso so foi descoberto lendo o header/`.cpp` reais da versao instalada da
lib (`M5Cardputer/src/utility/Keyboard/Keyboard.h` e `Keyboard.cpp`) — uma
pesquisa inicial (antes de instalar a lib de verdade) tinha encontrado uma
API diferente (com booleanos `esc`/`up`/`down`/`left`/`right`) que **nao
existe** na versao 1.1.1 realmente publicada; o build contra o hardware
pegou esse erro na hora (`'struct KeysState' has no member named 'esc'`).
A struct real so tem `tab/fn/shift/ctrl/opt/alt/del/enter/space` + os
caracteres imprimiveis em `word`. Duas convencoes deste firmware cobrem a
lacuna, documentadas em `ui.h`:

- **"Cancelar" = Ctrl+C** (universal, detectado dentro de `ui.cpp`) — nao
  conflita com a passphrase de texto livre porque ninguem digita um 'C' de
  verdade segurando Ctrl (isso e Shift+c).
- **Navegacao = teclas `;` `,` `.` `/`** (que tem setas serigrafadas no
  proprio teclado do Cardputer, uso pretendido pela M5Stack) — como sao
  caracteres imprimiveis validos, a decisao de trata-las como direcao ou
  como texto literal e de `main.cpp`, dependendo da tela atual (na
  passphrase, por exemplo, elas sao so caracteres normais).

**`hmac_sha256` colide com a stack WiFi do ESP32.** O framework
arduino-esp32 sempre linka `libwpa_supplicant.a` (parte do WiFi/BLE do
ESP-IDF, mesmo sem chamar nenhuma API de radio), e essa lib define sua
propria funcao `hmac_sha256` — mesmo nome, funcao diferente, colidindo com
`hmac_sha256` de `hmac.c` do trezor-crypto (linker error: "multiple
definition"). Resolvido com uma unica flag de compilador em
`platformio.ini` (`-Dhmac_sha256=btcseed_tc_hmac_sha256`, so um `#define`
de renomeacao, nao um patch no arquivo vendorizado) — essa funcao
especifica (o wrapper "one-shot" de HMAC-SHA256, nao os passos
Init/Update/Final) nao e chamada por nada que este firmware usa.

**RAM**: o build inicial (`kMaxPsbtFileSize = 64 KB`) media 81% de uso de
RAM (267 KB de 320 KB — este Cardputer nao tem PSRAM habilitada no board
usado). Reduzido para 16 KB (generoso o bastante para 20 inputs + 20
outputs, o proprio limite do firmware — ver comentario em `config.h`),
caindo para ~29% de uso.

**Ausencia de radio, confirmada no binario real** (nao so por grep no
codigo-fonte): `xtensa-esp32s3-elf-nm firmware.elf` nao mostra
`esp_wifi_init` nem `esp_bt_controller_init` nem simbolos bluedroid/nimble
de codigo (so limites de secao de memoria, que o linker script do chip
sempre define). O unico simbolo relacionado a BT presente e
`esp_bt_controller_mem_release` — o oposto de inicializar: e a funcao que
o proprio boilerplate do framework arduino-esp32 chama para LIBERAR a RAM
reservada ao controlador de Bluetooth quando ele nao e usado.

## O que falta

- **Validacao com o hardware fisico em maos**: o fluxo de telas builda mas
  nunca foi visto rodando — cores, quebra de linha, tempo de resposta do
  teclado, tudo isso precisa de ajuste visual num Cardputer real.
- Tela opcional de revisao do mnemonico em grupos pequenos (secao 6.4 do
  spec, "sob demanda") — nao implementada, e explicitamente opcional.
- Checklist de auditoria completo da secao 14 do spec: vetores oficiais e
  PSBTs maliciosos basicos feitos, ausencia de radio confirmada no binario
  linkado; falta o teste end-to-end com Sparrow em testnet/signet (exportar
  xpub, montar watch-only, criar PSBT, assinar no Cardputer, finalizar e
  transmitir) e o primeiro uso em mainnet com valores pequenos.

## Build

Pre-requisitos: Python 3 + PlatformIO (`pip install --user platformio`) e,
para os testes nativos, um compilador C++ no host (`gcc-c++`/`g++`).

### Rodar os testes de criptografia/PSBT (sem hardware)

```sh
cd firmware
pio test -e native
```

Isso builda e roda cada suite em `firmware/test/*/` como um binario
independente no host. Hoje: `test_bip39_vectors`, `test_bip32_vectors`,
`test_bip84_vectors`, `test_session`, `test_mnemonic_input`, `test_psbt_parse`,
`test_sd_io_paths`, `test_passphrase_input`, `test_review_screens` (61 casos,
todos passando). `ui.cpp` e `main.cpp` dependem de hardware (Arduino/M5Cardputer)
e por isso ficam de fora do ambiente `native` — nao ha como testa-los sem o
dispositivo fisico.

### Build do firmware (hardware)

```sh
pio run -e cardputer
```

Builda com sucesso e gera `firmware/.pio/build/cardputer/firmware.bin`
(~29% de RAM, ~17% de Flash usados no ultimo build). Build de release
(`env:cardputer`) desativa Serial/CDC e symbols de debug; `env:cardputer-debug`
mantem Serial ligado para desenvolvimento. Isso confirma que TUDO compila e
linka — nao confirma que as telas funcionam como esperado num Cardputer de
verdade (ver "O que falta").

### Merge bin para o M5Launcher

O M5Launcher instala a partir de um binario mesclado (bootloader + partition
table + app), nao do `firmware.bin` isolado. Depois de um `pio run -e
cardputer` bem sucedido:

```sh
esptool.py --chip esp32s3 merge_bin -o firmware/.pio/build/cardputer/merged.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     firmware/.pio/build/cardputer/bootloader.bin \
  0x8000  firmware/.pio/build/cardputer/partitions.bin \
  0x10000 firmware/.pio/build/cardputer/firmware.bin
```

(Offsets padrao do target `m5stack-stamps3`/ESP32-S3 com bootloader clássico;
confirmar com `pio run -e cardputer -v` caso a placa use offsets diferentes.)
Copie `merged.bin` para o microSD e instale pelo M5Launcher — **e o
`merged.bin`, nao o `firmware.bin` isolado**, que o M5Launcher espera, pois
ele nao tem seu proprio bootloader/partition table.

## Ausencia de radio (verificada no binario linkado)

Nenhum arquivo deste repositorio inclui `WiFi.h`, `BLEDevice.h`, `esp_wifi.h`
ou `esp_bt.h`. Alem disso — ja que "nenhum arquivo nosso inclui" nao prova
que uma dependencia nao puxe radio por baixo — o binario final de um build
real (`pio run -e cardputer`) foi inspecionado com
`xtensa-esp32s3-elf-nm firmware.elf`: nao ha `esp_wifi_init`,
`esp_bt_controller_init` nem simbolos bluedroid/nimble de codigo linkados
(so limites de secao de memoria que o linker script do proprio chip sempre
declara, radio usado ou nao). O unico simbolo relacionado a Bluetooth
presente e `esp_bt_controller_mem_release`, chamado pelo boilerplate do
framework arduino-esp32 para LIBERAR a RAM reservada ao controlador de BT
quando ele nao e usado — o oposto de inicializa-lo. Ver a secao
"`ui.{h,cpp}` e `main.cpp`" acima para o achado relacionado (colisao de
simbolo `hmac_sha256` com `libwpa_supplicant.a`, a lib de WiFi que o
framework sempre linka mesmo sem uso).

## Revisao da uBitcoin (secao 5 da spec)

**Decisao: nao usar a uBitcoin. Parser de PSBT proprio e minimo sobre
trezor-crypto (secao 9 da spec).**

Revisao de `github.com/micro-bitcoin/uBitcoin` feita em 2026-09-23:

1. **Manutenimento estagnado**: ultimo push de codigo em 2023-03-26. Sem
   commits ha mais de 3 anos; 13 issues abertas sem resposta de manutencao,
   incluindo pedidos de compatibilidade com ESP-IDF/ESP32 recentes (#33, #38)
   sem correcao.
2. **Bug conhecido na area de PSBT**: issue #19, "PSBT double-signing creates
   invalid output" (aberta em 2022-08-03, sem fix) — exatamente a superficie
   de codigo (parsing/assinatura PSBT) que este firmware dependeria.
3. **Positivo**: a aritmetica de curva elíptica delega para trezor-crypto
   ("We use elliptic curve implementation from trezor-crypto"), nao e
   implementacao propria — mas o parsing/serializacao BIP174 em volta e
   codigo proprio da uBitcoin, e e ali que esta o bug aberto.
4. **Bugs de compatibilidade sem correcao**: issues #28/#33 mostram
   redeclaracao de simbolos (`hmac_sha256`, `Network`) em builds ESP32
   recentes.

Como este firmware ja usa trezor-crypto diretamente para toda a
criptografia, o unico ganho de adotar a uBitcoin seria o parser BIP174 —
que e justamente onde ha um bug de correcao conhecido e sem manutencao ativa.
Por isso o plano e um parser PSBT proprio, minimo, restrito ao subconjunto
necessario (PSBT v0, P2WPKH, SIGHASH_ALL — ver secao 9 da spec), com testes
dedicados cobrindo PSBTs validas e maliciosas/malformadas.

## Dependencias e vendoring do trezor-crypto

Este firmware usa o diretorio `crypto/` do monorepo
[`trezor/trezor-firmware`](https://github.com/trezor/trezor-firmware),
adicionado como submodulo Git em `firmware/lib/trezor-firmware/`, pinado no
commit `148e530180937bdf9aa5f5744862b909a90a1c70`. O repositorio standalone
`trezor/trezor-crypto` esta arquivado desde 2019 e nao deve ser usado (o
proprio README dele redireciona para o monorepo).

O submodulo usa `sparse-checkout` para trazer so `crypto/` (evita puxar
`core/`, `legacy/`, `rust/` etc. do monorepo). Nem todo arquivo de `crypto/`
e compilado: `firmware/lib/trezor_crypto/` contem a lista explicita e
auditavel de quais arquivos `.c` sao usados (via trampolins `#include`, sem
nenhuma modificacao no codigo upstream) — ver
`firmware/lib/trezor_crypto/README.md` para a lista completa e a
justificativa de cada arquivo, incluindo os dois casos em que este projeto
escreve codigo proprio: stubs para simbolos inalcancaveis em tempo de
execucao (`ed25519_stub.c`) e os pontos de integracao que a lib exige da
plataforma (`firmware/src/trezor_platform.cpp`: `tc_fault_handler` e
`random_buffer`).

Vetores testados (todos passam via `pio test -e native`):

- BIP39: 8 vetores oficiais (12, 18 e 24 palavras) com passphrase `TREZOR`,
  extraidos de `trezor/python-mnemonic/vectors.json`.
- BIP32: Test vector 1 (derivacao hardened em profundidade) e Test vector 2
  (indice hardened maximo `2147483647'` e derivacao nao-hardened), de
  `bip-0032.mediawiki`.
- BIP84: vetor oficial de `bip-0084.mediawiki` (zpub da conta + 3 enderecos
  de recebimento/troco), exercitando a pilha completa deste firmware
  (mnemonic → seed → conta → zpub/enderecos), nao so o trezor-crypto cru.
- PSBT: um PSBT valido construido a mao (1 input nosso + 1 output externo +
  1 troco verdadeiro) — valida, calcula fee/aviso de taxa corretamente,
  assina, e a assinatura e conferida com `ecdsa_verify_digest` contra um
  sighash BIP143 recalculado de forma totalmente independente do codigo de
  producao (pegou um bug real: um array de scriptCode com um elemento a
  menos no initializer, que deslocava `OP_EQUALVERIFY`/`OP_CHECKSIG`).
  Casos maliciosos/malformados: fingerprint errado, sighash != ALL, troco
  falsificado (hash nao bate com a derivacao alegada), arquivo truncado,
  magic corrompido, scriptSig nao-vazio na unsigned tx, e round-trip
  binario/base64.

## Geracao da seed fora do dispositivo (secao 12 da spec)

Este firmware **nunca gera a seed** — ela e criada em outro computador, off-line:

1. Baixe o arquivo HTML standalone do
   [Ian Coleman BIP39 Tool](https://github.com/iancoleman/bip39/releases) do
   release oficial no GitHub e verifique o hash/assinatura do download.
2. Rode-o em um computador offline, de preferencia um live USB (ex: Tails)
   sem rede durante todo o processo.
3. Use entropia de dados fisicos (ex: 99 lancamentos de dado de 6 faces para
   256 bits) no campo de entropia da ferramenta, em vez de confiar so no
   gerador do navegador.
4. Anote as palavras a mao (papel ou metal) e anote o master fingerprint
   exibido. Feche o navegador e desligue a maquina. Sem prints, arquivos ou
   area de transferencia.
5. Digite as 24 palavras no Cardputer a cada sessao (secao 6) e confira que o
   master fingerprint exibido apos a passphrase (secao 7) bate com o anotado.

## Modelo de ameaca — limitacoes aceitas

- **Sem secure element**: nenhuma protecao contra ataques fisicos avancados
  (glitching, power analysis, dump de RAM com o dispositivo ligado e a seed
  carregada). Mitigado apenas pela posse fisica durante a sessao e pelo
  timeout de inatividade.
- **Sem camera**: nao ha leitura de QR code; toda entrada/saida de dados
  passa pelo microSD.
- **A seguranca da seed depende do processo de geracao externo** (secao
  acima) — este firmware nao pode validar como a seed foi gerada, so que o
  checksum BIP39 e valido.

## Estrutura do projeto

Ver `spec.md` secao 13. Uma diferenca do layout proposto: `session.{h,cpp}`
hoje e so um header (`session.h`), porque a logica inteira (maquina de
estados de timeout + wipe) e pequena o bastante para caber em metodos
inline sem ganhar nada em separar a implementacao — nao ha `session.cpp`.

## Auditoria

Toda a criptografia vem de `trezor-firmware/crypto` (ver secao acima) — este
projeto nao implementa curva eliptica, hash, HMAC, PBKDF2 nem derivacao
BIP32/39 do zero. As unicas linhas de codigo "sensiveis" escritas para este
projeto sao os wrappers finos em `firmware/src/keys.cpp` (orquestra chamadas
ao trezor-crypto, nao faz matematica de curva) e os dois hooks de plataforma
em `firmware/src/trezor_platform.cpp`.
