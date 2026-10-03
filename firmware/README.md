# BTCSigner Cardputer — firmware

Documentação técnica do firmware. Para a visão geral do projeto, ver o
[README principal](../README.md).

<p align="center">
  <a href="#status">Status</a> ·
  <a href="#módulos">Módulos</a> ·
  <a href="#parser-de-psbt">Parser de PSBT</a> ·
  <a href="#microsd">microSD</a> ·
  <a href="#backup-opcional-no-cartão-rfid">Backup RFID</a> ·
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
o teclado e a E/S no microSD rodam no aparelho físico: entrada de seed, área CARTEIRA, listagem de
`.psbt` e assinatura gravando `*_signed.psbt` no cartão, tudo em testnet. O firmware **não deve
ser usado com fundos reais** antes do primeiro uso em mainnet com valores pequenos (ver
[O que falta](#o-que-falta)).

O [backup opcional no cartão RFID](#backup-opcional-no-cartão-rfid) tem formato e criptografia
testados no host (inclusive contra uma implementação de referência independente), mas **ainda não
foi validado no aparelho** com a Unit RFID2.

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
| Backup RFID: formato e criptografia | `src/rfid_seed_card.{h,cpp}` | feito, testado |
| Backup RFID: Unit RFID2 (hardware) | `src/rfid_io.{h,cpp}` | feito, pendente validação no aparelho |
| Entropia real (salt/IV) | `src/strong_random.h` (em `trezor_platform.cpp`) | feito |
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
- **Estrutura estrita**: toda chave (keytype + keydata) tem que ser única dentro do seu mapa,
  inclusive as desconhecidas/proprietárias, que voltam verbatim na saída (`kDuplicateField`); a
  checagem relê o mapa em vez de guardar as chaves (zero RAM, sem teto de chaves). Bytes depois do
  último mapa de output rejeitam o arquivo (`kMalformed`), inclusive um `\n` no fim de um binário.
- **Base64 tolerante só nas pontas**: num arquivo de texto, um BOM UTF-8 no começo e
  espaço/tab/CR/LF nas duas pontas são cortados (editores acrescentam `\n`); espaço no meio continua
  inválido (base64 em várias linhas não é suportado). O binário nunca é cortado.
- **Limites** (`config.h`): 32 KB por arquivo, 20 inputs, 20 outputs. Avisos de taxa alta acima de
  5% do valor enviado ou 100.000 sats, de taxa estimada abaixo do mínimo de relay (0,1 sat/vB, padrão do
  Bitcoin Core; só aviso, a tx não propagaria) e de índice de troco acima de 1000.
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
- **Layout no cartão**: PSBTs em `/psbt/*.psbt`, ou na raiz se `/psbt` não existir (até 32
  listadas; a escolha é refeita a cada montagem), assinadas gravadas como
  `<nome>_signed.psbt`, export em `/wallet_export.txt`.
- **Troca a quente**: dá para inserir, tirar ou trocar o microSD com o aparelho ligado. Ao entrar na
  lista ASSINAR (e antes de exportar o xpub), o firmware desmonta e monta o cartão de novo
  (`sd_remount()`), para nunca escrever num cartão trocado com a FAT em cache do anterior. A
  tecla **R** na lista ASSINAR faz o mesmo na hora. Sem cartão montado, a lista tenta montar a cada
  2 s (`kSdPollMs`), então um cartão inserido aparece sozinho. Uma remoção só é percebida no
  próximo R, na próxima entrada na lista ou quando uma leitura/gravação falha.

---

## Backup opcional no cartão RFID

Recurso **opt-in**: por padrão nada muda, e a seed continua sendo digitada a cada sessão. Depois de
confirmar o fingerprint de uma seed **digitada**, o firmware oferece gravar uma cópia cifrada num
cartão MIFARE Classic 1K/4K pela **M5Stack Unit RFID2** (chip WS1850S, compatível com o MFRC522).
Na tela inicial, "Restaurar do cartão" lê essa cópia em vez de pedir as palavras. Durante a sessão,
a área **TOOLS** permite conferir o backup (em papel ou no cartão) contra a sessão aberta e apagar o
backup do cartão. A **passphrase
nunca vai para o cartão**: ela continua sendo digitada depois da restauração, então segue valendo
como segundo fator.

**Hardware.** Unit RFID2 no Grove do Cardputer: I2C `0x28`, SDA=G2, SCL=G1, `Wire` do Arduino
(`I2C_NUM_0`). No M5Unified 0.2.23 essa porta só seria usada pelo `Ex_I2C` com
`external_rtc`/`external_imu` ligados (não estão), e o I2C interno do Cardputer-ADV (teclado
TCA8418) fica em `I2C_NUM_1`. O `rfid_init()` sonda o endereço, confere o `VersionReg` e faz um
soft reset com limite de tempo antes do `PCD_Init()`, porque o `PCD_Reset()` da lib trava em loop
infinito se o chip não responder. O leitor é reinicializado a cada uso. A antena só é ligada
enquanto se espera ou opera o cartão; ela fica desligada inclusive na tela "Cartão em uso".

**Reseleção a cada operação.** No MIFARE Classic, depois de `PCD_StopCrypto1()` o cartão continua
autenticado e ignora uma nova autenticação em claro. Por isso cada leitura, gravação ou conferência
começa com um ciclo do campo de RF (o cartão volta a IDLE) seguido de WUPA e seleção, e exige o mesmo
UID detectado no início, o que acusa um cartão trocado. Os setores seguintes usam autenticação
aninhada, sem `StopCrypto1` entre eles, como faz o próprio `PICC_DumpMifareClassicToSerial()` do
upstream. Como os testes no host simulam o cartão, esse ponto **só é validado no aparelho**.

**Chaves do cartão.** O firmware tenta, em ordem, a Key A de fábrica `FFFFFFFFFFFF`, a Key A
`000000000000` e a Key B `FFFFFFFFFFFF` (`kMifareKeys`), guardando a que funcionou para os setores
seguintes. A segunda existe por causa de cópias: no trailer, a Key A não é legível e sai zerada no
dump, e uma ferramenta que grave o trailer como está no dump deixa o clone com Key A = 00..00. Uma
chave recusada deixa o cartão em HALT, por isso cada nova tentativa começa com uma reseleção. Os
trailers nunca são escritos.

**O cartão é tratado como público.** A proteção nativa do MIFARE Classic (Crypto1) está quebrada, e
o firmware usa as chaves de fábrica só para ter acesso de leitura e escrita. Quem pegar o cartão copia
tudo em segundos. Por isso toda a segurança vem da cifra (`src/rfid_seed_card.h`):

```
cartão (752 bytes): cópia A em [0,112), cópia B em [384,496), resto aleatório
cada cópia: +0 salt(16) | +16 iv(16) | +32 AES-256-CBC de 48 bytes fixos | +80 HMAC-SHA256(mac_key, [+0,+80))
texto plano: versão | nº de palavras (12|24) | entropia BIP39 (slot de 32) | aleatório
master = PBKDF2-HMAC-SHA256(senha, salt, kRfidPbkdf2Iterations), 1 bloco de 32 bytes
aes_key/mac_key = HMAC-SHA256(master, "BTCSigner-RFID-v1-enc" / "...-mac")
```

- **Duas cópias, a A gravada por último.** As cópias são independentes (salt, IV e chaves
  próprios, então nenhum trecho se repete e o cartão continua parecendo aleatório). A gravação
  (`rfid_write_order_index`) escreve primeiro a cópia B e o preenchimento e só depois os 7 blocos da
  cópia A. Se o cartão sair do leitor no meio, sobra sempre um backup legível: o antigo (A intacta)
  ou o novo (B completa). A restauração tenta A e depois B, então uma senha errada custa dois KDFs.
  O backup também custa dois KDFs. A tela de falha avisa isso, e o ESC só pula o backup no segundo
  toque, porque depois dele o mnemônico sai da RAM.

- **Indistinguível de dados aleatórios.** Não há magic, versão nem contagem de iterações em
  claro, e o conteúdo tem o mesmo tamanho para 12 ou 24 palavras. Os 47 blocos de dados são sempre
  regravados, então não sobra nada de um backup anterior.
- **Entropia real para salt, IV e preenchimento.** Sem WiFi/BT, o `esp_random()` é só
  pseudoaleatório; o `strong_random_buffer()` liga a fonte de ruído do SAR ADC
  (`bootloader_random_enable`) durante a geração.
- **PBKDF2 de um único bloco.** Com 64 bytes de saída, o aparelho pagaria o KDF duas vezes e o
  atacante uma só. O PBKDF2 é chamado via `Init/Update/Final`, porque o wrapper deixa o digest na
  stack.
- **MAC conferido antes de decifrar**, com `consteq()`. Um texto plano de tamanho fixo não tem
  padding, o que elimina padding oracle.
- **Wipe.** Chaves, contextos AES (a lib não os zera), texto plano e bits BIP39 ficam num único
  buffer estático, zerado em todo retorno. Em seguida um `scrub_stack()` sobrescreve 1,5 KB de
  stack, onde `aes_*_key256`, `aescrypt` e `sha256_Transform` do código vendorizado deixam round
  keys e estado sem zerar. O `mnemonic_clear()` é chamado logo após
  `mnemonic_from_data()`, que escreve num buffer estático da lib. As senhas ficam em
  `PassphraseInput`. Tudo entra em `wipe_seed_material()`.
- **Senha.** Mínimo de 12 caracteres, pelo menos 8 caracteres distintos, não pode ser só dígitos
  (`rfid_check_password`), diferente da passphrase, digitada duas vezes. Essas regras só barram o que
  cai rápido; não medem força de verdade. A cifra
  acontece antes de tocar no cartão, e a senha é zerada logo depois. Depois de gravar, o cartão é
  relido e comparado. Um cartão com dados pede confirmação antes de ser sobrescrito.
- **TOOLS > Testar backup.** Confere um backup contra a sessão aberta, partindo de três origens:
  papel com 12 palavras, papel com 24 palavras, ou cartão RFID (lê o cartão e pede a senha). Nos
  três casos, no fim a passphrase é digitada de novo. O firmware deriva a chave e compara com a da
  sessão por `same_account()` (`keys.h`): mesma rede, mesmo fingerprint, e mesma chave privada e
  chain code da conta, em tempo constante. O resultado é "Confere com a sessão" ou "NÃO confere",
  com o fingerprint obtido. Isso prova que o backup **mais a passphrase que você lembra**
  reconstroem a carteira aberta. Como o mnemônico e a passphrase saem da RAM quando a sessão começa,
  não há outro jeito sem guardar algo derivado da seed. As telas de digitação são as mesmas da
  entrada inicial, com checksum e correção de palavra. Durante o teste, o mnemônico volta à RAM
  (nunca é desenhado) e é zerado, com a passphrase e a chave derivada, antes do resultado aparecer.
  O ESC em qualquer etapa zera tudo e volta para TOOLS sem encerrar a sessão. Se só a cópia B do
  cartão abriu, a A está danificada, e a tela pede para gravar de novo.
- **TOOLS > Apagar backup RFID.** Lê o cartão (se já estiver vazio, avisa), pede para segurar
  Enter e grava zeros nos 47 blocos, conferindo depois. Não pede a senha de propósito: qualquer app
  NFC já apaga o cartão com a chave de fábrica, e exigir a senha impediria apagar um backup cuja
  senha foi esquecida. Como a cópia A é zerada por último, uma interrupção pode deixar o backup no
  cartão, e a tela avisa.
- **Erros da restauração em tela cheia.** Leitor ausente, cartão sem backup ou corrompido aparecem
  numa tela de erro por 3 s (`kCardErrorShowMs`), que volta sozinha ao início (Enter/Esc voltam
  antes). Tudo é zerado antes da tela aparecer. Senha errada continua na tela de senha, para tentar
  de novo.
- **`kRfidPbkdf2Iterations` (`config.h`) está congelado em 200k.** O valor não fica gravado no
  cartão (não há cabeçalho em claro), então mudá-lo tornaria ilegível todo backup existente, e o
  erro pareceria "senha errada". Um vetor golden com as iterações de produção
  (`test_production_iterations_are_frozen`) quebra se o valor mudar. Para mudar no futuro, a
  restauração precisa continuar tentando os valores antigos. A tela de sucesso mostra quanto o KDF
  levou (as duas cópias juntas).
- **Bateria depois do backup.** O `bootloader_random_disable()` reinicia o SAR ADC, e a leitura de
  bateria do cabeçalho pode ficar errada até o aparelho reiniciar. É só cosmético, mas precisa ser
  conferido no aparelho.

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

- **Menu em carrossel**: depois da seed, um carrossel infinito de ícones (ASSINAR, CARTEIRA, TOOLS,
  SESSAO): `,` `/` deslizam entre as áreas (do último volta ao primeiro), Enter abre a lista da
  área e ESC volta ao carrossel. Na lista, `;` `.` movem e Enter abre. ASSINAR = lista de `.psbt`
  do SD; CARTEIRA = fingerprint, rede, script, exportar xpub, endereço de recebimento; TOOLS =
  testar backup (papel ou cartão, contra a sessão), apagar o backup RFID e brilho (Enter cicla
  30/50/70/100%, não persiste); SESSAO = bloqueio automático (informativo) e encerrar sessão. A
  animação usa um sprite de 240x62 (~30 KB) alocado só durante o deslize; sem heap, troca direto.
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
- **Tipo de carteira (tela SCRIPT)**: depois da rede e antes da seed (ou da senha do cartão), como
  no Electrum, porque o tipo de script define a derivação. Só "SegWit nativo" (BIP84, `m/84'`) é
  selecionável; "Taproot (em breve)" aparece em cinza e o cursor não para nela. A escolha passa por
  `derive_master_key_for()` (`keys.h`), que recusa qualquer tipo que não seja P2WPKH.
- **Endereço de recebimento** (CARTEIRA): índice de 0 a 999 (`kMaxReceiveIndex`, no máximo 3
  dígitos). O endereço vem de `derive_receive_address_checked()`, que o calcula pela chave privada
  e de novo a partir do zpub exportado (derivação pública, como a watch-only faz), e decodifica o
  bech32 de volta. Só aparece se tudo bater; senão, "(falha na verificacao)". O endereço #0 da tela
  de fingerprint usa a mesma função.
- **Revisão**: cada saída é mostrada uma a uma com o endereço COMPLETO. Uma saída desta seed em
  `/1/i` é "TROCO #i"; em `/0/i` é "PROPRIO receb. #i". Depois vem o RESUMO (entradas/saídas,
  taxa, sat/vB estimado por tipo de script de cada saída e o total enviado = saídas externas +
  taxa). Se a tx sinaliza RBF (alguma `nSequence < 0xfffffffe`) ou tem `nLockTime`, aparece a tela
  DETALHES. Por fim, **segurar Enter por `kHoldToSignMs` (1,5 s)** para assinar. Soltar antes zera a barra, e
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
`test_psbt_parse`, `test_review_screens`, `test_rfid_seed_card`, `test_rfid_integration`,
`test_sd_io_paths`, `test_session`. `ui.cpp`, `main.cpp`, `sd_io.cpp` e `rfid_io.cpp` dependem de
hardware e ficam de fora do `native`.

Vetores e casos cobertos:

- **BIP39**: vetores oficiais (12, 18 e 24 palavras) com passphrase `TREZOR`, de
  `trezor/python-mnemonic/vectors.json`.
- **BIP32**: Test vector 1 (derivação hardened em profundidade) e Test vector 2 (índice hardened
  máximo `2147483647'` e derivação não-hardened), de `bip-0032.mediawiki`.
- **BIP84**: vetor oficial de `bip-0084.mediawiki` (zpub da conta + endereços de recebimento/troco),
  exercitando a pilha completa deste firmware (mnemonic → seed → conta → zpub/endereços), não só o
  trezor-crypto cru. O endereço de recebimento verificado é conferido contra vetores gerados à parte
  com o `embit` (Python; mainnet e testnet, índices 0, 1 e 999). Os dois caminhos (privado e pelo
  zpub) também são comparados em toda a faixa 0..999.
- **PSBT**: uma PSBT válida construída à mão (input nosso + output externo + troco verdadeiro) —
  valida, calcula taxa/aviso, assina, e a assinatura é conferida com `ecdsa_verify_digest` contra um
  sighash BIP143 recalculado de forma independente do código de produção (pegou um bug real: um
  array de scriptCode com um elemento a menos, que deslocava `OP_EQUALVERIFY`/`OP_CHECKSIG`). Casos
  maliciosos/malformados: fingerprint errado, sighash ≠ ALL, troco falsificado, arquivo truncado,
  magic corrompido, scriptSig não-vazio na unsigned tx, round-trip binário/base64, bytes sobrando
  no fim, chave duplicada (inclusive desconhecida) nos três tipos de mapa, base64 com BOM/espaço
  nas pontas, entre outros.
- **Backup RFID**: vetores fixos gerados por uma implementação independente (Python: `hashlib` +
  `cryptography`) com RNG de contador, das duas cópias, com 1000 iterações e com as de produção,
  tanto para codificar quanto para decodificar; uma cópia danificada cai para a outra; as cópias não
  compartilham nenhum bloco; a ordem de gravação deixa a cópia A por último; round-trip de
  12 e 24 palavras (inclusive com as iterações de produção); senha errada, prefixo da senha,
  iterações diferentes e 1 byte alterado em salt/iv/ciphertext/tag viram `kAuthFailed`, com a saída
  zerada; cartão de fábrica (0x00/0xFF) é detectado; MAC válido com conteúdo inválido vira
  `kMalformed`; dois backups da mesma seed não compartilham nenhum trecho; nenhum fragmento da
  entropia ou das palavras aparece no cartão; mapeamento de blocos nunca toca trailer nem bloco 0.
  `test_rfid_integration` percorre o fluxo inteiro (digitar → derivar → backup → cartão simulado →
  restaurar → mesma MasterKey e zpub), confere que o cartão restaurado sem a passphrase gera outra
  carteira e confere que nenhum segredo sobra nos buffers. Uma gravação de outra seed interrompida
  em cada bloco possível sempre deixa o backup antigo ou o novo legível, e apagar deixa o cartão
  vazio.

---

## Ausência de rádio

Nenhum arquivo deste repositório inclui `WiFi.h`, `BLEDevice.h`, `esp_wifi.h` ou `esp_bt.h`. Como
"nenhum arquivo nosso inclui" não prova que uma dependência não puxe rádio por baixo, o binário
final (`pio run -e cardputer`) foi inspecionado com `xtensa-esp32s3-elf-nm firmware.elf`: não há
`esp_wifi_init`, `esp_bt_controller_init` nem símbolos bluedroid/nimble de código (só limites de
seção de memória que o linker script do chip sempre declara). O único símbolo relacionado a BT é
`esp_bt_controller_mem_release`, que o boilerplate do arduino-esp32 chama para LIBERAR a RAM
reservada ao controlador — o oposto de inicializá-lo.

**Exceção opt-in: a Unit RFID2.** O leitor RFID é um módulo externo que emite um campo de 13,56 MHz
de curto alcance (menos de 2 cm para ler). A antena só fica ligada enquanto o usuário espera ou opera
o cartão num backup/restauração, e por ela passa só o blob já cifrado. Com o módulo desconectado, o
aparelho continua sem nenhum rádio.

**Colisões com a stack WiFi.** O arduino-esp32 sempre linka `libwpa_supplicant.a` (mesmo sem chamar
nenhuma API de rádio), que define suas próprias `hmac_sha256`, `aes_encrypt` e `aes_decrypt`,
colidindo com as do trezor-crypto ("multiple definition"). Isso é resolvido com flags em
`platformio.ini` (`-Dhmac_sha256=btcseed_tc_hmac_sha256`, `-Daes_encrypt=...`, `-Daes_decrypt=...`),
que são `#define`s de renomeação e não patches no código vendorizado. Como as flags valem para o
build inteiro, `rfid_seed_card.cpp` também chama os nomes renomeados, ou seja, sempre a versão do
trezor-crypto. Confira com `nm firmware.elf`: só aparecem `btcseed_tc_*`.

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
só para blinding de ECDSA, nunca como fonte da seed; e `strong_random_buffer`, com a fonte de ruído
do ADC ligada, para salt/IV do backup RFID).

O driver da Unit RFID2 (`lib/MFRC522_I2C/`) também é vendorizado, sem modificação e num commit
fixo, com hashes e a revisão feita em [`lib/MFRC522_I2C/README.md`](./lib/MFRC522_I2C/README.md).

**Auditoria**: este projeto não implementa curva elíptica, hash, HMAC, AES, PBKDF2 nem derivação
BIP32/39. As linhas "sensíveis" próprias são os wrappers finos em `src/keys.cpp`, os hooks de
plataforma e a **composição** das primitivas do trezor-crypto no formato do backup RFID
(`src/rfid_seed_card.cpp`: KDF, encrypt-then-MAC e wipe). Essa composição é o trecho que mais
merece revisão de terceiros.

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

### Backup opcional no cartão RFID

Ativar o backup **reintroduz uma cópia persistida da seed** (cifrada) que não existia antes. É
uma troca deliberada de segurança por praticidade, e vale a pena entender o que se ganha e o que se
perde:

- **O cartão é público.** Crypto1 está quebrado e o acesso usa a chave de fábrica; um leitor
  qualquer (inclusive um celular) copia o cartão. A comunicação por RF também pode ser capturada à
  distância durante o uso. Em todos os casos o atacante obtém só o blob cifrado.
- **A segurança depende só da senha e do KDF.** Com o blob em mãos, o atacante testa senhas offline,
  sem limite, numa GPU; não existe esquema que evite isso, porque qualquer verificação que o
  aparelho faz, o atacante também faz (inclusive conferindo endereços na blockchain). Ordens de
  grandeza para PBKDF2-SHA256 com 200k iterações numa GPU de ponta (cerca de 4·10⁴ tentativas/s):

  | Senha do cartão | Tempo para esgotar (1 GPU) |
  |---|---|
  | PIN de 6 dígitos | segundos |
  | 8 caracteres `[a-z0-9]` aleatórios | cerca de 2 anos (1 semana com 100 GPUs) |
  | 4 palavras diceware aleatórias | milhares de anos |
  | 6 palavras diceware aleatórias | inviável |

  Por isso o firmware exige no mínimo 12 caracteres. O recomendado são 4 a 6 palavras aleatórias.
- **A passphrase não vai para o cartão.** Quebrar a senha do cartão entrega o mnemônico, mas não a
  carteira protegida pela passphrase. Quem não usa passphrase fica só com a senha do cartão.
- **Não há bloqueio por tentativas.** Não teria efeito, já que o ataque real é offline sobre a cópia.
- **O cartão não substitui o backup em papel.** Cartões falham, e mudar
  `kRfidPbkdf2Iterations` ou o formato invalida os backups gravados. Qualquer pessoa com o cartão na
  mão pode apagá-lo.
- **Resíduo de stack.** Funções internas do SHA-256 do trezor-crypto podem deixar resíduo na stack
  durante o KDF, a mesma limitação que o caminho BIP39 já aceita (sem secure element, veja acima).

---

## O que falta

- **Primeiro uso em mainnet** com valores pequenos.
- **Backup RFID no aparelho**: validar a Unit RFID2 no Grove (alimentação de 5 V na bateria,
  convivência do `Wire` com o M5Unified, e o Cardputer-ADV se for o caso), a leitura e gravação dos
  16 setores com a reseleção + autenticação aninhada, a leitura de bateria depois de um backup, e
  calibrar
  `kRfidPbkdf2Iterations` pelo tempo exibido na tela de sucesso, e confirmar com um leitor externo
  que o dump do cartão não tem nada legível.
- Tela opcional de revisão do mnemônico em grupos pequenos — não implementada, explicitamente
  opcional.
