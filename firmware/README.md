# BTCSigner Cardputer — firmware

Firmware do signer de PSBT para o M5Stack Cardputer (ESP32-S3). Aqui ficam o build, a instalação e
o funcionamento básico. Para a visão geral do projeto, ver o [README principal](../README.md).

---

## Build

Pré-requisitos: Python 3 e PlatformIO (`pip install --user platformio`).

**Antes do primeiro build**, inicialize o submódulo `lib/trezor-firmware`. Ele vem vazio num clone
normal, e sem ele o build falha com `fatal error: bip32.h: No such file or directory`:

```sh
git submodule update --init --recursive
```

De dentro de `firmware/`:

```sh
pio run -e cardputer          # release (Serial/USB-CDC desligados)
pio run -e cardputer-debug    # mesmo firmware, com log na Serial, para desenvolver
```

O release gera `bootloader.bin`, `partitions.bin` e `firmware.bin` em `.pio/build/cardputer/`.

---

## Instalação

### Pelo M5Launcher

O M5Launcher instala a partir de um binário mesclado (bootloader + tabela de partições + app), não
do `firmware.bin` isolado. Depois do build, a partir da raiz do repositório:

```sh
esptool.py --chip esp32s3 merge_bin -o firmware/.pio/build/cardputer/merged.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     firmware/.pio/build/cardputer/bootloader.bin \
  0x8000  firmware/.pio/build/cardputer/partitions.bin \
  0x10000 firmware/.pio/build/cardputer/firmware.bin
```

Copie o `merged.bin` para o microSD e instale pelo M5Launcher.

### Direto pelo USB

Com o Cardputer em modo download (segure o botão G0 enquanto conecta o cabo USB):

```sh
pio run -e cardputer -t upload
```

---

## Funcionamento

### Fluxo

1. **Rede**: Mainnet ou Testnet/Signet (`TESTNET` fica em vermelho no header de toda tela).
2. **Tipo de carteira**: só SegWit nativo (BIP84, `m/84'`).
3. **Seed**: digitar as 12 ou 24 palavras (com autocomplete e checagem do checksum BIP39) ou
   "Restaurar do cartão" (ver [backup RFID](#backup-opcional-no-cartão-rfid)).
4. **Passphrase** (opcional).
5. **Fingerprint**: mostra o master fingerprint e o endereço #0 para conferir com o anotado.
6. Se a seed foi digitada, oferece gravar o backup no cartão RFID.
7. **Menu** em carrossel:
   - **ASSINAR**: lista os `.psbt` do microSD, revisa saída por saída, mostra o resumo (taxa,
     sat/vB, total enviado) e assina segurando Enter por 1,5 s.
   - **CARTEIRA**: fingerprint, rede, script, exportar xpub/zpub (na tela e em arquivo, com os
     descriptors) e endereço de recebimento (índice 0 a 999).
   - **TOOLS**: testar um backup (papel ou cartão) contra a sessão aberta, apagar o backup RFID e
     brilho.
   - **SESSAO**: encerrar a sessão.

A sessão expira após 3 minutos sem uso, e a chave é apagada da RAM. Nada da seed é gravado em
flash.

### Teclado

O Cardputer não tem Esc nem setas:

- **ESC** (tecla `` ` ``, canto superior esquerdo) volta ou cancela. **Fn+`** digita o `` ` ``
  literal na passphrase.
- **`;` `.`** sobem e descem; **`,` `/`** vão para a esquerda e a direita. Na passphrase, são
  caracteres comuns.
- **Enter** confirma. Na assinatura, é preciso segurar.

### microSD

- PSBTs em `/psbt/*.psbt`, ou na raiz se `/psbt` não existir (até 32 na lista). Binário ou base64.
- A assinada é gravada ao lado, como `<nome>_signed.psbt`.
- O export da carteira vai para `/wallet_export.txt`.
- Dá para trocar o cartão com o aparelho ligado. A tecla **R** na lista ASSINAR remonta o cartão.

### PSBT aceita

- PSBT v0, `SIGHASH_ALL`, até 32 KB, 20 entradas e 20 saídas.
- Toda entrada tem que ser P2WPKH desta seed, com `witness_utxo`, `non_witness_utxo` (tx anterior
  completa) e a derivação BIP32 com o fingerprint da sessão. Sparrow, Bitcoin Core e Electrum já
  incluem esses campos.
- Saídas P2WPKH, P2WSH, P2TR, P2PKH e P2SH são exibidas com o endereço completo. Qualquer outro
  script (ex.: `OP_RETURN`) faz a PSBT ser rejeitada.
- Uma saída que alega ser troco mas não deriva desta seed aparece como destino externo, com aviso.
- Taxa alta e taxa abaixo do mínimo de relay geram aviso. RBF e `nLockTime` aparecem numa tela de
  detalhes.

### Backup opcional no cartão RFID

Por padrão nada é gravado: a seed é digitada a cada sessão. Quem quiser pode gravar uma cópia
**cifrada** da seed num cartão MIFARE Classic 1K/4K com a **M5Stack Unit RFID2** ligada no Grove do
Cardputer.

- A cópia é cifrada com AES-256 + HMAC-SHA256, com chave derivada de uma senha por PBKDF2-SHA256.
  A senha precisa ter pelo menos 12 caracteres e é digitada duas vezes. O recomendado são 4 a 6
  palavras aleatórias.
- **A passphrase nunca vai para o cartão**: ela é digitada de novo depois de restaurar.
- O cartão deve ser tratado como público (qualquer leitor o copia). A segurança depende só da senha.
- O cartão guarda duas cópias independentes, e uma gravação interrompida sempre deixa o backup
  antigo ou o novo legível.
- Em **TOOLS** dá para conferir o backup contra a sessão aberta e apagar o cartão.
- O cartão não substitui o backup em papel.

---

## Arquivos

| Arquivo | O que faz |
|---|---|
| `src/main.cpp` | Máquina de estados das telas; liga todos os módulos |
| `src/ui.{h,cpp}` | Primitivas de desenho e leitura do teclado |
| `src/config.h` | Constantes (timeout, limites de PSBT, derivação, iterações do KDF) |
| `src/keys.{h,cpp}` | Derivação BIP32/BIP39/BIP84, endereços, xpub/zpub |
| `src/session.h` | Sessão ativa: chave, expiração e wipe |
| `src/mnemonic_input.{h,cpp}` | Digitação das palavras com autocomplete e checksum |
| `src/passphrase_input.{h,cpp}` | Digitação da passphrase e das senhas |
| `src/psbt.{h,cpp}` | Parser, validador e assinador de PSBT |
| `src/review_screens.{h,cpp}` | Formatação do texto da revisão (endereços, valores) |
| `src/sd_io.{h,cpp}`, `src/sd_io_paths.cpp` | Leitura/gravação no microSD e nomes de arquivo |
| `src/rfid_seed_card.{h,cpp}` | Formato e cifra do backup RFID |
| `src/rfid_io.{h,cpp}` | Comunicação com a Unit RFID2 |
| `src/trezor_platform.cpp`, `src/strong_random.h` | Hooks do trezor-crypto e gerador aleatório |
| `src/secure_wipe.{h,cpp}`, `src/emergency_wipe.{h,cpp}` | Limpeza de stack e de segredos em falha |
| `src/panic_hooks.{h,cpp}` | Panic sem core dump e sem vazar dados |
| `lib/trezor-firmware/` | Submódulo do [trezor-firmware](https://github.com/trezor/trezor-firmware) (só `crypto/`), num commit fixo |
| `lib/trezor_crypto/` | Lista dos `.c` do trezor-crypto que são compilados (ver o [README](./lib/trezor_crypto/README.md)) |
| `lib/MFRC522_I2C/` | Driver da Unit RFID2, vendorizado sem modificação |
| `test/` | Testes no host (`pio test -e native`) |
