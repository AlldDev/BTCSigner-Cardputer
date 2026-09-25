# Especificação de Firmware v2: Signer Bitcoin Stateless no M5Stack Cardputer

## 1. Objetivo

Firmware customizado para o M5Stack Cardputer (primeira geração, ESP32-S3) que funciona como signer Bitcoin stateless e air-gapped:

- A seed (BIP39, 24 palavras) é gerada fora do dispositivo (ex: Ian Coleman BIP39 Tool rodando offline) e digitada no teclado do Cardputer a cada sessão, com autocomplete.
- A passphrase BIP39 (25ª palavra) é digitada a cada sessão.
- O dispositivo assina PSBTs recebidas via microSD e grava o resultado assinado de volta no microSD.
- Nada secreto é persistido. Ao desligar, reiniciar, dar timeout ou encerrar a sessão, a seed e todas as chaves derivadas são apagadas da RAM.

O código deve ser pequeno, legível, comentado e auditável, sem ofuscação, com dependências fixadas em commits específicos. O build deve gerar um binário que possa ser carregado pelo M5Launcher.

## 2. Hardware alvo

- M5Stack Cardputer (primeira geração), SoC ESP32-S3
- Tela IPS 1.14" 240x135 (ST7789)
- Teclado físico em matriz
- Slot microSD (SPI)
- WiFi e Bluetooth presentes no chip, mas NUNCA inicializados por este firmware
- Microfone, IR e demais periféricos não são usados

## 3. Modelo de ameaça e princípios inegociáveis

1. **Sem rádio**: o firmware não inicializa WiFi nem Bluetooth em nenhum caminho de execução. Não incluir `WiFi.h`, `BLEDevice.h`, `esp_wifi.h`, `esp_bt.h` nem nenhuma biblioteca que os puxe como dependência. A ausência deve ser verificável no arquivo `.map` do linker (nenhum símbolo `esp_wifi_init`, `esp_bt_controller_init` ou similar linkado).
2. **Sem persistência de segredos**: nenhuma escrita de seed, passphrase, chave privada, xprv ou entropia em NVS, SPIFFS, LittleFS, flash ou microSD. O firmware não usa NVS para nada relacionado a chaves.
3. **Microsd é o único canal de dados**: entrada de PSBT não assinada e saída de PSBT assinada/xpub. Nenhum dado secreto é gravado no cartão.
4. **Confirmação humana obrigatória**: toda assinatura exige revisão na tela (destinos, valores, taxa, troco) e confirmação física no teclado.
5. **Verificação de troco**: o firmware deriva ele mesmo os endereços de troco e só os trata como troco se a derivação bater com a própria seed. Saída que alega ser troco mas não bate é exibida como destino externo, com aviso.
6. **Sem cripto caseira**: curva elíptica, hashes, HMAC, PBKDF2 e derivação BIP32/BIP39 vêm de biblioteca testada em produção.
7. **Limpeza de memória**: todo buffer que contenha segredo é zerado com `memzero()` do trezor-crypto (ou função equivalente que o compilador não otimize fora) imediatamente após o uso e ao encerrar a sessão.
8. **Sem logs de segredos**: nenhum `Serial.print` ou log de seed, passphrase, chaves ou entropia, nem em build de debug. Preferencialmente, o Serial fica desativado no build de release.

Limitações conhecidas e aceitas (documentar no README):

- Sem secure element: não há proteção contra ataques físicos avançados (glitching, power analysis, cold boot/dump de RAM com o dispositivo ligado e seed carregada).
- Sem câmera: não há leitura de QR code.
- A segurança da seed depende do processo de geração externo (ver seção 12).

## 4. Framework e build

- PlatformIO com framework Arduino e a biblioteca oficial M5Cardputer (baseada em M5Unified/M5GFX) para tela e teclado.
- Todas as dependências fixadas por commit ou versão exata no `platformio.ini`.
- O build deve gerar o binário da aplicação (`firmware.bin`) e, adicionalmente, um binário mesclado (bootloader + partition table + app) via `esptool.py merge_bin`, documentando no README qual dos dois o M5Launcher aceita para instalação via microSD.
- Build de release com Serial desativado e sem símbolos de debug.
- Documentar no README o comando único de build e o comando único de merge.

## 5. Bibliotecas

- **trezor-crypto** (submódulo com commit fixado): secp256k1, SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2, BIP32, BIP39 (wordlist e checksum), `memzero`.
- **uBitcoin** (avaliar antes de integrar): camada para parsing de PSBT (BIP174), construção de scripts e endereços.

Instruções obrigatórias para a implementação:

1. Antes de integrar a uBitcoin, verificar no repositório: data do último commit relevante, issues abertas relacionadas a segurança, e se a aritmética de curva e a assinatura ECDSA delegam para código conhecido e testado. Registrar o resultado dessa revisão no README.
2. Se houver qualquer dúvida razoável, não usar a uBitcoin e implementar um parser PSBT mínimo próprio sobre o trezor-crypto, suportando apenas o subconjunto necessário (seção 9). Um parser pequeno e restrito é preferível a uma lib grande pouco auditada.
3. Rodar os vetores de teste oficiais de BIP32, BIP39 (incluindo casos com passphrase "TREZOR" dos vetores oficiais) e BIP84 antes de qualquer uso real.

## 6. Entrada da seed com autocomplete

Fluxo da tela:

1. O usuário escolhe "Iniciar sessão" e informa 12 ou 24 palavras (24 como padrão).
2. Para cada palavra (exibe "Palavra 7/24"):
   - O usuário digita letras; a tela mostra em tempo real as palavras da wordlist BIP39 em inglês que começam com o prefixo digitado.
   - Como toda palavra BIP39 é identificável de forma única pelas 4 primeiras letras, ao haver apenas um candidato o firmware o destaca e o usuário confirma com Enter. Com 1 a 3 letras e vários candidatos, as setas (ou teclas designadas) navegam entre eles.
   - Letras que não levam a nenhuma palavra válida são rejeitadas (a tecla não é aceita).
   - Backspace apaga letra; Backspace com campo vazio volta para a palavra anterior para correção.
3. Ao final, o firmware valida o checksum BIP39. Se inválido, informa erro e permite revisar e corrigir palavra por palavra (sem exibir a seed completa de uma vez).
4. Opcional e sob demanda: tela de revisão que mostra as palavras em grupos pequenos, apenas se o usuário pedir.

Requisitos:

- As palavras digitadas ficam somente em um buffer em RAM, zerado ao final da derivação.
- Após gerar a seed BIP39 (512 bits via PBKDF2), o mnemônico em texto é apagado da RAM; mantém-se apenas o necessário para assinar durante a sessão.

## 7. Passphrase (25ª palavra)

1. Tela dedicada após a seed. Entrada livre (qualquer caractere que o teclado permita), com opção de passphrase vazia explícita.
2. Por padrão os caracteres são mascarados; uma tecla alterna a visualização para conferência.
3. Após derivar, a tela exibe o **master fingerprint** (8 caracteres hex) da carteira resultante. O usuário compara com o fingerprint anotado previamente (ou com o exibido na carteira watch-only). Isso detecta erro de digitação na passphrase, que de outra forma geraria silenciosamente uma carteira diferente.
4. A passphrase nunca é persistida e é zerada da RAM logo após a derivação.

## 8. Derivação e redes

- Padrão: BIP84 (P2WPKH, native SegWit), conta `m/84'/0'/0'` na mainnet.
- Suporte a testnet/signet (`m/84'/1'/0'`), selecionável no início da sessão, exibido de forma permanente e visível na tela durante toda a sessão (ex: faixa "TESTNET"). Recomendação: todo o desenvolvimento e testes devem ser feitos em testnet/signet.
- Fora do escopo da v1: P2TR (BIP86), multisig, P2SH-P2WPKH. Podem ser adicionados depois.

## 9. Assinatura de PSBT via microSD

Entrada:

1. O firmware lista arquivos com extensão `.psbt` na raiz do microSD (ou em pasta definida, ex: `/psbt`).
2. Aceitar PSBT em binário e em base64 (detectar pelo magic `psbt\xff` ou pelo prefixo base64 `cHNidP`).
3. Tamanho máximo de arquivo e limites de quantidade de inputs e outputs definidos como constantes (ex: 64 KB, 20 inputs, 20 outputs), rejeitando o que exceder.
4. Nomes de arquivo sanitizados e com tamanho limitado.

Validação (rejeitar com mensagem clara se falhar):

- PSBT versão 0 bem formada.
- Cada input a ser assinado deve ter `PSBT_IN_WITNESS_UTXO` e `PSBT_IN_BIP32_DERIVATION` com fingerprint igual ao master fingerprint da sessão e caminho dentro da conta configurada.
- Apenas scripts P2WPKH.
- Apenas `SIGHASH_ALL` (rejeitar qualquer outro sighash).
- Rede dos endereços compatível com a rede da sessão.
- Soma dos inputs maior ou igual à soma dos outputs; taxa calculada a partir disso.

Tela de revisão:

- Para cada output externo: endereço completo (quebrado em linhas legíveis, em grupos de 4 caracteres) e valor em BTC e sats.
- Outputs de troco verificados (derivação confere com `m/84'/x'/0'/1/i` da própria seed): exibidos separados e marcados como "Troco (verificado)".
- Taxa total em sats e, quando possível, sat/vB estimado.
- Aviso destacado se a taxa for alta (ex: acima de 5% do valor enviado ou acima de um limite absoluto configurável em constante).
- Confirmação final exige tecla específica (ex: `Y` ou Enter) após ter passado por todas as telas de output; `Esc` cancela a qualquer momento.

Saída:

- Grava a PSBT com as assinaturas parciais (`PSBT_IN_PARTIAL_SIG`) no microSD, com o nome original acrescido de `_signed` (ex: `pagamento_signed.psbt`), no mesmo formato de entrada (binário ou base64).
- Não finaliza nem faz broadcast; a finalização é feita pela carteira watch-only (ex: Sparrow, Electrum).
- Após gravar, confirma na tela e volta ao menu. Todo buffer temporário de chave privada usado na assinatura é zerado imediatamente após cada assinatura.

## 10. Exportação de xpub (para montar a carteira watch-only)

- Opção de menu "Exportar xpub": grava no microSD um arquivo texto (ex: `wallet_export.txt` ou formato JSON compatível com Sparrow/Electrum) contendo master fingerprint, caminho de derivação e zpub/vpub da conta.
- Exibe também na tela o fingerprint e a xpub, para conferência.
- Opção "Ver endereço de recebimento": exibe o endereço de índice escolhido, para conferir com o que a carteira watch-only mostra antes de receber fundos.
- Nunca exportar xprv, seed ou qualquer material privado.

## 11. Sessão, timeout e encerramento

- Timeout de inatividade (ex: 3 minutos, constante configurável) encerra a sessão: zera todos os segredos e volta à tela inicial.
- Opção "Encerrar sessão" no menu faz o mesmo imediatamente.
- Ao remover o microSD durante uma operação, abortar a operação sem gravar arquivo parcial.
- Não há PIN (não há o que proteger em repouso); a segurança em uso depende da posse física durante a sessão.

## 12. Geração da seed fora do dispositivo (documentar no README)

- Usar o arquivo HTML standalone do Ian Coleman BIP39 Tool baixado do release oficial no GitHub, com hash/assinatura verificados.
- Rodar em computador offline, de preferência live USB (ex: Tails) sem rede durante todo o processo.
- Recomendado: usar entropia de dados físicos (99 lançamentos de dado de 6 faces para 256 bits) no campo de entropia da ferramenta.
- Anotar as palavras à mão (papel ou metal), anotar o master fingerprint, fechar o navegador e desligar a máquina. Sem prints, arquivos ou área de transferência.

## 13. Estrutura de projeto

```
/firmware
  platformio.ini
  /src
    main.cpp              // máquina de estados das telas, loop principal
    session.cpp/.h        // estado da sessão, timeout, wipe
    mnemonic_input.cpp/.h // entrada com autocomplete e validação de checksum
    passphrase_input.cpp/.h
    keys.cpp/.h           // derivação BIP32/BIP84 (wrapper trezor-crypto)
    psbt.cpp/.h           // parsing, validação e assinatura
    review_screens.cpp/.h // telas de revisão da transação
    sd_io.cpp/.h          // listagem, leitura e escrita no microSD
    ui.cpp/.h             // primitivas de desenho e teclado
    config.h              // limites, timeout, redes, constantes
  /lib
    trezor-crypto         // submódulo, commit fixado
    ubitcoin              // submódulo, commit fixado (somente se aprovado)
  /test
    test_bip39_vectors.cpp
    test_bip32_vectors.cpp
    test_bip84_vectors.cpp
    test_psbt_parse.cpp   // PSBTs válidas e maliciosas/malformadas
    test_change_detection.cpp
  README.md
```

Os testes das seções de cripto e PSBT devem rodar também no host (PlatformIO `native`), sem hardware, para facilitar auditoria.

## 14. Checklist de auditoria antes de uso real

- Vetores oficiais de BIP32, BIP39 e BIP84 passando.
- `.map` do linker sem símbolos de WiFi/Bluetooth.
- Busca no código confirmando ausência de escrita em NVS/flash e de logs de segredos.
- Teste de PSBTs maliciosas: troco com derivação falsa, fingerprint errado, sighash diferente de ALL, rede trocada, arquivo truncado, arquivo gigante.
- Teste de ponta a ponta em testnet/signet com Sparrow: exportar xpub, montar watch-only, criar PSBT, assinar no Cardputer, finalizar e transmitir.
- Conferir que o master fingerprint exibido bate com o gerado no Ian Coleman.
- Primeiro uso na mainnet somente com valores pequenos.