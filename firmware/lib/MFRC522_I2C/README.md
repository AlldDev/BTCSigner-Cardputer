# MFRC522_I2C (vendorizada)

Driver I2C do leitor MFRC522, usado para a **M5Stack Unit RFID2 (chip WS1850S,
compativel em registradores com o MFRC522, endereco `0x28`)** no backup
opcional da seed (`src/rfid_io.cpp`). E a mesma lib que a documentacao da
M5Stack indica para RFID/RFID2.

- Upstream: https://github.com/kkloesener/MFRC522_I2C
- Commit: `8152dddc93cf743397ac225e34bf268698326664` (2026-05-11)
- Licenca: dominio publico (cabecalho de `src/MFRC522_I2C.h` e `.cpp`)
- Arquivos copiados sem nenhuma modificacao (sha256):
  - `src/MFRC522_I2C.cpp` `5705e5b13cfc9307583662270017665f9683cc81022f445b3672dc8d7f3173e7`
  - `src/MFRC522_I2C.h` `2c3ca9ef2d15cfc18098f1ceb99cb699958c9dad5435c8e9098a3536b81243bc`
  - `library.properties` `fa728b52314e582e18b6d22e6270a454b5831a6c2bf5086576cd4c0deeedde4b`

Vendorizada (em vez de `lib_deps` numa branch) porque roda no mesmo processo
que tem a seed na RAM: uma mudanca upstream so entra aqui com nova revisao.

## Revisao feita

- So inclui `Arduino.h` e `Wire.h`; toda E/S e `TwoWire` no endereco dado. Sem
  alocacao dinamica, sem radio, sem rede.
- Pelo leitor so passa o blob ja cifrado (ver `src/rfid_seed_card.h`).
- As funcoes `PICC_Dump*ToSerial` / `PCD_DumpVersionToSerial` imprimem o
  conteudo do cartao na Serial: **nunca** sao chamadas pelo firmware.
- `PCD_Reset()` (chamado por `PCD_Init()`) fica num `while` infinito se o chip
  nao responder (`Wire.read()` devolve 0xFF e o bit PowerDown parece sempre
  ligado). `rfid_init()` sonda o endereco no barramento **antes** de chamar
  `PCD_Init()`, para a Unit RFID2 desconectada nao travar o aparelho.
