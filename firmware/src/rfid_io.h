// E/S no cartao MIFARE Classic pela M5Stack Unit RFID2 (WS1850S, I2C 0x28 no
// Grove: SDA=G2, SCL=G1). So compila no ambiente `cardputer`. Por aqui so
// passa o blob ja cifrado por rfid_seed_card.cpp — nada em claro.
#pragma once

#include <cstddef>
#include <cstdint>

#include "config.h"

namespace btcseed {

enum class RfidIoStatus {
  kOk,
  kNoReader,        // Unit RFID2 nao responde no I2C
  kNoCard,          // nenhum cartao encostado dentro do timeout
  kUnsupportedCard, // nao e MIFARE Classic 1K/4K
  kAccessDenied,    // nenhuma chave de kMifareKeys aceita (access bits/chave nao-padrao)
  kIoError,         // cartao afastado no meio da operacao, CRC etc.
  kVerifyFailed,    // releitura apos gravar nao confere
  kCardChanged,     // outro cartao (UID diferente) no lugar do detectado
};

// Sonda o endereco e faz um reset com limite de tempo antes de PCD_Init()
// (que trava se o chip nao responder). Reinicializa o leitor a cada chamada.
RfidIoStatus rfid_init();

// Espera ate timeout_ms por um cartao MIFARE Classic 1K/4K e o seleciona.
RfidIoStatus rfid_wait_for_card(uint32_t timeout_ms);

// Operam sobre o cartao detectado por rfid_wait_for_card(): cada chamada o
// reseleciona e exige o mesmo UID. Sempre os 47 blocos de dados, nunca
// trailers nem o bloco 0. A gravacao deixa a copia A por ultimo.
RfidIoStatus rfid_read_all(uint8_t out[kMifareUsableBytes]);
RfidIoStatus rfid_write_all(const uint8_t in[kMifareUsableBytes]);
// Rele o cartao e compara com o que acabou de ser gravado.
RfidIoStatus rfid_verify(const uint8_t expected[kMifareUsableBytes]);

// Encerra a sessao com o cartao (StopCrypto1 + HaltA).
void rfid_release_card();

} // namespace btcseed
