// Barramento: `Wire` do Arduino (I2C_NUM_0) nos pinos do Grove. No M5Unified
// 0.2.23 essa porta so seria usada pelo Ex_I2C se external_rtc/external_imu
// estivessem ligados (nao estao); o I2C interno do Cardputer-ADV (teclado
// TCA8418, codec) fica em I2C_NUM_1. Pinos do Grove conferidos na tabela de
// pinos do proprio M5Unified (board_M5Cardputer / ADV: SCL=G1, SDA=G2).
//
// MIFARE Classic: depois de PCD_StopCrypto1() o cartao continua AUTENTICADO e
// ignora uma nova autenticacao em claro. Por isso cada operacao comeca
// reselecionando o cartao (ciclo do campo de RF -> IDLE -> WUPA -> select), e
// os setores seguintes usam autenticacao aninhada (sem StopCrypto1 entre eles),
// como o proprio upstream faz em PICC_DumpMifareClassicToSerial().
#include "rfid_io.h"

#include <Arduino.h>
#include <Wire.h>

#include <MFRC522_I2C.h>

extern "C" {
#include "memzero.h"
}

#include "rfid_seed_card.h" // mifare_physical_block_for_index

namespace btcseed {
namespace {

constexpr uint8_t kRfid2I2cAddr = 0x28;
constexpr int kGroveSdaPin = 2;
constexpr int kGroveSclPin = 1;
constexpr uint32_t kI2cHz = 100000;
constexpr int kBlocksPerSector = 4;
constexpr uint32_t kResetTimeoutMs = 250;
constexpr uint32_t kFieldCycleMs = 10;

MFRC522_I2C g_reader(kRfid2I2cAddr, -1, &Wire);
bool g_wire_started = false;
bool g_reader_ready = false;
MFRC522_I2C::Uid g_card_uid{}; // cartao detectado por rfid_wait_for_card()
bool g_card_known = false;
uint8_t g_block_buf[18]; // MIFARE_Read exige 16 + 2 de CRC
uint8_t g_verify_buf[kMifareUsableBytes];

bool reader_responds() {
  Wire.beginTransmission(kRfid2I2cAddr);
  return Wire.endTransmission() == 0;
}

// PCD_Init() chama PCD_Reset(), que espera o fim do reset sem limite de tempo.
// Fazemos antes um reset com limite: so segue se o chip realmente responde
// como um MFRC522/WS1850S (sem chip, o I2C devolve 0xFF e o bit nunca cai).
bool reader_resets_in_time() {
  byte version = g_reader.PCD_ReadRegister(MFRC522_I2C::VersionReg);
  if (version == 0x00 || version == 0xFF) return false;
  g_reader.PCD_WriteRegister(MFRC522_I2C::CommandReg, MFRC522_I2C::PCD_SoftReset);
  uint32_t start = millis();
  delay(50);
  while (g_reader.PCD_ReadRegister(MFRC522_I2C::CommandReg) & (1 << 4)) {
    if (millis() - start > kResetTimeoutMs) return false;
    delay(10);
  }
  return true;
}

// WUPA em vez do REQA de PICC_IsNewCardPresent(): acorda tambem um cartao em HALT.
bool card_present() {
  byte atqa[2];
  byte size = sizeof(atqa);
  byte st = g_reader.PICC_WakeupA(atqa, &size);
  return st == MFRC522_I2C::STATUS_OK || st == MFRC522_I2C::STATUS_COLLISION;
}

bool same_uid(const MFRC522_I2C::Uid &a, const MFRC522_I2C::Uid &b) {
  return a.size == b.size && a.size <= sizeof(a.uidByte) &&
         memcmp(a.uidByte, b.uidByte, a.size) == 0;
}

// Desliga e religa o campo (o cartao perde energia e volta a IDLE) e seleciona
// de novo, exigindo o mesmo UID do cartao detectado.
RfidIoStatus reselect_card() {
  if (!g_card_known) return RfidIoStatus::kNoCard;
  g_reader.PCD_StopCrypto1();
  g_reader.PCD_AntennaOff();
  delay(kFieldCycleMs);
  g_reader.PCD_AntennaOn();
  delay(kFieldCycleMs);
  if (!card_present() || !g_reader.PICC_ReadCardSerial()) return RfidIoStatus::kIoError;
  if (!same_uid(g_reader.uid, g_card_uid)) return RfidIoStatus::kCardChanged;
  return RfidIoStatus::kOk;
}

bool authenticate(int block) {
  MFRC522_I2C::MIFARE_Key key;
  memcpy(key.keyByte, kMifareDefaultKeyA, sizeof(key.keyByte));
  byte status = g_reader.PCD_Authenticate(MFRC522_I2C::PICC_CMD_MF_AUTH_KEY_A,
                                          static_cast<byte>(block), &key, &g_reader.uid);
  return status == MFRC522_I2C::STATUS_OK;
}

// Percorre os 47 blocos de dados, autenticando cada setor uma vez.
template <typename Fn>
RfidIoStatus for_each_block(Fn fn) {
  RfidIoStatus st = reselect_card();
  if (st != RfidIoStatus::kOk) return st;
  int authed_sector = -1;
  for (int i = 0; i < kMifareUsableBlocks && st == RfidIoStatus::kOk; i++) {
    int block = mifare_physical_block_for_index(i);
    int sector = block / kBlocksPerSector;
    if (sector != authed_sector) {
      // Autenticacao aninhada; se o cartao nao aceitar, uma tentativa limpa.
      bool ok = authenticate(block);
      if (!ok) {
        st = reselect_card();
        ok = st == RfidIoStatus::kOk && authenticate(block);
      }
      if (!ok) {
        if (st == RfidIoStatus::kOk) st = RfidIoStatus::kAccessDenied;
        break;
      }
      authed_sector = sector;
    }
    if (!fn(i, block)) st = RfidIoStatus::kIoError;
  }
  g_reader.PCD_StopCrypto1();
  return st;
}

RfidIoStatus read_into(uint8_t *out) {
  RfidIoStatus st = for_each_block([out](int i, int block) {
    byte size = sizeof(g_block_buf);
    if (g_reader.MIFARE_Read(static_cast<byte>(block), g_block_buf, &size) !=
            MFRC522_I2C::STATUS_OK ||
        size < kMifareBlockSize) {
      return false;
    }
    memcpy(out + i * kMifareBlockSize, g_block_buf, kMifareBlockSize);
    return true;
  });
  memzero(g_block_buf, sizeof(g_block_buf));
  return st;
}

} // namespace

RfidIoStatus rfid_init() {
  if (!g_wire_started) {
    Wire.begin(kGroveSdaPin, kGroveSclPin, kI2cHz);
    g_wire_started = true;
  }
  g_reader_ready = false;
  g_card_known = false;
  // Reinicializa a cada uso: o modulo pode ter sido desplugado/trocado.
  if (!reader_responds() || !reader_resets_in_time()) return RfidIoStatus::kNoReader;
  g_reader.PCD_Init();       // liga a antena...
  g_reader.PCD_AntennaOff(); // ...que so fica ligada enquanto o cartao e operado
  g_reader_ready = true;
  return RfidIoStatus::kOk;
}

RfidIoStatus rfid_wait_for_card(uint32_t timeout_ms) {
  if (!g_reader_ready || !reader_responds()) return RfidIoStatus::kNoReader;
  g_card_known = false;
  g_reader.PCD_AntennaOn();
  uint32_t start = millis();
  while (millis() - start < timeout_ms) {
    if (card_present() && g_reader.PICC_ReadCardSerial()) {
      byte type = g_reader.PICC_GetType(g_reader.uid.sak);
      if (type == MFRC522_I2C::PICC_TYPE_MIFARE_1K || type == MFRC522_I2C::PICC_TYPE_MIFARE_4K) {
        g_card_uid = g_reader.uid;
        g_card_known = true;
        return RfidIoStatus::kOk;
      }
      rfid_release_card();
      return RfidIoStatus::kUnsupportedCard;
    }
    delay(50);
  }
  g_reader.PCD_AntennaOff();
  return RfidIoStatus::kNoCard;
}

RfidIoStatus rfid_read_all(uint8_t out[kMifareUsableBytes]) {
  RfidIoStatus st = read_into(out);
  if (st != RfidIoStatus::kOk) memzero(out, kMifareUsableBytes);
  return st;
}

RfidIoStatus rfid_write_all(const uint8_t in[kMifareUsableBytes]) {
  return for_each_block([in](int i, int block) {
    memcpy(g_block_buf, in + i * kMifareBlockSize, kMifareBlockSize);
    bool ok = g_reader.MIFARE_Write(static_cast<byte>(block), g_block_buf, kMifareBlockSize) ==
              MFRC522_I2C::STATUS_OK;
    memzero(g_block_buf, sizeof(g_block_buf));
    return ok;
  });
}

RfidIoStatus rfid_verify(const uint8_t expected[kMifareUsableBytes]) {
  RfidIoStatus st = read_into(g_verify_buf);
  if (st == RfidIoStatus::kOk && memcmp(g_verify_buf, expected, kMifareUsableBytes) != 0) {
    st = RfidIoStatus::kVerifyFailed;
  }
  memzero(g_verify_buf, sizeof(g_verify_buf));
  return st;
}

void rfid_release_card() {
  if (!g_reader_ready || !reader_responds()) return;
  g_reader.PCD_StopCrypto1();
  g_reader.PICC_HaltA();
  g_reader.PCD_AntennaOff();
}

} // namespace btcseed
