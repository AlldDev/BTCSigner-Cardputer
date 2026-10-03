# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BTCSigner Cardputer: firmware for the M5Stack Cardputer (ESP32-S3) acting as a stateless, air-gapped
Bitcoin PSBT signer. The seed is typed in by hand each session (never generated or persisted on
device) and the only I/O channel is a microSD card — no WiFi/BLE, no camera/QR, no secure element.
Exception, opt-in only: an encrypted backup of the seed's BIP39 entropy (never the passphrase) on a
MIFARE Classic card via the M5Stack Unit RFID2 (WS1850S, I2C 0x28 on Grove G2/G1). See
`firmware/README.md` "Backup opcional no cartão RFID".
Scope is deliberately narrow: BIP84 native SegWit (P2WPKH) only, single-sig, SIGHASH_ALL only, PSBT v0.

`firmware/README.md` (in Portuguese, next to this file) holds the detailed technical docs — read it
for module status, threat model, and rationale. The root `README.md` is only the user-facing overview.
**Note:** `spec.md` is referenced throughout the README as "the spec" but is currently deleted in the
working tree (`git status` shows `D spec.md`) — check working-tree state before assuming it exists.

**Project status**: crypto core and PSBT parser are fully tested on host against official test
vectors and adversarial inputs. The UI/screen flow and SD I/O have been validated on a physical
Cardputer on testnet, but it has **never been used on mainnet**. Do not treat this as ready for real
funds.

## Build

PlatformIO project, run from `firmware/`:

```bash
git submodule update --init --recursive   # required before first build (see below)
pio run -e cardputer                      # release build for real hardware
pio run -e cardputer-debug                # debug build, Serial enabled
```

Three environments in `platformio.ini`:
- `cardputer` — real hardware, `board = m5stack-stamps3` (ESP32-S3), release build, Serial/USB-CDC
  disabled.
- `cardputer-debug` — same, but `-DCORE_DEBUG_LEVEL=3` and Serial on, for development.
- `native` — host-only, excludes `main.cpp`/`ui.cpp`/`sd_io.cpp`/`rfid_io.cpp`/`panic_hooks.cpp`
  (the hardware-dependent files) and `lib_ignore`s `MFRC522_I2C`, used exclusively to run tests.

To flash via M5Launcher (which only accepts a merged image, not the bare `firmware.bin`):

```bash
esptool.py --chip esp32s3 merge_bin -o firmware/.pio/build/cardputer/merged.bin \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0     firmware/.pio/build/cardputer/bootloader.bin \
  0x8000  firmware/.pio/build/cardputer/partitions.bin \
  0x10000 firmware/.pio/build/cardputer/firmware.bin
```

Hardware: ESP32-S3, 320KB RAM, **no PSRAM**, 8MB flash. RAM is the binding constraint — PSBT buffer
size was deliberately shrunk from 64KB to 16KB (`config.h`) after measuring 81% RAM usage at 64KB
vs ~29% at 16KB, then raised to 32KB (~46%) once full previous txs (`non_witness_utxo`) became
mandatory. Each KB of limit costs ~3.3KB of RAM.

## Tests

Unity framework (PlatformIO's built-in C test runner), runs on host via the `native` environment —
no hardware needed:

```bash
pio test -e native                              # all suites
pio test -e native -f test_review_screens        # one suite, by test/ directory name
```

Suites live under `firmware/test/`, one Unity binary per directory: `test_bip32_vectors`,
`test_bip39_vectors`, `test_bip84_vectors`, `test_mnemonic_input`, `test_passphrase_input`,
`test_psbt_parse`, `test_review_screens`, `test_rfid_seed_card`, `test_rfid_integration`,
`test_sd_io_paths`, `test_secure_wipe`, `test_session`. `main.cpp`, `ui.cpp`, `sd_io.cpp`,
`rfid_io.cpp` and `panic_hooks.cpp` have no host tests — they're hardware-only and excluded from
`native`. The golden vectors in
`test_rfid_seed_card` come from an independent Python implementation (hashlib + cryptography); if the
card format changes, regenerate them the same way rather than copying the firmware's own output.

No lint/format config and no CI is configured for this project (the `.clang-format`/`.github` files
found under `firmware/lib/trezor-firmware/` belong to the vendored upstream submodule, not this repo).

## Architecture

`firmware/src/` is flat. The split is deliberately between **host-testable pure logic** and
**hardware-only glue** (the latter excluded from the `native` test env):

- `config.h` — all tunable constants (session timeout, PSBT size/count limits, BIP84 derivation
  constants, `Network` enum). No logic.
- `keys.h/cpp` — thin wrapper over trezor-crypto for BIP32/BIP39/BIP84 derivation, address encoding,
  xpub/zpub serialization, and confirming a claimed change-output actually derives from this seed.
- `session.h` — header-only `Session` class holding the active `MasterKey`, with an injectable
  `MillisFn` for host-testability; expiry and secret wiping.
- `mnemonic_input.h/cpp`, `passphrase_input.h/cpp` — pure state machines for typing the seed phrase
  (with wordlist autocomplete and checksum validation) and passphrase. No drawing or keyboard reads.
- `psbt.h/cpp` — the largest module: a from-scratch, minimal BIP174 parser/validator/signer,
  restricted to PSBT v0 / single P2WPKH inputs / SIGHASH_ALL. Fails closed on anything it can't
  fully verify (fingerprint/derivation/pubkey mismatch, unrecognized scripts, network mismatch,
  unbalanced amounts). Internal buffers are large (`buf_[kMaxPsbtFileSize]`) and **must stay
  static/global, never stack-allocated** — ESP32 task stacks are only 8-16KB.
- `review_screens.h/cpp` — pure text formatting for the PSBT review UI (address grouping, line
  wrapping, BTC/sats formatting), intentionally decoupled from `psbt.h` so parsing and display don't
  couple.
- `sd_io_paths.cpp` — pure path/filename logic (sanitization against traversal, filename building),
  host-testable. `sd_io.cpp` — the actual SD card I/O via Arduino `SD.h`/`SPI.h`, hardware-only,
  hardcoded pins (SCK=40, MISO=39, MOSI=14, CS=12, 25MHz) matching M5Stack's official example.
- `trezor_platform.cpp` — the two hooks trezor-crypto needs from the platform: a fault handler and
  `random_buffer()` (`esp_random()` on device, `getrandom()` on host), used only for ECDSA blinding,
  never as the seed source. Also `strong_random_buffer()` (`strong_random.h`): with WiFi/BT off,
  `esp_random()` is only pseudo-random, so this wraps it in `bootloader_random_enable/disable` (SAR
  ADC noise). Anything needing real entropy (RFID salt/IV) must use it.
- `rfid_seed_card.h/cpp` — pure, host-tested format and crypto of the RFID backup. It composes
  trezor-crypto primitives (PBKDF2-SHA256 single block → HMAC-derived AES/MAC keys, AES-256-CBC,
  encrypt-then-MAC checked with `consteq` before decrypting), plus the MIFARE data-block mapping
  that skips block 0 and the sector trailers. All secrets live in one static scratch struct that is
  zeroed on every return. `rfid_io.h/cpp` — hardware-only Unit RFID2 I/O via the vendored
  `lib/MFRC522_I2C` on Arduino `Wire` (I2C_NUM_0; `Wire1` would collide with Cardputer-ADV's
  internal bus). It probes 0x28, checks `VersionReg` and does a time-bounded soft reset before
  `PCD_Init()` (the lib's `PCD_Reset` hangs forever without the chip), turns the antenna on only
  while operating the card, and only ever sees ciphertext. After `PCD_StopCrypto1()` a MIFARE
  Classic card stays authenticated and ignores a plain auth, so every operation starts with an RF
  field cycle + WUPA + select that must return the same UID, and later sectors use nested auth.
  That behavior can only be verified on real hardware, because host tests simulate the card.
- `ui.h/cpp` — hardware-only drawing and keyboard-reading primitives (M5Cardputer/M5GFX), no screen
  flow/state logic. The Cardputer keyboard has **no Esc or arrow keys**: ESC is mapped to the
  backtick key, navigation to `;` `,` `.` `/` — this is a real hardware constraint, not a design
  choice, and whether a key means "nav" or "literal text" is decided per-screen by `main.cpp`, never
  by `ui.cpp`.
- `main.cpp` — the composition root: a `State` enum driving `handle_key()`/`render()` dispatch,
  wiring together every module above with the `ui.cpp` primitives. No crypto or parsing logic lives
  here, only screen/state orchestration. Large I/O buffers are globals/statics per the same
  stack-size constraint as `psbt.cpp`.

`firmware/lib/trezor_crypto/` holds one-line "trampoline" `.c` files, each `#include`-ing one exact
file from the `trezor-firmware` submodule — this is how the project gets an explicit, auditable
allowlist of exactly which upstream crypto files are compiled (vs. pulling in the submodule's whole
multi-coin/test/fuzzer tree). `firmware/lib/trezor-firmware/` is a git submodule (sparse-checkout of
`crypto/` only), pinned to a specific commit — treat it as vendored upstream code, not to be edited.

libsecp256k1 (Bitcoin Core's library) is **not** used; trezor-crypto's own `secp256k1.c` is.

## Security invariants worth preserving

- No WiFi/BLE: the ESP32-S3 has the radio hardware, but it's never initialized, and this is verified
  against the *linked binary* (`nm` shows no `esp_wifi_init`/`esp_bt_controller_init`/bluedroid/nimble
  symbols), not just source grep. Don't introduce `WiFi.h`, `BLEDevice.h`, `esp_wifi.h`, or `esp_bt.h`.
- `arduino-esp32` always links `libwpa_supplicant.a`, which defines its own `hmac_sha256`,
  `aes_encrypt` and `aes_decrypt`, colliding with trezor-crypto's. Fixed via compiler-level renames
  (`-Dhmac_sha256=btcseed_tc_hmac_sha256`, `-Daes_encrypt=...`, `-Daes_decrypt=...` in
  `platformio.ini`), not by patching the vendored submodule — don't "fix" this the other way.
- The RFID card is public (Crypto1 broken, factory Key A): nothing in clear may be written to it,
  its size must not depend on the seed, the passphrase must never go on it, and every secret buffer
  (password inputs, card buffers, `rfid_wipe_scratch()`, `mnemonic_clear()`) is covered by
  `wipe_seed_material()`. The backup offer only exists between fingerprint confirmation and
  `confirm_fingerprint_and_start_session()`, the last moment the mnemonic is still in RAM.
- The card holds two independent copies (A at 0, B at 384; own salt/IV/keys, no repeated bytes).
  `rfid_write_all` follows `rfid_write_order_index`, which writes copy A **last**, so an interrupted
  write always leaves the old or the new backup readable. Keep that order and the host test
  `test_interrupted_write_keeps_old_or_new_backup` in sync.
- `kRfidPbkdf2Iterations` is frozen: it isn't stored on the card, and `test_production_iterations_are_frozen`
  pins it. Changing it requires restore to keep trying the old value.
- TOOLS > Testar backup (`g_verify_mode`) reuses the mnemonic/passphrase entry screens to re-derive
  a key from a paper or RFID backup and compares it with the session via `same_account()`. The
  mnemonic is never drawn; everything except the session is wiped before the result and on ESC
  (`abort_verify()`), which returns to TOOLS without ending the session. Sector trailers are never
  written; auth tries `kMifareKeys` in order.
- Never call the `PICC_Dump*`/`PCD_DumpVersionToSerial` functions of `MFRC522_I2C`, and don't add
  `Serial`/`ESP_LOG` output to `rfid_*` files.
- Panic/fault must never leak or persist secrets. The precompiled `sdkconfig` writes a core dump to
  flash and prints the panic on UART0/USB; `platformio.ini` counters it with
  `-Wl,--wrap=esp_core_dump_to_flash` (both device envs) and `-Wl,--wrap=esp_panic_handler`
  (release only), implemented in `src/panic_hooks.cpp`, plus `erase_stale_core_dump()` at the start
  of `setup()`. `tc_fault_handler` does `emergency_wipe()` + `esp_restart()` on device. The
  `emergency_wipe` callback runs in panic context: memzero only, no I2C/SPI, drawing or logging.
  Verify the wraps took effect with `objdump` (calls go to `__wrap_*`), not just that it builds.
- `loop()` ends with `scrub_free_stack()` (`secure_wipe.h`), which overwrites the loopTask's whole
  free stack with 0xA5 while sparing the FreeRTOS canary/end-of-stack watchpoint. Keep early returns
  inside `loop_once()` so the scrub always runs.
- PSBT validation is fail-closed by design: anything the parser can't fully verify (unrecognized
  script, unverifiable change claim, mismatched derivation) must be rejected or flagged, not
  silently accepted.
