# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BTCSigner Cardputer: firmware for the M5Stack Cardputer (ESP32-S3) acting as a stateless, air-gapped
Bitcoin PSBT signer. The seed is typed in by hand each session (never generated or persisted on
device) and the only I/O channel is a microSD card — no WiFi/BLE, no camera/QR, no secure element.
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
- `native` — host-only, excludes `main.cpp`/`ui.cpp`/`sd_io.cpp` (the hardware-dependent files),
  used exclusively to run tests.

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
`test_psbt_parse`, `test_review_screens`, `test_sd_io_paths`, `test_session`. `main.cpp` and
`ui.cpp` have no host tests — they're hardware-only and excluded from `native`.

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
  `random_buffer()` (hardware RNG on device, `getrandom()` on host). Used only for ECDSA blinding,
  never as the seed source.
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
- `arduino-esp32` always links `libwpa_supplicant.a`, which defines its own `hmac_sha256` colliding
  with trezor-crypto's. Fixed via a compiler-level rename (`-Dhmac_sha256=btcseed_tc_hmac_sha256` in
  `platformio.ini`), not by patching the vendored submodule — don't "fix" this the other way.
- PSBT validation is fail-closed by design: anything the parser can't fully verify (unrecognized
  script, unverifiable change claim, mismatched derivation) must be rejected or flagged, not
  silently accepted.
