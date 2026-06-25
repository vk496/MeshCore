# `mota` — MeshCore OTA packaging tool

Host-side tooling for building and validating `.mota` firmware-update containers.
Implements the wire spec in [`docs/ota_protocol.md`](../../docs/ota_protocol.md) (v1).

Part of the OTA-over-LoRa work — see `OTA_PLAN.md` (milestone **P0**).

## Setup

Uses the repo's Python venv (`meshcore/`). Dependencies: `detools` (delta), `cryptography` (Ed25519).

```bash
./meshcore/bin/pip install detools cryptography
```

## Files

| File | What |
|---|---|
| `motalib.py` | Core logic: multihash, EndF, merkle tree+proofs, manifest/container build+parse+verify. No CLI; unit-tested; the reference implementation of the spec. |
| `mota.py` | CLI: `keygen` / `build` / `inspect` / `verify`. |
| `endf.py` | Standalone `EndF` trailer injector (idempotent). |
| `pio_endf.py` | PlatformIO post-build hook to inject `EndF` (gated on `-D ENABLE_OTA`). |
| `test_mota.py` | Tests (run directly or via pytest). |

## Usage

```bash
PY=./meshcore/bin/python

# 1. one-time: generate a signing keypair (raw 32-byte hex)
$PY tools/mota/mota.py keygen --out-priv signer.priv

# 2a. full image (e.g. ESP32 A/B) — payload IS the flashable image
$PY tools/mota/mota.py build \
    --fw firmware.bin --target-id 0x11223344 --fw-version 1.16.0 \
    --codec full --sign signer.priv --out fw_v1.16.0_full.mota

# 2b. delta against a previous release (e.g. RAK4631) — small patch payload
$PY tools/mota/mota.py build \
    --fw firmware_new.bin --base firmware_old.bin \
    --target-id 0x11223344 --fw-version 1.16.0 \
    --codec sequential --sign signer.priv --out fw_v1.16.0_delta.mota
#   --codec inplace  for single-slot in-place apply (nRF52); params must match the bootloader contract

# 3. inspect / validate
$PY tools/mota/mota.py inspect fw_v1.16.0_delta.mota
$PY tools/mota/mota.py verify  fw_v1.16.0_delta.mota --pub signer.priv.pub --base firmware_old.bin
```

`build` notes:
- `--fw` may be a plain `.bin`; the tool appends `EndF` if absent (idempotent).
- For deltas, `base_hash` is taken from the base image's `EndF` and embedded so a device can confirm
  the delta applies to its current firmware.
- `image_hash` (full SHA-256, signed) is the security anchor checked on the reconstructed image before
  flashing; the 4-byte merkle tree is for per-block transfer verification.
- `--compression` (delta only) defaults to `crle` (decode-cheap). `lzma` gives smaller deltas but a
  heavier on-device decoder — the final choice is pinned by the bootloader/applier contract.

## Tests

```bash
./meshcore/bin/python tools/mota/test_mota.py      # 11 tests: EndF, merkle+proofs, full/delta,
                                                   # signing, tamper detection, approval enforcement
```

## `EndF` build integration

`EndF` must live in the **flashed** firmware (not just inside the `.mota`), because a node serves its
own firmware and matches a delta's `base_hash` against its own `EndF`. Wiring:

- **ESP32 / RP2040** (emit `firmware.bin`): add `post:tools/mota/pio_endf.py` to the env's
  `extra_scripts` and define `-D ENABLE_OTA=1`. The hook appends `EndF` to the app `.bin` before merge.
- **nRF52 / STM32** (emit `.hex` → `.uf2`): the `.hex` must be rewritten with the trailer at the image
  end before `create-uf2.py` runs. This path + the on-device round-trip is completed and validated in
  milestone **P2** (which builds/flashes the RAK4631). The byte logic is the same `motalib.ensure_endf`
  used everywhere.

Until build integration lands, `mota build` still produces correct containers (it appends `EndF` to the
image it packages); only the *running* firmware's self-`EndF` depends on the build hook.
