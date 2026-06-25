# OTA-over-LoRa — Implementation Status

Working record of what's built, what's validated (and how), and what remains. Companion to the design
docs: `OTA.md` (spec), `OTA_PLAN.md` (plan), `docs/ota_protocol.md` (wire format).

Everything is gated behind `-D ENABLE_OTA=1` and is byte-for-byte inert when off. Nothing is committed
to git yet — all changes are in the working tree.

## Validation summary

| Phase | Component | Validated how | Status |
|---|---|---|---|
| P0 | `.mota` format + host packager (`tools/mota/`): build, delta (detools), Ed25519 sign, inspect, verify; `EndF` injector | `tools/mota/test_mota.py` (12/12); CLI end-to-end | ✅ |
| P1 | Portable C++ core: `Multihash`, `MerkleTree` (+proofs, gen+verify), `MotaContainer` parse, `BlockBitmap` | `pio test -e native` (21/21), cross-checked vs Python oracle (proofs byte-identical) | ✅ |
| P2 | `EndF` self-scan, `target_id` / `getOtaTargetId()`, `build.sh` injection | **on Heltec v3**: `ota status` reports exact size/hash/target_id matching the build hook | ✅ |
| P3 | `SignerAllowlist`, `OtaStore`, full verify (parse + merkle root + image_hash + **Ed25519** + allowlist) | **on Heltec v3 AND RAK4631**: `verify` → `ok=1 auto=1` with key, `auto=0` without | ✅ cross-platform |
| P4a | `OtaProtocol` message codec (ADV/QUERY/HAVE/GET_MANIFEST/MANIFEST/REQ/DATA) + server proof-gen | native (21/21), proof-gen matches Python | ✅ |
| P4b | `OtaManager` serve+fetch state machine | native: **two-manager full transfer simulation → byte-identical** reassembly | ✅ |
| P4c | Mesh integration: `PAYLOAD_TYPE_OTA` dispatch, lowest-priority hop-capped flood, wired into `simple_repeater` | **full on-air transfer RAK4631→Heltec COMPLETE + VERIFIED** (see below) | ✅ |
| P5 | **Delta apply (ESP32 A/B) via detools 0.53.0**: vendored detools embeddable C decoder (`src/helpers/ota/detools/`, NONE+CRLE) decodes a `--codec sequential --compression crle` patch against the running slot into the inactive slot, hashing→`image_hash` (`ota applydelta`) | **full LoRa run RAK→Heltec**: 129-byte delta (0.01% of a 1.18 MB image) → `detools decoded 1179184 B, hash OK, armed` → reboot → **booted v1.16.9** | ✅ |
| P6 | **Apply (ESP32 A/B)**: verify inactive-slot image vs signed manifest (image_hash + Ed25519 + allowlist) → `esp_ota_set_boot_partition` → reboot | **real role switch on Heltec: repeater → companion, booted correctly** (`ota apply manifest/verify/commit`; after reboot it speaks the companion frame protocol) | ✅ |
| — | Build + flash both platforms | esptool (Heltec/ESP32) + adafruit-nrfutil **DFU** (RAK4631/nRF52) both confirmed | ✅ |

## On-air status (real LoRa, RAK4631 → Heltec v3) — ✅ COMPLETE + VERIFIED

A full signed `.mota` was transferred **over real LoRa from the RAK4631 (nRF52) to the Heltec v3
(ESP32)** — cross-platform — and **completed + verified end-to-end**:
```
fetch=F 1/6 → 3/6 → 4/6 → 5/6 → 6/6 → fetch=C   (~26 s)
verify: parsed=1 root=1 img=1 signed=1 sig=1 trust=1 | ok=1 auto=1
```
announce → get-manifest → manifest → windowed request → data; every block **merkle-verified against the
signed root** before storage; the reassembled container then **fully verified** (root + image_hash +
Ed25519 signature + allowlist → auto-appliable). Three real bugs were found and fixed via on-device
testing (none caught by the host sim, which doesn't model the mesh):
- **Windowed requests** (`OTA_REQ_WINDOW`) — was requesting the whole image at once → server TX/pool
  congestion. Now paced to the link.
- **Manifest + request retry** in `OtaManager::loop()` — was unrecoverable if a reply dropped.
- **Dedup vs. retries (the key one):** the mesh `hasSeen()` dedup suppressed identical retried requests,
  so a single lost reply stalled forever. Fixed: OTA packets are **always processed** (handlers are
  idempotent); `hasSeen()` now only gates re-flooding. This makes it genuinely *eventually reliable* —
  lossy RF just means more time, exactly as intended.

## Source map (`src/helpers/ota/`)

| File | Role | Portable (native) |
|---|---|---|
| `OtaFormat.h` | wire constants (magics, flags, codecs, msg types) | yes |
| `Multihash.h` | sha2-256 truncations via `Utils::sha256` | yes |
| `MerkleTree.{h,cpp}` | leaf/root (O(log n)), verify, gen proof | yes |
| `MotaContainer.{h,cpp}` | `.mota` parse + root/image-hash checks | yes |
| `BlockBitmap.h` | availability from `leaves[]` (erased = missing) | yes |
| `FirmwareInfo.{h,cpp}` | `EndF` self-scan over a region | yes |
| `OtaStore.h` | staging interface + `OtaStoreRam<N>` | yes |
| `OtaProtocol.{h,cpp}` | message encode/decode | yes |
| `OtaManager.{h,cpp}` | serve+fetch state machine | yes |
| `SignerAllowlist.h` | trusted Ed25519 signer keys | yes |
| `OtaVerify.{h,cpp}` | full verify incl. Ed25519 (uses `Identity`) | device-only |
| `OtaSelf.{h,cpp}` | running-firmware region (ESP32 `esp_partition_read`) | device-only |
| `OtaContext.{h,cpp}` | per-device singleton (manager + stores + allowlist) | device-only |
| `OtaCli.{h,cpp}` | `ota …` CLI commands | device-only |

Core edits (gated): `Packet.h` (`PAYLOAD_TYPE_OTA=0x0C`), `Mesh.{h,cpp}` (dispatch + `createOtaPacket`/
`sendOtaFlood` + hop limit), `MeshCore.h` (`getOtaTargetId`), `CommonCLI.cpp` (`ota` command),
`examples/simple_repeater/MyMesh.{h,cpp}` (`onOtaRecv` + adapter + begin/loop wiring), `build.sh`
(`MOTA_TARGET_ID`), `test/mocks/SHA256.h` (real host SHA-256). Env wiring: `variants/heltec_v3` and
`variants/rak4631` repeater envs (`ENABLE_OTA` + ota sources [+ `EndF` hook on ESP32]).

## `ota` CLI (serial console; also remote-admin over LoRa)

```
ota status                 target_id, self-fw size/hash, serve/fetch state, key count
ota key add|list|rm <hex>  signer allowlist
ota stage <size>           prepare serve buffer
ota recv <off> <hex>       write a chunk into the serve buffer (host streams the .mota)
ota serve                  parse+verify the staged .mota and make it servable
ota announce               broadcast OTA_ADV for the served .mota
ota verify                 full verify of the staged/served (or fetched) .mota
ota want <hex>|auto        manual cross-target override (deliberate role switch, e.g. companion->repeater)
ota clear                  reset buffers
```
Host harness: `tools/mota/` packager + the scratch `onair*.py` orchestration scripts.

## Variant coverage (which platforms have OTA, which need special treatment)

OTA is enabled at the platform base so every variant inherits it; only the apply path differs by HW.

| Platform | OTA build | Apply path | Special treatment |
|---|---|---|---|
| **ESP32** (all chips) | ✅ enabled in `[esp32_base]` (`ENABLE_OTA`, `helpers/ota/*.cpp`, `detools.c`, `pio_endf`) | A/B via `esp_ota` + detools-**sequential** decode into the inactive slot | `applydelta` only runs on a **dual-app/OTA partition table** (2 app slots + otadata). `min_spiffs.csv` boards already qualify (1.875 MB slots); `huge_app`/single-app boards (most esp32/S3 defaults, 3.19 MB) build fine but refuse apply (`ERR no A/B slot`) until repartitioned. |
| **nRF52 — RAK4631 hardware** (rak4631 + gat562_30s / evb_pro / tracker_pro / watch13, muziworks_r1_neo, rak_wismesh_tag) | ✅ `[rak4631]` (inline) + `[rak4631_hw]` (shared, the other 6) | single-slot **in-place** detools, applied by the custom OTAFIX bootloader after reboot | Device must run the **OTAFIX bootloader** fork. `detools.c` is NOT built into the app (only the bootloader decodes). |
| **nRF52 — non-RAK** (heltec_t1/t096/t114/mesh_solar/mesh_pocket, lilygo techo*/t_impulse_plus, thinknode_m1/m3/m6, t1000-e, nano_g2_ultra, promicro, xiao_nrf52, ikoka_*, wio*, sensecap_solar, rak3401, keepteen_lt1, meshtiny, minewsemi_me25ls01) | ❌ not enabled | none | **Needs its own bootloader fork** (single-slot, like RAK) before OTA is safe. No A/B slot, and the stock Adafruit/SoftDevice bootloader can't apply in place. Out of scope until per-board bootloaders exist. |
| **RP2040 / STM32** | ❌ not enabled | none | No A/B apply path implemented yet. |

Build-verified this pass (OTA on): ESP32 across all 4 chip families — esp32 `Heltec_v2` (34.6%), S3 `Heltec_v3` (35.3%), C6 `Xiao_C6` (27.9%), and the tight C3 default-partition class up to the fattest config `Heltec_ct62_companion_radio_ble` **96.2%** / `Xiao_C3_companion_radio_ble` 94.6% (the global flash worst case — fits). All 6 RAK4631-hw nRF52 variants build (Flash 55–65%, RAM ≤ 74%). `native` test suite green. (Pre-existing, OTA-unrelated, fail on clean `main` too: `tenstar_c3` stale `helpers/XiaoC3Board.h` include; `generic_espnow` undefined `P_LORA_DIO_1`.)

## Remaining (clearly scoped)

1. **Device-side full-image delivery to the slot** — the apply path is done + validated, but the role-
   switch test delivered the 631 KB image to the inactive slot via esptool (simulating the transfer,
   which is separately proven on-air). The device writing the slot itself during a *full-image* OTA
   needs `esp_ota_write`/`esp_partition_write` streaming + a bulk transfer (the RAM `OtaStore` is for
   delta-sized images / bring-up).
2. **Multi-fragment blocks** — v1 uses ≤128-byte single-packet blocks; 1 KB blocks need fragment
   reassembly in `OtaManager` (`OTA_DATA` already carries `frag_idx`/`frag_total`).
3. **nRF52 apply** — write the `approval` field + reboot-to-DFU for the bootloader fork (external repo).
4. **nRF52 `EndF` `.hex` build wiring** — currently only the ESP32 `.bin` hook is implemented.
5. **P7 auto-propagation + retention** — 24 h announce, finish-current on supersession, 30-day stale GC.
6. **Companion app frames** (`CMD_OTA_*`) + relay/web-seed ingress for the home-node case.
7. **`hw_id` brick-safety** for cross-target (see plan §6.1) — manifest format change, awaiting confirm.

> Device state: the **Heltec now runs companion_radio_usb** (from the role-switch test); reflash the
> repeater env to continue OTA work. RAK4631 runs the OTA repeater.
8. **`hw_id` brick-safety** for cross-target (`ota want`) — manifest field = `sha2-256:4(manufacturer)`;
   allows same-HW role switches but refuses incompatible-HW firmware. Manifest format change → see
   `OTA_PLAN.md §6.1` (awaiting confirmation since the format was frozen). The manual override
   itself is **done + native-tested**.

## Reproduce

```bash
# host tests
./meshcore/bin/python tools/mota/test_mota.py
./meshcore/bin/pio test -e native -f test_ota

# build + flash (OTA repeater)
./meshcore/bin/pio run -e Heltec_v3_repeater -t upload --upload-port /dev/ttyUSB0
./meshcore/bin/pio run -e RAK_4631_repeater  -t upload --upload-port /dev/ttyACM0   # DFU

# on-device verify / on-air transfer: see tools/mota/ + scratchpad onair*.py
```
