# MeshCore OTA — `.mota` container & LoRa protocol (v1 draft)

Goals: distribute firmware over LoRa as a self-verifying, resumable, BitTorrent-v2-style block
transfer that survives reboots, never auto-applies without consent, and is portable enough for other
projects (e.g. Meshtastic) to adopt.

---

## 1. Conventions

- **Endianness:** all multi-byte integers are little-endian unless stated.
- **Hashes (multihash):** the hash family is declared once per manifest via `hash_algo`. v1 uses
  `0x12` = **SHA-256** (the [multihash](https://github.com/multiformats/multihash) code for sha2-256).
  Truncations used:
  - `sha2-256:4` — first 4 bytes of the SHA-256 digest. Merkle leaves, internal nodes, root, proofs.
  - `sha2-256:8` — first 8 bytes. Base-firmware identity (`base_hash`, `EndF`).
  - `sha2-256:32` — full digest. The image security anchor (`image_hash`).
  Digests are stored **bare** (just the truncated bytes); the family is implied by `hash_algo`.
- **Signatures:** Ed25519 (RFC 8032), 64-byte detached signature, 32-byte public key.

Reference constants:

| Name | Bytes (hex) | ASCII |
|---|---|---|
| Container `MAGIC` | `6D 4F 54 41` | `mOTA` |
| Container `TRAILER` | `76 6B 34 39 36` | `vk496` |
| `EndF` marker | `45 6E 64 46` | `EndF` |
| `hash_algo` (sha2-256) | `12` | — |
| `approval` = not approved | `FF FF FF FF` | (erased) |
| `approval` = approved | `41 50 52 56` | `APRV` |
| `format_ver` | `01` | — |

---

## 2. Firmware image & the `EndF` trailer

Every OTA-capable firmware build appends a 16-byte `EndF` trailer to its flashed image so a running
node can discover its own size/identity on any MCU (no linker symbols needed).

```
flashed image = BODY (image bytes) || EndF trailer
EndF trailer (16 bytes):
  off 0  4  "EndF"        (45 6E 64 46)
  off 4  4  body_len      uint32 LE — length of BODY (excludes this 16-byte trailer)
  off 12 8  body_hash     sha2-256:8 of BODY
```

- **Size discovery:** scan flash from the partition top downward for the `EndF` marker; the byte
  before it is the last BODY byte. (Same technique as `NRF52Board::getBootloaderVersion`.)
- **Self-identity / delta base matching:** a node's `body_hash` is read directly from its own `EndF`;
  a delta's `base_hash` (§5) must equal it. No self-hashing pass required at match time.
- **No circularity:** `EndF` hashes only the BODY, never itself.

The "reconstructed image" referenced by the manifest is the full `BODY || EndF` (what gets flashed).

---

## 3. The `.mota` container

This is the **distributed** form (host-built, wire-transferred).

```
off            size   field
0              4      MAGIC = 6D 4F 54 41
4              4      MOTA_TOTAL_SIZE  uint32 LE — total container bytes (incl. manifest, leaves[],
                                       payload, trailer). Lets a node pre-reserve staging and compute
                                       write_start = staging_region_end − MOTA_TOTAL_SIZE.
8              M      MANIFEST         (§4; self-delimited, no length field)
8 + M          P      PAYLOAD          (payload_size bytes; delta or full image)
8 + M + P      5      TRAILER = 76 6B 34 39 36
```

`MOTA_TOTAL_SIZE = 4 + 4 + M + P + 5`.

**Staged (in-flash) form.** Written bottom-aligned so `TRAILER` ends at `staging_region_end`. Identical
bytes, except the device mutates two regions in place (both NOR-safe, no re-erase): the `leaves[]`
slots (filled as blocks arrive) and the 4-byte `approval` field (on user approval). Everything else is
immutable.

---

## 4. The manifest

Fields are serialized in this exact order. Conditional fields are present per `flags`.

```
off  size   field            notes
0    1      format_ver       = 0x01
1    1      flags            bit0 FULL (0=delta/partial, 1=full image)
                             bit1 SIGNED
                             bits2-7 reserved (0)
2    1      hash_algo        0x12 = sha2-256
3    4      target_id        device/arch/role discriminator (§9)
7    4      fw_version       MAJOR<<24 | MINOR<<16 | PATCH<<8 | pre   (comparable uint32)
11   4      image_size       size of the reconstructed image (BODY||EndF)
15   4      payload_size     PAYLOAD bytes in this container
19   1      block_size_log2  e.g. 0x0A = 1024
20   4      merkle_root      sha2-256:4 over PAYLOAD blocks (§6)
24   32     image_hash       sha2-256:32 of the reconstructed image — SECURITY anchor
56   1      codec_id         0=full/raw, 1=detools-sequential, 2=detools-in-place
57   8      base_hash        [present iff !FULL] sha2-256:8 of the BASE image's BODY (matches EndF.body_hash)
.    32     signer_pubkey    [present iff SIGNED] Ed25519 public key
.    64     signature        [present iff SIGNED] Ed25519 over all bytes from off 0 up to here (exclusive)
.    4      approval         ALWAYS present. FF FF FF FF = not approved; 41 50 52 56 ("APRV") = approved
.    4*BC   leaves[]         ALWAYS present. BC = ceil(payload_size / 2^block_size_log2). sha2-256:4 each
```

Self-delimiting: a parser knows every offset from `format_ver`/`flags` + `payload_size` (→ `BC`); no
explicit length field is stored.

Manifest size (excluding `leaves[]`): unsigned-full 57+4=61, signed-full 161, unsigned-delta 69,
**signed-delta 165**.

### 4.1 Signed region

`signature` covers manifest bytes `[0, signature_offset)` — i.e. everything before it, including
`signer_pubkey` and (for deltas) `base_hash`. It does **not** cover `approval` or `leaves[]`:
- `leaves[]` are verified against the signed `merkle_root` (§6), so they need no separate signature.
- `approval` is device-local consent (§7), deliberately outside the signature.

### 4.2 The `approval` field

- Distributed and **forced on ingest** to `FF FF FF FF` (a peer can never pre-approve).
- The local user's `ota apply` writes `41 50 52 56` (`"APRV"`) — a single NOR-safe write (only clears
  bits from the erased word). Any partial/other value reads as not-approved (fail-safe).
- Auto-bound to this image: it lives in this `.mota`'s manifest and is re-erased when a new `.mota` is
  staged.
- It is a **consent** marker, not a security primitive. Authenticity = `signature` + `image_hash`.

---

## 5. Payload, codecs & delta base

`PAYLOAD` is either the full reconstructed image (`FULL`) or a delta (`!FULL`).

| `codec_id` | Meaning | Notes |
|---|---|---|
| 0 | full / raw | PAYLOAD = reconstructed image (`BODY||EndF`). Typical for ESP32 (A/B). |
| 1 | detools sequential | needs random read of base + sequential write of result (e.g. ESP32 A→B). |
| 2 | detools in-place | bounded scratch; rewrites the app region in place (nRF52 single-slot). |

For deltas, `base_hash` = the base image's `EndF.body_hash` (sha2-256:8 of its BODY). A node applies a
delta only if `base_hash` matches its own `EndF.body_hash`. After applying, the result MUST hash
(sha2-256:32) to `image_hash` before it is flashed — this is the hard security gate.

Compression is internal to the detools patch; the chosen scheme must be supported by the applier
(bootloader contract, §12). Patches are produced by detools 0.53.0 (`tools/mota` → `detools.create_patch`)
and decoded on-device by detools' own embeddable C decoder, vendored verbatim at
`src/helpers/ota/detools/` (see its `README.meshcore.txt`). That build enables only the self-contained
`NONE` + `CRLE` compressions (no malloc / liblzma / heatshrink), so MeshCore deltas use
`--codec sequential --compression crle`. The ESP32 applier (`OtaApply.cpp::ota_apply_detools_mota`)
wires the decoder's callbacks to: read base ← running OTA slot, stream patch ← fetched bytes in RAM,
write output → inactive slot, hashing the output and checking it against `image_hash` before arming.

---

## 6. Merkle tree (sha2-256:4)

Purpose: verify each PAYLOAD block against the signed `merkle_root` **before** the whole payload
exists, so corruption/forgery is localized to a block.

- **Blocks:** PAYLOAD is split into `BC = ceil(payload_size / B)` blocks, `B = 2^block_size_log2`
  (default 1024). The last block is its real length (**no zero padding**).
- **Leaf:** `leaves[i] = sha2-256:4( block_i_bytes )`.
- **Internal node:** `node = sha2-256:4( left || right )` (4+4 = 8 input bytes).
- **Odd level:** if a level has an odd number of nodes, the **last node is promoted unchanged** to the
  next level (no duplication).
- **Root:** reduce until one node remains. `BC == 1` → root = `leaves[0]`. `BC == 0` is invalid.

### 6.1 Proofs

A proof for block `i` is the ordered list of sibling digests from leaf to root, each tagged
left/right. Promoted levels contribute **no** element. Verification (needs `BC` to know the shape):

```
h = leaf_i ; idx = i ; n = BC ; p = 0
while n > 1:
    if (n is odd) and (idx == n-1):        # this node was promoted
        pass
    else:
        sib, side = proof[p] ; p += 1
        h = sha2-256:4( sib || h ) if side==left else sha2-256:4( h || sib )
    idx //= 2 ; n = (n + 1) // 2
accept iff h == merkle_root and p == len(proof)
```

Over LoRa, `leaves[]` are **omitted** from the manifest transfer; a serving node computes a block's
proof on demand from its stored `leaves[]`, and the fetcher fills its own `leaves[i]` as each verified
block lands.

---

## 7. Block availability (persistent, derived from `leaves[]`)

There is no separate availability structure. **Block `i` is present ⟺ `leaves[i]` is non-erased**
(`!= FF FF FF FF`). Because `leaves[]` live in the staged flash region, availability **survives
reboot**. Commit order per block (crash-safe): (1) verify proof, (2) write block payload to its
offset, (3) write `leaves[i]` **last**. A power loss before step 3 leaves the slot erased → the block
is simply re-fetched (idempotent). On boot a node rebuilds a small in-RAM bitmap (`ceil(BC/8)` bytes)
by scanning `leaves[]`.

A node holding the complete payload (or relaying/serving its own firmware) advertises `have_all`
instead of a bitmap.

---

## 8. LoRa OTA protocol

Carried in MeshCore packets with **`PAYLOAD_TYPE_OTA = 0x0C`** (subject to change if core devs prefer
reusing `RAW_CUSTOM 0x0F` + subtype). Every OTA packet payload:

```
[0]    ota_msg_type
[1..]  body
```

- **Routing:** `OTA_ADV`/`OTA_QUERY` flood; `OTA_HAVE`/`OTA_MANIFEST`/`OTA_REQ`/`OTA_DATA` direct.
- **Hop cap:** OTA refuses to retransmit when `getPathHashCount() >= ota_hop_limit` (default **3**,
  configurable). No change to core routing.
- **Priority:** enqueued at the lowest TX priority (~250) and only when the duty-cycle/airtime budget
  has spare headroom, so OTA never competes with mesh traffic.
- **`manifest_id`** = the manifest's `merkle_root` (4 bytes) — a compact content id.

| `ota_msg_type` | val | dir | body |
|---|---|---|---|
| `OTA_ADV` | 0x01 | flood | `target_id(4) fw_version(4) image_size(4) block_size_log2(1) merkle_root(4) image_hash8(8) flags(1) [base_hash(8) if delta] have_all(1)` |
| `OTA_QUERY` | 0x02 | flood | `target_id(4) min_version(4) caps(1)` (caps bit0 want_delta, bit1 want_full) |
| `OTA_HAVE` | 0x03 | direct | `manifest_id(4) bitmap_off(2) bitmap[]` |
| `OTA_GET_MANIFEST` | 0x04 | direct | `manifest_id(4)` |
| `OTA_MANIFEST` | 0x05 | direct | `manifest_id(4) frag_idx(1) frag_total(1) bytes[]` (omits `leaves[]`) |
| `OTA_REQ` | 0x06 | direct | `manifest_id(4) want_off(2) want_bitmap[]` |
| `OTA_DATA` | 0x07 | direct | `manifest_id(4) block_idx(2) frag_idx(1) frag_total(1) [proof in frag0] bytes[]` |

Sizing against the 184-byte `MAX_PACKET_PAYLOAD`: `OTA_DATA` fixed overhead ≈ 9 B → ~175 B/fragment →
**6 fragments per 1 KB block**; a proof for ≤512 blocks ≤ 9×4 = 36 B (carried in `frag0`); an
availability bitmap for 500 blocks ≈ 63 B (one packet).

Reliability is *eventual*: the fetcher re-requests un-acked blocks after a timeout, possibly from a
different peer. No hard ACKs, no ordering.

### 8.1 Relay seeding (companion frames)

A node need not store a foreign-target `.mota` to serve it: a relay advertises a manifest on behalf of
an external source and **pulls blocks on demand**. Companion-app frames: `CMD_OTA_PROVIDE_MANIFEST`
(app→node, starts advertising), event `PUSH_OTA_BLOCK_REQ(manifest_id, block_idx)` (node→app), reply
`CMD_OTA_PROVIDE_BLOCK(manifest_id, block_idx, bytes)`.

---

## 9. Identity, trust & versioning

- **`target_id`** (4 B): compile-time `sha2-256:4(pio_env_name + radio_class + ldscript/partition +
  platform)`, injected by `build.sh`, read via `MainBoard::getOtaTargetId()`. A node only fetches/serves
  matching `target_id`. (The PlatformIO env name uniquely captures hardware AND role/partition.)
- **`fw_version`:** packed comparable uint32 (`MAJOR<<24|MINOR<<16|PATCH<<8|pre`).
- **Signing & allowlist:** a node keeps a runtime-managed allowlist of trusted Ed25519 signer pubkeys
  (none embedded in firmware). A `.mota` is eligible for **auto-apply** only if signed by an allowlisted
  key, the signature verifies, and `image_hash` matches; otherwise it is manual-apply only with explicit
  confirmation. **Transfer needs no trust** — blocks are content-addressed against the signed root, so
  any (untrusted) neighbor may relay them.

### 9.1 Supersession & retention

- **Finish-current:** a newer version announced mid-download does not abort the in-progress transfer.
- **Stale GC:** a staged `.mota` carries a persistent `staged_at` epoch; it is discarded after
  `ota_stale_ttl` (default **30 days**) unless pinned (`ota keep`) or applying — reclaiming flash from
  superseded-complete and stalled-partial images alike. `ota discard` frees the slot immediately.

---

## 10. Apply & bootloader contract (summary)

- **ESP32:** in-firmware via `Update`/`esp_ota_*` into the inactive A/B slot, then set boot + reboot
  (power-safe, rollback-capable). No bootloader changes.
- **nRF52:** running firmware **never** flashes the app. `ota apply` verifies fully, writes the
  `approval` field (`"APRV"`), then reboots into DFU. The modified bootloader
  (`Adafruit_nRF52_Bootloader_OTAFIX`) locates the staged `.mota` by scanning for `MAGIC`, re-checks
  `TRAILER` + signature + `image_hash` + `approval == "APRV"`, applies the codec (delta in-place over
  the app region), then clears state and boots. The signature proves author authenticity; `approval`
  proves local owner consent — both required.

---

## 11. Versioning of this spec

`format_ver = 1`. Future changes bump `format_ver`; the multihash `hash_algo` allows changing the
digest family without a format bump. Unknown `format_ver`/`codec_id`/`ota_msg_type` values are ignored
(forward-compatible).
