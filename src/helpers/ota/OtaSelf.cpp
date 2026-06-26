#include "OtaSelf.h"
#include "FirmwareInfo.h"
#include <string.h>

#if defined(ESP32_PLATFORM)
  #include "esp_ota_ops.h"
  #include "esp_partition.h"
#elif defined(NRF52_PLATFORM)
  #include "OtaFlashLayout_nrf52.h"
#endif

#if defined(ESP32_PLATFORM) || defined(NRF52_PLATFORM)
  #include "OtaContext.h"     // serve our own fw from flash (cache leaves, read payload on demand)
  #include "MerkleTree.h"
  #include <SHA256.h>
  #include <stdlib.h>
  #ifndef OTA_SELF_LEAVES_MAX
  #define OTA_SELF_LEAVES_MAX 65536u   // cap heap for cached leaves (~16k blocks @1 KB = up to ~16 MB image)
  #endif
#endif

namespace mesh {
namespace ota {

#if defined(ESP32_PLATFORM)
// Scan the running app partition for the firmware's EndF trailer using esp_partition_read (stable
// across IDF versions — no mmap). Same rule as find_self_firmware(): the marker's absolute offset
// must equal its stored body_len, which uniquely identifies the running firmware's own trailer.
bool ota_self_firmware(SelfFwInfo& out) {
  out = SelfFwInfo();
  const esp_partition_t* p = esp_ota_get_running_partition();
  if (!p) return false;

  const uint32_t CH = 512;
  uint8_t buf[CH + ENDF_LEN];                 // overlap so a marker spanning a chunk edge is still seen
  for (uint32_t base = 0; base + ENDF_LEN <= p->size; base += CH) {
    uint32_t want = CH + ENDF_LEN;
    if (base + want > p->size) want = p->size - base;
    if (esp_partition_read(p, base, buf, want) != ESP_OK) return false;
    for (uint32_t i = 0; i + ENDF_LEN <= want; i++) {
      if (buf[i] != ENDF_MAGIC[0]) continue;
      if (memcmp(buf + i, ENDF_MAGIC, 4) != 0) continue;
      uint32_t body_len = (uint32_t)buf[i+4] | ((uint32_t)buf[i+5] << 8)
                        | ((uint32_t)buf[i+6] << 16) | ((uint32_t)buf[i+7] << 24);
      if (body_len != base + i) continue;     // must sit immediately after a body of that length
      out.valid = true;
      out.endf_offset = base + i;
      out.body_len = body_len;
      out.image_len = body_len + ENDF_LEN;
      memcpy(out.body_hash, buf + i + 8, 8);
      return true;
    }
  }
  return false;
}
#elif defined(NRF52_PLATFORM)
// nRF52 internal flash is memory-mapped, so the running app is directly scannable. The body starts at
// APP_BASE; find_self_firmware() picks the EndF whose stored body_len equals its offset (the running
// firmware's own trailer), ignoring any staged `.mota` (which carries its own embedded EndF) higher up.
bool ota_self_firmware(SelfFwInfo& out) {
  const uint8_t* region = (const uint8_t*)(uintptr_t)MOTA_NRF52_APP_BASE;
  uint32_t region_len = MOTA_NRF52_FS_START - MOTA_NRF52_APP_BASE;
  return find_self_firmware(region, region_len, out, /*verify_body=*/true);
}
#else
bool ota_self_firmware(SelfFwInfo& out) {
  // STM32/RP2040: app-region access lands with their apply path.
  out = SelfFwInfo();
  return false;
}
#endif

#if defined(ESP32_PLATFORM)
bool ota_self_read(uint32_t off, uint8_t* buf, uint32_t len) {
  const esp_partition_t* p = esp_ota_get_running_partition();
  return p && esp_partition_read(p, off, buf, len) == ESP_OK;
}
#elif defined(NRF52_PLATFORM)
bool ota_self_read(uint32_t off, uint8_t* buf, uint32_t len) {
  if ((uint64_t)MOTA_NRF52_APP_BASE + off + len > MOTA_NRF52_FS_START) return false;
  memcpy(buf, (const uint8_t*)(uintptr_t)(MOTA_NRF52_APP_BASE + off), len);
  return true;
}
#else
bool ota_self_read(uint32_t, uint8_t*, uint32_t) { return false; }
#endif

#if defined(ESP32_PLATFORM) || defined(NRF52_PLATFORM)
static bool self_read_cb(void* ctx, uint32_t off, uint8_t* buf, uint32_t len) {
  (void)ctx; return ota_self_read(off, buf, len);
}
static void wr_u32le(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

// Build (once) the full-image manifest + merkle leaves for the running firmware, cache them in `c`, and
// hand the manager a flash-read callback for the payload. The image is read ONCE here to compute the
// leaves + image_hash; thereafter a block REQ reads only that block (proof comes from the cached leaves).
bool ota_serve_self(OtaContext& c, uint32_t fw_version) {
  SelfFwInfo fi;
  if (!ota_self_firmware(fi) || !fi.valid) return false;
  // 1 KB logical blocks (delivered as multiple LoRa fragments): 8x fewer merkle leaves than 128 B, so a
  // ~530 KB image is ~518 blocks (proof-gen scratch ~2 KB) instead of ~4150 (which overflowed the scratch).
  const uint32_t image_size = fi.image_len, BS = OTA_DEFAULT_BLOCK_SIZE;
  const uint32_t bc = (image_size + BS - 1) / BS;
  if ((uint64_t)bc * 4 > OTA_SELF_LEAVES_MAX) return false;

  free(c.serve_self_leaves); free(c.serve_self_proof);
  c.serve_self_leaves = (uint8_t*)malloc((size_t)bc * 4);
  c.serve_self_proof  = (uint8_t*)malloc((size_t)bc * 4);   // proof-gen working buffer (sized to OUR image)
  if (!c.serve_self_leaves || !c.serve_self_proof) {
    free(c.serve_self_leaves); free(c.serve_self_proof);
    c.serve_self_leaves = c.serve_self_proof = nullptr;
    return false;
  }

  SHA256 sha; uint8_t blk[BS];
  for (uint32_t i = 0, off = 0; i < bc; i++, off += BS) {
    uint32_t blen = (off + BS <= image_size) ? BS : (image_size - off);
    if (!ota_self_read(off, blk, blen)) {
      free(c.serve_self_leaves); free(c.serve_self_proof);
      c.serve_self_leaves = c.serve_self_proof = nullptr;
      return false;
    }
    merkle_leaf(c.serve_self_leaves + (size_t)i * 4, blk, blen);
    sha.update(blk, blen);
  }
  uint8_t image_hash[32]; sha.finalize(image_hash, 32);
  uint8_t root[4]; merkle_root(root, c.serve_self_leaves, bc);

  uint8_t* m = c.serve_self_manifest;        // assemble v2 manifest-minus-leaves (full, unsigned) = 93 bytes
  memset(m, 0, 96);
  m[0] = MOTA_FORMAT_VER; m[1] = MFLAG_FULL; m[2] = HASH_ALGO_SHA256;
  wr_u32le(m + 3, c.manager.target()); wr_u32le(m + 7, fw_version);
  wr_u32le(m + 11, image_size); wr_u32le(m + 15, image_size);   // full: payload == image
  m[19] = 10;                                 // block_size_log2 = 10 (1024 B logical block)
  memcpy(m + 20, root, 4);
  memcpy(m + 24, image_hash, 32);
  m[56] = CODEC_FULL;
  memcpy(m + 57, c.hw_id, strlen(c.hw_id) < 32 ? strlen(c.hw_id) : 32);   // hw_id[32] (NUL-padded by memset)
  memcpy(m + 89, APPROVAL_NOT, 4);            // approval marker (fetching device's apply-gate handles it)
  return c.manager.serve_self(m, 93, c.serve_self_leaves, bc,
                              c.serve_self_proof, (size_t)bc * 4, self_read_cb, nullptr);
}
#endif

} // namespace ota
} // namespace mesh
