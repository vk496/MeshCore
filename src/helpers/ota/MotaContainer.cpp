#include "MotaContainer.h"
#include "MerkleTree.h"
#include "Multihash.h"
#include <string.h>

namespace mesh {
namespace ota {

static uint32_t rd_u32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool MotaManifest::is_approved() const {
  return approval && memcmp(approval, APPROVAL_YES, 4) == 0;
}

bool mota_parse(const uint8_t* buf, uint32_t len, MotaManifest& out) {
  out = MotaManifest();
  if (len < 4 + 4 + 5) return false;
  if (memcmp(buf, MOTA_MAGIC, 4) != 0) return false;
  if (memcmp(buf + len - 5, MOTA_TRAILER, 5) != 0) return false;
  uint32_t total = rd_u32(buf + 4);
  if (total != len) return false;

  const uint8_t* p = buf + 8;                 // start of manifest
  const uint8_t* end = buf + len - 5;         // start of trailer
  out.manifest_start = p;
  // helper bounds check
  #define NEED(n) do { if ((uint32_t)(end - p) < (uint32_t)(n)) return false; } while (0)

  NEED(3 + 16 + 1 + 4 + 32 + 1 + 32);          // fixed head incl. hw_id[32]
  out.format_ver = p[0];
  if (out.format_ver != MOTA_FORMAT_VER) return false;
  out.flags = p[1];
  out.hash_algo = p[2];
  out.target_id    = rd_u32(p + 3);
  out.fw_version   = rd_u32(p + 7);
  out.image_size   = rd_u32(p + 11);
  out.payload_size = rd_u32(p + 15);
  out.block_size_log2 = p[19];
  out.merkle_root = p + 20;
  out.image_hash  = p + 24;
  out.codec_id    = p[56];
  out.hw_id       = p + 57;                     // 32-byte NUL-padded hardware tag (signed)
  p += 89;

  if (out.block_size_log2 == 0 || out.block_size_log2 > 24) return false;
  uint32_t bs = out.block_size();
  out.block_count = (out.payload_size + bs - 1) / bs;
  if (out.payload_size == 0 || out.block_count == 0) return false;

  if (!out.is_full()) { NEED(8); out.base_hash = p; p += 8; }

  if (out.is_signed()) {
    NEED(32);  out.signer_pubkey = p; p += 32;
    out.signed_len = (uint32_t)(p - (buf + 8));   // signature covers everything up to here
    NEED(64);  out.signature = p; p += 64;
  } else {
    out.signed_len = (uint32_t)(p - (buf + 8));
  }

  NEED(4); out.approval = p; p += 4;

  uint32_t leaves_bytes = out.block_count * 4;
  NEED(leaves_bytes); out.leaves = p; p += leaves_bytes;

  NEED(out.payload_size); out.payload = p; p += out.payload_size;

  // payload must end exactly at the trailer
  if (p != end) return false;
  #undef NEED
  return true;
}

bool mota_parse_manifest(const uint8_t* mf, uint32_t len, MotaManifest& out) {
  out = MotaManifest();
  const uint8_t* p = mf;
  const uint8_t* end = mf + len;
  #define NEEDM(n) do { if ((uint32_t)(end - p) < (uint32_t)(n)) return false; } while (0)

  NEEDM(89);                                   // fixed head incl. hw_id[32]
  out.manifest_start = mf;
  out.format_ver = p[0];
  if (out.format_ver != MOTA_FORMAT_VER) return false;
  out.flags = p[1];
  out.hash_algo = p[2];
  out.target_id    = rd_u32(p + 3);
  out.fw_version   = rd_u32(p + 7);
  out.image_size   = rd_u32(p + 11);
  out.payload_size = rd_u32(p + 15);
  out.block_size_log2 = p[19];
  out.merkle_root = p + 20;
  out.image_hash  = p + 24;
  out.codec_id    = p[56];
  out.hw_id       = p + 57;                     // 32-byte NUL-padded hardware tag (signed)
  p += 89;
  if (!out.is_full()) { NEEDM(8); out.base_hash = p; p += 8; }
  if (out.is_signed()) {
    NEEDM(32); out.signer_pubkey = p; p += 32;
    out.signed_len = (uint32_t)(p - mf);
    NEEDM(64); out.signature = p; p += 64;
  } else {
    out.signed_len = (uint32_t)(p - mf);
  }
  NEEDM(4); out.approval = p; p += 4;
  if (out.block_size_log2 == 0 || out.block_size_log2 > 24 || out.payload_size == 0) return false;
  out.block_count = (out.payload_size + out.block_size() - 1) / out.block_size();
  #undef NEEDM
  return true;
}

bool mota_check_root(const MotaManifest& m) {
  if (!m.leaves || m.block_count == 0) return false;
  uint8_t root[4];
  merkle_root(root, m.leaves, m.block_count);
  return memcmp(root, m.merkle_root, 4) == 0;
}

bool mota_check_image_hash_full(const MotaManifest& m) {
  if (!m.is_full() || !m.payload || !m.image_hash) return false;
  uint8_t h[32];
  mh32(h, m.payload, m.payload_size);
  return memcmp(h, m.image_hash, 32) == 0;
}

} // namespace ota
} // namespace mesh
