#include "FirmwareInfo.h"
#include "Multihash.h"
#include <string.h>

namespace mesh {
namespace ota {

static uint32_t rd_u32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool find_self_firmware(const uint8_t* region, uint32_t region_len,
                        SelfFwInfo& out, bool verify_body) {
  out = SelfFwInfo();
  if (!region || region_len < ENDF_LEN) return false;

  for (uint32_t off = 0; off + ENDF_LEN <= region_len; off++) {
    if (region[off] != ENDF_MAGIC[0]) continue;               // cheap pre-filter ('E')
    if (memcmp(region + off, ENDF_MAGIC, 4) != 0) continue;
    uint32_t body_len = rd_u32(region + off + 4);
    if (body_len != off) continue;                            // trailer must sit right after the body

    if (verify_body) {
      uint8_t h[8];
      mh8(h, region, body_len);
      if (memcmp(h, region + off + 8, 8) != 0) continue;       // coincidental marker — keep scanning
    }
    out.valid = true;
    out.endf_offset = off;
    out.body_len = body_len;
    out.image_len = off + ENDF_LEN;
    memcpy(out.body_hash, region + off + 8, 8);
    // Extended EndF? An "EnFx" block right after body_hash carries self-describing identity. The trailer is
    // then 60 bytes, so the reconstructed image extends to off + ENDF_EXT_LEN.
    if (off + ENDF_EXT_LEN <= region_len && memcmp(region + off + 16, ENDF_EXT_MAGIC, 4) == 0) {
      out.has_ident = true;
      out.fw_version = rd_u32(region + off + 20);
      out.target_id  = rd_u32(region + off + 24);
      memcpy(out.hw_id, region + off + 28, 32);
      out.hw_id[32] = 0;
      out.image_len = off + ENDF_EXT_LEN;
    }
    return true;
  }
  return false;
}

} // namespace ota
} // namespace mesh
