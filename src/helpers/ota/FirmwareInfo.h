#pragma once

#include <stdint.h>
#include <stddef.h>
#include "OtaFormat.h"

// Locate the EndF trailer in a firmware image to learn the running firmware's size + identity
// (docs/ota_protocol.md §2). Portable: operates on a contiguous, readable region — on nRF52/ESP32
// the application flash is memory-mapped, so the region pointer is just (const uint8_t*)APP_BASE.

namespace mesh {
namespace ota {

struct SelfFwInfo {
  bool     valid = false;
  uint32_t body_len = 0;       // firmware body length (excludes the 16-byte EndF trailer)
  uint32_t image_len = 0;      // body_len + ENDF_LEN  (what a delta base / full image hashes over)
  uint32_t endf_offset = 0;    // offset of the "EndF" marker within the region (== body_len)
  uint8_t  body_hash[8] = {0}; // sha2-256:8 of the body (read from EndF; == a delta's base_hash)
};

// Scan `region[0..region_len)` for the firmware's EndF trailer. The body starts at offset 0, so the
// trailer's offset must equal its stored body_len — this uniquely identifies the running firmware's
// EndF even if a staged `.mota` (which contains its own embedded EndF) sits higher in the region.
// If `verify_body` is true the body hash is recomputed and must match (rules out coincidental markers).
bool find_self_firmware(const uint8_t* region, uint32_t region_len,
                        SelfFwInfo& out, bool verify_body = false);

} // namespace ota
} // namespace mesh
