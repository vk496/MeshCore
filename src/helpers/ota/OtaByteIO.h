#pragma once

#include <stdint.h>
#include <stddef.h>

// A tiny bounds-checked little-endian cursor for reading the `.mota` container (docs/ota_protocol.md §3-§4)
// in a self-documenting way: each field is read by name in order, instead of hand-computed byte offsets
// (`p[0]`, `rd_u32(p+3)`, `p += 89`, `NEED(n)` ...). Any over-read flips `ok` false and yields zero/null, so
// callers parse the whole struct then check `r.ok` once. 32-bit offsets (a container can be >64 KB; the
// 16-byte LoRa wire messages keep their own uint16 cursor in OtaProtocol.cpp). No allocation; `take()`
// returns a pointer INTO the caller's buffer (zero-copy), matching the manifest's by-pointer fields.

namespace mesh {
namespace ota {

struct ByteReader {
  const uint8_t* p;
  uint32_t len;
  uint32_t n = 0;
  bool ok = true;

  ByteReader(const uint8_t* buf, uint32_t length) : p(buf), len(length) {}

  uint32_t pos() const { return n; }
  bool fits(uint32_t k) const { return ok && (uint64_t)n + k <= len; }

  uint8_t u8() { if (!fits(1)) { ok = false; return 0; } return p[n++]; }
  uint32_t u32() {                                   // little-endian
    if (!fits(4)) { ok = false; return 0; }
    uint32_t v = (uint32_t)p[n] | ((uint32_t)p[n+1] << 8) | ((uint32_t)p[n+2] << 16) | ((uint32_t)p[n+3] << 24);
    n += 4; return v;
  }
  // Borrow `k` bytes at the cursor (e.g. merkle_root[4], leaves[4*BC]) and advance; null on overflow.
  const uint8_t* take(uint32_t k) {
    if (!fits(k)) { ok = false; return nullptr; }
    const uint8_t* r = p + n; n += k; return r;
  }
  void skip(uint32_t k) { if (!fits(k)) { ok = false; return; } n += k; }
};

} // namespace ota
} // namespace mesh
