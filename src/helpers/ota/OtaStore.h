#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Staging backend for an in-transit `.mota` (docs/ota_protocol.md §7). Blocks may arrive out of order
// and progress must survive reboots, so the store is random-access. The transfer/verify logic is
// written against this interface; concrete impls are per-platform (RAM for tests/bring-up; persistent
// flash — ESP32 OTA slot / nRF52 raw region — for production, dropped in behind the same interface).

namespace mesh {
namespace ota {

class OtaStore {
public:
  virtual ~OtaStore() {}
  // Prepare staging for a container of `total_size` bytes (erases/clears). false if it won't fit.
  virtual bool begin(uint32_t total_size) = 0;
  virtual bool write(uint32_t offset, const uint8_t* data, uint32_t len) = 0;
  virtual bool read(uint32_t offset, uint8_t* buf, uint32_t len) const = 0;
  virtual uint32_t capacity() const = 0;
  virtual uint32_t staged_size() const = 0;   // total_size from begin(), 0 if none
  virtual void clear() = 0;

  // Optional: declare the size of the leading metadata (header + manifest + merkle leaves, i.e.
  // everything before the payload). A flash-backed store keeps that region — which is updated
  // throughout the transfer (a leaf is committed per block) — pinned in one RAM page, so it can
  // flush the bulk payload page-by-page without re-erasing the leaves' page on every block.
  // Returns false if the metadata won't fit the store's pinned region (transfer is then refused).
  virtual bool set_meta_size(uint32_t meta_bytes) { (void)meta_bytes; return true; }

  // Optional: commit any RAM-buffered data to persistent storage. Called once when the transfer
  // reaches COMPLETE (radio idle), so a flash store does its page writes off the RX critical path.
  // After this returns, a flash store's data() view is coherent. No-op for purely in-RAM stores.
  virtual void finalize() {}
};

// Fixed-capacity RAM store — for native tests and device bring-up of the transfer/verify path.
// (Does NOT survive reboot; a persistent flash store replaces it for production — see D1.)
template <uint32_t CAP>
class OtaStoreRam : public OtaStore {
  uint8_t _buf[CAP];
  uint32_t _total = 0;
public:
  bool begin(uint32_t total_size) override {
    if (total_size > CAP) return false;
    _total = total_size;
    memset(_buf, 0xFF, total_size);   // mimic erased flash (so unfilled leaf slots read as 'missing')
    return true;
  }
  bool write(uint32_t off, const uint8_t* d, uint32_t len) override {
    if ((uint64_t)off + len > _total) return false;
    memcpy(_buf + off, d, len);
    return true;
  }
  bool read(uint32_t off, uint8_t* b, uint32_t len) const override {
    if ((uint64_t)off + len > _total) return false;
    memcpy(b, _buf + off, len);
    return true;
  }
  uint32_t capacity() const override { return CAP; }
  uint32_t staged_size() const override { return _total; }
  void clear() override { _total = 0; }
  const uint8_t* data() const { return _buf; }   // contiguous view (RAM store only)
};

} // namespace ota
} // namespace mesh
