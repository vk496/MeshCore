#include "OtaSelf.h"
#include "FirmwareInfo.h"
#include <string.h>

#if defined(ESP32_PLATFORM)
  #include "esp_ota_ops.h"
  #include "esp_partition.h"
#elif defined(NRF52_PLATFORM)
  #include "OtaFlashLayout_nrf52.h"
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

} // namespace ota
} // namespace mesh
