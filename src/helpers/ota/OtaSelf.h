#pragma once

#include "FirmwareInfo.h"

// Device-side accessor for the running firmware's own image (to read its EndF trailer).
// Per-platform: ESP32 memory-maps the running app partition; other platforms TBD (nRF52 uses the
// bootloader-apply path, so its app-region wiring lands with that work). Not compiled on the native
// host — the portable scan logic in FirmwareInfo.{h,cpp} is what gets unit-tested there.

namespace mesh {
namespace ota {

// Locate this firmware's EndF trailer in its own flash image. Returns false if unsupported on this
// platform or no valid EndF is present (e.g. firmware built without the EndF build hook).
bool ota_self_firmware(SelfFwInfo& out);

} // namespace ota
} // namespace mesh
