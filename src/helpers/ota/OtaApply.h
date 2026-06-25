#pragma once

#include <stdint.h>
#include <stddef.h>
#include "SignerAllowlist.h"

// P6 apply (full-image, ESP32 A/B). The new image is delivered into the inactive OTA slot; the device
// then verifies that slot against the signed manifest's image_hash (+ Ed25519/allowlist), and commits
// by setting it as the boot partition and rebooting. Safe + rollback-capable (the bootloader validates
// the image; a bad image rolls back). nRF52 apply is the bootloader-handoff path (separate). Functions
// return false on platforms without an A/B OTA layout.

namespace mesh {
namespace ota {

struct ApplyState {
  bool     manifest_ok = false;
  bool     sig_ok = false;
  bool     trusted = false;     // signer in allowlist
  bool     slot_ok = false;     // inactive slot image hashes to manifest.image_hash
  uint32_t slot_addr = 0, slot_size = 0;
  uint32_t image_size = 0;
  uint8_t  image_hash[32] = {0};
};

bool ota_apply_slot_info(uint32_t* addr, uint32_t* size);                 // the inactive A/B slot
bool ota_apply_set_manifest(const uint8_t* mf, uint32_t len,
                            const SignerAllowlist& allow, ApplyState& st); // parse + verify signature
bool ota_apply_verify_slot(ApplyState& st);                              // hash the slot vs image_hash
bool ota_apply_commit();                                                 // set-boot + reboot (no return)

// Apply a detools-sequential delta `.mota` (whole container in `buf`) using detools' own embeddable
// C decoder (CODEC_DETOOLS_SEQUENTIAL, --compression crle). The running slot is the delta base; the
// decoder streams the patch (held in RAM) and writes the reconstructed image into the inactive slot,
// while we hash the output and check it against the signed manifest image_hash. On success the
// inactive slot is set as boot partition; the caller then reboots. `msg` (>=80 bytes) receives a
// human-readable result. Returns true if the slot is verified + armed.
bool ota_apply_detools_mota(const uint8_t* buf, uint32_t len,
                            const SignerAllowlist& allow, ApplyState& st, char* msg);

// nRF52 (RAK4631) single-slot apply. The running app can't rewrite itself, so it does NOT decode: it
// runs the gated verification chain (payload hash -> built-for-this-firmware -> signature/trust) and,
// only if all pass, marks the staged manifest APPROVED in flash. It does NOT reboot — so the caller can
// first send the result back to the operator — the actual handoff is ota_reboot_to_apply() below.
// Returns true (msg = "verified...") when approved, false (msg = the first failing gate) otherwise.
bool ota_apply_mota_nrf52(const uint8_t* buf, uint32_t len,
                          const SignerAllowlist& allow, ApplyState& st, char* msg);

// Commit the (already approved/armed) update and reboot into it — does NOT return. Call this only after
// a successful ota_apply_* AND after the confirmation reply has been delivered, so the operator knows
// the apply started (over LoRa the device then goes silent while the bootloader applies). nRF52: set
// the GPREGRET apply magic + reset (the bootloader does the in-place decode + verify). ESP32: reboot
// into the slot already armed by ota_apply_detools_mota.
void ota_reboot_to_apply();

} // namespace ota
} // namespace mesh
