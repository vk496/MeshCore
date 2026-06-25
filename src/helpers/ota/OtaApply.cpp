#include "OtaApply.h"
#include "OtaFormat.h"
#include "MotaContainer.h"
#include "Identity.h"
#include <string.h>

#if defined(ESP32_PLATFORM)
  #include <SHA256.h>            // rweather streaming SHA-256 (for hashing the slot in chunks)
  #include "esp_ota_ops.h"
  #include "esp_partition.h"
  #include "esp_system.h"
  extern "C" {
    #include "detools/detools.h" // vendored detools 0.53.0 embeddable decoder (CRLE-only build)
  }
#elif defined(NRF52_PLATFORM)
  #include "OtaVerify.h"
  #include "OtaSelf.h"
  #include "OtaFlashLayout_nrf52.h"
  #include "flash/flash_nrf5x.h"  // Adafruit core internal-flash driver (has its own extern "C")
  #include "nrf.h"
  #include "nrf_soc.h"
  #include "nrf_sdm.h"
#endif

namespace mesh {
namespace ota {

#if defined(ESP32_PLATFORM)

bool ota_apply_slot_info(uint32_t* addr, uint32_t* size) {
  const esp_partition_t* p = esp_ota_get_next_update_partition(nullptr);
  if (!p) return false;
  if (addr) *addr = p->address;
  if (size) *size = p->size;
  return true;
}

bool ota_apply_set_manifest(const uint8_t* mf, uint32_t len, const SignerAllowlist& allow, ApplyState& st) {
  st = ApplyState();
  ota_apply_slot_info(&st.slot_addr, &st.slot_size);
  MotaManifest m;
  if (!mota_parse_manifest(mf, len, m)) return false;
  if (!m.is_full()) return false;            // A/B apply takes a full image (delta would need decode)
  st.image_size = m.image_size;
  memcpy(st.image_hash, m.image_hash, 32);
  st.manifest_ok = true;
  if (m.is_signed()) {
    mesh::Identity signer(m.signer_pubkey);
    st.sig_ok = signer.verify(m.signature, m.manifest_start, (int)m.signed_len);
    st.trusted = st.sig_ok && allow.contains(m.signer_pubkey);
  }
  return true;
}

bool ota_apply_verify_slot(ApplyState& st) {
  st.slot_ok = false;
  if (!st.manifest_ok || st.image_size == 0 || st.image_size > st.slot_size) return false;
  const esp_partition_t* p = esp_ota_get_next_update_partition(nullptr);
  if (!p) return false;
  SHA256 sha;
  uint8_t buf[512];
  uint32_t off = 0;
  while (off < st.image_size) {
    uint32_t n = st.image_size - off; if (n > sizeof(buf)) n = sizeof(buf);
    if (esp_partition_read(p, off, buf, n) != ESP_OK) return false;
    sha.update(buf, n);
    off += n;
  }
  uint8_t h[32];
  sha.finalize(h, 32);
  st.slot_ok = (memcmp(h, st.image_hash, 32) == 0);
  return st.slot_ok;
}

bool ota_apply_commit() {
  const esp_partition_t* p = esp_ota_get_next_update_partition(nullptr);
  if (!p) return false;
  if (esp_ota_set_boot_partition(p) != ESP_OK) return false;
  esp_restart();   // does not return
  return true;
}

// --- detools callback context -----------------------------------------------------------------
// The delta base is the running OTA slot; the reconstructed image is streamed into the inactive slot
// via esp_ota_write (sequential, append-only -- matches detools' sequential output ordering) and
// hashed on the fly so we can check it against the signed manifest image_hash before arming.
struct DetoolsCtx {
  const esp_partition_t* base;    // delta base (running image), read at absolute `from_pos`
  long           from_pos;        // absolute byte offset into `base`
  const uint8_t* patch;           // .mota payload (whole patch held in RAM)
  uint32_t       patch_len;
  uint32_t       patch_pos;
  esp_ota_handle_t out;           // inactive slot write handle
  SHA256*        sha;             // running hash of the reconstructed output
  uint32_t       out_pos;         // #bytes written to the output slot
  bool           io_ok;
};

static int dt_from_read(void* arg, uint8_t* buf, size_t size) {
  DetoolsCtx* c = (DetoolsCtx*)arg;
  if (c->from_pos < 0 || (uint32_t)(c->from_pos) + size > c->base->size) return -DETOOLS_IO_FAILED;
  if (esp_partition_read(c->base, (size_t)c->from_pos, buf, size) != ESP_OK) { c->io_ok = false; return -DETOOLS_IO_FAILED; }
  c->from_pos += (long)size;
  return DETOOLS_OK;
}
static int dt_from_seek(void* arg, int offset) {          // detools uses relative seeks
  DetoolsCtx* c = (DetoolsCtx*)arg;
  c->from_pos += offset;
  if (c->from_pos < 0 || (uint32_t)c->from_pos > c->base->size) return -DETOOLS_IO_FAILED;
  return DETOOLS_OK;
}
static int dt_patch_read(void* arg, uint8_t* buf, size_t size) {
  DetoolsCtx* c = (DetoolsCtx*)arg;
  if (c->patch_pos + size > c->patch_len) return -DETOOLS_IO_FAILED;
  memcpy(buf, c->patch + c->patch_pos, size);
  c->patch_pos += (uint32_t)size;
  return DETOOLS_OK;
}
static int dt_to_write(void* arg, const uint8_t* buf, size_t size) {
  DetoolsCtx* c = (DetoolsCtx*)arg;
  if (esp_ota_write(c->out, buf, size) != ESP_OK) { c->io_ok = false; return -DETOOLS_IO_FAILED; }
  c->sha->update(buf, size);
  c->out_pos += (uint32_t)size;
  return DETOOLS_OK;
}

bool ota_apply_detools_mota(const uint8_t* buf, uint32_t len, const SignerAllowlist& allow,
                            ApplyState& st, char* msg) {
  st = ApplyState();
  MotaManifest m;
  if (!mota_parse(buf, len, m)) { strcpy(msg, "no valid .mota (parse failed)"); return false; }
  if (m.is_full() || m.codec_id != CODEC_DETOOLS_SEQUENTIAL) { strcpy(msg, "not a detools-sequential delta"); return false; }
  st.image_size = m.image_size;
  memcpy(st.image_hash, m.image_hash, 32);
  st.manifest_ok = true;
  // signature (if signed): valid Ed25519 AND signer in this device's allowlist — refuse otherwise,
  // BEFORE decoding an untrusted image into the slot. (The decoded result is also checked against the
  // manifest image_hash below, which is the target-firmware-hash gate.)
  if (m.is_signed()) {
    mesh::Identity signer(m.signer_pubkey);
    st.sig_ok = signer.verify(m.signature, m.manifest_start, (int)m.signed_len);
    st.trusted = st.sig_ok && allow.contains(m.signer_pubkey);
    if (!st.sig_ok)  { strcpy(msg, "bad signature"); return false; }
    if (!st.trusted) { strcpy(msg, "untrusted signer (pubkey not in allowlist)"); return false; }
  }

  const esp_partition_t* base = esp_ota_get_running_partition();      // delta base = what's running
  const esp_partition_t* out  = esp_ota_get_next_update_partition(nullptr);
  if (!base || !out) { strcpy(msg, "no A/B slot"); return false; }
  st.slot_addr = out->address; st.slot_size = out->size;
  if (m.image_size > out->size) { strcpy(msg, "image > slot"); return false; }

  esp_ota_handle_t h;
  if (esp_ota_begin(out, m.image_size, &h) != ESP_OK) { strcpy(msg, "ota_begin failed"); return false; }

  SHA256 sha;
  DetoolsCtx ctx;
  ctx.base = base; ctx.from_pos = 0;
  ctx.patch = m.payload; ctx.patch_len = m.payload_size; ctx.patch_pos = 0;
  ctx.out = h; ctx.sha = &sha; ctx.out_pos = 0; ctx.io_ok = true;

  int r = detools_apply_patch_callbacks(dt_from_read, dt_from_seek, dt_patch_read,
                                        (size_t)m.payload_size, dt_to_write, &ctx);
  if (r < 0 || !ctx.io_ok) { esp_ota_abort(h); sprintf(msg, "detools err %d @%u/%u",
                             ctx.io_ok ? r : -DETOOLS_IO_FAILED, (unsigned)ctx.out_pos, (unsigned)m.image_size); return false; }
  if ((uint32_t)r != m.image_size || ctx.out_pos != m.image_size) {
    esp_ota_abort(h); sprintf(msg, "size mismatch %u!=%u", (unsigned)ctx.out_pos, (unsigned)m.image_size); return false; }

  uint8_t hh[32]; sha.finalize(hh, 32);
  st.slot_ok = (memcmp(hh, m.image_hash, 32) == 0);
  if (!st.slot_ok) { esp_ota_abort(h); strcpy(msg, "image_hash MISMATCH after decode"); return false; }
  if (esp_ota_end(h) != ESP_OK) { strcpy(msg, "ota_end failed"); return false; }
  if (esp_ota_set_boot_partition(out) != ESP_OK) { strcpy(msg, "set_boot failed"); return false; }
  sprintf(msg, "verified%s; decoded %u B, image hash OK — armed, rebooting to apply",
          m.is_signed() ? " (signer trusted)" : " (unsigned)", (unsigned)m.image_size);
  return true;
}

bool ota_apply_mota_nrf52(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st, char* msg) {
  st = ApplyState(); strcpy(msg, "nRF52-only (ESP32 uses ota_apply_detools_mota)"); return false;
}

void ota_reboot_to_apply() { esp_restart(); }  // boots the slot armed by ota_apply_detools_mota; no return

#elif defined(NRF52_PLATFORM)  // single-slot: verify + mark APPROVED + hand off to the bootloader

// ESP32 A/B-only entry points are unsupported on nRF52.
bool ota_apply_slot_info(uint32_t*, uint32_t*) { return false; }
bool ota_apply_set_manifest(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st) { st = ApplyState(); return false; }
bool ota_apply_verify_slot(ApplyState&) { return false; }
bool ota_apply_commit() { return false; }
bool ota_apply_detools_mota(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st, char* msg) { st = ApplyState(); strcpy(msg, "use ota_apply_mota_nrf52"); return false; }

void ota_reboot_to_apply() {                   // public: set the apply magic + reset (does not return)
  uint8_t sd_en = 0;
  sd_softdevice_is_enabled(&sd_en);
  if (sd_en) {                                 // POWER is SD-restricted while the SoftDevice runs
    sd_power_gpregret_clr(0, 0xFFFFFFFF);
    sd_power_gpregret_set(0, GPREGRET_OTA_APPLY);
  } else {
    NRF_POWER->GPREGRET = GPREGRET_OTA_APPLY;
  }
  NVIC_SystemReset();                          // does not return
}

bool ota_apply_mota_nrf52(const uint8_t* buf, uint32_t len, const SignerAllowlist& allow,
                          ApplyState& st, char* msg) {
  st = ApplyState();
  MotaManifest m;
  if (!mota_parse(buf, len, m)) { strcpy(msg, "parse failed"); return false; }
  if (m.is_full() || m.codec_id != CODEC_DETOOLS_INPLACE) { strcpy(msg, "not an in-place delta"); return false; }
  st.image_size = m.image_size;
  memcpy(st.image_hash, m.image_hash, 32);
  st.manifest_ok = true;

  // Gated verification, in order, returning the FIRST failing reason (the bootloader re-checks integrity
  // again before booting, so authenticity is gated here and re-validated there):
  VerifyResult vr = ota_verify(buf, len, allow);
  st.sig_ok = vr.sig_ok; st.trusted = vr.trusted;

  // 1) downloaded payload: the fetched blocks must match the manifest's merkle root (intact + complete)
  if (!vr.root_ok || !vr.image_ok) { strcpy(msg, "payload hash mismatch (incomplete or corrupt .mota)"); return false; }

  // 2) target firmware: the delta must be built against THIS running image (base_hash == our EndF body
  //    hash). The resulting image_hash is re-checked by the bootloader after the in-place decode -- a
  //    single-slot device cannot produce the target image to hash it before applying.
  SelfFwInfo fi;
  if (!ota_self_firmware(fi) || !fi.valid) { strcpy(msg, "cannot read running firmware (no EndF)"); return false; }
  if (!m.base_hash || memcmp(m.base_hash, fi.body_hash, 8) != 0) { strcpy(msg, "not built for the running firmware (base mismatch)"); return false; }
  st.slot_ok = true;

  // 3) signature (only if the .mota is signed): valid Ed25519 AND signer in this device's allowlist
  if (vr.is_signed) {
    if (!vr.sig_ok)  { strcpy(msg, "bad signature"); return false; }
    if (!vr.trusted) { strcpy(msg, "untrusted signer (pubkey not in allowlist)"); return false; }
  }

  // mark the staged manifest APPROVED in flash (buf is the memory-mapped staging region, so
  // m.approval is a real flash address). NOR-clear over the erased 0xFFFFFFFF -> "APRV".
  uint32_t approval_addr = (uint32_t)(uintptr_t)m.approval;
  if (flash_nrf5x_write(approval_addr, APPROVAL_YES, 4) < 0) { strcpy(msg, "approval write failed"); return false; }
  flash_nrf5x_flush();
  if (memcmp((const void*)(uintptr_t)approval_addr, APPROVAL_YES, 4) != 0) { strcpy(msg, "approval not set"); return false; }

  // Approved. Do NOT reset here — return so the caller can deliver `msg` to the operator first; the
  // deferred ota_reboot_to_apply() (after the reply is sent) does the actual handoff to the bootloader.
  sprintf(msg, "verified%s; applying — rebooting into bootloader once this reply is sent",
          vr.is_signed ? " (signer trusted)" : " (unsigned)");
  return true;
}

#else  // native / other platforms

bool ota_apply_slot_info(uint32_t*, uint32_t*) { return false; }
bool ota_apply_set_manifest(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st) { st = ApplyState(); return false; }
bool ota_apply_verify_slot(ApplyState&) { return false; }
bool ota_apply_commit() { return false; }
bool ota_apply_detools_mota(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st, char* msg) { st = ApplyState(); strcpy(msg, "unsupported"); return false; }
bool ota_apply_mota_nrf52(const uint8_t*, uint32_t, const SignerAllowlist&, ApplyState& st, char* msg) { st = ApplyState(); strcpy(msg, "unsupported"); return false; }
void ota_reboot_to_apply() {}

#endif

} // namespace ota
} // namespace mesh
