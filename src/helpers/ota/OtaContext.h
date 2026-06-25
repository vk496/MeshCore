#pragma once

#include "OtaManager.h"
#include "OtaStore.h"
#include "SignerAllowlist.h"
#include "OtaApply.h"
#include "OtaFormat.h"
#if defined(NRF52_PLATFORM) && defined(OTA_FLASH_STORE)
  #include "OtaStoreFlashNrf52.h"
#endif

// Per-device OTA singleton shared by the CLI (OtaCli) and the mesh adapter (the example's MyMesh).
// Holds the session engine, a staging store (fetch), a RAM serve buffer, and the signer allowlist.
// nRF52 stages into FLASH (OtaStoreFlashNrf52): a delta can be 100 KB+, too big to hold in RAM, and the
// COMPLETE container must persist so the bootloader can apply it after reboot. A flash page-erase halts
// the CPU (~85 ms) and starves the LoRa RX, so the store COALESCES writes to the 4 KB page (the erase
// unit) and commits each page once, off the per-packet path (see OtaManager.h) — RAM stays O(one page).
// (v1 has no mid-transfer resume; an interrupted fetch simply restarts.) ESP32/native use the RAM store.

namespace mesh {
namespace ota {

#ifndef OTA_SERVE_BUF_SIZE
#define OTA_SERVE_BUF_SIZE 16384
#endif
#ifndef OTA_FETCH_BUF_SIZE
#define OTA_FETCH_BUF_SIZE 16384
#endif

struct OtaContext {
  OtaManager manager;
#if defined(NRF52_PLATFORM) && defined(OTA_FLASH_STORE)
  OtaStoreFlashNrf52 fetch_store;            // persistent flash staging (survives reboot; large deltas)
#else
  OtaStoreRam<OTA_FETCH_BUF_SIZE> fetch_store;
#endif
  SignerAllowlist allow;
  uint8_t  serve_buf[OTA_SERVE_BUF_SIZE];
  uint32_t serve_expected = 0;   // size declared by `ota stage`
  bool     serving = false;      // manager.serve() succeeded
  ApplyState apply_st;           // pending apply (P6)

  // Deferred apply-reboot: a verified `ota applydelta` approves the update but does NOT reboot inline,
  // so the CLI can first deliver the "verified; applying" reply (over LoRa it's the only way the
  // operator learns the apply started). The mesh loop then calls ota_reboot_to_apply() once that reply
  // has actually been transmitted. apply_at/apply_hard are mesh-clock deadlines the loop fills in.
  bool     apply_pending = false;
  uint32_t apply_at = 0;         // earliest reboot time (lets the reply get queued + start sending)
  uint32_t apply_hard = 0;       // hard cap, in case the TX queue never idles on a busy node

  void begin(uint32_t target_id, OtaSend send, void* ctx) {
    manager.begin(target_id, send, ctx);
    // a node only fetches firmware it can apply: ESP32 A/B -> sequential, nRF52 single-slot -> in-place
#if defined(NRF52_PLATFORM)
    manager.set_apply_codec(CODEC_DETOOLS_INPLACE);
#elif defined(ESP32_PLATFORM)
    manager.set_apply_codec(CODEC_DETOOLS_SEQUENTIAL);
#endif
    manager.set_fetch_store(&fetch_store);
  }
};

OtaContext& ota_ctx();   // process-wide singleton

} // namespace ota
} // namespace mesh
