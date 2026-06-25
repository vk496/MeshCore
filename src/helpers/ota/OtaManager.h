#pragma once

#include <stdint.h>
#include <stddef.h>
#include "OtaFormat.h"
#include "OtaStore.h"
#include "MotaContainer.h"

// Transport-agnostic OTA session engine (docs/ota_protocol.md §5/§8). It SERVES a complete `.mota`
// (answering GET_MANIFEST / REQ) and/or FETCHES one into an OtaStore (verifying every block against
// the signed merkle root via proofs). It is portable (no Arduino / radio / Ed25519) so it can be
// driven by a host simulation; a thin Mesh adapter wires it to PAYLOAD_TYPE_OTA on device.
//
// v1 assumes single-fragment blocks (block_size small enough to fit one packet). Multi-fragment
// reassembly (for 1 KB blocks) is a later optimization; the wire format already carries frag fields.

namespace mesh {
namespace ota {

// Emit an OTA message (one packet payload). `flood`=true for announce/query, false for direct replies.
typedef void (*OtaSend)(void* ctx, const uint8_t* msg, uint16_t len, bool flood);

#ifndef OTA_PROOFGEN_SCRATCH
#define OTA_PROOFGEN_SCRATCH 4096   // server proof-gen working buffer (supports up to 1024 blocks)
#endif

#ifndef OTA_REQ_WINDOW
#define OTA_REQ_WINDOW 6            // blocks requested per REQ (keeps the server's TX queue small)
#endif
// nRF52 note: a flash page-erase halts the CPU (~85 ms, code runs from flash) and starves the LoRa RX,
// so writing to flash on every received packet drops in-flight DATA and the transfer stalls. The SD-safe
// driver (Adafruit flash_nrf5x) always erases on flush, so there is no erase-free write; instead
// OtaStoreFlashNrf52 COALESCES to the 4 KB page (the erase unit) and writes each page once — RAM stays
// O(one page), never O(mota). It pins flash page 0 (header+manifest+merkle leaves, which update all
// transfer long) in RAM and streams the payload through one sliding page buffer, flushing page 0 and the
// last page at finalize() (radio idle). Flash is then touched ~once per 4 KB (≈1 per 4 blocks), not per
// packet; a small delta that fits page 0 does ZERO flash I/O until COMPLETE. (Pacing alone is not enough.)

class OtaManager {
public:
  enum FetchState : uint8_t { IDLE, WANT_MANIFEST, FETCHING, COMPLETE, FAILED };

  void begin(uint32_t my_target_id, OtaSend send, void* ctx);

  // --- serve ---  Provide a complete, contiguous `.mota` to serve (caller keeps it alive).
  bool serve(const uint8_t* mota, uint32_t len);
  void announce();                 // broadcast OTA_ADV for the served .mota

  // --- fetch ---  Provide the staging store; fetching starts on a matching OTA_ADV.
  void set_fetch_store(OtaStore* s) { _fetch = s; }

  // Manual cross-target override (decision: deliberate role switch, e.g. companion -> repeater on the
  // same hardware). Normally a node only auto-fetches its OWN target_id; `want(T)` makes it accept an
  // ADV for target T instead (T=0 restores auto). The user takes responsibility for HW compatibility;
  // a hw_id brick-safety check is the planned safety layer (see docs/ota_protocol.md / plan).
  void want(uint32_t target_id) { _desired_target = target_id; }
  uint32_t wanted() const { return _desired_target; }

  // Codec compatibility: a node only fetches/accepts fw it can actually apply. CODEC_FULL is always
  // acceptable; the platform's single delta codec is set here (ESP32 A/B -> sequential, nRF52 single-
  // slot -> in-place). A mismatching `.mota` is rejected at OTA_ADV time, before fetching anything.
  void set_apply_codec(uint8_t c) { _apply_codec = c; }
  bool codecOk(uint8_t c) const { return c == CODEC_FULL || c == _apply_codec; }

  void on_message(const uint8_t* msg, uint16_t len);   // feed one received OTA message
  void loop();                                         // drive fetch (re-request missing blocks)

  FetchState fetchState() const { return _fstate; }
  uint32_t blocksHave() const { return _have; }
  uint32_t blocksTotal() const { return _fbc; }
  const uint8_t* fetchManifestId() const { return _fid; }

private:
  void emit(const uint8_t* b, uint16_t n, bool flood) { if (_send && n) _send(_ctx, b, n, flood); }
  void handleAdv(const uint8_t* m, uint16_t n);
  void handleGetManifest(const uint8_t* m, uint16_t n);
  void handleManifest(const uint8_t* m, uint16_t n);
  void handleReq(const uint8_t* m, uint16_t n);
  void handleData(const uint8_t* m, uint16_t n);
  bool blockPresent(uint32_t i) const;
  void requestMissing();
  uint32_t blockLen(uint32_t i) const;

  uint32_t _target = 0;
  OtaSend  _send = nullptr;
  void*    _ctx = nullptr;

  // serve
  bool          _has_serve = false;
  const uint8_t* _serve_buf = nullptr;
  uint32_t      _serve_len = 0;
  MotaManifest  _sm;
  uint8_t       _scratch[OTA_PROOFGEN_SCRATCH];

  // fetch
  OtaStore*  _fetch = nullptr;
  FetchState _fstate = IDLE;
  uint8_t    _fid[4] = {0};
  uint8_t    _froot[4] = {0};
  uint32_t   _ftotal = 0, _fpoff = 0, _floff = 0, _fpsize = 0, _fbc = 0, _fbs = 0;
  uint32_t   _have = 0;
  uint32_t   _req_start = 0, _req_count = 0;   // current outstanding request window
  uint32_t   _loop_last_have = 0;              // for stall detection in loop()
  uint32_t   _desired_target = 0;              // manual cross-target override (0 = auto / own target)
  uint8_t    _apply_codec = CODEC_DETOOLS_SEQUENTIAL;  // platform's delta codec (OtaContext sets it)
};

} // namespace ota
} // namespace mesh
