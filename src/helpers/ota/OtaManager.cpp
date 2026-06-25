#include "OtaManager.h"
#include "OtaProtocol.h"
#include "MerkleTree.h"
#include "Multihash.h"
#include "OtaDebug.h"
#include <string.h>

namespace mesh {
namespace ota {

static uint32_t rd_u32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr_u32(uint8_t* p, uint32_t v) { p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }

void OtaManager::begin(uint32_t my_target_id, OtaSend send, void* ctx) {
  _target = my_target_id; _send = send; _ctx = ctx;
  _fstate = IDLE; _has_serve = false; _have = 0; _fbc = 0;
}

// ---------------- serve ----------------

bool OtaManager::serve(const uint8_t* mota, uint32_t len) {
  if (!mota_parse(mota, len, _sm)) return false;
  _serve_buf = mota; _serve_len = len; _has_serve = true;
  return true;
}

void OtaManager::announce() {
  if (!_has_serve) return;
  AdvMsg a;
  a.target_id = _sm.target_id;
  a.fw_version = _sm.fw_version;
  memcpy(a.manifest_id, _sm.merkle_root, 4);
  a.flags = _sm.flags;
  a.have_all = 1;
  a.codec_id = _sm.codec_id;
  uint8_t b[32];
  emit(b, encode_adv(b, sizeof(b), a), true);
}

void OtaManager::handleGetManifest(const uint8_t* m, uint16_t n) {
  GetManifestMsg gm;
  if (!decode_get_manifest(m, n, gm) || !_has_serve) return;
  if (memcmp(gm.manifest_id, _sm.merkle_root, 4) != 0) return;
  // manifest-minus-leaves == bytes [manifest_start, leaves)
  uint32_t mfl = (uint32_t)(_sm.leaves - _sm.manifest_start);
  uint8_t b[MAX_PACKET_PAYLOAD];
  ManifestMsg mm;
  memcpy(mm.manifest_id, _sm.merkle_root, 4);
  mm.frag_idx = 0; mm.frag_total = 1;   // fits one fragment (signed manifest <= ~165 B)
  mm.bytes = _sm.manifest_start; mm.len = (uint16_t)mfl;
  emit(b, encode_manifest(b, sizeof(b), mm), false);
}

void OtaManager::handleReq(const uint8_t* m, uint16_t n) {
  ReqMsg rq;
  if (!decode_req(m, n, rq) || !_has_serve) return;
  if (memcmp(rq.manifest_id, _sm.merkle_root, 4) != 0) return;
  uint32_t bs = _sm.block_size();
  for (uint32_t k = 0; k < rq.count; k++) {
    uint32_t idx = rq.start_block + k;
    if (idx >= _sm.block_count) break;
    uint32_t off = idx * bs;
    uint32_t blen = (off + bs <= _sm.payload_size) ? bs : (_sm.payload_size - off);
    uint8_t proof[32 * 4];
    uint8_t np = merkle_gen_proof(_sm.leaves, _sm.block_count, idx, _scratch, proof);
    DataMsg dm;
    memcpy(dm.manifest_id, _sm.merkle_root, 4);
    dm.block_idx = (uint16_t)idx; dm.frag_idx = 0; dm.frag_total = 1;
    dm.n_proof = np; dm.proof = proof;
    dm.data = _sm.payload + off; dm.data_len = (uint16_t)blen;
    uint8_t b[MAX_PACKET_PAYLOAD];
    emit(b, encode_data(b, sizeof(b), dm), false);
  }
}

// ---------------- fetch ----------------

void OtaManager::handleAdv(const uint8_t* m, uint16_t n) {
  AdvMsg a;
  if (!decode_adv(m, n, a)) return;
  // auto-fetch matches our own target; a manual `want(T)` override accepts target T instead.
  uint32_t accept = _desired_target ? _desired_target : _target;
  if (a.target_id != accept) return;             // not the firmware we're (auto/manually) after
  if (!codecOk(a.codec_id)) return;              // fw we can't apply on this platform — don't fetch
  if (!_fetch || _fstate == FETCHING || _fstate == WANT_MANIFEST) return;
  if (_fstate == COMPLETE && memcmp(a.manifest_id, _fid, 4) == 0) return;  // already have it
  // interested: ask for the manifest
  memcpy(_fid, a.manifest_id, 4);
  _fstate = WANT_MANIFEST;
  GetManifestMsg gm; memcpy(gm.manifest_id, _fid, 4);
  uint8_t b[16];
  emit(b, encode_get_manifest(b, sizeof(b), gm), false);
}

void OtaManager::handleManifest(const uint8_t* m, uint16_t n) {
  ManifestMsg mm;
  if (!decode_manifest(m, n, mm) || !_fetch) return;
  if (_fstate != WANT_MANIFEST || memcmp(mm.manifest_id, _fid, 4) != 0) return;
  if (mm.frag_total != 1) return;                // multi-fragment manifest not supported yet

  const uint8_t* mf = mm.bytes;                  // manifest-minus-leaves
  uint32_t mfl = mm.len;
  if (mfl < 57) { _fstate = FAILED; return; }
  if (!codecOk(mf[56])) { _fstate = IDLE; return; }   // codec we can't apply (lying/stale ADV) — abort
  uint32_t payload_size = rd_u32(mf + 15);
  uint8_t  bsl = mf[19];
  uint32_t bs = 1u << bsl;
  if (bs == 0 || payload_size == 0) { _fstate = FAILED; return; }
  uint32_t bc = (payload_size + bs - 1) / bs;
  memcpy(_froot, mf + 20, 4);

  uint32_t leaves_off = 8 + mfl;
  uint32_t payload_off = leaves_off + bc * 4;
  uint32_t total = payload_off + payload_size + 5;

  if (!_fetch->begin(total)) { _fstate = FAILED; return; }
  // declare the metadata extent so a flash store can pin it (leaves are written all transfer long)
  if (!_fetch->set_meta_size(payload_off)) { _fstate = FAILED; return; }
  uint8_t hdr[8];
  memcpy(hdr, MOTA_MAGIC, 4);
  wr_u32(hdr + 4, total);
  if (!_fetch->write(0, hdr, 8) ||
      !_fetch->write(8, mf, mfl) ||
      !_fetch->write(total - 5, MOTA_TRAILER, 5)) { _fstate = FAILED; return; }

  _fpoff = payload_off; _floff = leaves_off; _fpsize = payload_size; _fbc = bc; _fbs = bs;
  _ftotal = total; _have = 0; _fstate = FETCHING;
  OTA_DBG("OTA: FETCHING bc=%u bs=%u total=%u\n", (unsigned)bc, (unsigned)bs, (unsigned)total);
  requestMissing();
}

uint32_t OtaManager::blockLen(uint32_t i) const {
  uint32_t off = i * _fbs;
  return (off + _fbs <= _fpsize) ? _fbs : (_fpsize - off);
}

bool OtaManager::blockPresent(uint32_t i) const {
  uint8_t leaf[4];
  if (!_fetch->read(_floff + i * 4, leaf, 4)) return false;
  return !(leaf[0]==0xFF && leaf[1]==0xFF && leaf[2]==0xFF && leaf[3]==0xFF);
}

void OtaManager::handleData(const uint8_t* m, uint16_t n) {
  DataMsg dm;
  if (!decode_data(m, n, dm) || !_fetch) return;
  if (_fstate != FETCHING || memcmp(dm.manifest_id, _fid, 4) != 0) return;
  if (dm.frag_total != 1) return;                // single-fragment blocks only (v1)
  if (dm.block_idx >= _fbc) return;
  if (blockPresent(dm.block_idx)) return;        // already have it

  uint32_t want = blockLen(dm.block_idx);
  if (dm.data_len != want) return;

  // verify the block against the (signed) root via its proof — reject forged/corrupt data
  if (!merkle_verify(dm.data, dm.data_len, dm.block_idx, dm.proof, dm.n_proof, _froot, _fbc)) return;

  // commit: payload block first, then the leaf (the commit marker)
  if (!_fetch->write(_fpoff + dm.block_idx * _fbs, dm.data, dm.data_len)) return;
  uint8_t leaf[4];
  merkle_leaf(leaf, dm.data, dm.data_len);
  if (!_fetch->write(_floff + dm.block_idx * 4, leaf, 4)) return;

  _have++;
  OTA_DBG("OTA: block %u OK  have=%u/%u\n", (unsigned)dm.block_idx, (unsigned)_have, (unsigned)_fbc);

  // if the current request window is fully received, immediately ask for the next one
  // (paces the transfer to the link rate instead of flooding the whole image at once)
  if (_have < _fbc) {
    bool window_done = true;
    for (uint32_t i = _req_start; i < _req_start + _req_count && i < _fbc; i++) {
      if (!blockPresent(i)) { window_done = false; break; }
    }
    if (window_done) requestMissing();
  }

  if (_have >= _fbc) {
    // recompute the root over all stored leaves as a final cross-check
    // (read leaves into the scratch buffer; bounded by OTA_PROOFGEN_SCRATCH)
    if (_fbc * 4 <= sizeof(_scratch) && _fetch->read(_floff, _scratch, _fbc * 4)) {
      uint8_t root[4];
      merkle_root(root, _scratch, _fbc);
      _fstate = (memcmp(root, _froot, 4) == 0) ? COMPLETE : FAILED;
    } else {
      _fstate = COMPLETE;   // per-block proofs already guaranteed integrity vs the root
    }
    if (_fstate == COMPLETE) _fetch->finalize();   // commit the staged container to persistent storage
    OTA_DBG("OTA: transfer %s\n", _fstate == COMPLETE ? "COMPLETE" : "FAILED(root)");
  }
}

void OtaManager::requestMissing() {
  if (_fstate != FETCHING) return;
  // request a small WINDOW of the next missing blocks (keeps the server's TX queue small,
  // so OTA never floods/saturates the mesh — docs/ota_protocol.md §8)
  uint32_t start = 0;
  while (start < _fbc && blockPresent(start)) start++;
  if (start >= _fbc) return;
  uint32_t count = _fbc - start;
  if (count > OTA_REQ_WINDOW) count = OTA_REQ_WINDOW;
  _req_start = start; _req_count = count;
  ReqMsg rq; memcpy(rq.manifest_id, _fid, 4);
  rq.start_block = (uint16_t)start; rq.count = (uint8_t)count;
  uint8_t b[16];
  OTA_DBG("OTA: REQ start=%u count=%u (have=%u/%u)\n",
          (unsigned)start, (unsigned)count, (unsigned)_have, (unsigned)_fbc);
  emit(b, encode_req(b, sizeof(b), rq), false);
}

void OtaManager::loop() {
  if (_fstate == WANT_MANIFEST) {
    // the MANIFEST reply may have been lost on a marginal link — retry GET_MANIFEST
    GetManifestMsg gm; memcpy(gm.manifest_id, _fid, 4);
    uint8_t b[16];
    emit(b, encode_get_manifest(b, sizeof(b), gm), false);
    return;
  }
  if (_fstate != FETCHING) return;
  // retry only when a tick passed with no progress (avoids re-request spam during active flow)
  if (_have == _loop_last_have) requestMissing();
  _loop_last_have = _have;
}

// ---------------- dispatch ----------------

void OtaManager::on_message(const uint8_t* msg, uint16_t len) {
  switch (ota_msg_type(msg, len)) {
    case OTA_ADV:          handleAdv(msg, len); break;
    case OTA_GET_MANIFEST: handleGetManifest(msg, len); break;
    case OTA_MANIFEST:     handleManifest(msg, len); break;
    case OTA_REQ:          handleReq(msg, len); break;
    case OTA_DATA:         handleData(msg, len); break;
    default: break;
  }
}

} // namespace ota
} // namespace mesh
