#pragma once

#include <stdint.h>
#include <stddef.h>
#include "OtaFormat.h"

// Encode/decode for the OTA LoRa messages (docs/ota_protocol.md §8). Each message is a packet payload:
// [0]=ota_msg_type, then a fixed body. Portable + allocation-free; unit-tested on the host.
//
// manifest_id == the manifest's merkle_root (4 bytes), a compact content id.

namespace mesh {
namespace ota {

// ---- OTA_ADV: "I have (part of) fw X for target T" (flood, periodic + on demand) ----
struct AdvMsg {
  uint32_t target_id;
  uint32_t fw_version;
  uint8_t  manifest_id[4];   // = merkle_root
  uint8_t  flags;            // manifest flags (FULL/SIGNED)
  uint8_t  have_all;         // 1 = holder has the complete payload
  uint8_t  codec_id;         // manifest codec (0=full,1=detools-seq,2=detools-inplace) — lets a
                             // receiver reject fw it can't apply before fetching anything
};

// ---- OTA_GET_MANIFEST: request the manifest for a content id (direct) ----
struct GetManifestMsg { uint8_t manifest_id[4]; };

// ---- OTA_MANIFEST: the manifest-minus-leaves[], fragmented (direct) ----
// body: manifest_id(4) frag_idx(1) frag_total(1) bytes[]
struct ManifestMsg {
  uint8_t  manifest_id[4];
  uint8_t  frag_idx, frag_total;
  const uint8_t* bytes; uint16_t len;
};

// ---- OTA_REQ: request a window of blocks (direct) ----
struct ReqMsg { uint8_t manifest_id[4]; uint16_t start_block; uint8_t count; };

// ---- OTA_DATA: one (fragment of a) block (direct) ----
// body: manifest_id(4) block_idx(2) frag_idx(1) frag_total(1) [frag0: n_proof(1) proof(n_proof*4)] data[]
struct DataMsg {
  uint8_t  manifest_id[4];
  uint16_t block_idx;
  uint8_t  frag_idx, frag_total;
  uint8_t  n_proof;          // only meaningful on frag_idx==0
  const uint8_t* proof;      // n_proof*4 bytes (frag0 only)
  const uint8_t* data; uint16_t data_len;
};

// Each encode_* returns the total payload length (incl. the leading msg-type byte), 0 on overflow.
// Each decode_* returns true on success (and points struct fields into `buf`).

uint16_t encode_adv(uint8_t* buf, uint16_t cap, const AdvMsg& m);
bool     decode_adv(const uint8_t* buf, uint16_t len, AdvMsg& m);

uint16_t encode_get_manifest(uint8_t* buf, uint16_t cap, const GetManifestMsg& m);
bool     decode_get_manifest(const uint8_t* buf, uint16_t len, GetManifestMsg& m);

uint16_t encode_manifest(uint8_t* buf, uint16_t cap, const ManifestMsg& m);
bool     decode_manifest(const uint8_t* buf, uint16_t len, ManifestMsg& m);

uint16_t encode_req(uint8_t* buf, uint16_t cap, const ReqMsg& m);
bool     decode_req(const uint8_t* buf, uint16_t len, ReqMsg& m);

uint16_t encode_data(uint8_t* buf, uint16_t cap, const DataMsg& m);
bool     decode_data(const uint8_t* buf, uint16_t len, DataMsg& m);

inline uint8_t ota_msg_type(const uint8_t* buf, uint16_t len) { return len ? buf[0] : 0xFF; }

} // namespace ota
} // namespace mesh
