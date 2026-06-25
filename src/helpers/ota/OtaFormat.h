#pragma once

#include <stdint.h>
#include <stddef.h>

// On-the-wire constants for the MeshCore OTA `.mota` container and protocol.
// Normative definition: docs/ota_protocol.md (v1). Mirrors tools/mota/motalib.py.
//
// Portable: no Arduino / RadioLib includes. Compiles on the native host (unit tests) and on device.

namespace mesh {
namespace ota {

// ---- container framing ----------------------------------------------------
static const uint8_t  MOTA_MAGIC[4]    = { 'm', 'O', 'T', 'A' };   // 6D 4F 54 41
static const uint8_t  MOTA_TRAILER[5]  = { 'v', 'k', '4', '9', '6' }; // 76 6B 34 39 36
static const uint8_t  ENDF_MAGIC[4]    = { 'E', 'n', 'd', 'F' };   // 45 6E 64 46
static const uint32_t ENDF_LEN         = 16;                       // marker(4)+body_len(4)+body_hash8(8)

// ---- manifest -------------------------------------------------------------
static const uint8_t  MOTA_FORMAT_VER  = 1;
static const uint8_t  HASH_ALGO_SHA256 = 0x12;   // multihash code

static const uint8_t  MFLAG_FULL       = 0x01;   // 0 = delta/partial, 1 = full image
static const uint8_t  MFLAG_SIGNED     = 0x02;

static const uint8_t  CODEC_FULL                 = 0;
static const uint8_t  CODEC_DETOOLS_SEQUENTIAL   = 1;
static const uint8_t  CODEC_DETOOLS_INPLACE      = 2;

// ---- hash truncations -----------------------------------------------------
static const uint8_t  MH4  = 4;    // sha2-256:4  (merkle leaves/nodes/root/proofs)
static const uint8_t  MH8  = 8;    // sha2-256:8  (base/EndF body hash)
static const uint8_t  MH32 = 32;   // sha2-256:32 (image security anchor)

// ---- approval marker (manifest field, after the signature) ----------------
static const uint8_t  APPROVAL_NOT[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
static const uint8_t  APPROVAL_YES[4] = { 'A', 'P', 'R', 'V' };   // 41 50 52 56

// ---- LoRa protocol --------------------------------------------------------
// The packet payload type is PAYLOAD_TYPE_OTA (0x0C), defined in src/Packet.h for the core dispatch.

enum OtaMsgType : uint8_t {
  OTA_ADV          = 0x01,
  OTA_QUERY        = 0x02,
  OTA_HAVE         = 0x03,
  OTA_GET_MANIFEST = 0x04,
  OTA_MANIFEST     = 0x05,
  OTA_REQ          = 0x06,
  OTA_DATA         = 0x07,
};

static const uint16_t OTA_DEFAULT_BLOCK_SIZE = 1024;
static const uint8_t  OTA_DEFAULT_HOP_LIMIT  = 3;

} // namespace ota
} // namespace mesh
