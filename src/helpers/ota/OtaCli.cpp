#include "OtaCli.h"
#include "OtaContext.h"
#include "OtaVerify.h"
#include "OtaSelf.h"
#include "Utils.h"
#include <stdio.h>
#include <string.h>

namespace mesh {
namespace ota {

static uint32_t parse_u32(const char* s) {
  uint32_t n = 0;
  while (*s == ' ') s++;
  while (*s >= '0' && *s <= '9') n = n * 10 + (uint32_t)(*s++ - '0');
  return n;
}

static char fstate_char(OtaManager::FetchState s) {
  switch (s) {
    case OtaManager::IDLE: return 'I';
    case OtaManager::WANT_MANIFEST: return 'W';
    case OtaManager::FETCHING: return 'F';
    case OtaManager::COMPLETE: return 'C';
    default: return 'X';
  }
}

bool handle_ota_command(const char* command, char* reply, mesh::MainBoard& board) {
  const char* a = command + 3;
  if (*a != 0 && *a != ' ') return false;
  while (*a == ' ') a++;
  OtaContext& c = ota_ctx();

  if (*a == 0 || strncmp(a, "status", 6) == 0) {
    SelfFwInfo fi; bool s = ota_self_firmware(fi);
    sprintf(reply, "OTA tid=%08X self=%u serve=%u%s fetch=%c %u/%u keys=%u",
            (unsigned)board.getOtaTargetId(), (unsigned)(s ? fi.body_len : 0),
            (unsigned)c.serve_expected, c.serving ? "(on)" : "",
            fstate_char(c.manager.fetchState()),
            (unsigned)c.manager.blocksHave(), (unsigned)c.manager.blocksTotal(),
            (unsigned)c.allow.count());

  } else if (strncmp(a, "key add ", 8) == 0) {
    uint8_t pub[32];
    strcpy(reply, (mesh::Utils::fromHex(pub, 32, a + 8) && c.allow.add(pub)) ? "OK key added" : "ERR key");

  } else if (strncmp(a, "key list", 8) == 0) {
    int n = sprintf(reply, "keys=%u:", (unsigned)c.allow.count());
    for (uint8_t i = 0; i < c.allow.count() && n < 140; i++) {
      char hx[17]; mesh::Utils::toHex(hx, c.allow.get(i), 8);
      n += sprintf(reply + n, " %s", hx);
    }

  } else if (strncmp(a, "key rm ", 7) == 0) {
    uint8_t pub[32];
    strcpy(reply, (mesh::Utils::fromHex(pub, 32, a + 7) && c.allow.remove(pub)) ? "OK removed" : "ERR");

  } else if (strncmp(a, "stage ", 6) == 0) {
    uint32_t sz = parse_u32(a + 6);
    if (sz == 0 || sz > OTA_SERVE_BUF_SIZE) { sprintf(reply, "ERR size 1..%u", OTA_SERVE_BUF_SIZE); }
    else { memset(c.serve_buf, 0xFF, sz); c.serve_expected = sz; c.serving = false;
           sprintf(reply, "OK stage %u bytes", (unsigned)sz); }

  } else if (strncmp(a, "recv ", 5) == 0) {
    const char* p = a + 5; uint32_t off = parse_u32(p);
    const char* hex = strchr(p, ' ');
    if (!hex) { strcpy(reply, "ERR usage: ota recv <off> <hex>"); return true; }
    hex++;
    int blen = (int)strlen(hex) / 2;
    uint8_t tmp[80];
    if (blen <= 0 || blen > (int)sizeof(tmp) || !mesh::Utils::fromHex(tmp, blen, hex)) strcpy(reply, "ERR hex");
    else if (off + blen > c.serve_expected) strcpy(reply, "ERR off>size (stage first)");
    else { memcpy(c.serve_buf + off, tmp, blen); sprintf(reply, "OK %d@%u", blen, (unsigned)off); }

  } else if (strncmp(a, "serve", 5) == 0) {
    c.serving = c.manager.serve(c.serve_buf, c.serve_expected);
    if (!c.serving) { strcpy(reply, "ERR serve (bad .mota)"); return true; }
    VerifyResult r = ota_verify(c.serve_buf, c.serve_expected, c.allow);
    sprintf(reply, "OK serving | root=%d img=%d sig=%d trust=%d", r.root_ok, r.image_ok, r.sig_ok, r.trusted);

  } else if (strncmp(a, "announce", 8) == 0) {
    if (!c.serving) { strcpy(reply, "ERR not serving (ota serve first)"); return true; }
    c.manager.announce();
    strcpy(reply, "OK announced");

  } else if (strncmp(a, "verify", 6) == 0) {
    // verify whatever is staged-to-serve, OR the fetched container if a fetch is complete
    const uint8_t* buf; uint32_t len;
    if (c.manager.fetchState() == OtaManager::COMPLETE) { buf = c.fetch_store.data(); len = c.fetch_store.staged_size(); }
    else { buf = c.serve_buf; len = c.serve_expected; }
    if (len == 0) { strcpy(reply, "ERR nothing to verify"); return true; }
    VerifyResult r = ota_verify(buf, len, c.allow);
    sprintf(reply, "verify parsed=%d root=%d img=%d signed=%d sig=%d trust=%d | ok=%d auto=%d",
            r.parsed, r.root_ok, r.image_ok, r.is_signed, r.sig_ok, r.trusted,
            r.integrity_ok(), r.auto_appliable());

  } else if (strncmp(a, "applydelta", 10) == 0) {
    // Apply the fetched delta. ESP32: detools-sequential decode into the inactive A/B slot + verify +
    // arm (reboot after). nRF52: verify + mark APPROVED in flash + reboot into the bootloader, which
    // does the in-place decode + verify before booting it (this call does not return on success).
    //
    // This is destructive (it reboots and reflashes). It is GATED, not interactive — no "type yes"
    // round-trip (unreliable over LoRa). First, refuse unless a full update is present: the fetch must
    // be COMPLETE (every block received AND the merkle root re-verified). Then the apply path validates
    // in order and returns the FIRST failing gate, so the operator knows exactly why it refused
    // (payload hash -> built-for-this-firmware -> signature/trust); it proceeds only if all pass.
    if (c.manager.fetchState() != OtaManager::COMPLETE || c.fetch_store.staged_size() == 0) {
      sprintf(reply, "ERR no complete update fetched (fetch=%c %u/%u)",
              fstate_char(c.manager.fetchState()), (unsigned)c.manager.blocksHave(),
              (unsigned)c.manager.blocksTotal());
      return true;
    }
    char m2[100];
#if defined(NRF52_PLATFORM)
    bool ok = ota_apply_mota_nrf52(c.fetch_store.data(), c.fetch_store.staged_size(), c.allow, c.apply_st, m2);
#else
    bool ok = ota_apply_detools_mota(c.fetch_store.data(), c.fetch_store.staged_size(), c.allow, c.apply_st, m2);
#endif
    // On success the update is approved/armed but NOT yet rebooted — arm the deferred handoff so this
    // reply reaches the operator first; the mesh loop reboots once it has been transmitted.
    if (ok) c.apply_pending = true;
    sprintf(reply, "%s | %s", ok ? "OK" : "ERR", m2);

  } else if (strncmp(a, "self", 4) == 0) {
    // running firmware identity (EndF): body_len + body_hash:8 — compare against a delta's base_hash
    SelfFwInfo fi;
    if (!ota_self_firmware(fi) || !fi.valid) { strcpy(reply, "ERR no EndF (firmware lacks the trailer?)"); return true; }
    char hx[17]; mesh::Utils::toHex(hx, fi.body_hash, 8);
    sprintf(reply, "self body=%u image=%u base_hash=%s", (unsigned)fi.body_len, (unsigned)fi.image_len, hx);

  } else if (strncmp(a, "apply", 5) == 0) {
    const char* sub = a + 5;
    while (*sub == ' ') sub++;
    if (strncmp(sub, "slot", 4) == 0) {
      uint32_t addr = 0, size = 0;
      if (ota_apply_slot_info(&addr, &size)) sprintf(reply, "inactive slot addr=0x%X size=%u", (unsigned)addr, (unsigned)size);
      else strcpy(reply, "ERR no A/B slot (apply unsupported on this build)");
    } else if (strncmp(sub, "manifest", 8) == 0) {
      // the manifest-fixed bytes were loaded into serve_buf via `ota stage`/`ota recv`
      if (ota_apply_set_manifest(c.serve_buf, c.serve_expected, c.allow, c.apply_st))
        sprintf(reply, "manifest ok img=%u sig=%d trust=%d", (unsigned)c.apply_st.image_size,
                c.apply_st.sig_ok, c.apply_st.trusted);
      else strcpy(reply, "ERR manifest parse / not full-image / unsupported");
    } else if (strncmp(sub, "verify", 6) == 0) {
      bool ok = ota_apply_verify_slot(c.apply_st);
      sprintf(reply, "slot image_hash %s (size=%u)", ok ? "MATCH" : "MISMATCH", (unsigned)c.apply_st.image_size);
    } else if (strncmp(sub, "commit", 6) == 0) {
      if (!c.apply_st.slot_ok) { strcpy(reply, "ERR run 'ota apply verify' first (slot must match)"); return true; }
      // (D2: auto-apply would also require c.apply_st.trusted; a manual commit is allowed here.)
      ota_apply_commit();                 // sets boot partition + reboots into the new image; no return
      strcpy(reply, "ERR commit failed (no A/B slot?)");
    } else {
      strcpy(reply, "ERR ota apply (slot|manifest|verify|commit)");
    }

  } else if (strncmp(a, "want ", 5) == 0) {
    const char* p = a + 5;
    while (*p == ' ') p++;
    if (strncmp(p, "auto", 4) == 0) { c.manager.want(0); strcpy(reply, "OK auto (own target only)"); }
    else {
      uint32_t t = (uint32_t)strtoul(p, nullptr, 16);   // hex target_id (e.g. from another env)
      c.manager.want(t);
      sprintf(reply, "OK cross-target: will fetch %08X (you ensure HW compatible)", (unsigned)t);
    }

  } else if (strncmp(a, "clear", 5) == 0) {
    c.serve_expected = 0; c.serving = false; c.fetch_store.clear();
    strcpy(reply, "OK cleared");

  } else {
    strcpy(reply, "ERR (status|self|key|stage|recv|serve|announce|verify|want|applydelta|clear)");
  }
  return true;
}

} // namespace ota
} // namespace mesh
