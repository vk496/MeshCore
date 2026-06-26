#include "OtaCli.h"
#include "OtaContext.h"
#include "OtaVerify.h"
#include "OtaSelf.h"
#include "Utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Arduino.h>   // millis() for session-age display (device-only command surface)

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

static const char* codec_name(uint8_t c) {
  return c == CODEC_FULL ? "full" : (c == CODEC_DETOOLS_SEQUENTIAL ? "seq"
       : (c == CODEC_DETOOLS_INPLACE ? "inpl" : "?"));
}

// The everyday OTA surface is BitTorrent-shaped: `ota` shows what you're holding (your running firmware
// as a full mOTA + your one fetch session), `ota neighbors` shows the mOTAs heard around you, `ota pull`
// starts fetching one, `ota drop` frees the session. The raw primitives (manual content load, low-level
// apply steps) live under `ota dev ...` so they don't clutter the everyday surface. Every reply fits one
// packet so it works as remote-admin over LoRa.
static bool handle_dev(const char* d, char* reply, OtaContext& c);

bool handle_ota_command(const char* command, char* reply, mesh::MainBoard& board) {
  const char* a = command + 3;
  if (*a != 0 && *a != ' ') return false;
  while (*a == ' ') a++;
  OtaContext& c = ota_ctx();

  // ---- raw / internal primitives, tucked under `ota dev ...` ----
  if (strncmp(a, "dev", 3) == 0 && (a[3] == 0 || a[3] == ' ')) {
    const char* d = a + 3; while (*d == ' ') d++;
    return handle_dev(d, reply, c);
  }

  // ---- inventory dashboard: running fw (self), the one fetch session, serving state ----
  if (*a == 0 || strncmp(a, "status", 6) == 0) {
    SelfFwInfo fi; bool s = ota_self_firmware(fi);
    char selfhx[9]; if (s && fi.valid) mesh::Utils::toHex(selfhx, fi.body_hash, 4); else strcpy(selfhx, "?");
    OtaManager::FetchState fs = c.manager.fetchState();
    char midhx[9]; strcpy(midhx, "-");
    if (fs != OtaManager::IDLE) mesh::Utils::toHex(midhx, c.manager.fetchManifestId(), 4);
    unsigned age = (fs != OtaManager::IDLE && c.session_started_ms) ? (unsigned)((millis() - c.session_started_ms) / 1000) : 0;
    sprintf(reply, "OTA tgt=%08X fw=%s | self:%s%uK | sess:%c %u/%u mid=%s age=%us | serv:%s keys=%u",
            (unsigned)board.getOtaTargetId(), selfhx, s ? "full " : "?",
            (unsigned)((s ? fi.image_len : 0) / 1024), fstate_char(fs),
            (unsigned)c.manager.blocksHave(), (unsigned)c.manager.blocksTotal(),
            midhx, age, c.serving ? "on" : "off", (unsigned)c.allow.count());

  // ---- what's available around me (catalogued from beacons + OTA_HAVE), best/most-recent first ----
  } else if (strncmp(a, "neighbors", 9) == 0 || strncmp(a, "nbrs", 4) == 0) {
    // Kick a fresh round of catalog queries (async — rows arrive over the next seconds); render what we
    // have now. The reply buffer is 160 B (serial / one LoRa packet for remote-admin) so writes are bounded.
    c.manager.queryAll();
    const int CAP = 160;
    int n = snprintf(reply, CAP, "nbrs #:mid t=tgt codec seed age *=cur (src=%u)", (unsigned)c.manager.sourceCount());
    const uint8_t* cur = (c.manager.fetchState() != OtaManager::IDLE) ? c.manager.fetchManifestId() : nullptr;
    uint32_t now = millis(); int shown = 0, more = 0;
    for (uint8_t i = 0; i < c.manager.catalogCount(); i++) {
      const OtaManager::CatRow* h = c.manager.catalogRow(i);
      if (CAP - n < 60) { more++; continue; }
      char midhx[9]; mesh::Utils::toHex(midhx, h->mid, 4);
      bool on = cur && memcmp(cur, h->mid, 4) == 0;
      uint32_t age = (now - h->last_ms) / 1000; if (age > 99999) age = 99999;
      n += snprintf(reply + n, CAP - n, "\n %d:%s t=%08X %s seed=%u %us%s", shown + 1, midhx,
                    (unsigned)h->target_id, codec_name(h->codec), (unsigned)h->n_seeders,
                    (unsigned)age, on ? "*" : "");
      shown++;
    }
    if (more && n < CAP) snprintf(reply + n, CAP - n, "\n +%d more", more);
    if (shown == 0) strcpy(reply, "nbrs: none yet — sources beacon periodically; re-run in a few s (queried now)");

  // ---- start fetching a specific catalogued mOTA (by list index or manifest_id) ----
  } else if (strncmp(a, "pull", 4) == 0 && (a[4] == 0 || a[4] == ' ')) {
    const char* p = a + 4; while (*p == ' ') p++;
    if (*p == 0) { strcpy(reply, "usage: ota pull <#|mid8>  (see `ota neighbors`)"); return true; }
    const OtaManager::CatRow* sel = nullptr; uint8_t mid[4];
    if (*p == '#' || (p[0] >= '1' && p[0] <= '9' && (p[1] == 0 || p[1] == ' '))) {   // index among catalogue
      int idx = atoi(*p == '#' ? p + 1 : p);
      if (idx >= 1 && idx <= c.manager.catalogCount()) sel = c.manager.catalogRow((uint8_t)(idx - 1));
    } else if (mesh::Utils::fromHex(mid, 4, p)) {                                    // explicit manifest_id
      for (uint8_t i = 0; i < c.manager.catalogCount(); i++)
        if (memcmp(c.manager.catalogRow(i)->mid, mid, 4) == 0) { sel = c.manager.catalogRow(i); break; }
    }
    if (!sel) { strcpy(reply, "ERR no such neighbor (see `ota neighbors`)"); return true; }
    if (c.apply_pending) { strcpy(reply, "ERR busy applying"); return true; }
    uint8_t selmid[4]; uint32_t seltgt = sel->target_id; memcpy(selmid, sel->mid, 4);   // sel may move on reset
    c.manager.reset_session(); c.fetch_store.clear();
    c.manager.pull(selmid, seltgt);                          // sets want + begins the manifest fetch now
    char midhx[9]; mesh::Utils::toHex(midhx, selmid, 4);
    sprintf(reply, "OK pulling mid=%s target=%08X (low priority)", midhx, (unsigned)seltgt);

  // ---- discard the current session (e.g. a stalled old fetch) to free the slot ----
  } else if (strncmp(a, "drop", 4) == 0) {
    OtaManager::FetchState fs = c.manager.fetchState();
    char midhx[9]; strcpy(midhx, "-");
    if (fs != OtaManager::IDLE) mesh::Utils::toHex(midhx, c.manager.fetchManifestId(), 4);
    c.manager.reset_session(); c.manager.want(0); c.manager.want_mid(nullptr);
    c.fetch_store.clear(); c.serving = false; c.serve_expected = 0; c.session_started_ms = 0;
    sprintf(reply, "OK dropped session (was %c mid=%s); slot free for a new pull", fstate_char(fs), midhx);

  // ---- broadcast our tiny beacon so peers discover us. If not already serving, set up flash-backed
  //      self-serve first (so we're a real, fetchable source of our own running firmware). ----
  } else if (strncmp(a, "announce", 8) == 0) {
    if (!c.serving) c.serving = ota_serve_self(c, 0);
    c.manager.announce();
    sprintf(reply, "OK beacon sent (serving=%s)", c.serving ? "self fw" : "nothing");

  // ---- running firmware identity (compare against a delta's base_hash) ----
  } else if (strncmp(a, "self", 4) == 0) {
    SelfFwInfo fi;
    if (!ota_self_firmware(fi) || !fi.valid) { strcpy(reply, "ERR no EndF (firmware lacks the trailer?)"); return true; }
    char hx[17]; mesh::Utils::toHex(hx, fi.body_hash, 8);
    sprintf(reply, "self body=%u image=%u base_hash=%s", (unsigned)fi.body_len, (unsigned)fi.image_len, hx);

  } else if (strncmp(a, "applydelta", 10) == 0) {
    // Apply the fetched update. Destructive (reflashes + reboots) and GATED, not interactive (no "type
    // yes" round-trip — unreliable over LoRa): refuse unless the fetch is COMPLETE, then the apply path
    // validates in order (payload hash -> built-for-this-firmware -> signature/trust) and returns the
    // FIRST failing gate, so the operator knows exactly why it refused; it proceeds only if all pass.
    if (c.manager.fetchState() != OtaManager::COMPLETE || c.fetch_store.staged_size() == 0) {
      sprintf(reply, "ERR no complete update fetched (fetch=%c %u/%u)",
              fstate_char(c.manager.fetchState()), (unsigned)c.manager.blocksHave(),
              (unsigned)c.manager.blocksTotal());
      return true;
    }
    // On success the slot is armed but NOT yet rebooted — defer so this reply reaches the operator first;
    // the mesh loop reboots once it has been transmitted (same path used by auto-install).
    char m2[100];
    bool ok = c.apply_fetched(m2);
    sprintf(reply, "%s | %s", ok ? "OK" : "ERR", m2);

  // ---- external folder relay: advertise + serve `.mota` from a host daemon over the seeder UART, so the
  //      node hosts MANY images (any architecture) it doesn't hold in flash. Trustless (fetchers verify). --
  } else if (strncmp(a, "folder", 6) == 0) {
    const char* p = a + 6; while (*p == ' ') p++;
    if (strncmp(p, "on", 2) == 0) {
#if defined(OTA_FOLDER_SERIAL)
      if (!c.serving) c.serving = ota_serve_self(c, 0);   // keep serving our own fw alongside the folder
      char m2[120]; c.attach_folder(m2, sizeof(m2)); c.manager.announce();
      strncpy(reply, m2, 159); reply[159] = 0;
#else
      strcpy(reply, "ERR not built with OTA_FOLDER_SERIAL (set the seeder UART in platformio.ini)");
#endif
    } else if (strncmp(p, "off", 3) == 0) {
      c.detach_folder(); c.manager.announce();
      strcpy(reply, "OK folder detached (still serving own fw)");
    } else {                                              // status + list served entries (* = our own fw)
      int n = snprintf(reply, 159, "folder=%s serving=%u:", c.folder_active ? "on" : "off",
                       (unsigned)c.manager.servedCount());
      for (uint8_t i = 0; i < c.manager.servedCount() && n < 148; i++) {
        const OtaManager::ServeEntry* e = c.manager.servedEntry(i);
        if (!e) break;
        char midhx[9]; mesh::Utils::toHex(midhx, e->mid, 4);
        n += snprintf(reply + n, 159 - n, " %s%s/%08X", e->is_self ? "*" : "", midhx, (unsigned)e->target_id);
      }
    }

  // ---- policy config (persisted via NodePrefs). conservative defaults: autofetch/autoinstall off ----
  } else if (strncmp(a, "config", 6) == 0) {
    const char* p = a + 6; while (*p == ' ') p++;
    if (strncmp(p, "autofetch ", 10) == 0) {
      const char* v = p + 10;
      uint8_t pol = strncmp(v, "any", 3) == 0    ? OtaManager::AUTOFETCH_ANY
                  : strncmp(v, "signed", 6) == 0 ? OtaManager::AUTOFETCH_SIGNED
                  : strncmp(v, "off", 3) == 0    ? OtaManager::AUTOFETCH_OFF : 0xFF;
      if (pol == 0xFF) { strcpy(reply, "ERR usage: ota config autofetch <off|any|signed>"); return true; }
      c.manager.set_autofetch(pol); c.config_dirty = true; strcpy(reply, "OK autofetch updated (saved)");
    } else if (strncmp(p, "autoinstall ", 12) == 0) {
      const char* v = p + 12;
      uint8_t pol = strncmp(v, "trusted", 7) == 0 ? OtaContext::AUTOINSTALL_TRUSTED
                  : strncmp(v, "off", 3) == 0     ? OtaContext::AUTOINSTALL_OFF : 0xFF;
      if (pol == 0xFF) { strcpy(reply, "ERR usage: ota config autoinstall <off|trusted>"); return true; }
      c.autoinstall = pol; c.config_dirty = true; strcpy(reply, "OK autoinstall updated (saved)");
    } else if (strncmp(p, "checkpoint ", 11) == 0) {    // resume checkpoint cadence (blocks; 0=never)
      long n = atol(p + 11);
      if (n < 0 || n > 4096) { strcpy(reply, "ERR usage: ota config checkpoint <0..4096>  (blocks; 0=never)"); return true; }
      c.manager.set_checkpoint_blocks((uint16_t)n); c.config_dirty = true;
      sprintf(reply, "OK checkpoint every %ld blocks (saved)%s", n, n == 0 ? " — periodic resume disabled" : "");
    } else {                                            // show current policy
      uint8_t af = c.manager.autofetch();
      sprintf(reply, "ota config: autofetch=%s autoinstall=%s checkpoint=%u keys=%u  (persisted)",
              af == OtaManager::AUTOFETCH_ANY ? "any" : af == OtaManager::AUTOFETCH_SIGNED ? "signed" : "off",
              c.autoinstall == OtaContext::AUTOINSTALL_TRUSTED ? "trusted" : "off",
              (unsigned)c.manager.checkpoint_blocks(), (unsigned)c.allow.count());
    }

  // ---- trusted signer allowlist (security config; persisted) ----
  } else if (strncmp(a, "key add ", 8) == 0) {
    uint8_t pub[32];
    if (mesh::Utils::fromHex(pub, 32, a + 8) && c.allow.add(pub)) { c.config_dirty = true; strcpy(reply, "OK key added (saved)"); }
    else strcpy(reply, "ERR key");
  } else if (strncmp(a, "key list", 8) == 0) {
    int n = sprintf(reply, "keys=%u:", (unsigned)c.allow.count());
    for (uint8_t i = 0; i < c.allow.count() && n < 140; i++) {
      char hx[17]; mesh::Utils::toHex(hx, c.allow.get(i), 8);
      n += sprintf(reply + n, " %s", hx);
    }
  } else if (strncmp(a, "key rm ", 7) == 0) {
    uint8_t pub[32];
    if (mesh::Utils::fromHex(pub, 32, a + 7) && c.allow.remove(pub)) { c.config_dirty = true; strcpy(reply, "OK removed (saved)"); }
    else strcpy(reply, "ERR");

  } else {
    strcpy(reply, "ota: status|neighbors|announce|pull <#|mid>|drop|folder|config|self|applydelta|key|dev");
  }
  return true;
}

// Raw / internal primitives (manual content load + low-level apply steps), under `ota dev ...`.
static bool handle_dev(const char* d, char* reply, OtaContext& c) {
  if (strncmp(d, "stage ", 6) == 0) {
    uint32_t sz = parse_u32(d + 6);
    if (sz == 0 || sz > OTA_SERVE_BUF_SIZE) { sprintf(reply, "ERR size 1..%u", OTA_SERVE_BUF_SIZE); }
    else { memset(c.serve_buf, 0xFF, sz); c.serve_expected = sz; c.serving = false;
           sprintf(reply, "OK stage %u bytes", (unsigned)sz); }

  } else if (strncmp(d, "recv ", 5) == 0) {
    const char* p = d + 5; uint32_t off = parse_u32(p);
    const char* hex = strchr(p, ' ');
    if (!hex) { strcpy(reply, "ERR usage: ota dev recv <off> <hex>"); return true; }
    hex++;
    int blen = (int)strlen(hex) / 2;
    uint8_t tmp[80];
    if (blen <= 0 || blen > (int)sizeof(tmp) || !mesh::Utils::fromHex(tmp, blen, hex)) strcpy(reply, "ERR hex");
    else if (off + blen > c.serve_expected) strcpy(reply, "ERR off>size (stage first)");
    else { memcpy(c.serve_buf + off, tmp, blen); sprintf(reply, "OK %d@%u", blen, (unsigned)off); }

  } else if (strncmp(d, "serve self", 10) == 0) {     // host our own running firmware, served from flash
    if (ota_serve_self(c, 0)) {
      c.serving = true;
      char midhx[9]; mesh::Utils::toHex(midhx, c.serve_self_manifest + 20, 4);
      uint32_t img = (uint32_t)c.serve_self_manifest[11] | ((uint32_t)c.serve_self_manifest[12] << 8)
                   | ((uint32_t)c.serve_self_manifest[13] << 16) | ((uint32_t)c.serve_self_manifest[14] << 24);
      sprintf(reply, "OK serving self fw mid=%s (%u B, flash-backed) — peers can pull it", midhx, (unsigned)img);
    } else strcpy(reply, "ERR serve self (no EndF / image too big / OOM)");
  } else if (strncmp(d, "serve", 5) == 0) {
    c.serving = c.manager.serve(c.serve_buf, c.serve_expected);
    if (!c.serving) { strcpy(reply, "ERR serve (bad .mota)"); return true; }
    VerifyResult r = ota_verify(c.serve_buf, c.serve_expected, c.allow);
    sprintf(reply, "OK serving | root=%d img=%d sig=%d trust=%d", r.root_ok, r.image_ok, r.sig_ok, r.trusted);

  } else if (strncmp(d, "resume", 6) == 0) {     // re-adopt a container already staged in flash (test/debug)
    bool ok = c.manager.resumeStaged(nullptr);
    sprintf(reply, "%s resume: sess=%c %u/%u", ok ? "OK" : "ERR", fstate_char(c.manager.fetchState()),
            (unsigned)c.manager.blocksHave(), (unsigned)c.manager.blocksTotal());

  } else if (strncmp(d, "announce", 8) == 0) {
    if (!c.serving) { strcpy(reply, "ERR not serving (ota dev serve first)"); return true; }
    c.manager.announce();
    strcpy(reply, "OK announced");

  } else if (strncmp(d, "verify", 6) == 0) {
    const uint8_t* buf; uint32_t len;
    if (c.manager.fetchState() == OtaManager::COMPLETE) { buf = c.fetch_store.data(); len = c.fetch_store.staged_size(); }
    else { buf = c.serve_buf; len = c.serve_expected; }
    if (len == 0 || !buf) { strcpy(reply, "ERR nothing to verify (flash-staged: applydelta verifies)"); return true; }
    VerifyResult r = ota_verify(buf, len, c.allow);
    sprintf(reply, "verify parsed=%d root=%d img=%d signed=%d sig=%d trust=%d | ok=%d auto=%d",
            r.parsed, r.root_ok, r.image_ok, r.is_signed, r.sig_ok, r.trusted, r.integrity_ok(), r.auto_appliable());

  } else if (strncmp(d, "want ", 5) == 0) {
    const char* p = d + 5; while (*p == ' ') p++;
    if (strncmp(p, "auto", 4) == 0) { c.manager.want(0); c.manager.want_mid(nullptr); strcpy(reply, "OK auto (own target only)"); }
    else { uint32_t t = (uint32_t)strtoul(p, nullptr, 16); c.manager.want(t); c.manager.want_mid(nullptr);
           sprintf(reply, "OK cross-target: will fetch %08X (you ensure HW compatible)", (unsigned)t); }

  } else if (strncmp(d, "apply", 5) == 0) {
    const char* sub = d + 5; while (*sub == ' ') sub++;
    if (strncmp(sub, "slot", 4) == 0) {
      uint32_t addr = 0, size = 0;
      if (ota_apply_slot_info(&addr, &size)) sprintf(reply, "inactive slot addr=0x%X size=%u", (unsigned)addr, (unsigned)size);
      else strcpy(reply, "ERR no A/B slot (apply unsupported on this build)");
    } else if (strncmp(sub, "manifest", 8) == 0) {
      if (ota_apply_set_manifest(c.serve_buf, c.serve_expected, c.allow, c.apply_st))
        sprintf(reply, "manifest ok img=%u sig=%d trust=%d", (unsigned)c.apply_st.image_size, c.apply_st.sig_ok, c.apply_st.trusted);
      else strcpy(reply, "ERR manifest parse / not full-image / unsupported");
    } else if (strncmp(sub, "verify", 6) == 0) {
      bool ok = ota_apply_verify_slot(c.apply_st);
      sprintf(reply, "slot image_hash %s (size=%u)", ok ? "MATCH" : "MISMATCH", (unsigned)c.apply_st.image_size);
    } else if (strncmp(sub, "commit", 6) == 0) {
      if (!c.apply_st.slot_ok) { strcpy(reply, "ERR run 'ota dev apply verify' first (slot must match)"); return true; }
      ota_apply_commit();                 // set boot partition + reboot; no return
      strcpy(reply, "ERR commit failed (no A/B slot?)");
    } else {
      strcpy(reply, "ERR ota dev apply (slot|manifest|verify|commit)");
    }

  } else if (strncmp(d, "clear", 5) == 0) {
    c.serve_expected = 0; c.serving = false; c.fetch_store.clear(); c.manager.reset_session();
    strcpy(reply, "OK cleared");

  } else {
    strcpy(reply, "ota dev: stage|recv|serve|announce|verify|want|apply slot|manifest|verify|commit|clear");
  }
  return true;
}

} // namespace ota
} // namespace mesh
