"""
PlatformIO post-build extra-script: append the MeshCore ``EndF`` trailer to the
firmware image so a running node can self-locate its size/identity (docs/ota_protocol.md §2).

Wire it (ONLY for OTA-enabled builds) from a variant/env, e.g.:

    extra_scripts =
      ${nrf52_base.extra_scripts}
      post:tools/mota/pio_endf.py

and define ``-D ENABLE_OTA=1``. With ENABLE_OTA unset this script is a no-op, so it is safe to
leave wired everywhere.

The byte logic is the same `motalib.ensure_endf` exercised by `endf.py` and the unit tests.

ESP32 / RP2040 emit ${PROGNAME}.bin (the raw app image) -> EndF appended to the .bin.
nRF52 emits ${PROGNAME}.hex (the app, for DFU/UF2) -> EndF appended into the .hex right after the
app's last byte (so the downstream .uf2 / DFU .zip carry it). Both feed the same on-device EndF scan.
"""

Import("env")  # noqa: F821  (injected by PlatformIO/SCons)

import os
import sys

sys.path.insert(0, os.path.join(env["PROJECT_DIR"], "tools", "mota"))  # noqa: F821
import motalib as ml


def _ota_enabled() -> bool:
    for d in env.get("CPPDEFINES", []):  # noqa: F821
        name = d[0] if isinstance(d, (list, tuple)) else d
        if name == "ENABLE_OTA":
            return True
    return False


def _is_nrf52() -> bool:
    for d in env.get("CPPDEFINES", []):  # noqa: F821
        name = d[0] if isinstance(d, (list, tuple)) else d
        if name == "NRF52_PLATFORM":
            return True
    return False


def _append_endf(source, target, env):           # raw .bin path (ESP32 / RP2040)
    path = str(target[0])
    with open(path, "rb") as f:
        data = f.read()
    out, h8 = ml.ensure_endf(data)
    if len(out) != len(data):
        with open(path, "wb") as f:
            f.write(out)
        print(f"EndF: appended to {os.path.basename(path)} "
              f"(body_len={len(data)} body_hash={h8.hex()})")
    else:
        print(f"EndF: already present in {os.path.basename(path)} (no change)")


def _append_endf_hex(source, target, env):        # Intel-HEX path (nRF52: app for DFU/UF2)
    from intelhex import IntelHex
    path = str(target[0])
    ih = IntelHex(path)
    segs = ih.segments()
    if not segs:
        print("EndF: empty .hex, skipping"); return
    app_start, app_end = segs[0]                  # first (lowest) segment = the application image
    body = bytes(ih.tobinarray(start=app_start, size=app_end - app_start))
    out, h8 = ml.ensure_endf(body)
    if len(out) == len(body):
        print(f"EndF: already present in {os.path.basename(path)} (no change)"); return
    trailer = out[len(body):]                      # the 16-byte EndF trailer
    for i, b in enumerate(trailer):
        ih[app_end + i] = b                        # write it right after the app's last byte
    ih.write_hex_file(path)
    print(f"EndF: appended to {os.path.basename(path)} at 0x{app_end:X} "
          f"(app=0x{app_start:X}.. body_len={len(body)} body_hash={h8.hex()})")


if _ota_enabled():
    if _is_nrf52():
        env.AddPostAction("$BUILD_DIR/${PROGNAME}.hex", _append_endf_hex)  # noqa: F821
    else:
        env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", _append_endf)      # noqa: F821
else:
    print("EndF: ENABLE_OTA not defined; skipping trailer injection")
