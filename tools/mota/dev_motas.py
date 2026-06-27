#!/usr/bin/env python3
"""Package a full + same-image-delta .mota for ONE built firmware (dev rolling release).

Extracts the OTA image (BODY||EndF) from a PlatformIO build and runs `mota build` twice:
  - full   .mota (codec full)      — the flashable image, universally applicable
  - delta  .mota (same-image)      — base == target, so the patch is tiny (a format/transport demo).
                                     ESP32 -> sequential+crle ; nRF52 -> in-place (RAK4631 flash layout).

Image source per platform:
  ESP32 : <build_dir>/firmware.bin            (pio_endf has already appended EndF)
  nRF52 : app region of <build_dir>/firmware.hex, extracted via intelhex (EndF already appended to the .hex)

Usage:
  dev_motas.py --env RAK_4631_repeater --platform NRF52 --build-dir .pio/build/RAK_4631_repeater \
               --target-env RAK_4631_repeater --out-prefix out/RAK_4631_repeater-dev-abc1234
Writes <out-prefix>.full.mota and (best-effort) <out-prefix>.delta.mota.
"""
import argparse, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
MOTA = os.path.join(HERE, "mota.py")

# nRF52 (RAK4631) flash layout — keep in sync with src/helpers/ota/OtaFlashLayout_nrf52.h
NRF52_APP_BASE = 0x26000
NRF52_FS_START = 0xD4000
NRF52_INPLACE_MEMORY = NRF52_FS_START - NRF52_APP_BASE   # 0xAE000 working size for in-place apply
NRF52_INPLACE_SEGMENT = 4096


def extract_image(platform, build_dir, work):
    """Return the path to the OTA image (BODY||EndF) as a raw .bin, or None if not found."""
    if platform == "ESP32":
        bin_path = os.path.join(build_dir, "firmware.bin")
        return bin_path if os.path.isfile(bin_path) else None
    if platform == "NRF52":
        hex_path = os.path.join(build_dir, "firmware.hex")
        if not os.path.isfile(hex_path):
            return None
        from intelhex import IntelHex
        ih = IntelHex(hex_path)
        # the app .hex is a single contiguous segment [APP_BASE .. app_end]; take it verbatim
        start = ih.minaddr()
        data = ih.tobinarray(start=start, end=ih.maxaddr())
        out = os.path.join(work, "app_image.bin")
        with open(out, "wb") as f:
            f.write(bytes(data))
        return out
    return None


def run_mota(args):
    print("  +", "mota.py", " ".join(args))
    subprocess.run([sys.executable, MOTA, "build", *args], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--platform", required=True, choices=["ESP32", "NRF52"])
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--target-env", required=True)
    ap.add_argument("--out-prefix", required=True)
    ap.add_argument("--work", default=".")
    a = ap.parse_args()

    img = extract_image(a.platform, a.build_dir, a.work)
    if not img:
        print(f"::warning::no OTA image for {a.env} ({a.platform}) — skipping .mota")
        return 0
    print(f"OTA image for {a.env}: {img} ({os.path.getsize(img)} bytes)")

    # full .mota (always)
    run_mota(["--fw", img, "--target-env", a.target_env, "--fw-version", "0.0.0",
              "--codec", "full", "--out", a.out_prefix + ".full.mota"])

    # same-image delta .mota (best-effort; codec per platform's applier)
    try:
        if a.platform == "ESP32":
            run_mota(["--fw", img, "--base", img, "--target-env", a.target_env, "--fw-version", "0.0.1",
                      "--codec", "sequential", "--compression", "crle", "--out", a.out_prefix + ".delta.mota"])
        else:  # NRF52 in-place
            run_mota(["--fw", img, "--base", img, "--target-env", a.target_env, "--fw-version", "0.0.1",
                      "--codec", "inplace", "--compression", "crle",
                      "--inplace-memory", str(NRF52_INPLACE_MEMORY), "--inplace-segment", str(NRF52_INPLACE_SEGMENT),
                      "--out", a.out_prefix + ".delta.mota"])
    except subprocess.CalledProcessError as e:
        print(f"::warning::delta .mota for {a.env} failed ({e}); full .mota still produced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
