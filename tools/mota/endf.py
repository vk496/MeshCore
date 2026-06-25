#!/usr/bin/env python3
"""
endf — append the MeshCore ``EndF`` trailer to a firmware image.

The trailer lets a running node discover its own firmware size/identity on any MCU:

    EndF (16 bytes): "EndF"(4) | body_len(4 LE) | sha2-256:8(body)(8)

Standalone usage (idempotent — a no-op if a valid EndF is already present):

    ./meshcore/bin/python tools/mota/endf.py firmware.bin                 # in place
    ./meshcore/bin/python tools/mota/endf.py firmware.bin out.bin         # to a new file

As a PlatformIO post-build step (see tools/mota/README.md), wire it so that for OTA-enabled builds
the flashed artifact carries the trailer. EndF must be in the FLASHED image (not just the .mota),
because a node serves its own firmware and matches a delta's base against its own EndF.
"""

from __future__ import annotations

import sys
from pathlib import Path

import motalib as ml


def inject(in_path: str, out_path: str | None = None) -> int:
    image = Path(in_path).read_bytes()
    if ml.has_endf(image):
        body, h8 = ml.parse_endf(image)
        print(f"EndF already present: body_len={len(body)} body_hash={h8.hex()} (no change)")
        out = image
    else:
        out, h8 = ml.ensure_endf(image)
        print(f"EndF appended: body_len={len(image)} body_hash={h8.hex()} "
              f"({len(image)} -> {len(out)} bytes)")
    Path(out_path or in_path).write_bytes(out)
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    raise SystemExit(inject(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None))
