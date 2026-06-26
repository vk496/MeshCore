#!/usr/bin/env python3
"""mota-seeder: serve a FOLDER of .mota firmware to a MeshCore node over a serial link.

The node (a SerialMotaSource) pulls the catalog + bytes on demand and RELAYS them into the mesh as if it
held them — peers just see "this node has N mOTAs". Drop several .mota (any architecture) into a folder
and point this daemon at the node's seeder UART; the node advertises + serves them all. The relay is
trustless (fetchers verify merkle+signature), so this daemon never needs the signing keys.

Protocol: src/helpers/ota/MotaSeederProto.h (little-endian, XOR-checksummed, resync on magic).
  request  (node -> here):  'M''S' op(1) args... xsum
  response (here -> node):  'm''s' op(1) status(1) payload... xsum
  OP_COUNT 0x01 -> count(1) ; OP_DESCRIBE 0x02 idx -> MotaDesc(38) ; OP_READ 0x03 idx off(4) len(2) -> bytes

Usage:  mota_seeder.py --port /dev/ttyUSB0 --baud 115200 --dir ./firmware_folder [--watch]
Requires: pyserial, and motalib.py (this same tools/mota dir) for parsing.
"""
import argparse, glob, os, struct, sys, time
import serial  # pyserial
import motalib

REQ_MAGIC = b"MS"
RSP_MAGIC = b"ms"
OP_COUNT, OP_DESCRIBE, OP_READ = 0x01, 0x02, 0x03
ST_OK, ST_ERR = 0x00, 0x01
DESC_WIRE = 38

HEAD = 89  # fixed manifest head incl hw_id[32]


def mota_offsets(blob: bytes):
    """Parse a .mota and return its catalog descriptor + region offsets (mirrors MotaContainer.cpp)."""
    p = motalib.parse_container(blob)
    m = p.manifest
    base = 0 if m.is_full else 8
    sig = 96 if m.is_signed else 0
    mfl = HEAD + base + sig + 4               # manifest-minus-leaves: head + base_hash? + sig? + approval
    leaves_off = 8 + mfl                      # container = MAGIC(4) total(4) manifest...
    bc = m.block_count
    payload_off = leaves_off + bc * 4
    return {
        "mid": bytes(m.merkle_root),
        "target_id": m.target_id,
        "fw_version": m.fw_version,
        "codec_id": m.codec_id,
        "flags": m.flags,
        "total_size": len(blob),
        "leaves_off": leaves_off,
        "block_count": bc,
        "payload_off": payload_off,
        "payload_size": m.payload_size,
    }


def desc_wire(d) -> bytes:
    w = bytearray(DESC_WIRE)
    w[0:4] = d["mid"]
    struct.pack_into("<IIB", w, 4, d["target_id"], d["fw_version"], d["codec_id"])
    w[13] = d["flags"]
    struct.pack_into("<IIII", w, 14, d["total_size"], d["leaves_off"], d["block_count"], d["payload_off"])
    struct.pack_into("<I", w, 30, d["payload_size"])
    # [34:38) reserved 0
    return bytes(w)


def load_folder(path):
    """Return a sorted list of {path, blob, desc} for every parseable .mota in the folder."""
    items = []
    for f in sorted(glob.glob(os.path.join(path, "*.mota"))):
        try:
            blob = open(f, "rb").read()
            d = mota_offsets(blob)
            items.append({"path": f, "blob": blob, "desc": d})
        except Exception as e:
            print(f"  ! skip {os.path.basename(f)}: {e}", file=sys.stderr)
    return items


def xor(data: bytes, seed: int = 0) -> int:
    x = seed
    for b in data:
        x ^= b
    return x & 0xFF


def send_rsp(ser, op, status, payload=b""):
    body = bytes([op, status]) + payload
    frame = RSP_MAGIC + body + bytes([xor(RSP_MAGIC + body)])
    ser.write(frame)
    ser.flush()


def read_exact(ser, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = ser.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def handle_one(ser, items, verbose):
    """Read one request body (magic already consumed) and send its response."""
    op = read_exact(ser, 1)
    if op is None:
        return
    op = op[0]
    if op == OP_COUNT:
        args = b""
    elif op == OP_DESCRIBE:
        args = read_exact(ser, 1)
    elif op == OP_READ:
        args = read_exact(ser, 7)
    else:
        return
    if args is None:
        return
    xs = read_exact(ser, 1)
    if xs is None or xs[0] != xor(args, op):
        return  # bad checksum -> ignore; node retries

    if op == OP_COUNT:
        send_rsp(ser, op, ST_OK, bytes([min(len(items), 255)]))
        if verbose:
            print(f"  COUNT -> {len(items)}")
    elif op == OP_DESCRIBE:
        idx = args[0]
        if idx < len(items):
            send_rsp(ser, op, ST_OK, desc_wire(items[idx]["desc"]))
            if verbose:
                print(f"  DESCRIBE {idx} -> {os.path.basename(items[idx]['path'])}")
        else:
            send_rsp(ser, op, ST_ERR)
    elif op == OP_READ:
        idx = args[0]
        off, lo, hi = struct.unpack("<IBB", args[1:7])
        length = lo | (hi << 8)
        if idx < len(items) and off + length <= len(items[idx]["blob"]):
            send_rsp(ser, op, ST_OK, items[idx]["blob"][off:off + length])
            if verbose:
                print(f"  READ {idx} @{off} +{length}")
        else:
            send_rsp(ser, op, ST_ERR)


def serve(ser, items, verbose):
    """Scan the shared USB stream for request frames ('M''S'), answering each. Device CLI replies / logs
    interleave on the same wire — they're surfaced as [dev] lines and skipped (resync on the magic)."""
    skipped = bytearray()

    def emit(byte):
        skipped.append(byte)
        if byte == 0x0A:                       # newline: flush one device text line
            line = bytes(skipped).decode("utf-8", "replace").strip()
            skipped.clear()
            if line:
                print(f"  [dev] {line}")

    prev = None
    while True:
        b = ser.read(1)
        if not b:
            continue
        c = b[0]
        if prev == ord('M') and c == ord('S'):
            handle_one(ser, items, verbose)    # 'M''S' consumed; read the rest of the request
            prev = None
            continue
        if prev is not None:                   # confirmed device text (not a frame start)
            emit(prev)
        prev = c


def main():
    ap = argparse.ArgumentParser(description="Serve a folder of .mota to a MeshCore node over serial.")
    ap.add_argument("--port", required=True, help="serial device of the node's seeder UART (e.g. /dev/ttyUSB0)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--dir", required=True, help="folder containing .mota files to serve")
    ap.add_argument("--no-enable", action="store_true",
                    help="don't auto-send `ota folder on/off` (run those on the node CLI yourself)")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    items = load_folder(a.dir)
    print(f"mota-seeder: {len(items)} mOTA in {a.dir}")
    for it in items:
        d = it["desc"]
        print(f"  - {os.path.basename(it['path'])}: mid={d['mid'].hex().upper()} "
              f"target={d['target_id']:08X} fw={d['fw_version']} codec={d['codec_id']} "
              f"blocks={d['block_count']} size={d['total_size']}")
    if not items:
        print("  (no .mota found — nothing to serve)", file=sys.stderr)

    ser = serial.Serial(a.port, a.baud, timeout=0.2)
    if not a.no_enable:
        time.sleep(0.5)                        # let the node settle, then turn folder relay on via its CLI
        ser.write(b"ota folder on\r\n"); ser.flush()
        print("sent `ota folder on` to the node")
    print(f"serving on {a.port} @ {a.baud} — Ctrl-C to stop")
    try:
        serve(ser, items, a.verbose)
    except KeyboardInterrupt:
        if not a.no_enable:
            try:
                ser.write(b"ota folder off\r\n"); ser.flush(); time.sleep(0.2)
            except Exception:
                pass
        print("\nbye")


if __name__ == "__main__":
    main()
