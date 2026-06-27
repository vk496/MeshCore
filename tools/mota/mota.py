#!/usr/bin/env python3
"""
mota — build / inspect / verify MeshCore ``.mota`` firmware-update containers.

Implements docs/ota_protocol.md (v1). Run with the meshcore venv:

    ./meshcore/bin/python tools/mota/mota.py <command> ...

Commands:
    keygen   generate an Ed25519 signing keypair (raw 32-byte hex)
    build    build a .mota from a firmware image (full, or delta against a base)
    inspect  print a .mota's manifest fields
    verify   validate a .mota (magic/trailer/merkle/signature[/delta vs base])
"""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

import motalib as ml


# ---------------------------------------------------------------------------
# key helpers
# ---------------------------------------------------------------------------

def _load_priv(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = bytes.fromhex(Path(path).read_text().strip())
    if len(raw) != 32:
        sys.exit(f"private key must be 32 raw bytes (64 hex chars), got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _parse_target_id(s) -> int:
    return int(s, 0) & 0xFFFFFFFF  # accepts 0x.. or decimal


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def cmd_keygen(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    if args.out_priv:
        Path(args.out_priv).write_text(priv_hex + "\n")
        Path(args.out_pub or (args.out_priv + ".pub")).write_text(pub_hex + "\n")
        print(f"private -> {args.out_priv}")
        print(f"public  -> {args.out_pub or (args.out_priv + '.pub')}")
    print(f"pubkey: {pub_hex}")


def _resolve_target_id(args) -> int:
    if args.target_env:
        return ml.target_id_for_env(args.target_env)
    if args.target_id:
        return _parse_target_id(args.target_id)
    sys.exit("provide --target-id or --target-env")


def cmd_build(args):
    fw = Path(args.fw).read_bytes()
    new_image, _ = ml.ensure_endf(fw)              # reconstructed image == BODY || EndF
    image_hash = ml.mh32(new_image)
    image_size = len(new_image)

    # Self-describing identity: if the firmware carries an extended EndF (target_id/fw_version/hw_id), use
    # it as the default so a raw .bin from a folder packages correctly WITHOUT --target-env/--fw-version/
    # --hw-id (we can't rely on filenames). Explicit flags still override.
    ident = ml.parse_endf_ident(new_image)
    if args.target_env:   target_id = ml.target_id_for_env(args.target_env)
    elif args.target_id:  target_id = _parse_target_id(args.target_id)
    elif ident and ident.target_id: target_id = ident.target_id
    else: sys.exit("no target: pass --target-env/--target-id, or build a firmware whose EndF carries one")
    fw_version = ml.pack_version(args.fw_version) if args.fw_version else (ident.fw_version if ident else 0)
    hw_id = args.hw_id or (ident.hw_id if ident else "")

    codec_map = {"full": ml.CODEC_FULL,
                 "sequential": ml.CODEC_DETOOLS_SEQUENTIAL,
                 "inplace": ml.CODEC_DETOOLS_INPLACE}
    codec_id = codec_map[args.codec]
    is_full = codec_id == ml.CODEC_FULL

    base_hash = None
    if is_full:
        if args.base:
            sys.exit("--base is only for delta codecs")
        payload = new_image
    else:
        if not args.base:
            sys.exit("delta codec requires --base <old-firmware.bin>")
        old_image, base_hash = ml.ensure_endf(Path(args.base).read_bytes())
        # A delta is only applicable to the SAME hardware+role as the target. Verify via the firmwares'
        # self-describing EndF identity (not the filenames), so we never ship a cross-HW delta that would
        # brick a node. Skippable with --force for deliberate cross-target experiments.
        base_ident = ml.parse_endf_ident(old_image)
        if ident and base_ident:
            mismatch = []
            if ident.hw_id and base_ident.hw_id and ident.hw_id != base_ident.hw_id:
                mismatch.append(f"hw_id {base_ident.hw_id!r} (base) != {ident.hw_id!r} (target)")
            if ident.target_id and base_ident.target_id and ident.target_id != base_ident.target_id:
                mismatch.append(f"target_id {base_ident.target_id:#010x} != {ident.target_id:#010x}")
            if mismatch and not args.force:
                sys.exit("refusing cross-hardware delta (use --force to override):\n  " + "\n  ".join(mismatch))
            if mismatch:
                print("WARNING: building a cross-hardware delta (--force): " + "; ".join(mismatch))
        elif not args.force:
            print("note: base and/or target firmware has no EndF identity — cannot verify same-hardware "
                  "(build a firmware whose EndF carries identity, or pass --force to silence)")
        payload = _make_delta(old_image, new_image, args.codec, args.compression, args)

    sign_priv = _load_priv(args.sign) if args.sign else None

    manifest = ml.build_manifest(
        target_id=target_id,
        fw_version=fw_version,
        image_size=image_size,
        payload=payload,
        block_size=args.block_size,
        image_hash=image_hash,
        codec_id=codec_id,
        is_full=is_full,
        base_hash=base_hash,
        sign_priv=sign_priv,
        hw_id=hw_id,
    )
    blob = ml.build_container(manifest, payload)
    Path(args.out).write_bytes(blob)

    print(f"wrote {args.out}  ({len(blob)} bytes)")
    print(f"  codec        : {ml.CODEC_NAMES[codec_id]}")
    print(f"  hw_id        : {manifest.hw_id.rstrip(bytes([0])).decode('ascii', 'replace') or '(none)'}")
    print(f"  payload      : {len(payload)} bytes  ({manifest.block_count} blocks of {args.block_size})")
    print(f"  image_size   : {image_size} bytes  (BODY+EndF)")
    print(f"  merkle_root  : {manifest.merkle_root.hex()}")
    print(f"  image_hash   : {manifest.image_hash.hex()}")
    if base_hash:
        print(f"  base_hash    : {base_hash.hex()}")
    print(f"  signed       : {manifest.is_signed}"
          + (f"  by {manifest.signer_pubkey.hex()}" if manifest.is_signed else ""))


def _make_delta(old_image: bytes, new_image: bytes, codec: str, compression: str, args) -> bytes:
    import detools
    patch_type = "in-place" if codec == "inplace" else "sequential"
    fp = io.BytesIO()
    kwargs = dict(patch_type=patch_type, compression=compression)
    if patch_type == "in-place":
        # bounded-scratch params — MUST match the bootloader's applier contract (TBD with the fork).
        kwargs.update(memory_size=args.inplace_memory,
                      segment_size=args.inplace_segment)
    detools.create_patch(io.BytesIO(old_image), io.BytesIO(new_image), fp, **kwargs)
    delta = fp.getvalue()
    full = len(new_image)
    print(f"  delta        : {len(delta)} bytes  ({100*len(delta)/full:.1f}% of full {full})")
    return delta


def cmd_inspect(args):
    parsed = ml.parse_container(Path(args.mota).read_bytes())
    m = parsed.manifest
    print(f"total_size     : {parsed.total_size}")
    print(f"format_ver     : {m.format_ver}")
    print(f"flags          : 0x{m.flags:02x}  FULL={m.is_full} SIGNED={m.is_signed}")
    print(f"hash_algo      : 0x{m.hash_algo:02x} (sha2-256)")
    print(f"target_id      : 0x{m.target_id:08x}")
    print(f"fw_version     : {ml.unpack_version(m.fw_version)}  (0x{m.fw_version:08x})")
    print(f"image_size     : {m.image_size}")
    print(f"payload_size   : {m.payload_size}")
    print(f"block_size     : {m.block_size}  (log2={m.block_size_log2})  block_count={m.block_count}")
    print(f"codec_id       : {m.codec_id} ({ml.CODEC_NAMES.get(m.codec_id, '?')})")
    print(f"merkle_root    : {m.merkle_root.hex()}")
    print(f"image_hash     : {m.image_hash.hex()}")
    if m.base_hash:
        print(f"base_hash      : {m.base_hash.hex()}")
    if m.is_signed:
        print(f"signer_pubkey  : {m.signer_pubkey.hex()}")
        print(f"signature      : {m.signature.hex()}")
    approved = m.approval == ml.APPROVAL_YES
    print(f"approval       : {m.approval.hex()}  ({'APPROVED' if approved else 'not approved'})")
    print(f"leaves[]       : {len(m.leaves)} x 4 bytes")


def cmd_verify(args):
    parsed = ml.parse_container(Path(args.mota).read_bytes())
    expect_pub = bytes.fromhex(Path(args.pub).read_text().strip()) if args.pub else None
    base_image = Path(args.base).read_bytes() if args.base else None
    problems = ml.verify(parsed, expect_pub=expect_pub, base_image=base_image)
    if problems:
        print("INVALID:")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print("OK — container, merkle tree"
          + (", signature" if parsed.manifest.is_signed else "")
          + (", delta->image_hash" if (base_image and not parsed.manifest.is_full) else
             (", image_hash" if parsed.manifest.is_full else ""))
          + " all valid.")


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(prog="mota", description="MeshCore .mota packaging tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    g.add_argument("--out-priv", help="write 32-byte private key (hex) here")
    g.add_argument("--out-pub", help="write 32-byte public key (hex) here")
    g.set_defaults(func=cmd_keygen)

    b = sub.add_parser("build", help="build a .mota")
    b.add_argument("--fw", required=True, help="new firmware image (.bin / EndF appended if absent)")
    b.add_argument("--out", required=True, help="output .mota path")
    b.add_argument("--target-id", help="target_id (0x.. or decimal)")
    b.add_argument("--target-env", help="PlatformIO env name; target_id = sha2-256:4(env) "
                                        "(matches build.sh / device getOtaTargetId)")
    b.add_argument("--fw-version", help="e.g. 1.16.0 (or .pre as 1.16.0.2). Optional: read from the "
                                        "firmware's EndF identity if present.")
    b.add_argument("--force", action="store_true",
                   help="build a delta even if base/target hardware identities differ (normally refused)")
    b.add_argument("--codec", choices=["full", "sequential", "inplace"], default="full")
    b.add_argument("--base", help="base firmware (.bin) for delta codecs")
    b.add_argument("--compression", default="crle",
                   choices=["none", "crle", "lz4", "zstd", "lzma", "bz2"],
                   help="delta patch compression (decode-cheap 'crle' default; must be supported by "
                        "the applier. Ignored for --codec full, whose payload is the raw flashable image)")
    b.add_argument("--block-size", type=int, default=ml.DEFAULT_BLOCK_SIZE)
    b.add_argument("--hw-id", default="", help="hardware tag (<=32 ASCII chars, e.g. RAK4631) the firmware "
                   "can boot on; the device refuses a .mota whose hw_id differs from its own. Empty = unset.")
    b.add_argument("--sign", help="Ed25519 private key file (hex) to sign the manifest")
    b.add_argument("--inplace-memory", type=int, default=4096, help="detools in-place memory_size")
    b.add_argument("--inplace-segment", type=int, default=4096, help="detools in-place segment_size")
    b.set_defaults(func=cmd_build)

    i = sub.add_parser("inspect", help="dump a .mota manifest")
    i.add_argument("mota")
    i.set_defaults(func=cmd_inspect)

    v = sub.add_parser("verify", help="validate a .mota")
    v.add_argument("mota")
    v.add_argument("--pub", help="expected signer public key file (hex)")
    v.add_argument("--base", help="base firmware to fully validate a delta -> image_hash")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
