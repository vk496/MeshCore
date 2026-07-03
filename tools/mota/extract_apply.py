"""Extract the payload (bootable image) + manifest-fixed bytes from a firmware .bin for the apply test.
Usage: extract_apply.py <firmware.bin> <signer.priv> <out_payload.bin> <out_manifest.bin>"""
import sys
import motalib as ml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

fw = open(sys.argv[1], "rb").read()
priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(sys.argv[2]).read().strip()))
image, _ = ml.ensure_endf(fw)                       # payload = bootable image (+ EndF), what goes to the slot
m = ml.build_manifest(target_id=0, fw_version=ml.pack_version("1.16.0"),
                      image_size=len(image), payload=image, block_size=1024,
                      image_hash=ml.mh32(image), codec_id=ml.CODEC_FULL, is_full=True, sign_priv=priv)
manifest_fixed = m.signed_region() + m.signature + m.approval   # manifest WITHOUT leaves[]
open(sys.argv[3], "wb").write(image)
open(sys.argv[4], "wb").write(manifest_fixed)
print(f"payload(image)={len(image)}  manifest_fixed={len(manifest_fixed)}")
print(f"image_hash={m.image_hash.hex()}")
print(f"signer={priv.public_key().public_bytes_raw().hex()}")
