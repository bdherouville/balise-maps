#!/usr/bin/env python3
"""Re-sign a package manifest and bring the catalogue's copy of its digest in step.

Run this after editing a manifest. The signature covers the manifest bytes
exactly as they sit on disk, so any edit -- even one digit -- invalidates it, and
the catalogue records the manifest's own size and SHA-256, which change with it.
Doing those three things by hand is how they drift apart.

The private key never leaves your machine and is never written anywhere by this
script.

    python3 tools/sign-manifest.py packages/fr-paris-core-1.0.0.manifest.json \
        --key ~/.wearosm/balise-map-signing.key

Then confirm the result with:

    python3 tools/verify-package-consistency.py \
        --key-id balise-r1-2026 --key <base64 public key>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=pathlib.Path, help="path to the manifest JSON to sign")
    parser.add_argument("--key", required=True, type=pathlib.Path, help="PEM Ed25519 private key")
    args = parser.parse_args()

    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("RED: python-cryptography is required to sign", file=sys.stderr)
        return 1

    manifest_path = args.manifest.resolve()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)

    private_key = serialization.load_pem_private_key(args.key.expanduser().read_bytes(), password=None)
    signature = private_key.sign(manifest_bytes)
    if len(signature) != 64:
        print(f"RED: produced a {len(signature)}-byte signature, expected 64", file=sys.stderr)
        return 1

    signature_path = manifest_path.with_suffix("").with_suffix(".manifest.sig")
    signature_path.write_bytes(signature)

    size = len(manifest_bytes)
    sha = hashlib.sha256(manifest_bytes).hexdigest()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    updated = False
    for entry in catalog["entries"]:
        if (
            entry["packageId"] == manifest["packageId"]
            and entry["packageVersion"] == manifest["packageVersion"]
        ):
            entry["objects"]["manifest"]["bytes"] = size
            entry["objects"]["manifest"]["sha256"] = sha
            updated = True
    if not updated:
        print(
            f"RED: catalogue has no entry for {manifest['packageId']} {manifest['packageVersion']}",
            file=sys.stderr,
        )
        return 1
    CATALOG.write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"signed {manifest_path.name} ({size} bytes, sha256 {sha})")
    print(f"wrote  {signature_path.name}")
    print("updated catalog.json manifest bytes and sha256")
    print("\nnow run: python3 tools/verify-package-consistency.py --key-id <id> --key <base64 public key>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
