#!/usr/bin/env python3
"""Check that every published package agrees with itself, before anyone downloads it.

Balise refuses a package whose manifest contradicts its archive, and it is right
to: the manifest is the signed statement about the archive, so a disagreement
means one of them is not what was signed for. But the app can only discover that
after transferring the whole archive, and all it can tell the wearer is "Map
verification failed".

That is exactly what happened with fr-paris-core 1.0.0. The manifest declared a
centre of 2.35 / zoom 11 while the archive's own PMTiles header said 2.335 /
zoom 10, so every download of an 84 MiB archive -- byte-perfect, correct digest
-- ended in that message. Nothing here was corrupt. The two documents simply
disagreed, and nothing checked.

This runs the same comparisons the app does, against the files as published:

  * archive size and SHA-256 match the manifest and the catalogue
  * manifest size and SHA-256 match the catalogue
  * the Ed25519 signature verifies over the manifest bytes, under the key id the
    manifest names
  * the PMTiles header's version, zoom range, bounds and centre match the
    manifest -- the check that failed

Usage:  python3 tools/verify-package-consistency.py [--key-id ID --key BASE64]

Coordinates compare as E7 integers, the way the app compares them, so that
0.1 + 0.2 arithmetic cannot make a passing package fail here or vice versa.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog.json"

PMTILES_MAGIC = b"PMTiles"
HEADER_BYTES = 127


def e7(value: float) -> int:
    """Match the app's fixed-point comparison rather than comparing floats."""
    return round(value * 1e7)


def read_header(path: pathlib.Path) -> dict:
    with path.open("rb") as archive:
        header = archive.read(HEADER_BYTES)
    if len(header) < HEADER_BYTES or not header.startswith(PMTILES_MAGIC):
        raise SystemExit(f"RED: {path.name} is not a PMTiles archive")

    def i32(offset: int) -> int:
        return struct.unpack_from("<i", header, offset)[0]

    return {
        "version": header[7],
        "minZoom": header[100],
        "maxZoom": header[101],
        "bounds": {
            "west": i32(102) / 1e7,
            "south": i32(106) / 1e7,
            "east": i32(110) / 1e7,
            "north": i32(114) / 1e7,
        },
        "center": {
            "longitude": i32(119) / 1e7,
            "latitude": i32(123) / 1e7,
            "zoom": header[118],
        },
    }


def digest(path: pathlib.Path) -> tuple[int, str]:
    sha = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        while chunk := source.read(1 << 20):
            sha.update(chunk)
            size += len(chunk)
    return size, sha.hexdigest()


def verify_signature(manifest_bytes: bytes, signature: bytes, key_b64: str) -> bool | None:
    """None means "could not check here" — never silently treated as a pass."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return None
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(key_b64)).verify(signature, manifest_bytes)
        return True
    except Exception:
        return False


def check(entry: dict, failures: list[str], key_id: str | None, key_b64: str | None) -> None:
    package = f"{entry['packageId']} {entry['packageVersion']}"

    def fail(message: str) -> None:
        failures.append(f"{package}: {message}")

    objects = entry["objects"]
    manifest_path = ROOT / "packages" / pathlib.Path(objects["manifest"]["url"]).name
    signature_path = ROOT / "packages" / pathlib.Path(objects["signature"]["url"]).name
    archive_path = ROOT / "packages" / pathlib.Path(objects["archive"]["url"]).name

    for path in (manifest_path, signature_path, archive_path):
        if not path.exists():
            fail(f"{path.name} is missing")
            return

    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()

    if len(manifest_bytes) != objects["manifest"]["bytes"]:
        fail(f"catalogue says manifest is {objects['manifest']['bytes']} bytes, file is {len(manifest_bytes)}")
    if manifest_sha != objects["manifest"]["sha256"]:
        fail("catalogue manifest sha256 does not match the manifest file")

    archive_size, archive_sha = digest(archive_path)
    if archive_size != manifest["archive"]["bytes"]:
        fail(f"manifest says archive is {manifest['archive']['bytes']} bytes, file is {archive_size}")
    if archive_sha != manifest["archive"]["sha256"]:
        fail("manifest archive sha256 does not match the archive file")
    if archive_size != entry["archiveBytes"]:
        fail("catalogue archiveBytes disagrees with the archive file")
    if archive_sha != objects["archive"]["sha256"]:
        fail("catalogue archive sha256 disagrees with the archive file")

    signature = signature_path.read_bytes()
    # The signature object has its own size and digest in the catalogue, exactly like the manifest.
    # This check was missing in the first version of this script, and its absence let a catalogue
    # ship whose signature digest still described the pre-re-signing file. The script reported
    # GREEN; the watch refused the package. A consistency checker with a hole is worse than none,
    # because it is believed.
    if len(signature) != objects["signature"]["bytes"]:
        fail(f"catalogue says signature is {objects['signature']['bytes']} bytes, file is {len(signature)}")
    signature_sha = hashlib.sha256(signature).hexdigest()
    if signature_sha != objects["signature"]["sha256"]:
        fail("catalogue signature sha256 does not match the signature file")
    if len(signature) != 64:
        fail(f"signature is {len(signature)} bytes, expected 64")
    elif key_b64 and key_id:
        if manifest["signingKeyId"] != key_id:
            fail(f"manifest is signed by {manifest['signingKeyId']}, expected {key_id}")
        else:
            verdict = verify_signature(manifest_bytes, signature, key_b64)
            if verdict is False:
                fail("Ed25519 signature does not verify over the manifest bytes")
            elif verdict is None:
                print("  note: python-cryptography absent, signature not checked", file=sys.stderr)

    header = read_header(archive_path)
    if header["version"] != manifest["archive"]["pmtilesSpecVersion"]:
        fail(f"header spec version {header['version']} != manifest {manifest['archive']['pmtilesSpecVersion']}")
    for field in ("minZoom", "maxZoom"):
        if header[field] != manifest["compatibility"][field]:
            fail(f"header {field} {header[field]} != manifest {manifest['compatibility'][field]}")
    for edge in ("west", "south", "east", "north"):
        if e7(header["bounds"][edge]) != e7(manifest["bounds"][edge]):
            fail(f"header bounds.{edge} {header['bounds'][edge]} != manifest {manifest['bounds'][edge]}")
    # The check that fr-paris-core 1.0.0 failed.
    for field in ("longitude", "latitude"):
        if e7(header["center"][field]) != e7(manifest["center"][field]):
            fail(f"header center.{field} {header['center'][field]} != manifest {manifest['center'][field]}")
    if header["center"]["zoom"] != manifest["center"]["zoom"]:
        fail(f"header center.zoom {header['center']['zoom']} != manifest {manifest['center']['zoom']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-id", help="expected signingKeyId, e.g. balise-r1-2026")
    parser.add_argument("--key", help="base64 of the raw 32-byte Ed25519 public key")
    args = parser.parse_args()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    failures: list[str] = []
    for entry in catalog["entries"]:
        print(f"checking {entry['packageId']} {entry['packageVersion']}")
        check(entry, failures, args.key_id, args.key)

    if failures:
        for failure in failures:
            print(f"RED: {failure}", file=sys.stderr)
        print(f"RED: {len(failures)} inconsistency(ies) across {len(catalog['entries'])} package(s)", file=sys.stderr)
        return 1
    print(f"GREEN: {len(catalog['entries'])} package(s) internally consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
