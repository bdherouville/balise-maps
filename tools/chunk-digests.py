#!/usr/bin/env python3
"""Compute the signed chunk-digest vector for a package archive.

Why this exists: the manifest signs the archive as one blob
(`archive.sha256`), which can only be checked once the whole 84 MB has been
transferred. Fetching part of an archive by HTTP range -- the basis of
"the map 1 km around me" (#158) -- therefore has nothing to verify against, and
naive range fetching silently drops the app to HTTPS-only trust, discarding the
signed-package guarantee the whole contract exists to provide.

A vector of digests over fixed-size aligned chunks fixes that: any byte range is
verified by fetching the chunks covering it and checking them against the signed
list. The whole-archive digest stays exactly as it is, so full installs are
unaffected.

The chunk size is a trade: smaller chunks mean less over-fetch when a tile
straddles a boundary, and a longer vector. At 1 MiB an 84 MB archive needs 84
digests -- about 5.7 KB of JSON as hex, which is negligible next to a manifest
that is already fetched in full before anything else happens.

Usage:
    chunk-digests.py ARCHIVE [--chunk-bytes N]        compute from a local file
    chunk-digests.py --verify MANIFEST ARCHIVE        re-check a manifest's vector
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

DEFAULT_CHUNK_BYTES = 1024 * 1024


def digests(path: str, chunk_bytes: int) -> tuple[list[str], str, int]:
    """Chunk digests, the whole-archive digest, and the total size, in one pass."""
    whole = hashlib.sha256()
    chunks: list[str] = []
    total = 0
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_bytes)
            if not block:
                break
            total += len(block)
            whole.update(block)
            chunks.append(hashlib.sha256(block).hexdigest())
    return chunks, whole.hexdigest(), total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("--chunk-bytes", type=int, default=DEFAULT_CHUNK_BYTES)
    parser.add_argument("--verify", metavar="MANIFEST")
    args = parser.parse_args()

    if args.chunk_bytes <= 0:
        print("RED: --chunk-bytes must be positive.", file=sys.stderr)
        return 2

    if args.verify:
        with open(args.verify, encoding="utf-8") as handle:
            manifest = json.load(handle)
        archive = manifest.get("archive", {})
        recorded = archive.get("chunks")
        if not recorded:
            print("RED: this manifest carries no chunk vector.", file=sys.stderr)
            return 1

        chunks, whole, total = digests(args.archive, recorded["bytes"])

        # The whole-archive digest is checked too. A chunk vector that agrees with
        # itself but not with the blob it claims to describe would verify every
        # range and still be describing a different file.
        if whole != archive.get("sha256"):
            print(
                f"RED: archive.sha256 does not match the file: "
                f"{archive.get('sha256')} != {whole}",
                file=sys.stderr,
            )
            return 1
        if total != archive.get("bytes"):
            print(f"RED: archive.bytes is {archive.get('bytes')}, file is {total}", file=sys.stderr)
            return 1
        if chunks != recorded["sha256"]:
            first = next(
                (i for i, (a, b) in enumerate(zip(chunks, recorded["sha256"])) if a != b),
                min(len(chunks), len(recorded["sha256"])),
            )
            print(
                f"RED: chunk vector differs from the file, first at index {first} "
                f"(offset {first * recorded['bytes']}).",
                file=sys.stderr,
            )
            return 1

        print(f"GREEN: {len(chunks)} chunks of {recorded['bytes']} bytes verify against the archive.")
        return 0

    chunks, whole, total = digests(args.archive, args.chunk_bytes)
    print(
        json.dumps(
            {
                "bytes": args.chunk_bytes,
                "count": len(chunks),
                "sha256": chunks,
                "_archiveSha256": whole,
                "_archiveBytes": total,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
