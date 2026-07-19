#!/usr/bin/env python3
"""Avoid redundant S3 uploads by aging byte-identical local files.

`aws s3 sync` uploads a local file when its size differs from the remote object or
when the local modification time is newer. mdBook rebuilds refresh mtimes even
when output bytes are unchanged, which causes unnecessary PutObject requests.

Given a ListObjectsV2 manifest, this script compares local MD5 digests with
single-part S3 ETags. Byte-identical files are assigned an old mtime so the
following `aws s3 sync --delete` skips them. New, changed, multipart, and
otherwise unverifiable objects are left untouched and therefore upload normally.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

OLD_MTIME_SECONDS = 1


def file_md5(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_remote_objects(manifest_path: Path, remote_prefix: str) -> dict[str, dict[str, Any]]:
    if remote_prefix.startswith("/"):
        raise ValueError("remote prefix must not start with '/'")
    if remote_prefix and not remote_prefix.endswith("/"):
        remote_prefix += "/"

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    contents = payload.get("Contents", [])
    if contents is None:
        contents = []
    if not isinstance(contents, list):
        raise ValueError("manifest Contents must be a list")

    objects: dict[str, dict[str, Any]] = {}
    for item in contents:
        if not isinstance(item, dict):
            continue
        key = str(item.get("Key") or "")
        if not key.startswith(remote_prefix):
            continue
        relative_key = key[len(remote_prefix):]
        if not relative_key or relative_key.endswith("/"):
            continue
        objects[relative_key] = item
    return objects


def mark_unchanged_files(source: Path, remote: dict[str, dict[str, Any]]) -> dict[str, int]:
    if not source.is_dir():
        raise ValueError(f"source is not a directory: {source}")

    stats = {"local_files": 0, "unchanged": 0, "upload_candidates": 0}
    for path in source.rglob("*"):
        if not path.is_file():
            continue
        stats["local_files"] += 1
        relative_key = path.relative_to(source).as_posix()
        item = remote.get(relative_key)
        if not item:
            stats["upload_candidates"] += 1
            continue

        etag = str(item.get("ETag") or "").strip('"').lower()
        raw_size = item.get("Size")
        try:
            remote_size = int(raw_size) if raw_size is not None else -1
        except (TypeError, ValueError):
            remote_size = -1

        # A dashed ETag is normally multipart and is not the object's MD5.
        verifiable = len(etag) == 32 and "-" not in etag and all(c in "0123456789abcdef" for c in etag)
        if verifiable and remote_size == path.stat().st_size and file_md5(path) == etag:
            os.utime(path, (OLD_MTIME_SECONDS, OLD_MTIME_SECONDS), follow_symlinks=True)
            stats["unchanged"] += 1
        else:
            stats["upload_candidates"] += 1
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--remote-prefix", default="")
    args = parser.parse_args()

    remote = load_remote_objects(args.manifest, args.remote_prefix)
    stats = mark_unchanged_files(args.source, remote)
    stats["remote_objects"] = len(remote)
    print(json.dumps(stats, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
