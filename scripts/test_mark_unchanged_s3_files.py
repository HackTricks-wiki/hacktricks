import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.mark_unchanged_s3_files import OLD_MTIME_SECONDS, load_remote_objects, mark_unchanged_files


class MarkUnchangedS3FilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.source = self.root / "book"
        self.source.mkdir()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _etag(data: bytes) -> str:
        return hashlib.md5(data, usedforsecurity=False).hexdigest()

    def _write_manifest(self, contents: list[dict]) -> Path:
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"Contents": contents}), encoding="utf-8")
        return path

    def test_only_byte_identical_single_part_objects_are_aged(self) -> None:
        unchanged = self.source / "nested" / "same.html"
        changed = self.source / "changed.html"
        multipart = self.source / "large.bin"
        new = self.source / "new.txt"
        unchanged.parent.mkdir()
        unchanged.write_bytes(b"same")
        changed.write_bytes(b"local")
        multipart.write_bytes(b"large")
        new.write_bytes(b"new")
        for path in (unchanged, changed, multipart, new):
            os.utime(path, (1000, 1000))

        manifest = self._write_manifest([
            {"Key": "en/nested/same.html", "Size": 4, "ETag": f'"{self._etag(b"same")}"'},
            {"Key": "en/changed.html", "Size": 5, "ETag": f'"{self._etag(b"other")}"'},
            {"Key": "en/large.bin", "Size": 5, "ETag": '"0123456789abcdef0123456789abcdef-2"'},
            {"Key": "other/ignored.txt", "Size": 1, "ETag": '"0cc175b9c0f1b6a831c399e269772661"'},
        ])

        remote = load_remote_objects(manifest, "en")
        stats = mark_unchanged_files(self.source, remote)

        self.assertEqual(int(unchanged.stat().st_mtime), OLD_MTIME_SECONDS)
        self.assertEqual(int(changed.stat().st_mtime), 1000)
        self.assertEqual(int(multipart.stat().st_mtime), 1000)
        self.assertEqual(int(new.stat().st_mtime), 1000)
        self.assertEqual(stats, {"local_files": 4, "unchanged": 1, "upload_candidates": 3})
        self.assertNotIn("ignored.txt", remote)

    def test_rejects_absolute_remote_prefix(self) -> None:
        manifest = self._write_manifest([])
        with self.assertRaises(ValueError):
            load_remote_objects(manifest, "/en/")

    def test_rejects_non_list_contents(self) -> None:
        path = self.root / "manifest.json"
        path.write_text('{"Contents": {}}', encoding="utf-8")
        with self.assertRaises(ValueError):
            load_remote_objects(path, "en/")


if __name__ == "__main__":
    unittest.main()
