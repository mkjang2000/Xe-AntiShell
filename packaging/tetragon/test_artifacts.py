"""Isolated archive integrity and extraction checks; no host services are used."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location("tetragon_artifacts", Path(__file__).with_name("artifacts.py"))
ARTIFACTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARTIFACTS)
ROOT = ARTIFACTS.ARCHIVE_ROOT


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tetragon-artifact-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.downloads = self.root / "downloads"
        self.downloads.mkdir(mode=0o700)

    def archive(self, extras=(), missing=()) -> Path:
        path = self.root / "release.tar.gz"
        entries = [
            (ROOT + "/usr/local/bin/tetragon", b"daemon"),
            (ROOT + "/usr/local/bin/tetra", b"client"),
            (ROOT + "/usr/local/lib/tetragon/bpf/base.o", b"object"),
            (ROOT + "/install.sh", b"do not execute"),
        ]
        with tarfile.open(path, "w:gz") as archive:
            for name, content in entries:
                if name in missing:
                    continue
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            for member, content in extras:
                archive.addfile(member, io.BytesIO(content) if content is not None else None)
        return path

    def pinned(self, path: Path):
        return mock.patch.object(ARTIFACTS, "SHA256", hashlib.sha256(path.read_bytes()).hexdigest())

    def assert_rejected_before_writing(self, path: Path, message: str):
        with self.pinned(path), self.assertRaisesRegex(ARTIFACTS.ArtifactError, message):
            ARTIFACTS.extract_release(path, self.stage)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_private_verified_copy_and_selected_extraction(self):
        source = self.archive()
        with self.pinned(source):
            private = ARTIFACTS.acquire_archive(source, self.downloads)
            self.assertNotEqual(private, source)
            self.assertEqual(private.read_bytes(), source.read_bytes())
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
            ARTIFACTS.extract_release(private, self.stage)
        self.assertEqual({p.relative_to(self.stage).as_posix() for p in self.stage.rglob("*")},
                         {"tetragon", "tetra", "bpf", "bpf/base.o"})
        self.assertEqual((self.stage / "tetra").read_bytes(), b"client")
        self.assertEqual(stat.S_IMODE((self.stage / "tetragon").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((self.stage / "bpf/base.o").stat().st_mode), 0o644)

    def test_checksum_failure_removes_private_copy_and_prevents_extraction(self):
        path = self.archive()
        with self.assertRaisesRegex(ARTIFACTS.ArtifactError, "SHA-256"):
            ARTIFACTS.acquire_archive(path, self.downloads)
        self.assertEqual(list(self.downloads.iterdir()), [])
        with self.assertRaisesRegex(ARTIFACTS.ArtifactError, "SHA-256"):
            ARTIFACTS.extract_release(path, self.stage)
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_local_symlinks_and_nonregular_files_are_rejected(self):
        source = self.archive()
        link = self.root / "link.tar.gz"
        link.symlink_to(source)
        fifo = self.root / "fifo.tar.gz"
        os.mkfifo(fifo)
        for path in (link, fifo, self.root):
            with self.subTest(path=path.name), self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.acquire_archive(path, self.downloads)
        self.assertEqual(list(self.downloads.iterdir()), [])

    def test_archive_limit_covers_stat_and_stream_size(self):
        source = self.archive()
        with self.pinned(source), mock.patch.object(ARTIFACTS, "MAX_ARCHIVE_BYTES", 5):
            with self.assertRaisesRegex(ARTIFACTS.ArtifactError, "128 MiB"):
                ARTIFACTS.acquire_archive(source, self.downloads)
            with self.assertRaisesRegex(ARTIFACTS.ArtifactError, "128 MiB"):
                ARTIFACTS._copy_and_hash(io.BytesIO(b"too long"))
        self.assertEqual(list(self.downloads.iterdir()), [])

    def test_all_members_are_validated_even_when_not_selected(self):
        paths = ["/etc/outside", ROOT + "/../outside", ROOT + "/./inside", ROOT + "//inside",
                 "other-release/inside", ROOT + "/bad\\path", ROOT + "/bad\npath"]
        for name in paths:
            with self.subTest(name=name):
                member = tarfile.TarInfo(name)
                member.size = 1
                path = self.archive(extras=[(member, b"x")])
                self.assert_rejected_before_writing(path, "unsafe member path")

    def test_links_devices_fifo_and_duplicate_members_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo(ROOT + "/ignored")
                member.type = kind
                member.linkname = "/etc/outside"
                path = self.archive(extras=[(member, None)])
                self.assert_rejected_before_writing(path, "only regular files and directories")
        member = tarfile.TarInfo(ROOT + "/install.sh")
        path = self.archive(extras=[(member, b"")])
        self.assert_rejected_before_writing(path, "duplicate")

    def test_expanded_size_and_member_count_are_bounded(self):
        path = self.archive()
        with mock.patch.object(ARTIFACTS, "MAX_EXPANDED_BYTES", 1):
            self.assert_rejected_before_writing(path, "512 MiB")
        with mock.patch.object(ARTIFACTS, "MAX_MEMBERS", 1):
            self.assert_rejected_before_writing(path, "too many members")

    def test_required_objects_and_bpf_path_are_checked(self):
        path = self.archive(missing=[ROOT + "/usr/local/bin/tetra"])
        self.assert_rejected_before_writing(path, "missing required")
        member = tarfile.TarInfo(ROOT + "/usr/local/lib/tetragon/bpf/sub/file.o")
        member.size = 1
        path = self.archive(extras=[(member, b"x")])
        self.assert_rejected_before_writing(path, "invalid BPF object")

    def test_special_permissions_and_invalid_root_are_rejected(self):
        member = tarfile.TarInfo(ROOT + "/ignored")
        member.mode = 0o4755
        path = self.archive(extras=[(member, b"")])
        self.assert_rejected_before_writing(path, "unsupported file metadata")
        member = tarfile.TarInfo(ROOT)
        path = self.archive(extras=[(member, b"")])
        self.assert_rejected_before_writing(path, "root must be a directory")

    def test_staging_directory_must_be_empty_and_not_a_symlink(self):
        source = self.archive()
        (self.stage / "preserve").write_text("existing")
        with self.pinned(source), self.assertRaisesRegex(ARTIFACTS.ArtifactError, "must be empty"):
            ARTIFACTS.extract_release(source, self.stage)
        self.assertEqual((self.stage / "preserve").read_text(), "existing")
        link = self.root / "stage-link"
        link.symlink_to(self.stage)
        with self.pinned(source), self.assertRaises(ARTIFACTS.ArtifactError):
            ARTIFACTS.extract_release(source, link)

    def test_download_uses_fixed_url_and_rejects_non_https_results(self):
        source = self.archive()
        response = io.BytesIO(source.read_bytes())
        response.geturl = lambda: "https://release-assets.githubusercontent.com/fixed-artifact"
        opener = mock.Mock()
        opener.open.return_value = response
        with self.pinned(source), mock.patch.object(ARTIFACTS.urllib.request, "build_opener", return_value=opener):
            private = ARTIFACTS.acquire_archive(None, self.downloads)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, ARTIFACTS.URL)
        self.assertEqual(private.read_bytes(), source.read_bytes())
        response = io.BytesIO(b"ignored")
        response.geturl = lambda: "http://insecure.invalid/artifact"
        opener.open.return_value = response
        with mock.patch.object(ARTIFACTS.urllib.request, "build_opener", return_value=opener):
            with self.assertRaisesRegex(ARTIFACTS.ArtifactError, "HTTPS"):
                ARTIFACTS.acquire_archive(None, self.downloads)
        self.assertEqual(list(self.downloads.iterdir()), [private])

    def test_https_redirect_handler_rejects_http_and_credentials(self):
        handler = ARTIFACTS._HTTPSRedirectHandler()
        request = ARTIFACTS.urllib.request.Request(ARTIFACTS.URL)
        for target in ("http://insecure.invalid/a", "https://user:password@example.invalid/a", "file:///etc/outside"):
            with self.subTest(target=target), self.assertRaisesRegex(ARTIFACTS.ArtifactError, "HTTPS"):
                handler.redirect_request(request, None, 302, "Found", {}, target)

    def test_failed_private_copy_is_removed_even_after_valid_hash(self):
        source = self.archive()
        with self.pinned(source), mock.patch.object(ARTIFACTS.os, "fsync", side_effect=OSError("fixture")):
            with self.assertRaises(ARTIFACTS.ArtifactError):
                ARTIFACTS.acquire_archive(source, self.downloads)
        self.assertEqual(list(self.downloads.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
