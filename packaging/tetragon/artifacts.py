"""Acquire and inspect the pinned standalone release without running its scripts."""

from __future__ import annotations

import contextlib
import hashlib
import os
import stat
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from pathlib import Path
from typing import BinaryIO, Iterator, Optional


VERSION = "v1.8.0"
SHA256 = "e88691c5f05a2a61aba58974a080603050b924c7f13ecc06f3d05172feb05f59"
ARCHIVE_ROOT = "tetragon-v1.8.0-amd64"
ARCHIVE_NAME = ARCHIVE_ROOT + ".tar.gz"
URL = "https://github.com/cilium/tetragon/releases/download/" + VERSION + "/" + ARCHIVE_NAME
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 4096
CHUNK_BYTES = 1024 * 1024


class ArtifactError(RuntimeError):
    """The release could not be acquired or did not pass validation."""


def _https_url(url: str) -> bool:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password


class _HTTPSRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if not _https_url(new_url):
            raise ArtifactError("release download redirected outside HTTPS")
        return super().redirect_request(request, response, code, message, headers, new_url)


@contextlib.contextmanager
def _open_regular(path: Path) -> Iterator[BinaryIO]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactError("release archive must be a regular file")
        if info.st_size > MAX_ARCHIVE_BYTES:
            raise ArtifactError("release archive exceeds the 128 MiB limit")
        with os.fdopen(descriptor, "rb") as archive:
            descriptor = -1
            yield archive
    finally:
        if descriptor != -1:
            os.close(descriptor)


def _copy_and_hash(source: BinaryIO, destination: Optional[BinaryIO] = None) -> str:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            raise ArtifactError("release archive exceeds the 128 MiB limit")
        digest.update(chunk)
        if destination is not None:
            destination.write(chunk)
    return digest.hexdigest()


def acquire_archive(source: Optional[Path], directory: Path) -> Path:
    """Make a mode-0600 verified private copy of a local file or the fixed URL."""
    descriptor = -1
    private_path = None
    complete = False
    try:
        descriptor, name = tempfile.mkstemp(prefix="tetragon-release-", suffix=".tar.gz", dir=directory)
        private_path = Path(name)
        with os.fdopen(descriptor, "wb") as destination:
            descriptor = -1
            if source is not None:
                with _open_regular(source) as archive:
                    actual = _copy_and_hash(archive, destination)
            else:
                opener = urllib.request.build_opener(_HTTPSRedirectHandler())
                request = urllib.request.Request(URL, headers={"User-Agent": "Xe-AntiShell-Tetragon-setup"})
                with opener.open(request, timeout=30) as response:
                    if not _https_url(response.geturl()):
                        raise ArtifactError("release download did not use HTTPS")
                    actual = _copy_and_hash(response, destination)
            destination.flush()
            os.fsync(destination.fileno())
        if actual != SHA256:
            raise ArtifactError("release archive SHA-256 does not match the pinned official release")
        complete = True
        return private_path
    except (OSError, urllib.error.URLError, ValueError) as error:
        raise ArtifactError("could not acquire the pinned Tetragon archive") from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        if private_path is not None and not complete:
            private_path.unlink(missing_ok=True)


def _inspect_members(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, str]]:
    selected = []
    names = set()
    total = 0
    bpf_prefix = ARCHIVE_ROOT + "/usr/local/lib/tetragon/bpf/"
    binaries = {
        ARCHIVE_ROOT + "/usr/local/bin/tetragon": "tetragon",
        ARCHIVE_ROOT + "/usr/local/bin/tetra": "tetra",
    }
    for index, member in enumerate(archive):
        if index >= MAX_MEMBERS:
            raise ArtifactError("release archive contains too many members")
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (not name or "\\" in name or any(ord(char) < 32 for char in name)
                or any(part in ("", ".", "..") for part in parts)
                or parts[0] != ARCHIVE_ROOT):
            raise ArtifactError("release archive contains an unsafe member path")
        if name in names:
            raise ArtifactError("release archive contains duplicate members")
        names.add(name)
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ArtifactError("release archive may contain only regular files and directories")
        if name == ARCHIVE_ROOT and not member.isdir():
            raise ArtifactError("release archive root must be a directory")
        if member.sparse is not None or member.mode & 0o7000:
            raise ArtifactError("release archive contains unsupported file metadata")
        if member.size < 0 or (member.isdir() and member.size != 0):
            raise ArtifactError("release archive contains an invalid member size")
        total += member.size
        if total > MAX_EXPANDED_BYTES:
            raise ArtifactError("expanded release exceeds the 512 MiB limit")
        if name in binaries:
            if not member.isfile() or member.size == 0:
                raise ArtifactError("release executable is missing or empty")
            selected.append((member, binaries[name]))
        elif name.startswith(bpf_prefix) and member.isfile():
            basename = name[len(bpf_prefix):]
            if "/" in basename or not basename.endswith(".o") or member.size == 0:
                raise ArtifactError("release contains an invalid BPF object path")
            selected.append((member, "bpf/" + basename))
    targets = {target for _, target in selected}
    if not {"tetragon", "tetra"}.issubset(targets) or not any(target.startswith("bpf/") for target in targets):
        raise ArtifactError("release is missing required executables or BPF objects")
    return selected


def extract_release(archive: Path, destination: Path) -> None:
    """Validate every member, then copy only tetragon, tetra and BPF objects."""
    root_descriptor = -1
    bpf_descriptor = -1
    try:
        root_descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if os.listdir(root_descriptor):
            raise ArtifactError("release staging directory must be empty")
        with _open_regular(archive) as source:
            if _copy_and_hash(source) != SHA256:
                raise ArtifactError("release archive SHA-256 does not match the pinned official release")
            source.seek(0)
            with tarfile.open(fileobj=source, mode="r:gz") as release:
                selected = _inspect_members(release)
                os.mkdir("bpf", 0o755, dir_fd=root_descriptor)
                bpf_descriptor = os.open("bpf", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         dir_fd=root_descriptor)
                for member, target in selected:
                    parent = bpf_descriptor if target.startswith("bpf/") else root_descriptor
                    filename = target.split("/")[-1]
                    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                         0o600, dir_fd=parent)
                    with os.fdopen(descriptor, "wb") as output, release.extractfile(member) as content:
                        remaining = member.size
                        while remaining:
                            chunk = content.read(min(CHUNK_BYTES, remaining))
                            if not chunk:
                                raise ArtifactError("release archive contains truncated file data")
                            output.write(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fchmod(output.fileno(), 0o644 if target.startswith("bpf/") else 0o755)
    except (OSError, tarfile.TarError, EOFError, ValueError, zlib.error) as error:
        raise ArtifactError("could not validate or stage the pinned Tetragon release") from error
    finally:
        if bpf_descriptor != -1:
            os.close(bpf_descriptor)
        if root_descriptor != -1:
            os.close(root_descriptor)
