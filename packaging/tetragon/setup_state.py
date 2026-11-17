"""Verified installed-file manifests and a recoverable service/config transaction."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from artifacts import SHA256, VERSION
from setup_common import SetupError, atomic_write, ensure_dir, trusted_path


MANIFEST = ".xeas-manifest.json"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def file_manifest(directory):
    files, total = {}, 0
    trusted_path(directory, directory=True)
    for path in sorted(directory.rglob("*")):
        if path.name == MANIFEST and path.parent == directory:
            continue
        trusted_path(path, directory=path.is_dir())
        if path.is_file():
            total += path.stat().st_size
            if total > 512 * 1024 * 1024 or len(files) >= 4096:
                raise SetupError("설치된 Tetragon 파일이 검증 크기 제한을 초과했습니다.")
            files[str(path.relative_to(directory))] = digest(path)
    if "tetragon" not in files or "tetra" not in files or not any(key.startswith("bpf/") for key in files):
        raise SetupError("설치된 Tetragon 파일이 완전하지 않습니다.")
    return files


def seal_release(directory):
    for path in directory.rglob("*"):
        trusted_path(path, directory=path.is_dir())
        os.chmod(path, 0o755 if path.is_dir() or path.name in ("tetragon", "tetra") else 0o644)
    os.chmod(directory, 0o755)
    value = {"version": VERSION, "archive_sha256": SHA256, "files": file_manifest(directory)}
    atomic_write(directory / MANIFEST, json.dumps(value, sort_keys=True).encode("ascii"), mode=0o600)


def installed_release(directory):
    if not directory.exists() and not directory.is_symlink():
        return False
    trusted_path(directory, directory=True)
    manifest = directory / MANIFEST
    trusted_path(manifest)
    if manifest.stat().st_size > 1024 * 1024:
        raise SetupError("기존 Tetragon 설치 manifest가 올바르지 않습니다.")
    try:
        value = json.loads(manifest.read_bytes())
    except (ValueError, RecursionError):
        raise SetupError("기존 Tetragon 설치 manifest가 올바르지 않습니다.") from None
    if (not isinstance(value, dict) or value.get("version") != VERSION
            or value.get("archive_sha256") != SHA256 or value.get("files") != file_manifest(directory)):
        raise SetupError("기존 Tetragon 파일이 설치기 검증 기록과 달라 수동 확인이 필요합니다.")
    return True


class Transaction:
    def __init__(self, paths, services, original_config):
        self.paths, self.services = paths, services
        self.original_config = original_config
        self.config_info = paths.config.stat()
        self.original_unit = paths.unit.read_bytes() if paths.unit.exists() else None
        self.unit_info = paths.unit.stat() if paths.unit.exists() else None
        self.original_dropin = paths.agent_dropin.read_bytes() if paths.agent_dropin.exists() else None
        self.dropin_info = paths.agent_dropin.stat() if paths.agent_dropin.exists() else None
        self.tetragon = services.snapshot("tetragon.service")
        self.agent = services.snapshot("sentineld.service")
        self.config_changed = self.unit_changed = self.release_added = False
        self.dropin_changed = False
        self.tetragon_changed = self.agent_changed = False
        self.created_dirs = []
        self.backup = None

    def backup_originals(self):
        ensure_dir(self.paths.backups, 0o700)
        if stat.S_IMODE(self.paths.backups.stat().st_mode) != 0o700:
            raise SetupError("Tetragon 진단 백업 디렉터리는 root 0700이어야 합니다.")
        self.backup = Path(tempfile.mkdtemp(prefix="attempt-", dir=str(self.paths.backups)))
        atomic_write(self.backup / "sentineld.yaml", self.original_config)
        if self.original_unit is not None:
            atomic_write(self.backup / "tetragon.service", self.original_unit)
        if self.original_dropin is not None:
            atomic_write(self.backup / "sentineld-tetragon.conf", self.original_dropin)
        metadata = {"tetragon": vars(self.tetragon), "sentineld": vars(self.agent),
                    "config_mode": stat.S_IMODE(self.config_info.st_mode),
                    "config_uid": self.config_info.st_uid, "config_gid": self.config_info.st_gid,
                    "unit_existed": self.original_unit is not None}
        atomic_write(self.backup / "state.json", json.dumps(metadata).encode("ascii"))

    def create_dir(self, path, mode=0o755):
        if not path.exists():
            self.created_dirs.append(path)
        ensure_dir(path, mode)

    def install_release(self, stage):
        self.create_dir(self.paths.base)
        # Copy into a private sibling first so cross-filesystem /tmp is supported.
        temporary = Path(tempfile.mkdtemp(prefix=".install-", dir=str(self.paths.base)))
        try:
            shutil.copytree(stage, temporary, dirs_exist_ok=True)
            seal_release(temporary)
            if self.paths.version.exists() or self.paths.version.is_symlink():
                raise SetupError("Tetragon 설치 경로가 실행 중 변경되었습니다.")
            os.rename(temporary, self.paths.version)
            self.release_added = True
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def write_config(self, content):
        self.config_changed = True
        atomic_write(self.paths.config, content, stat.S_IMODE(self.config_info.st_mode),
                     self.config_info.st_uid, self.config_info.st_gid)

    def write_unit(self, content):
        self.unit_changed = True
        atomic_write(self.paths.unit, content, mode=0o644)

    def write_dropin(self, content):
        self.create_dir(self.paths.agent_dropin.parent)
        self.dropin_changed = True
        atomic_write(self.paths.agent_dropin, content, mode=0o644)

    def restore(self):
        failures = []

        def attempt(action):
            try:
                action()
            except Exception:
                failures.append(True)

        if self.agent_changed:
            attempt(lambda: self.services.call("stop", "sentineld.service"))
        if self.tetragon_changed:
            attempt(lambda: self.services.call("stop", "tetragon.service"))
            if self.tetragon.enabled not in ("enabled", "enabled-runtime"):
                attempt(lambda: self.services.call("disable", "tetragon.service"))
        if self.config_changed:
            attempt(lambda: atomic_write(self.paths.config, self.original_config,
                                         stat.S_IMODE(self.config_info.st_mode),
                                         self.config_info.st_uid, self.config_info.st_gid))
        if self.unit_changed:
            if self.original_unit is None:
                attempt(lambda: self.paths.unit.unlink(missing_ok=True))
            else:
                attempt(lambda: atomic_write(self.paths.unit, self.original_unit,
                                             stat.S_IMODE(self.unit_info.st_mode),
                                             self.unit_info.st_uid, self.unit_info.st_gid))
        if self.dropin_changed:
            if self.original_dropin is None:
                attempt(lambda: self.paths.agent_dropin.unlink(missing_ok=True))
            else:
                attempt(lambda: atomic_write(self.paths.agent_dropin, self.original_dropin,
                                             stat.S_IMODE(self.dropin_info.st_mode),
                                             self.dropin_info.st_uid, self.dropin_info.st_gid))
        if self.unit_changed or self.dropin_changed:
            attempt(lambda: self.services.call("daemon-reload"))
        if self.release_added:
            attempt(lambda: shutil.rmtree(self.paths.version))
        if self.tetragon_changed and self.tetragon.enabled in ("enabled", "enabled-runtime"):
            attempt(lambda: self.services.restore_enabled("tetragon.service", self.tetragon))
        if self.tetragon_changed and self.tetragon.active:
            attempt(lambda: self.services.call("start", "tetragon.service"))
        if self.agent_changed and self.agent.active:
            attempt(lambda: self.services.call("start", "sentineld.service"))
        for directory in reversed(self.created_dirs):
            if directory.exists():
                attempt(lambda directory=directory: directory.rmdir())
        if failures:
            raise SetupError("자동 복구 일부가 실패했습니다. root 전용 진단 백업과 서비스 상태를 확인하십시오.")
