"""Small, root-owned filesystem operations shared by the opt-in installer."""

import os
from contextlib import contextmanager
import fcntl
from pathlib import Path
import signal
import stat
import tempfile


class SetupError(Exception):
    """A fixed diagnostic safe to show without process-event contents."""


@contextmanager
def rollback_guard():
    previous = {}
    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, signal.SIG_IGN)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


class Paths:
    """Production paths; a private root is injectable only through Python tests."""

    def __init__(self, root=Path("/")):
        self.root = Path(root)
        self.config = self.at("/etc/xe-antishell/sentineld.yaml")
        self.unit = self.at("/etc/systemd/system/tetragon.service")
        self.agent_dropin = self.at("/etc/systemd/system/sentineld.service.d/tetragon.conf")
        self.base = self.at("/opt/xe-antishell/tetragon")
        self.version = self.base / "v1.8.0"
        self.policies = self.base / "policies"
        self.backups = self.at("/var/lib/xe-antishell/tetragon-install-backups")
        self.btf = self.at("/sys/kernel/btf/vmlinux")
        self.lock = self.at("/run/xe-antishell/tetragon-install.lock")

    def at(self, absolute):
        return self.root / absolute.lstrip("/")


def trusted_path(path, *, directory=False, required=True):
    """Reject symlink ancestors and files writable by a non-root identity."""
    path = Path(path)
    for item in list(reversed(path.parents)) + [path]:
        try:
            info = item.lstat()
        except FileNotFoundError:
            if required and item == path:
                raise SetupError("필수 파일 또는 디렉터리가 없습니다.") from None
            continue
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise SetupError("설치 경로의 root 소유권 또는 심볼릭 링크를 확인하십시오.")
        # /tmp may be a sticky ancestor of isolated test roots.
        if info.st_mode & 0o022 and not (stat.S_ISDIR(info.st_mode) and info.st_mode & stat.S_ISVTX):
            raise SetupError("설치 경로가 다른 사용자에게 쓰기 가능하여 중단했습니다.")
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise SetupError("설치 경로의 상위 경로가 디렉터리가 아닙니다.")
        if item == path and directory and not stat.S_ISDIR(info.st_mode):
            raise SetupError("설치 디렉터리 경로가 일반 디렉터리가 아닙니다.")
        if item == path and not directory and not stat.S_ISREG(info.st_mode):
            raise SetupError("설치 파일 경로가 일반 파일이 아닙니다.")


def ensure_dir(path, mode=0o755):
    path = Path(path)
    trusted_path(path, directory=True, required=False)
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    trusted_path(path, directory=True)


def atomic_write(path, content, mode=0o600, uid=0, gid=0):
    path = Path(path)
    trusted_path(path, required=False)
    ensure_dir(path.parent)
    descriptor, name = tempfile.mkstemp(prefix=".xeas-", dir=str(path.parent))
    try:
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.lexists(name):
            os.unlink(name)


@contextmanager
def install_lock(paths):
    ensure_dir(paths.lock.parent, 0o750)
    trusted_path(paths.lock, required=False)
    descriptor = os.open(str(paths.lock), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise SetupError("Tetragon 설치 잠금 파일의 root 0600 소유권을 확인하십시오.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError("다른 Tetragon 설치가 실행 중입니다. 완료 후 다시 실행하십시오.") from None
        yield
    finally:
        os.close(descriptor)
