"""Preflight, stage, switch, verify, or restore the previous collector."""

import os
import platform
from pathlib import Path
import tempfile

from artifacts import acquire_archive, extract_release
from setup_common import Paths, SetupError, install_lock, rollback_guard, trusted_path
from setup_config import prepare_config
from setup_runtime import Runner, verify_agent, verify_exec, wait_health
from setup_services import AGENT_DROPIN, Services, UNIT, check_conflicts
from setup_state import Transaction, installed_release


def check_host(paths):
    if os.geteuid() != 0:
        raise SetupError("Tetragon 설치는 root 권한으로 실행하십시오.")
    if platform.machine() != "x86_64":
        raise SetupError("자동 Tetragon 설치는 현재 x86_64만 지원합니다.")
    if not paths.btf.is_file() or not os.access(paths.btf, os.R_OK):
        raise SetupError("커널 BTF(/sys/kernel/btf/vmlinux)가 없어 변경 전에 중단했습니다.")


def preflight(paths, services):
    check_host(paths)
    for absolute in ("/usr/bin/systemctl", "/usr/bin/sentinel", "/usr/sbin/sentineld", "/usr/bin/true"):
        trusted_path(paths.at(absolute))
    original, target, socket = prepare_config(paths.config)
    check_conflicts(paths, services)
    installed = installed_release(paths.version)
    if paths.unit.exists() and not installed:
        raise SetupError("기존 설치기 unit의 검증된 Tetragon 파일이 없어 수동 확인이 필요합니다.")
    return original, target, socket, installed


def run_setup(archive=None, *, paths=None, runner=None):
    paths = paths or Paths()
    runner = runner or Runner()
    # Hardware rejection precedes even creation of the coordination lock.
    check_host(paths)
    with install_lock(paths):
        _run_locked(archive, paths, runner)


def _run_locked(archive, paths, runner):
    services = Services(runner)
    original, target, socket, installed = preflight(paths, services)
    transaction = Transaction(paths, services, original)
    with tempfile.TemporaryDirectory(prefix="xeas-tetragon-setup-") as work:
        work = Path(work)
        stage = None
        if not installed or archive is not None:
            verified = acquire_archive(Path(archive) if archive is not None else None, work)
            if not installed:
                stage = work / "release"
                stage.mkdir(mode=0o700)
                extract_release(verified, stage)
        # An already verified installation needs no writes or restarts.
        unchanged = (installed and paths.unit.exists() and paths.agent_dropin.exists()
                     and paths.policies.is_dir() and original == target
                     and transaction.tetragon.active and transaction.agent.active
                     and transaction.tetragon.enabled in ("enabled", "enabled-runtime"))
        if unchanged:
            wait_health(runner)
            verify_exec(runner)
            verify_agent(runner, socket)
            return
        try:
            # The diagnostic backup is part of the rollback scope, before a switch.
            if paths.config.read_bytes() != original:
                raise SetupError("설치 중 에이전트 설정이 변경되어 전환 전에 중단했습니다.")
            transaction.backup_originals()
            if stage is not None:
                transaction.install_release(stage)
            transaction.create_dir(paths.policies)
            if not paths.unit.exists():
                transaction.write_unit(UNIT)
            if not paths.agent_dropin.exists():
                transaction.write_dropin(AGENT_DROPIN)
            if transaction.unit_changed or transaction.dropin_changed:
                services.call("daemon-reload")
            transaction.tetragon_changed = True
            if transaction.tetragon.enabled not in ("enabled", "enabled-runtime"):
                services.call("enable", "tetragon.service")
            if not transaction.tetragon.active:
                services.call("start", "tetragon.service")
            wait_health(runner)
            verify_exec(runner)
            if original != target:
                if paths.config.read_bytes() != original:
                    raise SetupError("설치 중 에이전트 설정이 변경되어 전환 전에 중단했습니다.")
                transaction.write_config(target)
            transaction.agent_changed = True
            services.call("restart" if transaction.agent.active else "start", "sentineld.service")
            verify_agent(runner, socket)
        except BaseException:
            with rollback_guard():
                transaction.restore()
            raise
