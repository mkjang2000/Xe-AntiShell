"""Explicit owned-policy installation with API/file/config rollback."""

import datetime
import json
import os
from pathlib import Path
import stat
import tempfile

import yaml

from observation_agent import receipt_checkpoint, verify_agent_receipt
from observation_policies import DEFAULT_FILE_PREFIXES, INLINE, NETWORK_POLICY, discover_runtime_names, encoded_policies, policy_hashes
from observation_probes import verify_observations
from observation_state import manifest_path, owned_policy_state
from setup_common import Paths, SetupError, atomic_write, ensure_dir, install_lock, rollback_guard, trusted_path
from setup_config import OBSERVATION_ARGS, TETRA, TETRA_ARGS, UniqueLoader, prepare_config
from setup_runtime import Runner, verify_agent, wait_health
from setup_services import Services, check_conflicts
from setup_state import installed_release
from setup_workflow import check_host


class PolicyAPI:
    def __init__(self, runner):
        self.runner = runner

    def call(self, *args):
        return self.runner.command([TETRA, "--server-address", "unix:///run/tetragon/tetragon.sock",
                                    "--timeout", "5s", "--retries", "0", "tracingpolicy"] + list(args), timeout=12)

    def listing(self):
        _, output = self.call("list", "-o", "json")
        try:
            value = json.loads(output)
            policies = value.get("policies", [])
            if not isinstance(policies, list) or any(not isinstance(item, dict) for item in policies):
                raise ValueError
            return policies
        except (ValueError, AttributeError, TypeError, RecursionError):
            raise SetupError("Tetragon 정책 상태 응답을 안전하게 확인할 수 없습니다.") from None

    def add(self, path):
        self.call("add", str(path), "--domain", "static")

    def delete(self, name):
        self.call("delete", name, "--domain", "static")


def enabled_monitor(policy):
    hooks = policy.get("hook_statuses", policy.get("hookStatuses", []))
    # v1.8.0 generic tracepoints never populate Sensor.Statuses. Only our
    # fixed inline policies may omit per-hook status; actual exec-ID probes
    # remain mandatory before success. Kprobes must report every loaded hook.
    inline = isinstance(policy.get("name"), str) and policy["name"] in INLINE
    return (policy.get("state") == "TP_STATE_ENABLED" and policy.get("mode") == "TP_MODE_MONITOR_ONLY"
            and not policy.get("error") and isinstance(hooks, list) and (bool(hooks) or inline)
            and all(isinstance(hook, dict) and hook.get("state") == "STATUS_LOADED" for hook in hooks))


def policy_snapshot(api, names, owned):
    found = {}
    for item in api.listing():
        name = item.get("name")
        if name not in names:
            continue
        if name in found or not owned or item.get("domain") != "static" or item.get("namespace"):
            raise SetupError("동일 이름의 비소유 Tetragon 정책은 수동 통합이 필요합니다.")
        if not enabled_monitor(item):
            raise SetupError("기존 소유 정책이 완전한 monitor-only 상태가 아닙니다. 수동 확인하십시오.")
        found[name] = item
    return found


def preflight(paths, services, api, prefixes):
    check_host(paths)
    for path in (paths.config, paths.unit, paths.version / "tetra"):
        trusted_path(path)
    check_conflicts(paths, services)
    if not paths.unit.exists() or not installed_release(paths.version):
        raise SetupError("먼저 선택적 Tetragon 기본 설치를 완료하십시오.")
    if not services.snapshot("tetragon.service").active or not services.snapshot("sentineld.service").active:
        raise SetupError("기존 Tetragon과 sentineld가 실행 중이어야 합니다.")
    original, target, socket = prepare_config(paths.config, observations=True)
    current = yaml.load(original, Loader=UniqueLoader)
    collector = current.get("collector", {})
    tetra = collector.get("tetragon", {}) if isinstance(collector, dict) else {}
    if (collector.get("mode") != "tetragon" or tetra.get("command") != TETRA
            or tetra.get("args") not in (TETRA_ARGS, OBSERVATION_ARGS)):
        raise SetupError("설치기 소유 Tetragon 수집 설정에만 관측 정책을 추가할 수 있습니다.")
    old = owned_policy_state(paths)
    chosen = tuple(prefixes or (old.get("file_prefixes") if old else DEFAULT_FILE_PREFIXES))
    families = tuple(old.get("network_families", []) if old else ("ipv4", "ipv6"))
    runtime_suffixes = old.get("runtime_suffixes", {}) if old else discover_runtime_names(paths.root)
    files = encoded_policies(chosen, families, runtime_suffixes)
    if old and old["policies"] != policy_hashes(files):
        raise SetupError("기존 소유 정책의 범위 변경은 수동 검토가 필요합니다.")
    # The bounded write probe is intentionally confined to private /tmp files.
    if not any("/tmp/".startswith(prefix) for prefix in chosen):
        raise SetupError("실제 파일 쓰기 검증을 위해 /tmp/ 접두사를 포함하십시오.")
    names = {name[:-5] for name in files}
    present = policy_snapshot(api, names, old is not None)
    return original, target, socket, old, chosen, families, runtime_suffixes, files, present


def _backup(paths, original, old_files, old_manifest):
    ensure_dir(paths.backups, 0o700)
    directory = Path(tempfile.mkdtemp(prefix="observations-", dir=str(paths.backups)))
    atomic_write(directory / "agent.yaml", original)
    if old_manifest is not None:
        atomic_write(directory / "observations.json", old_manifest)
    for name, content in old_files.items():
        atomic_write(directory / name, content)
    return directory


def _run_locked(paths, runner, prefixes, verifier, announce):
    services, api = Services(runner), PolicyAPI(runner)
    original, target, socket, old, chosen, families, runtime_suffixes, files, present = preflight(paths, services, api, prefixes)
    if announce:
        print("적용 계획: Python/Node/PHP/Perl/Ruby의 고정 인라인 옵션과 허용 실행파일의 파일 쓰기·TCP 시작 메타데이터를 관측합니다.")
        print("인라인 옵션은 첫 인자부터 세 번째 인자까지 확인하며, 앞선 승인 단순 옵션은 최대 2개입니다. 그 이후 위치는 정책 관측 범위 밖입니다.")
        print("파일 접두사: " + ", ".join(chosen))
        print("요청 주소 계열: " + ", ".join(families) + "; 설치된 런타임과 커널 훅은 실제 이벤트로 검증합니다.")
    wait_health(runner)
    config_info = paths.config.stat()
    old_files = {path.name: path.read_bytes() for path in paths.policies.iterdir()} if old else {}
    old_manifest = manifest_path(paths).read_bytes() if old else None
    attempted, config_changed, disk_changed = [], False, False
    try:
        _backup(paths, original, old_files, old_manifest)
        if paths.config.read_bytes() != original:
            raise SetupError("검증 중 에이전트 설정이 변경되어 적용 전에 중단했습니다.")
        for name, content in files.items():
            if name[:-5] in present:
                continue
            disk_changed = True
            atomic_write(paths.policies / name, content)
            attempted.append(name[:-5])
            try:
                api.add(paths.policies / name)
            except SetupError:
                if name[:-5] != NETWORK_POLICY or old or families != ("ipv4", "ipv6"):
                    raise
        listing = {item.get("name"): item for item in api.listing() if item.get("domain") == "static"}
        network = listing.get(NETWORK_POLICY, {})
        if not enabled_monitor(network) and not old and families == ("ipv4", "ipv6"):
            # A missing IPv6 kernel hook must not disable working IPv4 coverage.
            if network:
                api.delete(NETWORK_POLICY)
            families = ("ipv4",)
            files = encoded_policies(chosen, families, runtime_suffixes)
            atomic_write(paths.policies / (NETWORK_POLICY + ".yaml"), files[NETWORK_POLICY + ".yaml"])
            api.add(paths.policies / (NETWORK_POLICY + ".yaml"))
        names = {name[:-5] for name in files}
        if set(policy_snapshot(api, names, True)) != names:
            raise SetupError("모든 소유 관측 정책의 완전한 로드를 확인하지 못했습니다.")
        if original != target:
            if paths.config.read_bytes() != original:
                raise SetupError("검증 중 에이전트 설정이 변경되어 적용 전에 중단했습니다.")
            config_changed = True
            atomic_write(paths.config, target, stat.S_IMODE(config_info.st_mode), config_info.st_uid, config_info.st_gid)
            services.call("restart", "sentineld.service")
        verify_agent(runner, socket)
        checkpoint = receipt_checkpoint(runner, socket)
        proof = verifier(chosen, families)
        receipt = verify_agent_receipt(runner, socket, checkpoint,
                                       interpreter=bool(proof.get("verified_runtime_policies")))
        document = {"schema_version": 1, "tetragon_version": "v1.8.0", "state": "verified",
                    "exec_raw_tracepoint": True, "argv_excluded": True, "file_prefixes": list(chosen),
                    "network_families": list(families), "policies": policy_hashes(files),
                    "runtime_suffixes": runtime_suffixes,
                    "verified_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), **proof,
                    "agent_receipt": receipt}
        disk_changed = True
        atomic_write(manifest_path(paths), (json.dumps(document, sort_keys=True) + "\n").encode())
        return document
    except BaseException:
        failed = False
        with rollback_guard():
            for name in reversed(attempted):
                try:
                    if any(item.get("name") == name and item.get("domain") == "static" for item in api.listing()):
                        api.delete(name)
                except Exception:
                    failed = True
            if disk_changed:
                try:
                    for name in files:
                        path = paths.policies / name
                        if name in old_files:
                            atomic_write(path, old_files[name])
                        elif path.exists():
                            path.unlink()
                    if old_manifest is None:
                        manifest_path(paths).unlink(missing_ok=True)
                    else:
                        atomic_write(manifest_path(paths), old_manifest)
                except Exception:
                    failed = True
            if config_changed:
                try:
                    atomic_write(paths.config, original, stat.S_IMODE(config_info.st_mode), config_info.st_uid, config_info.st_gid)
                    services.call("restart", "sentineld.service")
                except Exception:
                    failed = True
        if failed:
            raise SetupError("관측 정책 복구 일부가 실패했습니다. root 전용 진단 백업과 서비스 상태를 확인하십시오.") from None
        raise


def run_observations(prefixes=None, *, paths=None, runner=None, verifier=verify_observations, announce=False):
    paths, runner = paths or Paths(), runner or Runner()
    check_host(paths)
    with install_lock(paths):
        return _run_locked(paths, runner, prefixes, verifier, announce)
