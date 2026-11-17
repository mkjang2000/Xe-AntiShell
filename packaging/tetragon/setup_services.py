"""Own one explicit unit and reject ambiguous existing service/configuration state."""

from dataclasses import dataclass
import re
import shlex

from setup_common import SetupError, trusted_path


MARKER = "# Managed by Xe-AntiShell opt-in Tetragon installer v1\n"
AGENT_DROPIN = (MARKER + "[Unit]\nWants=tetragon.service\nAfter=tetragon.service\n").encode("utf-8")
UNIT = (MARKER + """[Unit]
Description=Xe-AntiShell opt-in Tetragon process observer
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/
RuntimeDirectory=tetragon
RuntimeDirectoryMode=0700
UMask=0077
LimitMEMLOCK=infinity
ExecStart=/opt/xe-antishell/tetragon/v1.8.0/tetragon --bpf-lib=/opt/xe-antishell/tetragon/v1.8.0/bpf --server-address=unix:///run/tetragon/tetragon.sock --export-filename= --health-server-address=127.0.0.1:6789 --metrics-server=127.0.0.1:2112 --enable-k8s-api=false --k8s-kubeconfig-path= --enable-process-cred=true --enable-process-environment-variables=false --enable-ancestors=base --process-cache-size=32768 --tracing-policy-dir=/opt/xe-antishell/tetragon/policies --tracing-policy= --persist-grpc-policies=false
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
""").encode("utf-8")


@dataclass
class ServiceState:
    enabled: str
    active: bool


class Services:
    def __init__(self, runner):
        self.runner = runner

    def call(self, *args, check=True):
        return self.runner.command(["/usr/bin/systemctl"] + list(args), timeout=45, check=check)

    def show(self, service, property_name):
        code, value = self.call("show", "--property=" + property_name, "--value", service, check=False)
        if code:
            return ""
        return value.decode("utf-8", errors="replace").strip()

    def snapshot(self, service):
        _, enabled = self.call("is-enabled", service, check=False)
        enabled = enabled.decode("ascii", errors="replace").strip() or "not-found"
        if enabled not in ("enabled", "enabled-runtime", "disabled", "static", "indirect", "not-found"):
            raise SetupError("서비스의 enable/mask 상태가 자동 설치와 호환되지 않습니다.")
        _, active = self.call("is-active", service, check=False)
        active = active.decode("ascii", errors="replace").strip()
        if active not in ("active", "inactive", "failed", "unknown", ""):
            raise SetupError("서비스가 전환 중입니다. 안정된 상태에서 다시 실행하십시오.")
        return ServiceState(enabled, active == "active")

    def restore_enabled(self, service, state):
        if state.enabled == "enabled-runtime":
            self.call("enable", "--runtime", service)
        elif state.enabled == "enabled":
            self.call("enable", service)
        else:
            self.call("disable", service)


def exec_arguments(value):
    matches = re.findall(r"argv\[\]=(.*?)\s+;", value)
    try:
        return shlex.split(matches[0]) if len(matches) == 1 else []
    except ValueError:
        return []


def check_agent_exec(services):
    args = exec_arguments(services.show("sentineld.service", "ExecStart"))
    if not args or args[0] != "/usr/sbin/sentineld":
        raise SetupError("기존 sentineld ExecStart를 확인할 수 없어 수동 통합이 필요합니다.")
    args = args[1:]
    if args not in ([], ["--config", "/etc/xe-antishell/sentineld.yaml"],
                    ["--config=/etc/xe-antishell/sentineld.yaml"]):
        raise SetupError("sentineld의 사용자 지정 --collector/--config 실행 설정은 수동 통합이 필요합니다.")


def check_conflicts(paths, services):
    check_agent_exec(services)
    if paths.agent_dropin.exists() or paths.agent_dropin.is_symlink():
        trusted_path(paths.agent_dropin)
        if paths.agent_dropin.read_bytes() != AGENT_DROPIN:
            raise SetupError("기존 sentineld Tetragon drop-in은 수동 통합이 필요합니다.")
    code, environment = services.call("show-environment", check=False)
    if code or any(line.startswith(b"TETRAGON_") for line in environment.splitlines()):
        raise SetupError("systemd의 TETRAGON 환경 설정을 제거하거나 수동 통합하십시오.")
    if paths.unit.exists() or paths.unit.is_symlink():
        trusted_path(paths.unit)
        if paths.unit.read_bytes() != UNIT:
            raise SetupError("기존 Tetragon unit은 이 설치기의 소유가 아니므로 수동 통합이 필요합니다.")
    for absolute in ("/usr/lib/systemd/system/tetragon.service", "/lib/systemd/system/tetragon.service"):
        candidate = paths.at(absolute)
        if candidate.exists() or candidate.is_symlink():
            raise SetupError("기존 Tetragon vendor unit이 있어 수동 통합이 필요합니다.")
    for absolute in ("/etc/systemd/system/tetragon.service.d", "/run/systemd/system/tetragon.service.d",
                     "/usr/lib/systemd/system/tetragon.service.d", "/lib/systemd/system/tetragon.service.d"):
        candidate = paths.at(absolute)
        if candidate.exists() or candidate.is_symlink():
            trusted_path(candidate, directory=True)
            if any(candidate.iterdir()):
                raise SetupError("기존 Tetragon drop-in이 있어 수동 통합이 필요합니다.")
    for absolute in ("/etc/tetragon", "/usr/lib/tetragon/tetragon.conf.d",
                     "/usr/local/lib/tetragon/tetragon.conf.d"):
        candidate = paths.at(absolute)
        if candidate.exists() or candidate.is_symlink():
            trusted_path(candidate, directory=True)
            if any(candidate.iterdir()):
                raise SetupError("기존 Tetragon 설정이 있어 수동 통합이 필요합니다.")
    if paths.at("/tetragon.yaml").exists() or paths.at("/tetragon.yaml").is_symlink():
        raise SetupError("Tetragon 작업 디렉터리의 기존 설정은 수동 통합이 필요합니다.")
    dropins = services.show("tetragon.service", "DropInPaths")
    fragment = services.show("tetragon.service", "FragmentPath")
    if dropins or fragment not in ("", "/etc/systemd/system/tetragon.service"):
        raise SetupError("로드된 기존 Tetragon 서비스는 수동 통합이 필요합니다.")
    if fragment and not paths.unit.exists():
        raise SetupError("로드된 Tetragon unit과 파일이 달라 수동 통합이 필요합니다.")
    if fragment:
        expected = next(line[len("ExecStart="):] for line in UNIT.decode().splitlines() if line.startswith("ExecStart="))
        if (services.show("tetragon.service", "NeedDaemonReload") == "yes"
                or exec_arguments(services.show("tetragon.service", "ExecStart")) != shlex.split(expected)):
            raise SetupError("로드된 Tetragon 실행 설정이 설치기 unit과 달라 수동 통합이 필요합니다.")
    if paths.policies.exists() or paths.policies.is_symlink():
        trusted_path(paths.policies, directory=True)
        if any(paths.policies.iterdir()):
            raise SetupError("설치기 전용 정책 디렉터리가 비어 있지 않습니다.")
