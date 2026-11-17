"""Bounded readiness probes; process-event payloads never reach terminal output."""

import datetime
import json
import os
import selectors
import subprocess
import time

from setup_common import SetupError
from setup_config import TETRA, TETRA_ARGS


def quiet_env():
    # Upstream automatically consumes TETRAGON_* environment variables.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
    if child.stdout:
        child.stdout.close()


class Runner:
    def command(self, args, *, timeout=15, limit=1024 * 1024, check=True):
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=quiet_env())
        output = bytearray()
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SetupError("명령 실행 제한 시간을 초과했습니다.")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > limit:
                                raise SetupError("명령 출력의 안전한 크기 제한을 초과했습니다.")
            code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            raise SetupError("필수 명령을 완료할 수 없습니다.") from None
        finally:
            stop_child(child)
        if check and code:
            raise SetupError("필수 명령이 실패했습니다. 호스트 서비스 상태를 확인하십시오.")
        return code, bytes(output)

    def true(self):
        child = subprocess.Popen(["/usr/bin/true"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=quiet_env())
        pid = child.pid
        child.wait(timeout=2)
        return pid

    def stream(self):
        return subprocess.Popen([TETRA] + TETRA_ARGS, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=quiet_env())


def health_running(output):
    return b"Health Status: running" in output.splitlines()


def wait_health(runner, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, output = runner.command([TETRA, "--server-address", "unix:///run/tetragon/tetragon.sock",
                                       "--timeout", "5s", "--retries", "0", "status"],
                                      timeout=7, check=False)
        if code == 0 and health_running(output):
            return
        time.sleep(0.5)
    raise SetupError("Tetragon이 running 상태가 되지 않았습니다. 커널/BPF 연결을 확인하십시오.")


def matches_true(line, pids):
    try:
        value = json.loads(line)
        process = value["process_exec"]["process"]
        pid = process["pid"]
        return type(pid) is int and pid in pids and process.get("binary") == "/usr/bin/true"
    except (ValueError, KeyError, TypeError, RecursionError):
        return False


def verify_exec(runner, timeout=15):
    child = runner.stream()
    pids, buffer, received = set(), bytearray(), 0
    deadline = time.monotonic() + timeout
    next_probe = time.monotonic() + 0.5
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while time.monotonic() < deadline:
                now = time.monotonic()
                if now >= next_probe:
                    pids.add(runner.true())
                    next_probe = now + 0.5
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        raise SetupError("Tetragon 검증 스트림이 이벤트 확인 전에 종료되었습니다.")
                    received += len(chunk)
                    buffer.extend(chunk)
                    if received > 16 * 1024 * 1024:
                        raise SetupError("Tetragon 검증 스트림의 크기 제한을 초과했습니다.")
                    while b"\n" in buffer:
                        line, _, tail = buffer.partition(b"\n")
                        buffer = bytearray(tail)
                        if len(line) > 262144:
                            raise SetupError("Tetragon 이벤트의 크기 제한을 초과했습니다.")
                        if matches_true(line, pids):
                            return
                    if len(buffer) > 262144:
                        raise SetupError("Tetragon 이벤트의 크기 제한을 초과했습니다.")
        raise SetupError("실제 프로세스 실행 이벤트가 없어 Tetragon 전환을 중단했습니다.")
    finally:
        stop_child(child)


def timestamp(value):
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, AttributeError):
        return 0


def agent_ready(status, since, baseline=0):
    if not isinstance(status, dict):
        return False
    stream = status.get("collector_health", {})
    if (status.get("collector") != "tetragon-json" or status.get("mode") != "active"
            or status.get("health") != "healthy" or not isinstance(stream, dict)
            or stream.get("running") is not True or stream.get("last_error") or status.get("last_error")):
        return False
    count = stream.get("events_received", 0)
    if type(count) is not int or count <= baseline:
        return False
    report = status.get("capability_report", {})
    capabilities = report.get("capabilities", {}) if isinstance(report, dict) else {}
    if not isinstance(capabilities, dict):
        return False
    for name in ("collector.tetragon", "observation.process_exec"):
        evidence = capabilities.get(name, {})
        if (not isinstance(evidence, dict) or evidence.get("runtime_state") != "active"
                or timestamp(evidence.get("verified_at")) < since):
            return False
    return True


def read_agent(runner, socket):
    code, output = runner.command(["/usr/bin/sentinel", "--socket", socket, "--json", "status"],
                                  timeout=5, check=False)
    if code:
        return {}
    try:
        value = json.loads(output)
        return value if isinstance(value, dict) else {}
    except (ValueError, RecursionError):
        return {}


def verify_agent(runner, socket, timeout=20):
    initial = read_agent(runner, socket)
    stream = initial.get("collector_health", {})
    baseline = stream.get("events_received", 0) if isinstance(stream, dict) else 0
    if type(baseline) is not int:
        baseline = 0
    since = time.time()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        runner.true()
        time.sleep(0.5)
        if agent_ready(read_agent(runner, socket), since, baseline):
            return
    raise SetupError("에이전트의 실제 Tetragon 수집 상태를 확인하지 못해 이전 설정으로 복구합니다.")
