"""Bounded in-memory probes; no process arguments or event payloads are printed."""

import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import tempfile
import time

from observation_policies import (FILE_POLICY, INLINE, INLINE_OPTION_POSITIONS, NETWORK_POLICY,
                                  PRIOR_SWITCHES, RUNTIME_PATTERN, runtime_names)
from setup_common import SetupError, trusted_path
from setup_config import OBSERVATION_ARGS, TETRA
from setup_runtime import quiet_env, stop_child, timestamp


class EventProof:
    def __init__(self):
        self.executions = {}
        self.facts = []

    def accept(self, line):
        try:
            envelope = json.loads(line)
            if not isinstance(envelope, dict) or not timestamp(envelope.get("time")):
                return
            key = next((name for name in ("process_exec", "process_tracepoint", "process_kprobe") if name in envelope), None)
            value = envelope.get(key)
            if not isinstance(value, dict):
                return
            process = value.get("process", {})
            if not isinstance(process, dict):
                return
            contexts = [process, value.get("parent", {})] + (value.get("ancestors") or [])
            if any(isinstance(item, dict) and (item.get("arguments") or item.get("environment_variables")) for item in contexts):
                raise SetupError("gRPC 원문 argv/환경변수 제외를 확인하지 못했습니다.")
            pid, identity = process.get("pid"), process.get("exec_id")
            binary = process.get("binary")
            if (type(pid) is not int or pid < 1 or not isinstance(identity, str) or not identity or len(identity) > 1024
                    or not timestamp(process.get("start_time")) or not isinstance(binary, str)
                    or len(binary) > 4096 or not binary.startswith("/")):
                return
            if key == "process_exec":
                if len(self.executions) >= 8192:
                    raise SetupError("관측 검증 이벤트 수 제한을 초과했습니다.")
                self.executions[pid] = identity
                return
            policy = value.get("policy_name")
            if policy not in INLINE and policy not in (FILE_POLICY, NETWORK_POLICY):
                return
            if (value.get("action") != "KPROBE_ACTION_POST" or value.get("data")
                    or value.get("return_action", "KPROBE_ACTION_POST") != "KPROBE_ACTION_POST"):
                return
            fact = {"pid": pid, "exec_id": identity, "policy": policy}
            if key == "process_tracepoint":
                if (policy not in INLINE or value.get("subsys") != "sched" or value.get("event") != "sched_process_exec"
                        or value.get("args") or value.get("return")):
                    return
            else:
                args = value.get("args", [])
                if not isinstance(args, list) or len(args) != 1 or not isinstance(args[0], dict):
                    return
                fact["function"] = value.get("function_name")
                if policy == FILE_POLICY:
                    file = args[0].get("file_arg", {})
                    if not isinstance(file, dict) or file.get("flags"):
                        return
                    fact["path"] = file.get("path")
                else:
                    address = args[0].get("sockaddr_arg", {})
                    if not isinstance(address, dict):
                        return
                    fact.update({key: address.get(key) for key in ("family", "addr", "port")})
                result = value.get("return", {})
                if not isinstance(result, dict):
                    return
                result = result.get("long_arg" if policy == FILE_POLICY else "int_arg")
                if isinstance(result, bool) or not isinstance(result, (int, str)):
                    return
                fact["result"] = int(result)
            if len(self.facts) >= 4096 or len(self.executions) >= 8192:
                raise SetupError("관측 검증 이벤트 수 제한을 초과했습니다.")
            self.facts.append(fact)
        except (ValueError, TypeError, KeyError, RecursionError):
            return

    def matching(self, pid, policy, **values):
        identity = self.executions.get(pid)
        return [fact for fact in self.facts if identity and fact["pid"] == pid and fact["exec_id"] == identity
                and fact["policy"] == policy and all(fact.get(key) == value for key, value in values.items())]


class ProbeStream:
    def __init__(self):
        self.child = None
        self.proof = EventProof()
        self.buffer = bytearray()
        self.received = 0

    def __enter__(self):
        self.child = subprocess.Popen([TETRA] + OBSERVATION_ARGS, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, env=quiet_env())
        self.selector = selectors.DefaultSelector()
        try:
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
            self.drain(0.5)
        except BaseException:
            self.selector.close()
            stop_child(self.child)
            raise
        return self

    def __exit__(self, *args):
        self.selector.close()
        stop_child(self.child)

    def drain(self, duration):
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            for key, _ in self.selector.select(min(0.1, deadline - time.monotonic())):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    raise SetupError("관측 검증 스트림이 조기에 종료되었습니다.")
                self.received += len(chunk)
                self.buffer.extend(chunk)
                if self.received > 32 * 1024 * 1024:
                    raise SetupError("관측 검증 스트림의 크기 제한을 초과했습니다.")
                while b"\n" in self.buffer:
                    line, _, tail = self.buffer.partition(b"\n")
                    self.buffer = bytearray(tail)
                    if len(line) > 262144:
                        raise SetupError("관측 검증 이벤트의 크기 제한을 초과했습니다.")
                    self.proof.accept(line)
                if len(self.buffer) > 262144:
                    raise SetupError("관측 검증 이벤트의 크기 제한을 초과했습니다.")

    def run(self, args):
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=quiet_env())
        try:
            if child.wait(timeout=5) != 0:
                raise SetupError("무해한 관측 확인 프로세스가 실패했습니다.")
            return child.pid
        except subprocess.TimeoutExpired:
            raise SetupError("무해한 관측 확인 프로세스의 제한 시간을 초과했습니다.") from None
        finally:
            stop_child(child)


def runtime_binary(runtime):
    for name in runtime_names()[runtime]:
        for directory in ("/usr/bin", "/usr/local/bin", "/bin"):
            candidate = Path(directory) / name
            if not candidate.exists():
                continue
            # OS language packages commonly use alternatives symlinks. Validate
            # their fully resolved target, and execute that absolute target.
            resolved = candidate.resolve(strict=True)
            trusted_path(resolved)
            if re.fullmatch(RUNTIME_PATTERN[runtime], resolved.name) and os.access(resolved, os.X_OK):
                return str(resolved)
    return None


def verify_observations(files_prefixes, network_families, *, stream_factory=ProbeStream):
    with tempfile.TemporaryDirectory(prefix="xeas-observation-probe-", dir="/tmp") as directory, stream_factory() as stream:
        directory = Path(directory)
        verified = verify_inline(stream, directory)
        # A private /tmp path must be inside the explicitly selected coverage.
        path = directory / "write-proof"
        if not any(str(path).startswith(prefix) for prefix in files_prefixes):
            raise SetupError("파일 관측 검증을 위해 /tmp/ 접두사를 포함하십시오.")
        trusted_path(Path(sys.executable).resolve(strict=True))
        pid = stream.run([sys.executable, "-c", "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(f,b'x'); os.close(f)", str(path)])
        stream.drain(1.0)
        if not stream.proof.matching(pid, FILE_POLICY, function="vfs_write", path=str(path), result=1):
            raise SetupError("실제 1바이트 파일 쓰기 반환 이벤트를 확인하지 못했습니다.")
        families = verify_network(stream, network_families)
        return {"verified_runtime_policies": verified, "verified_network_families": families}


def verify_inline(stream, directory):
    verified = []
    samples = {"python": ("pass", "pass\n"), "node": ("", ""), "php": ("", "<?php\n"),
               "perl": ("", ""), "ruby": ("", "")}
    for name, (runtime, option) in INLINE.items():
        binary = runtime_binary(runtime)
        if not binary:
            continue
        code, script = samples[runtime]
        path = directory / (runtime + ".script")
        path.write_text(script)
        switch = PRIOR_SWITCHES[runtime][0]
        positives = [stream.run([binary] + [switch] * count + [option, code])
                     for count in range(INLINE_OPTION_POSITIONS)]
        # A real inline invocation beyond our documented index bound remains
        # outside this policy's coverage. It must not produce a policy claim.
        negatives = [stream.run([binary, str(path), option, code]),
                     stream.run([binary] + [switch] * INLINE_OPTION_POSITIONS + [option, code])]
        stream.drain(1.0)
        if (any(not stream.proof.matching(pid, name) for pid in positives)
                or any(pid not in stream.proof.executions or stream.proof.matching(pid, name) for pid in negatives)):
            raise SetupError("인라인 옵션 정책의 양성/음성 동일 실행 ID 검증에 실패했습니다.")
        verified.append(name)
    return verified


def verify_network(stream, network_families):
    families = []
    for family in network_families:
        af, address, function = ((socket.AF_INET, "127.0.0.1", "tcp_v4_connect") if family == "ipv4"
                                 else (socket.AF_INET6, "::1", "tcp_v6_connect"))
        try:
            listener = socket.socket(af, socket.SOCK_STREAM)
            listener.bind((address, 0))
            listener.listen(1)
        except OSError:
            if "listener" in locals():
                listener.close()
            if family == "ipv6":
                continue
            raise SetupError("loopback TCP 관측 검증을 준비하지 못했습니다.") from None
        try:
            port = listener.getsockname()[1]
            code = "import socket,sys; s=socket.socket(int(sys.argv[1]),socket.SOCK_STREAM); s.settimeout(2); s.connect((sys.argv[2],int(sys.argv[3]))); s.close()"
            pid = stream.run([sys.executable, "-c", code, str(int(af)), address, str(port)])
            stream.drain(1.0)
            if not stream.proof.matching(pid, NETWORK_POLICY, function=function,
                                         family="AF_INET" if family == "ipv4" else "AF_INET6", addr=address, port=port, result=0):
                if family == "ipv6":
                    continue
                raise SetupError("실제 loopback TCP 연결 시작 반환 이벤트를 확인하지 못했습니다.")
            families.append(family)
        finally:
            listener.close()
    return families
