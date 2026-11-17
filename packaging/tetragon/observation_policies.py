"""Generate fixed, monitor-only v1.8.0 policies without code or packet capture."""

import hashlib
from pathlib import Path
from pathlib import PurePosixPath
import re

import yaml

from setup_common import SetupError, trusted_path


FILE_POLICY = "xeas-file-write-v1"
NETWORK_POLICY = "xeas-network-connect-v1"
# v1.8.0 string_maps_N is an ARRAY_OF_MAPS with only eight slots. Every
# Equal matchCmdArgs filter consumes a slot for its string-length bucket.
# Positions 0..2 need 1+2+3=6 slots; positions 0..4 need 15 and fail to load.
INLINE_OPTION_POSITIONS = 3
INLINE = {
    "xeas-exec-python-c-v1": ("python", "-c"),
    "xeas-exec-node-e-v1": ("node", "-e"),
    "xeas-exec-node-eval-v1": ("node", "--eval"),
    "xeas-exec-node-p-v1": ("node", "-p"),
    "xeas-exec-node-print-v1": ("node", "--print"),
    "xeas-exec-php-r-v1": ("php", "-r"),
    "xeas-exec-perl-e-v1": ("perl", "-e"),
    "xeas-exec-perl-capital-e-v1": ("perl", "-E"),
    "xeas-exec-ruby-e-v1": ("ruby", "-e"),
}
# Only complete switches that do not consume a following value are accepted.
# Script names, --, value options, and earlier inline options cannot pass.
PRIOR_SWITCHES = {
    "python": ["-B", "-E", "-I", "-O", "-OO", "-q", "-s", "-S", "-u", "-v", "-vv", "-b", "-bb", "-d", "-i", "-x", "-P"],
    "node": ["--no-warnings", "--trace-warnings", "--use-strict", "--no-deprecation", "--trace-deprecation"],
    "php": ["-n", "-q"],
    "perl": ["-w", "-W", "-X", "-n", "-p", "-a", "-l", "-T", "-t"],
    "ruby": ["-w", "-W0", "-W1", "-W2", "--verbose", "--disable-gems", "--disable-did_you_mean", "-n", "-p", "-a", "-l"],
}
DEFAULT_FILE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/var/www/", "/srv/")
RUNTIME_PATTERN = {
    "python": r"python(?:[23](?:\.[0-9]{1,2})?)?", "node": r"node(?:js)?",
    "php": r"php(?:[578](?:\.[0-9]{1,2})?)?", "perl": r"perl(?:5(?:\.[0-9]{1,2}){1,2})?",
    "ruby": r"ruby(?:[23](?:\.[0-9]{1,2})?)?", "php_fpm": r"php-fpm(?:[578](?:\.[0-9]{1,2})?)?",
}


def runtime_names(extra=None):
    result = {
        "python": ["python", "python2", "python3"] + ["python3." + str(n) for n in range(6, 16)],
        "node": ["node", "nodejs"],
        "php": ["php", "php7", "php8"] + ["php8." + str(n) for n in range(0, 6)],
        "perl": ["perl"],
        "ruby": ["ruby", "ruby2", "ruby3"] + ["ruby3." + str(n) for n in range(0, 6)],
    }
    if extra is not None:
        if not isinstance(extra, dict) or set(extra) - set(RUNTIME_PATTERN):
            raise SetupError("런타임 실행파일 이름 목록이 올바르지 않습니다.")
        for runtime, names in extra.items():
            if (not isinstance(names, list) or len(names) > 32
                    or any(not isinstance(name, str) or not re.fullmatch(RUNTIME_PATTERN[runtime], name) for name in names)):
                raise SetupError("지원되는 정규 런타임 이름만 정책에 추가할 수 있습니다.")
            result[runtime] = sorted(set(result.get(runtime, []) + names))
    return result


def discover_runtime_names(root=Path("/")):
    """Read trusted package names/alternatives, never argv, files or processes."""
    result = {}
    for directory in ("usr/bin", "usr/local/bin", "bin"):
        directory = root / directory
        if not directory.is_dir():
            continue
        entries = list(directory.iterdir())
        if len(entries) > 16384:
            raise SetupError("런타임 실행파일 탐색의 크기 제한을 초과했습니다.")
        for candidate in entries:
            for runtime, pattern in RUNTIME_PATTERN.items():
                if not re.fullmatch(pattern, candidate.name):
                    continue
                try:
                    resolved = candidate.resolve(strict=True)
                    trusted_path(resolved)
                except (FileNotFoundError, OSError, SetupError):
                    continue
                if re.fullmatch(pattern, resolved.name):
                    result.setdefault(runtime, set()).add(resolved.name)
    return {runtime: sorted(names) for runtime, names in result.items()}


def observation_binaries(extra=None):
    names = {item for values in runtime_names(extra).values() for item in values}
    names.update(("sh", "bash", "dash", "ash", "busybox", "nginx", "apache2", "httpd", "php-fpm", "java", "dotnet",
                  "php-fpm7", "php-fpm8", "curl", "wget", "nc", "ncat", "netcat", "socat"))
    names.update("php-fpm8." + str(n) for n in range(6))
    return {"operator": "Postfix", "values": ["/" + name for name in sorted(names)]}


def base_policy(name, key, hooks):
    return {"apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicy", "metadata": {"name": name},
            "spec": {"options": [{"name": "policy-mode", "value": "monitor"}], key: hooks}}


def inline_policy(name, runtime, option, extra=None):
    binary = {"operator": "Postfix", "values": ["/" + item for item in runtime_names(extra)[runtime]]}
    selectors = []
    for index in range(INLINE_OPTION_POSITIONS):
        arguments = [{"index": n, "operator": "Equal", "values": list(PRIOR_SWITCHES[runtime])} for n in range(index)]
        arguments.append({"index": index, "operator": "Equal", "values": [option]})
        selectors.append({"matchBinaries": [binary], "matchCmdArgs": arguments})
    # The base exec raw tracepoint is loaded first. A non-raw hook has no such
    # registration ordering guarantee and must not replace this hook.
    return base_policy(name, "tracepoints", [{"subsystem": "sched", "event": "sched_process_exec",
                                               "raw": True, "selectors": selectors}])


def validate_prefixes(prefixes):
    prefixes = tuple(prefixes)
    if not prefixes or len(prefixes) > 16:
        raise SetupError("파일 경로 접두사는 1~16개여야 합니다.")
    for prefix in prefixes:
        if (not isinstance(prefix, str) or not prefix.startswith("/") or not prefix.endswith("/")
                or len(prefix) > 512 or not prefix.isprintable() or ".." in PurePosixPath(prefix).parts
                or str(PurePosixPath(prefix)) + "/" != prefix or prefix == "/"):
            raise SetupError("파일 경로 접두사는 정규화된 절대 디렉터리여야 합니다.")
    return prefixes


def policies(prefixes=DEFAULT_FILE_PREFIXES, network_families=("ipv4", "ipv6"), runtime_suffixes=None):
    prefixes = validate_prefixes(prefixes)
    if tuple(network_families) not in (("ipv4",), ("ipv4", "ipv6")):
        raise SetupError("TCP 관측 주소 계열 설정이 올바르지 않습니다.")
    result = {name: inline_policy(name, *description, runtime_suffixes) for name, description in INLINE.items()}
    result[FILE_POLICY] = base_policy(FILE_POLICY, "kprobes", [{
        "call": "vfs_write", "syscall": False, "return": True,
        "args": [{"index": 0, "type": "file", "label": "target"}],
        "returnArg": {"index": 0, "type": "long", "label": "result"},
        "selectors": [{"matchBinaries": [observation_binaries(runtime_suffixes)],
                       "matchArgs": [{"index": 0, "operator": "Prefix", "values": list(prefixes)},
                                      {"index": 0, "operator": "FileType", "values": ["regular"]}]}],
    }])
    result[NETWORK_POLICY] = base_policy(NETWORK_POLICY, "kprobes", [{
        "call": function, "syscall": False, "return": True,
        "args": [{"index": 1, "type": "sockaddr", "label": "destination"}],
        "returnArg": {"index": 0, "type": "int", "label": "result"},
        "selectors": [{"matchBinaries": [observation_binaries(runtime_suffixes)]}],
    } for function in ["tcp_v4_connect"] + (["tcp_v6_connect"] if "ipv6" in network_families else [])])
    return result


def encoded_policies(prefixes=DEFAULT_FILE_PREFIXES, network_families=("ipv4", "ipv6"), runtime_suffixes=None):
    return {name + ".yaml": yaml.safe_dump(value, sort_keys=False).encode("utf-8")
            for name, value in policies(prefixes, network_families, runtime_suffixes).items()}


def policy_hashes(files):
    return {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}
