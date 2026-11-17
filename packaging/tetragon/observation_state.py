"""Validate exact owned static-policy files; metadata lives outside their dir."""

import json
import stat

from observation_policies import DEFAULT_FILE_PREFIXES, encoded_policies, policy_hashes
from setup_common import SetupError, trusted_path


def manifest_path(paths):
    return paths.base / "observations.json"


def owned_policy_state(paths):
    marker = manifest_path(paths)
    exists = marker.exists() or marker.is_symlink()
    if not exists:
        if paths.policies.exists():
            trusted_path(paths.policies, directory=True)
            if any(paths.policies.iterdir()):
                raise SetupError("소유권 메타데이터가 없는 기존 관측 정책은 수동 통합이 필요합니다.")
        return None
    trusted_path(marker)
    if marker.stat().st_size > 32768 or stat.S_IMODE(marker.stat().st_mode) != 0o600:
        raise SetupError("관측 정책 소유권 메타데이터의 크기 또는 권한이 올바르지 않습니다.")
    try:
        document = json.loads(marker.read_bytes())
        if (not isinstance(document, dict) or document.get("schema_version") != 1
                or document.get("tetragon_version") != "v1.8.0" or document.get("state") != "verified"
                or document.get("exec_raw_tracepoint") is not True or document.get("argv_excluded") is not True):
            raise ValueError
        files = encoded_policies(document.get("file_prefixes", DEFAULT_FILE_PREFIXES), document.get("network_families", []),
                                 document.get("runtime_suffixes", {}))
        if document.get("policies") != policy_hashes(files):
            raise ValueError
        trusted_path(paths.policies, directory=True)
        if {p.name for p in paths.policies.iterdir()} != set(files):
            raise ValueError
        for name, content in files.items():
            candidate = paths.policies / name
            trusted_path(candidate)
            if (candidate.stat().st_size != len(content) or stat.S_IMODE(candidate.stat().st_mode) != 0o600
                    or candidate.read_bytes() != content):
                raise ValueError
        return document
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise SetupError("기존 관측 정책과 소유권 메타데이터가 달라 수동 확인이 필요합니다.") from None
