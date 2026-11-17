"""Conservative YAML transformation without touching policy or database state."""

import copy
import json
import yaml

from setup_common import SetupError, trusted_path


TETRA = "/opt/xe-antishell/tetragon/v1.8.0/tetra"
TETRA_ARGS = ["--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json"]
OBSERVATION_EXCLUDES = ",".join(parent + "." + field for parent in ("process", "parent", "ancestors")
                               for field in ("arguments", "environment_variables"))
OBSERVATION_ARGS = TETRA_ARGS + ["--exclude-fields", OBSERVATION_EXCLUDES]


class LiteralScalar(str):
    """Retain spelling/tag: Go's typed string decoding differs from PyYAML."""

    def __new__(cls, value, tag):
        result = super().__new__(cls, value)
        result.tag = tag
        return result

    def __reduce__(self):
        return type(self), (str(self), self.tag)


class UniqueLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise SetupError("에이전트 YAML의 alias를 명시적인 값으로 펼친 뒤 다시 실행하십시오.")
        return super().compose_node(parent, index)


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key_node.tag != "tag:yaml.org,2002:str" or not isinstance(key, str) or key in result:
            raise SetupError("에이전트 YAML의 중복 키 또는 문자열이 아닌 키를 수정하십시오.")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)
for scalar_tag in ("bool", "int", "float", "null", "timestamp"):
    UniqueLoader.add_constructor("tag:yaml.org,2002:" + scalar_tag,
                                 lambda loader, node: LiteralScalar(loader.construct_scalar(node), node.tag))
yaml.SafeDumper.add_representer(LiteralScalar, lambda dumper, value: dumper.represent_scalar(value.tag, str(value)))


def mapping(parent, key):
    value = parent.setdefault(key, {})
    if not isinstance(value, dict):
        raise SetupError("에이전트 YAML의 설정 구역은 mapping이어야 합니다.")
    return value


def prepare_config(path, *, observations=False):
    trusted_path(path)
    if path.stat().st_size > 1024 * 1024:
        raise SetupError("에이전트 YAML이 크기 제한을 초과했습니다.")
    original = path.read_bytes()
    try:
        current = yaml.load(original, Loader=UniqueLoader)
    except (yaml.YAMLError, UnicodeError, ValueError, RecursionError):
        raise SetupError("에이전트 YAML을 안전하게 읽을 수 없습니다.") from None
    if not isinstance(current, dict):
        raise SetupError("에이전트 YAML의 최상위 값은 mapping이어야 합니다.")
    try:
        # Refuse YAML aliases that form cycles or non-JSON scalar types.
        json.dumps(current, allow_nan=False)
        target = copy.deepcopy(current)
        collector = mapping(target, "collector")
        tetragon = mapping(collector, "tetragon")
        detection = target.get("detection", {})
        agent = target.get("agent", {})
        if not isinstance(detection, dict) or not isinstance(agent, dict):
            raise SetupError("에이전트 YAML의 agent/detection 구역을 확인하십시오.")
        collector["mode"] = "tetragon"
        tetragon["command"] = TETRA
        # A repeat of the base installer must retain the observation helper's
        # server-side privacy filter rather than silently exposing argv again.
        tetragon["args"] = list(OBSERVATION_ARGS if observations or tetragon.get("args") == OBSERVATION_ARGS else TETRA_ARGS)
        socket = agent.get("socket_path", "/run/xe-antishell/sentineld.sock")
        if not isinstance(socket, str) or not socket.startswith("/") or "\x00" in socket or socket == "/":
            raise SetupError("에이전트의 절대 Unix 소켓 경로를 확인하십시오.")
        encoded = yaml.safe_dump(target, sort_keys=False, allow_unicode=True).encode("utf-8")
        if yaml.load(encoded, Loader=UniqueLoader) != target:
            raise SetupError("에이전트 YAML의 무손실 값 보존을 확인할 수 없습니다.")
    except (TypeError, ValueError, RecursionError, yaml.YAMLError):
        raise SetupError("에이전트 YAML에 지원하지 않는 값이 있습니다.") from None
    return original, encoded if target != current else original, socket
