"""Check live agent receipt separately from Tetragon's own probe stream."""

import datetime
import math
import time

from setup_common import SetupError
from setup_runtime import agent_ready, read_agent, timestamp


FILE_CAPABILITY = "observation.file"
NETWORK_CAPABILITY = "observation.network"
INTERPRETER_CAPABILITY = "observation.interpreter_exec"


def _capabilities(status):
    report = status.get("capability_report", {}) if isinstance(status, dict) else {}
    values = report.get("capabilities", {}) if isinstance(report, dict) else {}
    return values if isinstance(values, dict) else {}


def receipt_checkpoint(runner, socket):
    """Capture a boundary after base readiness and before generating probes."""
    status = read_agent(runner, socket)
    capabilities = _capabilities(status)
    if any(not isinstance(capabilities.get(name), dict)
           or capabilities[name].get("implementation") != "implemented"
           for name in (FILE_CAPABILITY, NETWORK_CAPABILITY)):
        raise SetupError("에이전트의 파일·TCP 관측 지원을 확인하지 못했습니다. 지원 버전으로 갱신한 뒤 다시 적용하십시오.")
    stream = status.get("collector_health", {})
    count = stream.get("events_received") if isinstance(stream, dict) else None
    if type(count) is not int or count < 0:
        raise SetupError("에이전트의 관측 수신 기준을 확인하지 못했습니다.")
    return {"since": time.time(), "events_received": count}


def observation_receipt_ready(status, checkpoint, *, interpreter=False, now=None):
    """Receipt is not a promise that candidate-filtered events were retained."""
    since = checkpoint["since"]
    if not agent_ready(status, since, checkpoint["events_received"]):
        return False
    capabilities = _capabilities(status)
    names = [FILE_CAPABILITY, NETWORK_CAPABILITY]
    if interpreter:
        names.append(INTERPRETER_CAPABILITY)
    now = time.time() if now is None else now
    for name in names:
        evidence = capabilities.get(name, {})
        if (not isinstance(evidence, dict) or evidence.get("implementation") != "implemented"
                or evidence.get("runtime_state") != "active"
                or evidence.get("state") not in ("supported", "limited", "unsupported", "error")):
            return False
        verified = timestamp(evidence.get("verified_at"))
        if not math.isfinite(verified) or not since <= verified <= now + 5:
            return False
    return True


def verify_agent_receipt(runner, socket, checkpoint, *, interpreter=False, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = read_agent(runner, socket)
        if observation_receipt_ready(status, checkpoint, interpreter=interpreter):
            names = [FILE_CAPABILITY, NETWORK_CAPABILITY]
            if interpreter:
                names.append(INTERPRETER_CAPABILITY)
            capabilities = _capabilities(status)
            return {"state": "verified", "capabilities": names,
                    "received_at": {name: capabilities[name]["verified_at"] for name in names},
                    "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        time.sleep(0.25)
    raise SetupError("Tetragon 센서 이벤트는 확인했지만 에이전트의 기능별 실제 수신은 확인하지 못해 이전 상태로 복구합니다.")
