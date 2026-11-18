#!/usr/bin/env python3
"""Check isolated binary replay using synthetic metadata, without executing it."""

from __future__ import annotations

import argparse
import copy
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "testdata/events/webshell-process-scenarios.json"
CONFIG = ROOT / "configs/examples/agent-webshell-detection.yaml"
MARKER = "webshell-process-selftest-end"


class CheckError(Exception):
    """A fixed diagnostic that never contains captured host information."""


class QuietParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "detection check: invalid arguments\n")


def require(condition, message):
    if not condition:
        raise CheckError(message)


def load_scenarios():
    require(FIXTURE.is_file() and CONFIG.is_file(), "missing shareable inputs")
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    cases = data["scenarios"]
    require(data["format_version"] == 1 and len(cases) == 20, "invalid fixture format")
    ids, pids = set(), set()
    for case in cases:
        event, expected = case["event"], case["expected"]
        process = event["process"]
        require(event["event_type"] == "process.exec" and event["source"] in ("audit", "tetragon"),
                "invalid fixture event")
        require(event["event_id"] not in ids and event["event_id"] != MARKER and
                process["pid"] > 0 and process["pid"] not in pids, "duplicate fixture identity")
        require(process["euid"] == 1000 and process["cwd"] == "/srv/application" and
                process["origin_service"], "invalid fixture process context")
        require(type(expected["retained"]) is bool, "invalid fixture retention expectation")
        ids.add(event["event_id"])
        pids.add(process["pid"])
    require(sum(case["expected"]["finding"] is not None for case in cases) == 9,
            "fixture must contain nine observations and eleven negative cases")
    return cases


def binary_paths(directory):
    directory = directory.resolve(strict=True)
    require(directory.is_dir() and directory != Path("/"), "invalid binary directory")
    paths = [directory / name for name in ("sentineld", "sentinel")]
    for path in paths:
        require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and
                os.access(path, os.X_OK), "missing regular executable; run make static")
    return paths


def write_replay(cases, work):
    now = datetime.now(timezone.utc)
    events = [copy.deepcopy(case["event"]) for case in cases]
    events.append({"schema_version": "0.1", "event_id": MARKER,
                   "event_type": "security.selftest_end", "source": "replay",
                   "completeness": "partial", "process": {}})
    path = work / "events.jsonl"
    with path.open("w", encoding="utf-8") as output:
        for index, event in enumerate(events):
            event["event_time"] = (now + timedelta(microseconds=index)).isoformat()
            event["stream_id"] = "webshell-process-selftest"
            output.write(json.dumps(event, separators=(",", ":")) + "\n")
    return path


def query(client, socket, kind, work, log, timeout):
    # Captured API responses can contain host metadata; keep them in the private
    # temporary directory and never include them in failure diagnostics.
    with (work / (kind + ".json")).open("w+b") as output:
        try:
            result = subprocess.run(
                [str(client), "--json", "--socket", str(socket), kind, "--limit", "1000"],
                stdin=subprocess.DEVNULL, stdout=output, stderr=log,
                timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        if result.returncode != 0:
            return None
        require(output.tell() <= 4 * 1024 * 1024, "oversized API response")
        output.seek(0)
        data = json.load(output)
        require(isinstance(data, list) and all(isinstance(item, dict) for item in data),
                "invalid API response")
        return data


def await_marker(daemon, client, socket, work, log):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        require(daemon.poll() is None, "isolated daemon exited before completion")
        if socket.exists():
            events = query(client, socket, "events", work, log,
                           max(.01, min(1, deadline - time.monotonic())))
            if events is not None and any(event.get("event_id") == MARKER for event in events):
                return events
        time.sleep(min(.1, max(0, deadline - time.monotonic())))
    raise CheckError("durable completion marker was not observed within 15 seconds")


def verify(cases, events, findings):
    event_map = {event["event_id"]: event for event in events}
    expected_ids = {case["event"]["event_id"] for case in cases if case["expected"]["retained"]}
    require(len(event_map) == len(events) and set(event_map) == expected_ids | {MARKER},
            "retained event set differs from fixture")
    require(event_map[MARKER]["event_type"] == "security.selftest_end" and
            event_map[MARKER]["source"] == "replay", "invalid completion marker")
    require(findings is not None and len(findings) == 9, "expected exactly nine findings")
    finding_map = {}
    for finding in findings:
        evidence = finding["evidence_event_ids"]
        require(len(evidence) == 1 and evidence[0] not in finding_map, "duplicate or invalid finding evidence")
        finding_map[evidence[0]] = finding
    for index, case in enumerate(cases, 1):
        original, expected = case["event"], case["expected"]
        prefix = "case %02d: " % index
        event = event_map.get(original["event_id"])
        if expected["retained"]:
            require(event["source"] == original["source"], prefix + "source changed")
            require(event.get("missing_fields", []) == original.get("missing_fields", []), prefix + "evidence quality changed")
            redactions = list(original.get("redacted_fields", []))
            if expected.get("argv_redacted") and "process.argv" not in redactions:
                redactions.append("process.argv")
            require(event.get("redacted_fields", []) == redactions, prefix + "privacy evidence mismatch")
            for field in ("pid", "exe", "euid", "cwd", "origin_service"):
                require(event["process"].get(field, []) == original["process"].get(field, []),
                        prefix + "process metadata changed")
            argv = [] if expected.get("argv_redacted") else original["process"].get("argv", [])
            require(event["process"].get("argv", []) == argv, prefix + "argv privacy mismatch")
            require(event.get("execution") == expected.get("execution"), prefix + "invocation metadata mismatch")
        finding = finding_map.pop(original["event_id"], None)
        retained = json.dumps({"event": event, "finding": finding})
        for forbidden in expected.get("forbidden_values", []):
            require(forbidden not in retained, prefix + "private argument survived normalization")
        if expected["finding"] is None:
            require(finding is None, prefix + "legitimate or uncertain execution produced a finding")
            continue
        require(finding is not None, prefix + "expected observation missing")
        for field, value in expected["finding"].items():
            require(finding.get(field) == value, prefix + "finding contract mismatch")
        require(finding.get("detection_only") is True and finding.get("response_decision") == "detection_only",
                prefix + "observation is not detection-only")
        factors = finding["risk_factors"]
        require(2 <= len(factors) <= 8 and min(100, sum(factor["score"] for factor in factors)) == finding["risk_score"],
                prefix + "invalid additive score")
        require(finding["origin_service"] == original["process"]["origin_service"], prefix + "origin changed")
    require(not finding_map, "unexpected finding evidence")


def stop_child(daemon):
    if daemon is None:
        return
    if daemon.poll() is None:
        daemon.send_signal(signal.SIGTERM)
    try:
        daemon.wait(timeout=12)
    except subprocess.TimeoutExpired:
        daemon.kill()
        daemon.wait(timeout=5)


def handle_stop(_number, _frame):
    raise KeyboardInterrupt


def run(bin_dir):
    cases = load_scenarios()
    server, client = binary_paths(bin_dir)
    with tempfile.TemporaryDirectory(prefix="xeas-detection-", dir="/tmp") as directory:
        work = Path(directory)
        work.chmod(0o700)
        socket = work / "sock"
        require(len(os.fsencode(socket)) < 104, "temporary Unix socket path is too long")
        replay = write_replay(cases, work)
        # This replay verifies the full legacy encoding, including argv.
        config = work / "replay.yaml"
        source = CONFIG.read_text(encoding="utf-8")
        require("\nlimits:\n" in source, "replay configuration has no limits section")
        config.write_text(
            source.replace("\nlimits:\n", "\nlimits:\n  observation_history_minutes: 0\n", 1),
            encoding="utf-8",
        )
        daemon = None
        with (work / "daemon.log").open("wb") as log:
            try:
                daemon = subprocess.Popen(
                    [str(server), "--config", str(config), "--data-dir", str(work),
                     "--socket", str(socket), "--replay", str(replay)],
                    stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True,
                )
                events = await_marker(daemon, client, socket, work, log)
                findings = query(client, socket, "findings", work, log, 3)
                verify(cases, events, findings)
            finally:
                stop_child(daemon)
    print("detection check: 20 scenarios passed (9 observations, 11 legitimate/uncertain)")


def main():
    parser = QuietParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "build",
                        help="directory containing freshly built sentineld and sentinel")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, handle_stop)
    try:
        run(args.bin_dir)
    except CheckError as error:
        print("detection check: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("detection check: interrupted; isolated child stopped", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print("detection check: cannot complete isolated replay", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
