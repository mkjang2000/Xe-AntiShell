#!/usr/bin/env python3
"""Isolated installer checks; never call host systemctl or attach BPF."""

import copy
import datetime
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import signal
import tempfile
import unittest
from unittest import mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from setup_common import Paths, SetupError, install_lock
from setup_config import TETRA, prepare_config
from setup_runtime import Runner, agent_ready, health_running, matches_true, verify_exec, wait_health
from setup_services import AGENT_DROPIN, Services, UNIT, check_conflicts
from setup_state import Transaction
from setup_workflow import run_setup
import setup as installer


CONFIG = {
    "version": 1,
    "agent": {"id": "keep-identity", "socket_path": "/run/custom-agent.sock", "database_path": "/state/keep.db"},
    "collector": {"mode": "audit", "tetragon": {"include_executables": [], "only_detection_origins": False},
                  "audit": {"input_path": "/run/keep-audit.sock"}},
    "detection": {"enabled": True, "extended_process_rules": True, "web_services": ["custom.service"]},
    "response": {"allow_terminate": False},
    "privacy": {"store_raw_events": False, "redact_argv": True},
    "limits": {"retention_days": 11},
}


class FakeRunner:
    def __init__(self, paths):
        self.paths = paths
        self.calls = []
        self.active = {"tetragon.service": False, "sentineld.service": True}
        self.enabled = {"tetragon.service": "not-found", "sentineld.service": "enabled"}
        self.exec_start = "{ path=/usr/sbin/sentineld ; argv[]=/usr/sbin/sentineld --config /etc/xe-antishell/sentineld.yaml ; ignore_errors=no ; }"
        self.fail_start = False
        self.environment = b"PATH=/usr/bin\n"

    def command(self, args, **kwargs):
        self.calls.append(args[1:])
        if args[0] != "/usr/bin/systemctl":
            raise AssertionError("Only mocked systemctl is allowed")
        action = args[1]
        service = args[-1]
        if action == "show-environment":
            return 0, self.environment
        if action == "show":
            prop = args[2]
            if prop == "--property=ExecStart":
                if service == "tetragon.service":
                    command = next(line[len("ExecStart="):] for line in UNIT.decode().splitlines() if line.startswith("ExecStart="))
                    return 0, ("{ argv[]=" + command + " ; }").encode()
                return 0, self.exec_start.encode()
            if prop == "--property=FragmentPath":
                return 0, b"/etc/systemd/system/tetragon.service" if self.paths.unit.exists() else b""
            return 0, b""
        if action == "is-enabled":
            value = self.enabled[service]
            return (0 if value == "enabled" else 1), value.encode()
        if action == "is-active":
            return (0 if self.active[service] else 3), b"active" if self.active[service] else b"inactive"
        if action in ("start", "restart"):
            self.active[service] = True
            if self.fail_start and service == "tetragon.service":
                raise SetupError("mock start failure after partial activation")
        if action == "stop":
            self.active[service] = False
        if action == "enable":
            self.enabled[service] = "enabled-runtime" if "--runtime" in args else "enabled"
        if action == "disable":
            self.enabled[service] = "disabled"
        return 0, b""


def stage_release(archive, destination):
    (destination / "tetragon").write_bytes(b"verified mock binary")
    (destination / "tetra").write_bytes(b"verified mock cli")
    (destination / "bpf").mkdir()
    (destination / "bpf" / "process.o").write_bytes(b"verified mock bpf")


class Fixture(unittest.TestCase):
    def setUp(self):
        current_uid = os.getuid()
        actual_lstat = Path.lstat
        actual_fstat = os.fstat

        def root_info(info):
            values = list(info)
            if values[4] == current_uid:
                values[4] = 0
            return os.stat_result(values)

        def root_owned_test_paths(path, *args, **kwargs):
            return root_info(actual_lstat(path, *args, **kwargs))

        self.identity_patches = [mock.patch("setup_workflow.os.geteuid", return_value=0),
                                 mock.patch.object(Path, "lstat", root_owned_test_paths),
                                 mock.patch("setup_common.os.fstat", side_effect=lambda fd: root_info(actual_fstat(fd))),
                                 mock.patch("setup_common.os.fchown")]
        for patch in self.identity_patches:
            patch.start()
        self.temporary = tempfile.TemporaryDirectory(prefix="xeas-tetragon-test-")
        self.paths = Paths(Path(self.temporary.name))
        self.paths.config.parent.mkdir(parents=True)
        self.original = ("# original comment remains after rollback\n" + yaml.safe_dump(CONFIG)).encode()
        self.paths.config.write_bytes(self.original)
        self.paths.config.chmod(0o640)
        self.paths.btf.parent.mkdir(parents=True)
        self.paths.btf.write_bytes(b"BTF")
        for name in ("/usr/bin/systemctl", "/usr/bin/sentinel", "/usr/sbin/sentineld", "/usr/bin/true"):
            path = self.paths.at(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture, never execute")
        self.paths.unit.parent.mkdir(parents=True)
        self.runner = FakeRunner(self.paths)
        self.patches = [
            mock.patch("setup_workflow.platform.machine", return_value="x86_64"),
            mock.patch("setup_workflow.acquire_archive", return_value=Path("/fixture/verified.tar.gz")),
            mock.patch("setup_workflow.extract_release", side_effect=stage_release),
            mock.patch("setup_workflow.wait_health"),
            mock.patch("setup_workflow.verify_exec"),
            mock.patch("setup_workflow.verify_agent"),
        ]
        self.mocks = [patch.start() for patch in self.patches]

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()
        for patch in reversed(self.identity_patches):
            patch.stop()

    def run_setup(self):
        run_setup(paths=self.paths, runner=self.runner)

    def mutations(self):
        return [call for call in self.runner.calls if call[0] in ("enable", "disable", "start", "restart", "stop", "daemon-reload")]


class ConfigurationTests(Fixture):
    def test_preserves_values_and_explicit_filters(self):
        _, target, socket = prepare_config(self.paths.config)
        result = yaml.safe_load(target)
        expected = copy.deepcopy(CONFIG)
        expected["collector"]["mode"] = "tetragon"
        expected["collector"]["tetragon"]["command"] = TETRA
        expected["collector"]["tetragon"]["args"] = ["--server-address", "unix:///run/tetragon/tetragon.sock", "getevents", "-o", "json"]
        self.assertEqual(result, expected)
        self.assertEqual(socket, "/run/custom-agent.sock")

    def test_absent_filters_remain_absent(self):
        current = copy.deepcopy(CONFIG)
        current["collector"]["tetragon"] = {}
        current["detection"]["extended_process_rules"] = False
        self.paths.config.write_text(yaml.safe_dump(current))
        result = yaml.safe_load(prepare_config(self.paths.config)[1])
        self.assertNotIn("include_executables", result["collector"]["tetragon"])
        self.assertNotIn("only_detection_origins", result["collector"]["tetragon"])

    def test_go_typed_string_scalar_spelling_is_preserved(self):
        for literal in ("on", "yes", "00123", "0x10", "1.00", "2026-11-17"):
            with self.subTest(literal=literal):
                self.paths.config.write_text("agent:\n  id: " + literal + "\ndetection:\n  web_services: [" + literal + "]\nresponse:\n  allow_terminate: false\n")
                _, target, _ = prepare_config(self.paths.config)
                node = yaml.compose(target)
                # Nodes preserve the scalar sent to the Go typed string field.
                agent = next(value for key, value in node.value if key.value == "agent")
                identifier = next(value for key, value in agent.value if key.value == "id")
                self.assertEqual(identifier.value, literal)
                detection = next(value for key, value in node.value if key.value == "detection")
                services = next(value for key, value in detection.value if key.value == "web_services")
                self.assertEqual(services.value[0].value, literal)
                self.assertFalse(yaml.safe_load(target)["response"]["allow_terminate"])

    def test_duplicate_keys_aliases_and_non_mapping_rejected(self):
        for source in ("version: 1\nversion: 2\n", "collector: []\n", "[]\n", "agent: &x {id: y}\ndetection: *x\n"):
            with self.subTest(source=source):
                self.paths.config.write_text(source)
                with self.assertRaises(SetupError):
                    prepare_config(self.paths.config)


class TransactionTests(Fixture):
    def test_success_and_repeat_do_not_restart(self):
        self.run_setup()
        self.assertEqual(self.paths.unit.read_bytes(), UNIT)
        self.assertEqual(self.paths.agent_dropin.read_bytes(), AGENT_DROPIN)
        self.assertTrue(self.runner.active["tetragon.service"])
        self.assertEqual(yaml.safe_load(self.paths.config.read_bytes())["collector"]["mode"], "tetragon")
        self.runner.calls.clear()
        self.run_setup()
        self.assertEqual(self.mutations(), [])
        self.assertEqual(self.mocks[3].call_count, 2)
        self.assertEqual(self.mocks[4].call_count, 2)
        self.assertEqual(self.mocks[5].call_count, 2)

    def test_failed_agent_verification_restores_and_can_retry(self):
        self.mocks[5].side_effect = SetupError("no live agent events")
        with self.assertRaises(SetupError):
            self.run_setup()
        self.assertEqual(self.paths.config.read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE(self.paths.config.stat().st_mode), 0o640)
        self.assertFalse(self.paths.unit.exists())
        self.assertFalse(self.paths.agent_dropin.exists())
        self.assertFalse(self.paths.version.exists())
        self.assertFalse(self.runner.active["tetragon.service"])
        self.assertTrue(self.runner.active["sentineld.service"])
        self.assertEqual(self.runner.enabled["tetragon.service"], "disabled")
        self.assertEqual(stat.S_IMODE(self.paths.backups.stat().st_mode), 0o700)
        backup = next(self.paths.backups.iterdir())
        self.assertEqual((backup / "sentineld.yaml").read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE((backup / "sentineld.yaml").stat().st_mode), 0o600)
        self.mocks[5].side_effect = None
        self.run_setup()
        self.assertTrue(self.runner.active["tetragon.service"])

    def test_start_failure_restores_even_partial_start(self):
        self.runner.fail_start = True
        with self.assertRaises(SetupError):
            self.run_setup()
        self.assertFalse(self.runner.active["tetragon.service"])
        self.assertTrue(self.runner.active["sentineld.service"])
        self.assertEqual(self.paths.config.read_bytes(), self.original)
        self.assertFalse(self.paths.unit.exists())

    def test_runtime_only_enable_remains_runtime_only_after_failure(self):
        self.runner.enabled["tetragon.service"] = "enabled-runtime"
        self.mocks[5].side_effect = SetupError("fail after switch")
        with self.assertRaises(SetupError):
            self.run_setup()
        self.assertNotIn(["enable", "tetragon.service"], self.mutations())
        self.assertEqual(self.runner.enabled["tetragon.service"], "enabled-runtime")

    def test_no_kernel_events_does_not_switch_collector(self):
        self.mocks[4].side_effect = SetupError("no process events")
        with self.assertRaises(SetupError):
            self.run_setup()
        self.assertEqual(self.paths.config.read_bytes(), self.original)
        self.assertFalse(self.runner.active["tetragon.service"])
        self.assertNotIn(["restart", "sentineld.service"], self.mutations())

    def test_backup_failure_has_no_service_mutations(self):
        with mock.patch.object(Transaction, "backup_originals", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.run_setup()
        self.assertEqual(self.paths.config.read_bytes(), self.original)
        self.assertEqual(self.mutations(), [])

    def test_interrupt_restores_previous_collector(self):
        self.mocks[5].side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_setup()
        self.assertEqual(self.paths.config.read_bytes(), self.original)
        self.assertFalse(self.runner.active["tetragon.service"])
        self.assertTrue(self.runner.active["sentineld.service"])

    def test_parallel_installer_lock_refuses_second_attempt(self):
        with install_lock(self.paths):
            with self.assertRaises(SetupError):
                self.run_setup()
        self.assertEqual(self.mutations(), [])
        self.run_setup()

    def test_missing_btf_fails_before_any_mutation(self):
        self.paths.btf.unlink()
        with self.assertRaises(SetupError):
            self.run_setup()
        self.assertFalse(self.paths.backups.exists())
        self.assertEqual(self.mutations(), [])

    def test_custom_exec_and_config_conflicts_fail_before_mutation(self):
        for suffix in (" --collector audit", " --config /etc/custom.yaml"):
            self.runner.exec_start = "{ argv[]=/usr/sbin/sentineld" + suffix + " ; }"
            with self.assertRaises(SetupError):
                self.run_setup()
            self.assertEqual(self.mutations(), [])

    def test_unowned_unit_dropin_config_environment_are_refused(self):
        for path in (self.paths.unit, self.paths.at("/etc/tetragon/tetragon.yaml"), self.paths.agent_dropin):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("unowned custom state")
            with self.assertRaises(SetupError):
                check_conflicts(self.paths, Services(self.runner))
            path.unlink()
        self.runner.environment += b"TETRAGON_EXPORT_FILENAME=/private/events.json\n"
        with self.assertRaises(SetupError):
            check_conflicts(self.paths, Services(self.runner))
        self.assertEqual(self.mutations(), [])


class RuntimeTests(unittest.TestCase):
    def test_sigterm_uses_controlled_interruption_and_restores_handlers(self):
        original = signal.getsignal(signal.SIGTERM)
        with mock.patch("setup_workflow.run_setup", side_effect=lambda archive: signal.raise_signal(signal.SIGTERM)):
            with mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(installer.main([]), 130)
        self.assertEqual(signal.getsignal(signal.SIGTERM), original)

    def test_initializing_exit_zero_is_not_running(self):
        self.assertFalse(health_running(b"Health Status: initializing\n"))
        self.assertFalse(health_running(b"prefix Health Status: running\n"))
        self.assertTrue(health_running(b"Health Status: running\n"))
        runner = mock.Mock()
        runner.command.return_value = (0, b"Health Status: initializing\n")
        with mock.patch("setup_runtime.time.sleep"):
            with self.assertRaises(SetupError):
                wait_health(runner, timeout=0.001)

    def test_true_pid_is_numeric_and_matches_exec_binary(self):
        def event(pid, binary="/usr/bin/true"):
            return json.dumps({"process_exec": {"process": {"pid": pid, "binary": binary, "arguments": "never print"}}})
        self.assertTrue(matches_true(event(123), {123}))
        self.assertFalse(matches_true(event("123"), {123}))
        self.assertFalse(matches_true(event(True), {1}))
        self.assertFalse(matches_true(event(123, "/bin/sh"), {123}))

    def test_no_events_is_failure_and_stream_is_reaped(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        runner = mock.Mock()
        runner.stream.return_value = child
        with self.assertRaises(SetupError):
            verify_exec(runner, timeout=0.02)
        self.assertIsNotNone(child.poll())

    def test_stream_uses_devnull_stdin(self):
        with mock.patch("setup_runtime.subprocess.Popen") as spawn:
            Runner().stream()
        self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_agent_requires_live_counter_and_fresh_evidence(self):
        since = datetime.datetime.now(datetime.timezone.utc).timestamp()
        verified = datetime.datetime.fromtimestamp(since + 1, datetime.timezone.utc).isoformat()
        status = {"collector": "tetragon-json", "mode": "active", "health": "healthy",
                  "collector_health": {"running": True, "events_received": 4},
                  "capability_report": {"capabilities": {key: {"runtime_state": "active", "verified_at": verified}
                                                        for key in ("collector.tetragon", "observation.process_exec")}}}
        self.assertTrue(agent_ready(status, since, 3))
        self.assertFalse(agent_ready(status, since, 4))
        self.assertFalse(agent_ready(status, since + 2, 3))
        status["collector_health"]["running"] = False
        self.assertFalse(agent_ready(status, since, 3))


if __name__ == "__main__":
    unittest.main()
