"""Synthetic policy/probe/transaction regression tests, never attach host BPF."""

import copy
import io
import json
from pathlib import Path
import unittest
from unittest import mock

import yaml

from test_setup import Fixture, FakeRunner
from observation_policies import (DEFAULT_FILE_PREFIXES, FILE_POLICY, INLINE, INLINE_OPTION_POSITIONS, NETWORK_POLICY,
                                  PRIOR_SWITCHES, discover_runtime_names, encoded_policies, policies)
from observation_probes import EventProof, verify_network
from observation_state import manifest_path, owned_policy_state
from observation_workflow import enabled_monitor, run_observations
from setup_common import SetupError
from setup_config import OBSERVATION_ARGS, prepare_config
import observations


def status(name):
    return {"name": name, "domain": "static", "state": "TP_STATE_ENABLED", "mode": "TP_MODE_MONITOR_ONLY",
            "hook_statuses": [{"state": "STATUS_LOADED"}]}


class ObservationRunner(FakeRunner):
    def __init__(self, source):
        super().__init__(source.paths)
        self.active = dict(source.active)
        self.enabled = dict(source.enabled)
        self.loaded = {}
        self.fail_policy = None
        self.no_ipv6 = False

    def command(self, args, **kwargs):
        if args[0] == "/usr/bin/systemctl":
            return super().command(args, **kwargs)
        self.calls.append(args)
        index = args.index("tracingpolicy")
        action, rest = args[index + 1], args[index + 2:]
        if action == "list":
            return 0, json.dumps({"policies": list(self.loaded.values())}).encode()
        if action == "add":
            value = yaml.safe_load(Path(rest[0]).read_bytes())
            name = value["metadata"]["name"]
            self.loaded[name] = status(name)
            if name in INLINE:
                # Real v1.8.0 tracepoint status omits this protobuf field.
                self.loaded[name].pop("hook_statuses")
            if name == self.fail_policy:
                raise SetupError("mock policy attach failure")
            if name == NETWORK_POLICY and self.no_ipv6 and len(value["spec"]["kprobes"]) > 1:
                self.loaded[name]["state"] = "TP_STATE_PARTIALLY_ENABLED"
                raise SetupError("mock IPv6 hook unavailable")
        elif action == "delete":
            self.loaded.pop(rest[0], None)
        else:
            raise AssertionError("Only mocked tracingpolicy operations are permitted")
        return 0, b""


class PolicyTests(unittest.TestCase):
    def test_no_argument_cli_has_no_effect(self):
        with mock.patch("observation_workflow.run_observations") as apply, mock.patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(observations.main([]), 0)
            apply.assert_not_called()

    def test_inline_raw_hook_and_strict_preceding_arguments(self):
        for name, (runtime, option) in INLINE.items():
            hook = policies()[name]["spec"]["tracepoints"][0]
            self.assertTrue(hook["raw"])
            self.assertEqual((hook["subsystem"], hook["event"]), ("sched", "sched_process_exec"))
            self.assertNotIn("args", hook)
            self.assertEqual(len(hook["selectors"]), 3)
            # All current options fit string_maps_0. Its v1.8.0 outer map has
            # eight slots even though the selector API permits five selectors.
            string_filters = sum(len(selector["matchCmdArgs"]) for selector in hook["selectors"])
            self.assertEqual(string_filters, 6)
            self.assertLessEqual(string_filters, 8)
            for index, selector in enumerate(hook["selectors"]):
                arguments = selector["matchCmdArgs"]
                self.assertEqual(len(arguments), index + 1)
                self.assertEqual(arguments[-1], {"index": index, "operator": "Equal", "values": [option]})
                for previous in arguments[:-1]:
                    self.assertEqual(previous["values"], PRIOR_SWITCHES[runtime])
                    self.assertNotIn("/tmp/script", previous["values"])
                    self.assertNotIn("--", previous["values"])
                    self.assertNotIn(option, previous["values"])

    def test_inline_coverage_stops_before_outer_string_map_capacity(self):
        self.assertEqual(INLINE_OPTION_POSITIONS, 3)
        for name, (_, option) in INLINE.items():
            selectors = policies()[name]["spec"]["tracepoints"][0]["selectors"]
            def matches(arguments):
                return any(all(part["index"] < len(arguments)
                               and arguments[part["index"]] in part["values"]
                               for part in selector["matchCmdArgs"]) for selector in selectors)
            runtime = INLINE[name][0]
            switch = PRIOR_SWITCHES[runtime][0]
            for count in (0, 1, 2):
                self.assertTrue(matches([switch] * count + [option, "fixture"]))
            self.assertFalse(matches([switch] * 3 + [option, "fixture"]))
            self.assertFalse(matches(["/tmp/fixture.script", option, "fixture"]))
            self.assertFalse(matches(["--", option, "fixture"]))

    def test_io_captures_only_finite_metadata(self):
        all_policies = policies()
        file = all_policies[FILE_POLICY]["spec"]["kprobes"][0]
        self.assertEqual(file["args"], [{"index": 0, "type": "file", "label": "target"}])
        self.assertEqual(file["returnArg"]["type"], "long")
        self.assertEqual(file["selectors"][0]["matchArgs"][0]["values"], list(DEFAULT_FILE_PREFIXES))
        for hook in all_policies[NETWORK_POLICY]["spec"]["kprobes"]:
            self.assertEqual(hook["args"], [{"index": 1, "type": "sockaddr", "label": "destination"}])
            self.assertEqual(hook["returnArg"]["type"], "int")
            self.assertTrue(hook["selectors"][0]["matchBinaries"])
        serialized = json.dumps(all_policies)
        for forbidden in ("char_buf", "Sigkill", "Override", "FollowFD", "Signal", "rateLimit"):
            self.assertNotIn(forbidden, serialized)
        for value in all_policies.values():
            self.assertEqual(value["spec"]["options"], [{"name": "policy-mode", "value": "monitor"}])

    def test_prefix_boundaries_and_ipv4_fallback(self):
        for bad in ([], ["/"], ["relative/"], ["/tmp"], ["/tmp/../"], ["/tmp/\n/"], ["/tmp/"] * 17):
            with self.subTest(bad=bad), self.assertRaises(SetupError):
                encoded_policies(bad)
        network = policies(network_families=("ipv4",))[NETWORK_POLICY]["spec"]["kprobes"]
        self.assertEqual([hook["call"] for hook in network], ["tcp_v4_connect"])

    def test_policy_ready_requires_monitor_only_and_every_loaded_hook(self):
        value = status("sample")
        self.assertTrue(enabled_monitor(value))
        for patch in ({"mode": "TP_MODE_ENFORCE"}, {"state": "TP_STATE_PARTIALLY_ENABLED"},
                      {"hook_statuses": []}, {"hook_statuses": [{"state": "STATUS_CALL_NOT_FOUND"}]}):
            self.assertFalse(enabled_monitor({**value, **patch}))

    def test_fixed_inline_tracepoints_may_omit_hook_status_but_not_policy_readiness(self):
        for name in INLINE:
            value = status(name)
            del value["hook_statuses"]
            self.assertTrue(enabled_monitor(value))
            self.assertTrue(enabled_monitor({**value, "hook_statuses": []}))
            self.assertTrue(enabled_monitor({**value, "hookStatuses": []}))
            for patch in ({"state": "TP_STATE_PARTIALLY_ENABLED"}, {"state": "TP_STATE_DISABLED"},
                          {"mode": "TP_MODE_MONITOR"}, {"mode": "TP_MODE_ENFORCE"},
                          {"error": "synthetic attach failure"}, {"hook_statuses": None},
                          {"hook_statuses": {}}, {"hook_statuses": [None]},
                          {"hook_statuses": [{"state": "STATUS_CALL_NOT_FOUND"}]}):
                with self.subTest(name=name, patch=patch):
                    self.assertFalse(enabled_monitor({**value, **patch}))
        for name in (FILE_POLICY, NETWORK_POLICY, "xeas-exec-unknown-c-v1", "foreign-inline-policy"):
            value = status(name)
            del value["hook_statuses"]
            self.assertFalse(enabled_monitor(value))
            self.assertFalse(enabled_monitor({**value, "hook_statuses": []}))

    def test_only_canonical_extra_names_can_extend_policy(self):
        value = policies(runtime_suffixes={"perl": ["perl5.36.0"], "php_fpm": ["php-fpm8.4"]})
        binary = value["xeas-exec-perl-e-v1"]["spec"]["tracepoints"][0]["selectors"][0]["matchBinaries"][0]
        self.assertIn("/perl5.36.0", binary["values"])
        for extra in ({"python": ["custom-interpreter"]}, {"php": ["/usr/bin/php"]}, {"other": ["java"]}):
            with self.subTest(extra=extra), self.assertRaises(SetupError):
                policies(runtime_suffixes=extra)


class ProbeTests(unittest.TestCase):
    def envelope(self, kind="process_tracepoint", **updates):
        value = {"process": {"pid": 23, "exec_id": "same-exec", "start_time": "2026-01-01T00:00:00Z", "binary": "/usr/bin/python3"},
                 "policy_name": next(iter(INLINE)), "subsys": "sched", "event": "sched_process_exec", "action": "KPROBE_ACTION_POST"}
        value.update(updates)
        return json.dumps({"time": "2026-01-01T00:00:01Z", kind: value})

    def test_identity_must_match_base_exec_and_no_raw_fields_retained(self):
        proof = EventProof()
        proof.accept(self.envelope())
        self.assertFalse(proof.matching(23, next(iter(INLINE))))
        proof.accept(self.envelope("process_exec"))
        self.assertTrue(proof.matching(23, next(iter(INLINE))))
        self.assertNotIn("arguments", json.dumps(proof.__dict__))
        wrong = {"pid": 23, "exec_id": "different-exec", "start_time": "2026-01-01T00:00:00Z", "binary": "/usr/bin/python3"}
        proof.accept(self.envelope("process_exec", process=wrong))
        self.assertFalse(proof.matching(23, next(iter(INLINE))))

    def test_unexcluded_private_fields_fail_closed(self):
        proof = EventProof()
        process = {"pid": 23, "exec_id": "same-exec", "start_time": "2026-01-01T00:00:00Z", "arguments": "synthetic-private"}
        with self.assertRaises(SetupError):
            proof.accept(self.envelope(process=process))
        self.assertNotIn("synthetic-private", json.dumps(proof.__dict__))

    def test_ipv6_without_actual_receipt_stays_unverified_and_ipv4_survives(self):
        stream, listener = mock.Mock(), mock.Mock()
        stream.run.return_value = 23
        stream.proof.matching.side_effect = lambda pid, policy, **facts: [True] if facts["function"] == "tcp_v4_connect" else []
        listener.getsockname.return_value = ("127.0.0.1", 45678)
        with mock.patch("observation_probes.socket.socket", return_value=listener):
            self.assertEqual(verify_network(stream, ("ipv4", "ipv6")), ["ipv4"])
        stream.proof.matching.return_value = []
        stream.proof.matching.side_effect = None
        with mock.patch("observation_probes.socket.socket", return_value=listener), self.assertRaises(SetupError):
            verify_network(stream, ("ipv4",))


class WorkflowTests(Fixture):
    def setUp(self):
        super().setUp()
        self.run_setup()
        self.runner = ObservationRunner(self.runner)
        self.before = self.paths.config.read_bytes()
        self.extra_patches = [mock.patch("observation_workflow.wait_health"), mock.patch("observation_workflow.verify_agent"),
                              mock.patch("observation_workflow.receipt_checkpoint", return_value={"since": 1, "events_received": 0}),
                              mock.patch("observation_workflow.verify_agent_receipt", return_value={"state": "verified", "capabilities": ["observation.file", "observation.network"]})]
        self.extra_mocks = [patch.start() for patch in self.extra_patches]

    def tearDown(self):
        for patch in reversed(self.extra_patches):
            patch.stop()
        super().tearDown()

    def apply(self, verifier=None):
        verifier = verifier or mock.Mock(return_value={"verified_runtime_policies": list(INLINE), "verified_network_families": ["ipv4", "ipv6"]})
        return run_observations(paths=self.paths, runner=self.runner, verifier=verifier)

    def test_success_preserves_other_configuration_and_repeat_does_not_restart(self):
        document = self.apply()
        before = yaml.safe_load(self.before)
        after = yaml.safe_load(self.paths.config.read_bytes())
        before["collector"]["tetragon"]["args"] = OBSERVATION_ARGS
        self.assertEqual(before, after)
        self.assertEqual(owned_policy_state(self.paths), document)
        self.assertEqual(self.paths.config.stat().st_mode & 0o777, 0o640)
        self.runner.calls.clear()
        self.apply()
        self.assertFalse(any("restart" in call for call in self.runner.calls))
        self.assertFalse(any("add" in call for call in self.runner.calls))
        # The original base installer must preserve owned policy/privacy state.
        self.assertEqual(prepare_config(self.paths.config)[0], prepare_config(self.paths.config)[1])
        self.run_setup()

    def test_verification_failure_restores_all_and_can_retry(self):
        with self.assertRaises(SetupError):
            self.apply(mock.Mock(side_effect=SetupError("synthetic no events")))
        self.assertEqual(self.paths.config.read_bytes(), self.before)
        self.assertFalse(manifest_path(self.paths).exists())
        self.assertFalse(list(self.paths.policies.iterdir()))
        self.assertEqual(self.runner.loaded, {})
        self.assertTrue(self.runner.active["sentineld.service"])
        self.apply()

    def test_sensor_success_but_agent_receipt_failure_restores_all(self):
        self.extra_mocks[3].side_effect = SetupError("synthetic agent has no observation receipt")
        verifier = mock.Mock(return_value={"verified_runtime_policies": list(INLINE), "verified_network_families": ["ipv4"]})
        with self.assertRaises(SetupError):
            self.apply(verifier)
        verifier.assert_called_once()
        self.assertEqual(self.paths.config.read_bytes(), self.before)
        self.assertFalse(manifest_path(self.paths).exists())
        self.assertFalse(list(self.paths.policies.iterdir()))
        self.assertEqual(self.runner.loaded, {})
        self.assertTrue(self.runner.active["sentineld.service"])

    def test_receipt_boundary_precedes_probes_and_runtime_receipt_follows_verified_scope(self):
        order = []
        self.extra_mocks[2].side_effect = lambda *args: order.append("checkpoint") or {"since": 1, "events_received": 0}
        self.extra_mocks[3].side_effect = lambda *args, **kwargs: order.append(("receipt", kwargs["interpreter"])) or {"state": "verified"}
        proof = {"verified_runtime_policies": [], "verified_network_families": ["ipv4"]}
        document = self.apply(lambda *args: order.append("sensor") or proof)
        self.assertEqual(order, ["checkpoint", "sensor", ("receipt", False)])
        self.assertEqual(document["agent_receipt"]["state"], "verified")
        order.clear()
        self.apply(lambda *args: order.append("sensor") or {**proof, "verified_runtime_policies": list(INLINE)})
        self.assertEqual(order, ["checkpoint", "sensor", ("receipt", True)])

    def test_policy_attach_failure_rolls_back_partial_api_add(self):
        self.runner.fail_policy = "xeas-exec-node-e-v1"
        with self.assertRaises(SetupError):
            self.apply()
        self.assertEqual(self.runner.loaded, {})
        self.assertEqual(self.paths.config.read_bytes(), self.before)

    def test_discovery_uses_resolved_canonical_package_name(self):
        directory = self.paths.at("/usr/bin")
        (directory / "perl5.36.0").write_bytes(b"fixture, never execute")
        (directory / "perl").symlink_to(directory / "perl5.36.0")
        discovered = discover_runtime_names(self.paths.root)
        self.assertEqual(discovered["perl"], ["perl5.36.0"])
        self.assertNotIn("custom-runtime", discovered)

    def test_ipv6_missing_keeps_ipv4_monitoring(self):
        self.runner.no_ipv6 = True
        document = self.apply(mock.Mock(return_value={"verified_runtime_policies": [], "verified_network_families": ["ipv4"]}))
        self.assertEqual(document["network_families"], ["ipv4"])
        self.assertEqual(owned_policy_state(self.paths), document)

    def test_foreign_policy_or_modified_owned_file_fails_before_mutation(self):
        self.runner.loaded[FILE_POLICY] = {**status(FILE_POLICY), "domain": "grpc"}
        with self.assertRaises(SetupError):
            self.apply()
        self.assertEqual(self.paths.config.read_bytes(), self.before)
        self.runner.loaded.clear()
        self.apply()
        (self.paths.policies / (FILE_POLICY + ".yaml")).write_bytes(b"foreign policy")
        self.runner.calls.clear()
        with self.assertRaises(SetupError):
            self.apply()
        self.assertFalse(any("add" in call or "delete" in call or "restart" in call for call in self.runner.calls))

    def test_failed_backup_or_agent_verification_restores_services(self):
        with mock.patch("observation_workflow._backup", side_effect=OSError("synthetic backup failure")), self.assertRaises(OSError):
            self.apply()
        self.assertEqual(self.paths.config.read_bytes(), self.before)
        self.assertFalse(self.runner.loaded)
        self.extra_mocks[1].side_effect = SetupError("synthetic agent failure")
        with self.assertRaises(SetupError):
            self.apply()
        self.assertEqual(self.paths.config.read_bytes(), self.before)
        self.assertFalse(self.runner.loaded)


if __name__ == "__main__":
    unittest.main()
