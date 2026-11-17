"""Agent receipt checks use synthetic status only, never host API or BPF."""

import copy
import datetime
import unittest
from unittest import mock

from observation_agent import (FILE_CAPABILITY, INTERPRETER_CAPABILITY, NETWORK_CAPABILITY,
                               observation_receipt_ready, receipt_checkpoint, verify_agent_receipt)
from setup_common import SetupError


SINCE = 1760000000.0


def stamp(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()


def agent_status():
    capability = {"state": "limited", "implementation": "implemented", "runtime_state": "active",
                  "verified_at": stamp(SINCE + 1)}
    return {"collector": "tetragon-json", "mode": "active", "health": "healthy",
            "collector_health": {"running": True, "events_received": 11},
            "capability_report": {"capabilities": {name: dict(capability) for name in
                ("collector.tetragon", "observation.process_exec", FILE_CAPABILITY,
                 NETWORK_CAPABILITY, INTERPRETER_CAPABILITY)}}}


class AgentReceiptTests(unittest.TestCase):
    checkpoint = {"since": SINCE, "events_received": 10}

    def ready(self, status, **kwargs):
        return observation_receipt_ready(status, self.checkpoint, now=SINCE + 2, **kwargs)

    def test_probe_boundary_requires_implemented_observation_support(self):
        runner = mock.Mock()
        status = agent_status()
        with mock.patch("observation_agent.read_agent", return_value=status), mock.patch("observation_agent.time.time", return_value=SINCE):
            self.assertEqual(receipt_checkpoint(runner, "/fixture.sock"), {"since": SINCE, "events_received": 11})
        for name in (FILE_CAPABILITY, NETWORK_CAPABILITY):
            for implementation in (None, "planned", "future"):
                with self.subTest(name=name, implementation=implementation):
                    status = agent_status()
                    status["capability_report"]["capabilities"][name]["implementation"] = implementation
                    with mock.patch("observation_agent.read_agent", return_value=status), self.assertRaises(SetupError):
                        receipt_checkpoint(runner, "/fixture.sock")
        for status in ({}, {"capability_report": None}, {"capability_report": {"capabilities": []}}):
            with mock.patch("observation_agent.read_agent", return_value=status), self.assertRaises(SetupError):
                receipt_checkpoint(runner, "/fixture.sock")
        runner.command.assert_not_called()

    def test_supported_agent_needs_fresh_receipt_of_each_scoped_capability(self):
        status = agent_status()
        before = copy.deepcopy(status)
        self.assertTrue(self.ready(status, interpreter=True))
        self.assertEqual(status, before)
        for name in (FILE_CAPABILITY, NETWORK_CAPABILITY, INTERPRETER_CAPABILITY):
            for patch in ({"runtime_state": "unverified"}, {"runtime_state": "available"},
                          {"runtime_state": "error"}, {"implementation": "planned"},
                          {"state": "future"}, {"verified_at": None}, {"verified_at": "invalid"},
                          {"verified_at": stamp(SINCE - 1)}, {"verified_at": stamp(SINCE + 100)}):
                with self.subTest(name=name, patch=patch):
                    value = agent_status()
                    value["capability_report"]["capabilities"][name].update(patch)
                    self.assertFalse(self.ready(value, interpreter=True))
        for name in (FILE_CAPABILITY, NETWORK_CAPABILITY):
            status = agent_status()
            del status["capability_report"]["capabilities"][name]
            self.assertFalse(self.ready(status))

    def test_optional_unprobed_runtime_does_not_fabricate_runtime_verification(self):
        status = agent_status()
        del status["capability_report"]["capabilities"][INTERPRETER_CAPABILITY]
        self.assertTrue(self.ready(status))
        self.assertFalse(self.ready(status, interpreter=True))

    def test_old_exec_only_agent_and_failed_or_unchanged_stream_are_rejected(self):
        status = agent_status()
        for name in (FILE_CAPABILITY, NETWORK_CAPABILITY, INTERPRETER_CAPABILITY):
            del status["capability_report"]["capabilities"][name]
        self.assertFalse(self.ready(status))
        for patch in ({"health": "error"}, {"mode": "degraded"}, {"collector": "audit-dispatcher"},
                      {"last_error": "synthetic storage failure"}):
            value = agent_status()
            value.update(patch)
            self.assertFalse(self.ready(value))
        for patch in ({"running": False}, {"events_received": 10}, {"events_received": True},
                      {"last_error": "synthetic reader failure"}):
            value = agent_status()
            value["collector_health"].update(patch)
            self.assertFalse(self.ready(value))

    def test_passive_disagreement_does_not_discard_actual_receipt(self):
        for support in ("unsupported", "error"):
            status = agent_status()
            for name in (FILE_CAPABILITY, NETWORK_CAPABILITY, INTERPRETER_CAPABILITY):
                status["capability_report"]["capabilities"][name]["state"] = support
            self.assertTrue(self.ready(status, interpreter=True))

    def test_success_returns_only_receipt_metadata_not_process_or_diagnostic_data(self):
        status = agent_status()
        status["capability_report"]["capabilities"][FILE_CAPABILITY]["reason"] = "PRIVATE_MARKER"
        with mock.patch("observation_agent.read_agent", return_value=status), mock.patch("observation_agent.time.time", return_value=SINCE + 2):
            result = verify_agent_receipt(mock.Mock(), "/fixture.sock", self.checkpoint, interpreter=True)
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["capabilities"], [FILE_CAPABILITY, NETWORK_CAPABILITY, INTERPRETER_CAPABILITY])
        self.assertEqual(result["received_at"][FILE_CAPABILITY], stamp(SINCE + 1))
        self.assertNotIn("PRIVATE_MARKER", str(result))
        self.assertNotIn("payload", result)

    def test_sensor_only_evidence_times_out_without_claiming_agent_receipt(self):
        old = agent_status()
        del old["capability_report"]["capabilities"][FILE_CAPABILITY]
        with mock.patch("observation_agent.read_agent", return_value=old), \
             mock.patch("observation_agent.time.monotonic", side_effect=[0, 0, 21]), \
             mock.patch("observation_agent.time.sleep"), \
             self.assertRaisesRegex(SetupError, "센서 이벤트는 확인했지만.*실제 수신은 확인하지 못해"):
            verify_agent_receipt(mock.Mock(), "/fixture.sock", self.checkpoint)


if __name__ == "__main__":
    unittest.main()
