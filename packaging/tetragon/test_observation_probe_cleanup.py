"""Interrupted smoke probes must not leave subprocesses behind."""

import subprocess
import datetime
import unittest
from unittest import mock

from observation_probes import ProbeStream
from setup_common import SetupError
from setup_runtime import timestamp


class ProbeCleanupTests(unittest.TestCase):
    def test_protobuf_nanosecond_timestamps_on_python39(self):
        expected = datetime.datetime(2026, 11, 17, 13, 33, 12, 123456, tzinfo=datetime.timezone.utc).timestamp()
        self.assertEqual(timestamp("2026-11-17T13:33:12.123456789Z"), expected)
        self.assertEqual(timestamp("2026-11-17T22:33:12.123456789+09:00"), expected)
        for invalid in (None, {}, "2026-11-17", "2026-11-17T13:33:12", "2026-99-17T13:33:12Z", "2026-11-17T13:33:12.1234567890Z"):
            self.assertEqual(timestamp(invalid), 0)

    def test_interruption_and_timeout_stop_probe_process(self):
        for interruption in (KeyboardInterrupt(), subprocess.TimeoutExpired("probe", 5)):
            with self.subTest(interruption=type(interruption).__name__):
                child = mock.Mock(stdout=None)
                child.wait.side_effect = [interruption, 0]
                child.poll.return_value = None
                expected = KeyboardInterrupt if isinstance(interruption, KeyboardInterrupt) else SetupError
                with mock.patch("observation_probes.subprocess.Popen", return_value=child):
                    with self.assertRaises(expected):
                        ProbeStream().run(["/usr/bin/true"])
                child.terminate.assert_called_once()
                self.assertEqual(child.wait.call_count, 2)
