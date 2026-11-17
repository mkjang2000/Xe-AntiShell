"""Network proof subprocess compatibility; no kernel or real sockets used."""

from enum import IntEnum
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from observation_probes import ProbeStream, verify_network
from setup_common import SetupError


class Python39Family(IntEnum):
    AF_INET = 2
    AF_INET6 = 10

    def __str__(self):
        # Python <3.11 IntEnum used its symbolic name, not its integer value.
        return "AddressFamily." + self.name


class NetworkProbeTests(unittest.TestCase):
    def test_child_receives_numeric_family_on_python39_and_newer(self):
        listener, stream = mock.Mock(), mock.Mock()
        listener.getsockname.return_value = ("127.0.0.1", 12345)
        stream.proof.matching.return_value = [True]
        child_families = []

        def run(args):
            # Exactly the conversion made inside the benign child script.
            child_families.append(int(args[3]))
            return 71

        stream.run.side_effect = run
        with mock.patch("observation_probes.socket.AF_INET", Python39Family.AF_INET), \
                mock.patch("observation_probes.socket.AF_INET6", Python39Family.AF_INET6), \
                mock.patch("observation_probes.socket.socket", return_value=listener):
            self.assertEqual(verify_network(stream, ("ipv4", "ipv6")), ["ipv4", "ipv6"])
        self.assertEqual(child_families, [2, 10])

    def test_nonzero_benign_child_is_fixed_failure_and_always_cleaned(self):
        child = mock.Mock(pid=71)
        child.wait.return_value = 1
        with mock.patch("observation_probes.subprocess.Popen", return_value=child) as launch, \
                mock.patch("observation_probes.stop_child") as cleanup:
            with self.assertRaisesRegex(SetupError, "무해한 관측 확인 프로세스가 실패했습니다"):
                ProbeStream().run(["/fixture/benign-program"])
            self.assertIs(launch.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertIs(launch.call_args.kwargs["stdout"], subprocess.DEVNULL)
            self.assertIs(launch.call_args.kwargs["stderr"], subprocess.DEVNULL)
            cleanup.assert_called_once_with(child)

    def test_success_returns_pid_and_always_cleans_child(self):
        child = mock.Mock(pid=71)
        child.wait.return_value = 0
        with mock.patch("observation_probes.subprocess.Popen", return_value=child), \
                mock.patch("observation_probes.stop_child") as cleanup:
            self.assertEqual(ProbeStream().run(["/fixture/benign-program"]), 71)
            cleanup.assert_called_once_with(child)


if __name__ == "__main__":
    unittest.main()
