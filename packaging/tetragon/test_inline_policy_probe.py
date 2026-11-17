"""Verify bounded inline probes without launching runtimes or attaching BPF."""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

from observation_policies import INLINE, PRIOR_SWITCHES, policies
from observation_probes import verify_inline
from setup_common import SetupError


class InlineStream:
    def __init__(self, *, missing_preceding=False, broad_match=False, missing_negative_exec=False):
        self.calls = []
        self.proof = mock.Mock()
        self.proof.executions = {}
        self.proof.matching.side_effect = self.matching
        self.missing_preceding = missing_preceding
        self.broad_match = broad_match
        self.missing_negative_exec = missing_negative_exec

    def run(self, args):
        self.calls.append(args)
        pid = len(self.calls)
        if not self.missing_negative_exec or pid != 4:
            self.proof.executions[pid] = "fixture-exec-" + str(pid)
        return pid

    def drain(self, duration):
        pass

    def matching(self, pid, name):
        if self.missing_preceding and pid == 2:
            return []
        if self.broad_match and pid == 5:
            return ["incorrect-beyond-bound-proof"]
        arguments = self.calls[pid - 1][1:]
        selectors = policies()[name]["spec"]["tracepoints"][0]["selectors"]
        matched = any(all(part["index"] < len(arguments) and arguments[part["index"]] in part["values"]
                          for part in selector["matchCmdArgs"]) for selector in selectors)
        return ["fixture-proof"] if matched else []


class InlineProbeTests(unittest.TestCase):
    def verify(self, stream):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("observation_probes.runtime_binary", side_effect=lambda runtime: "/fixture/python3" if runtime == "python" else None):
            return verify_inline(stream, Path(directory))

    def test_zero_one_two_switch_positives_and_beyond_bound_negative(self):
        stream = InlineStream()
        self.assertEqual(self.verify(stream), [next(iter(INLINE))])
        switch = PRIOR_SWITCHES["python"][0]
        self.assertEqual(len(stream.calls), 5)
        for count in range(3):
            self.assertEqual(stream.calls[count], ["/fixture/python3"] + [switch] * count + ["-c", "pass"])
        self.assertTrue(stream.calls[3][1].endswith("python.script"))
        self.assertEqual(stream.calls[4], ["/fixture/python3"] + [switch] * 3 + ["-c", "pass"])

    def test_missing_positive_overbroad_negative_or_absent_exec_cannot_verify(self):
        for options in ({"missing_preceding": True}, {"broad_match": True}, {"missing_negative_exec": True}):
            with self.subTest(options=options), self.assertRaises(SetupError):
                self.verify(InlineStream(**options))


if __name__ == "__main__":
    unittest.main()
