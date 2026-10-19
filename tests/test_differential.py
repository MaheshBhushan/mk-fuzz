"""Exercise real ASan parsers and the harness's failure and replay paths."""
import contextlib
import io
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

from differential.replay import compare, main, preserve, run_parser

ROOT = Path(__file__).resolve().parents[1]
LEGACY = [str(ROOT / "build/parameters_legacy")]
MIGRATED = [str(ROOT / "build/parameters_migrated")]


def fake(result, code):
    return [sys.executable, "-c", f"import sys; print({json.dumps(result)!r}); sys.exit({code})"]


class DifferentialTests(unittest.TestCase):
    def test_shared_fixtures_and_oracles(self):
        for fixture in sorted((ROOT / "tests/fixtures").glob("parameters*.json")):
            cases = json.loads(fixture.read_text(encoding="utf-8"))
            for case in cases:
                with self.subTest(case=case["name"]):
                    matches, report = compare(bytes.fromhex(case["hex"]), LEGACY,
                                              MIGRATED, expected=case["expected"])
                    self.assertTrue(matches, report)

    def test_deterministic_mutations(self):
        rng = random.Random(20261019)
        seeds = [bytes.fromhex(case["hex"]) for case in json.loads(
            (ROOT / "tests/fixtures/parameters.json").read_text(encoding="utf-8"))]
        for index in range(96):
            data = bytearray(rng.choice(seeds))
            for _ in range(rng.randint(1, 4)):
                where = rng.randrange(len(data) + 1)
                if rng.randrange(2):
                    data[where:where] = bytes([rng.randrange(256)])
                elif where < len(data):
                    data[where] = rng.randrange(256)
            matches, report = compare(bytes(data), LEGACY, MIGRATED)
            if not matches:
                preserve(ROOT / "out_diff/counterexamples", bytes(data),
                         {"name": f"mutation/{index}", "seed": 20261019, **report})
            self.assertTrue(matches, (index, data.hex(), report))

    def test_values_reasons_and_oracles_are_compared(self):
        accepted = {"status": "ok", "count": 2, "offset": 0, "mode": "safe"}
        syntax = {"status": "reject", "reason": "syntax"}
        range_error = {"status": "reject", "reason": "range"}
        pairs = [(fake(accepted, 0), MIGRATED, None),
                 (fake(syntax, 2), fake(range_error, 2), None),
                 (fake(syntax, 2), MIGRATED, None),
                 (MIGRATED, MIGRATED, accepted)]
        for left, right, expected in pairs:
            self.assertFalse(compare(b"count=1", left, right, expected=expected)[0])
        # Formatting and object order do not change valid semantics.
        self.assertTrue(compare(b"count=2", fake(accepted, 0), MIGRATED)[0])

    def test_crash_timeout_stderr_and_bad_protocol_never_match(self):
        commands = [([sys.executable, "-c", "raise SystemExit(3)"], "execution"),
                    ([sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"],
                     "execution"),
                    ([sys.executable, "-c", "import time; time.sleep(5)"], "timeout"),
                    ([sys.executable, "-c", "print('not json')"], "protocol"),
                    (fake({"status": "ok"}, 0), "protocol"),
                    (fake({"status": "reject", "reason": "range"}, 0), "protocol"),
                    (fake({"status": "ok", "count": True, "offset": 0, "mode": "safe"}, 0),
                     "protocol"),
                    ([sys.executable, "-c", "import sys; sys.stderr.write('AddressSanitizer: fault')"],
                     "execution"),
                    ([str(ROOT / "build/nonexistent-parser")], "launch")]
        for command, reason in commands:
            with self.subTest(reason=reason):
                self.assertEqual(run_parser(command, b"", 0.2)["failure"], reason)
                self.assertFalse(compare(b"", command, command, timeout=0.2)[0])

    def test_counterexample_cli_roundtrip_and_dedup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixtures.json"
            data = b"count=7\x00\xff"
            fixture.write_text(json.dumps([{"name": "binary", "hex": data.hex(),
                                           "expected": {"status": "reject", "reason": "syntax"}}]),
                               encoding="utf-8")
            # Swap real executables via an on-disk script to exercise CLI preservation.
            wrapper = root / "wrong.py"
            wrapper.write_text("#!/usr/bin/env python3\nimport sys\n"
                               "print('{\"status\":\"reject\",\"reason\":\"range\"}')\n"
                               "sys.exit(2)\n", encoding="utf-8")
            wrapper.chmod(0o755)
            out = root / "saved"
            arguments = ["--legacy", LEGACY[0], "--migrated", str(wrapper),
                         "--fixtures", str(fixture), "--out", str(out)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 1)
            raw, = out.glob("*.bin")
            self.assertEqual(raw.read_bytes(), data)
            metadata = raw.with_suffix(".json").read_bytes()
            self.assertEqual(preserve(out, data, {"replacement": True}), raw)
            self.assertEqual(raw.with_suffix(".json").read_bytes(), metadata)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--legacy", LEGACY[0], "--migrated", MIGRATED[0],
                                       "--replay", str(out)]), 0)

    def test_cli_rejects_vacuous_success(self):
        with tempfile.TemporaryDirectory() as directory:
            for extra in ([], ["--replay", directory], ["--timeout", "nan"],
                          ["--replay", str(Path(directory) / "absent")]):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    main(["--legacy", LEGACY[0], "--migrated", MIGRATED[0], *extra])
                self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
