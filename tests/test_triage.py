"""Crash clustering: trace parsing, scikit-learn grouping, and per-cluster repros."""
import json
import tempfile
import unittest
from pathlib import Path

from triage.cluster import cluster, main, minimise, parse_trace

ROOT = Path(__file__).resolve().parents[1]
TOY = ROOT / "build/toy_parser"


def asan(kind, *funcs):
    lines = [f"==1==ERROR: AddressSanitizer: {kind} on address 0x1234"]
    lines += [f"    #0 0xdead in __asan_memcpy (/bin/x+0x1)"]
    lines += [f"    #{i + 1} 0xbeef in {f} /src/{f}.c:{i + 3}:5" for i, f in enumerate(funcs)]
    lines += [f"    #{len(funcs) + 1} 0xcafe in main /src/rt.c:130:5"]
    return "\n".join(lines)


class ParseTests(unittest.TestCase):
    def test_strips_runtime_frames_and_second_stack(self):
        text = asan("heap-buffer-overflow", "parse_rec", "parse_file") + \
            "\n    #0 0x1 in malloc /x\n    #1 0x2 in alloc_site /src/a.c:1"
        sig = parse_trace(text)
        self.assertEqual(sig, {"kind": "heap-buffer-overflow",
                               "frames": ["parse_rec", "parse_file"]})

    def test_signal_without_report(self):
        self.assertEqual(parse_trace("", -11), {"kind": "signal-11", "frames": []})


class ClusterTests(unittest.TestCase):
    def test_duplicates_collapse_and_root_causes_split(self):
        sigs = [parse_trace(t) for t in [
            asan("stack-buffer-overflow", "copy_rec", "parse", "entry"),
            asan("stack-buffer-overflow", "copy_rec", "parse", "entry"),
            asan("stack-buffer-overflow", "copy_rec", "parse", "other_entry"),
            asan("heap-use-after-free", "free_list", "teardown"),
            asan("heap-use-after-free", "free_list", "teardown"),
        ]]
        labels = cluster(sigs)
        self.assertEqual(labels[0], labels[1])
        self.assertEqual(labels[0], labels[2])  # same crash site, different caller
        self.assertEqual(labels[3], labels[4])
        self.assertNotEqual(labels[0], labels[3])
        self.assertEqual(len(set(labels)), 2)

    def test_single_and_empty(self):
        self.assertEqual(cluster([]), [])
        self.assertEqual(cluster([parse_trace(asan("x", "f"))]), [0])


class MinimiseTests(unittest.TestCase):
    def test_keeps_predicate(self):
        out = minimise(b"xxxxMAGICyyyyzzzz", lambda d: b"MAGIC" in d)
        self.assertEqual(out, b"MAGIC")


@unittest.skipUnless(TOY.exists(), "run `make build/toy_parser` first")
class ToyTargetTests(unittest.TestCase):
    def test_two_planted_bugs_give_two_clusters_with_minimal_repros(self):
        crashes = [b"MKF1\x01\x03\xff\x00\x00trailing", b"MKF1\x02\x02\xff\x01junkjunkjunk",
                   b"MKF1\x01\x14" + b"A" * 20 + b"tail", b"MKF1\x01\x20" + b"B" * 40,
                   b"MKF1\x00not-a-crash"]
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp, "crashes"), Path(tmp, "triage")
            src.mkdir()
            for i, c in enumerate(crashes):
                (src / f"id_{i:06d}").write_bytes(c)
            self.assertEqual(main(["-i", str(src), "-o", str(out), "--", str(TOY)]), 0)
            report = json.loads((out / "clusters.json").read_text())
            by_kind = {c["kind"]: c for c in report["clusters"]}
            self.assertEqual(set(by_kind), {"ABRT", "stack-buffer-overflow"})
            self.assertEqual(by_kind["ABRT"]["count"], 2)
            self.assertEqual(by_kind["stack-buffer-overflow"]["count"], 2)
            self.assertEqual(len(report["not_reproduced"]), 1)
            for c in report["clusters"]:
                repro = Path(c["repro"]).read_bytes()
                self.assertTrue(repro.startswith(b"MKF1"))
                self.assertLess(len(repro), c["original_len"])
                self.assertIn("LLVMFuzzerTestOneInput", c["frames"])


if __name__ == "__main__":
    unittest.main()
