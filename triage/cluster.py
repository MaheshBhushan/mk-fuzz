"""Cluster fuzzer crashes by stack trace so duplicates collapse per root cause.

Each crashing input is replayed against the target (stdin, standalone mode)
and its sanitizer report is parsed into a normalised signature: the fault kind
plus the innermost application frames. Signatures are featurised with TF-IDF
over frame tokens and frame bigrams, then grouped with scikit-learn's
agglomerative clustering on cosine distance. Every cluster gets one minimal
repro, shrunk by delta debugging while the trace stays in the same cluster.

    python triage/cluster.py -i out/crashes -o out/triage -- build/toy_parser
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction.text import TfidfVectorizer

FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)(?:\s+(\S+))?")
ASAN_RE = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)")
UBSAN_RE = re.compile(r"runtime error: ([^\n]+)")
# Frames from sanitizers, libc, and the mk-fuzz runtime say nothing about the bug.
NOISE = re.compile(r"^(__asan|__sanitizer|__interceptor|__ubsan|__libc|__GI_|_start$|"
                   r"abort$|raise$|__assert|__pthread|pthread_kill|main$|run_one|"
                   r"__memcpy|__memmove|memcpy$|memmove$|memset$|strcpy$|gsignal$)")
DEFAULT_ENV = {"ASAN_OPTIONS": "abort_on_error=1:handle_abort=1:detect_leaks=0:symbolize=1"}


def parse_trace(text, exit_code=None, depth=5):
    """Return {kind, frames} for a sanitizer/stderr report."""
    kind = None
    if m := ASAN_RE.search(text):
        kind = m.group(1)
    elif m := UBSAN_RE.search(text):
        kind = "ubsan:" + re.sub(r"[^a-z]+", "-", m.group(1).lower()).strip("-")[:40]
    elif "Assertion" in text:
        kind = "assertion"
    elif exit_code is not None and exit_code < 0:
        kind = f"signal-{-exit_code}"
    frames, stacks = [], 0
    for line in text.splitlines():
        if not (m := FRAME_RE.match(line)):
            continue
        if m.group(1) == "0":
            stacks += 1
            if stacks > 1:
                break  # a second stack (e.g. allocation site) starts; keep the crash stack
        func = m.group(2)
        if NOISE.match(func):
            continue
        loc = Path(m.group(3).split(":")[0]).name if m.group(3) else ""
        if loc == "rt.c":
            continue
        frames.append(func)
        if len(frames) == depth:
            break
    return {"kind": kind or "unknown", "frames": frames}


def signature_doc(sig):
    """Token document: kind, frames weighted by depth, and caller->callee bigrams."""
    toks = [f"kind:{sig['kind']}"]
    for i, f in enumerate(sig["frames"]):
        toks += [f"fn:{f}"] * max(1, 3 - i) + [f"at{i}:{f}"]
    toks += [f"edge:{a}>{b}" for a, b in zip(sig["frames"][1:], sig["frames"])]
    return " ".join(toks)


def cluster(sigs, threshold=0.5):
    """Label each signature; identical signatures always share a label.

    Different fault kinds never merge. Within a kind, traces group by
    agglomerative clustering on cosine distance between TF-IDF vectors.
    """
    raw = [None] * len(sigs)
    by_kind = {}
    for i, s in enumerate(sigs):
        by_kind.setdefault(s["kind"], []).append(i)
    for kind, idx in by_kind.items():
        docs = [signature_doc(sigs[i]) for i in idx]
        if len(set(docs)) == 1:
            sub = [0] * len(idx)
        else:
            vec = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, sublinear_tf=True)
            x = vec.fit_transform(docs).toarray()
            model = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold,
                                            metric="cosine", linkage="average")
            sub = model.fit_predict(x)
        for i, label in zip(idx, sub):
            raw[i] = (kind, int(label))
    # Renumber by first appearance so output is deterministic.
    order = {}
    return [order.setdefault(r, len(order)) for r in raw]


def replay(cmd, data, timeout, env):
    run_env = {**os.environ, **env}
    try:
        p = subprocess.run(cmd, input=data, capture_output=True, timeout=timeout, env=run_env)
    except subprocess.TimeoutExpired:
        return None, ""
    return p.returncode, p.stderr.decode("utf-8", "replace")


def crashed(code):
    return code is not None and code != 0


def minimise(data, still_same, max_tests=500):
    """ddmin-style chunk removal, then byte simplification, under a test budget."""
    tests = 0
    n = 2
    while len(data) >= 2 and tests < max_tests:
        chunk = max(1, len(data) // n)
        shrunk = False
        for start in range(0, len(data), chunk):
            cand = data[:start] + data[start + chunk:]
            tests += 1
            if cand and still_same(cand):
                data, n, shrunk = cand, max(n - 1, 2), True
                break
            if tests >= max_tests:
                break
        if not shrunk:
            if chunk == 1:
                break
            n = min(len(data), n * 2)
    return data


def triage(inputs, cmd, threshold=0.5, timeout=5.0, env=DEFAULT_ENV, depth=5,
           shrink=True, max_tests=500):
    records = []
    for path in inputs:
        data = path.read_bytes()
        code, err = replay(cmd, data, timeout, env)
        if not crashed(code):
            records.append({"input": str(path), "reproduced": False})
            continue
        records.append({"input": str(path), "reproduced": True, "data": data,
                        "exit_code": code, "sig": parse_trace(err, code, depth)})
    live = [r for r in records if r["reproduced"]]
    labels = cluster([r["sig"] for r in live], threshold)
    clusters = {}
    for r, label in zip(live, labels):
        clusters.setdefault(label, []).append(r)

    report = []
    for label, members in sorted(clusters.items()):
        rep = min(members, key=lambda r: (len(r["data"]), r["input"]))
        target_sig = rep["sig"]

        def same(cand, target_sig=target_sig):
            code, err = replay(cmd, cand, timeout, env)
            return crashed(code) and parse_trace(err, code, depth) == target_sig

        repro = minimise(rep["data"], same, max_tests) if shrink else rep["data"]
        report.append({"cluster": label, "kind": target_sig["kind"],
                       "frames": target_sig["frames"], "count": len(members),
                       "inputs": sorted(m["input"] for m in members),
                       "repro": repro, "original_len": len(rep["data"])})
    skipped = [r["input"] for r in records if not r["reproduced"]]
    return report, skipped


def write_report(report, skipped, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    summary = []
    lines = ["# Crash clusters", ""]
    for c in report:
        d = out / f"cluster_{c['cluster']:03d}"
        d.mkdir(exist_ok=True)
        (d / "repro").write_bytes(c["repro"])
        entry = {k: v for k, v in c.items() if k != "repro"}
        entry["repro"] = str(d / "repro")
        entry["repro_len"] = len(c["repro"])
        entry["repro_hex"] = c["repro"].hex()
        summary.append(entry)
        top = " <- ".join(c["frames"]) or "(no frames)"
        lines.append(f"- cluster {c['cluster']}: {c['kind']} in {top} — {c['count']} crash(es), "
                     f"repro {len(c['repro'])}B (from {c['original_len']}B)")
    if skipped:
        lines += ["", f"{len(skipped)} input(s) did not reproduce."]
    (out / "clusters.json").write_text(json.dumps({"clusters": summary, "not_reproduced": skipped},
                                                  indent=2) + "\n")
    (out / "README.md").write_text("\n".join(lines) + "\n")
    return summary


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: cluster.py -i CRASH_DIR -o OUT_DIR [options] -- TARGET [ARGS...]",
              file=sys.stderr)
        return 2
    split = argv.index("--")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--input", required=True, help="directory of crashing inputs")
    ap.add_argument("-o", "--output", required=True, help="directory for cluster reports")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="cosine distance below which traces merge (default 0.5)")
    ap.add_argument("--depth", type=int, default=5, help="application frames kept per trace")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--max-tests", type=int, default=500, help="minimisation budget per cluster")
    ap.add_argument("--no-minimise", action="store_true")
    args = ap.parse_args(argv[:split])
    cmd = argv[split + 1:]
    if not cmd:
        ap.error("missing target command after --")
    inputs = sorted(p for p in Path(args.input).iterdir() if p.is_file())
    report, skipped = triage(inputs, cmd, args.threshold, args.timeout, depth=args.depth,
                             shrink=not args.no_minimise, max_tests=args.max_tests)
    write_report(report, skipped, args.output)
    print(f"[triage] {len(inputs)} input(s) -> {len(report)} cluster(s); "
          f"{len(skipped)} not reproduced; report in {args.output}/README.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
