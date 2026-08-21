#!/usr/bin/env python3
"""
Turn results/*.{csv,json} into the summary table and the coverage-over-time
plot.

Reporting rules, chosen before looking at any numbers:

  * Median and full range (min..max) per configuration, never mean +- sd.
    Coverage-vs-execs across seeds is skewed and n=5 is far too small for a
    normal-theory interval to mean anything.
  * A configuration with fewer than 5 seeds is a hard failure, not a footnote.
  * Comparisons against baseline are PAIRED by seed: seed k gives both arms the
    same RNG start and the same seed corpus, so the pairing is real. With n=5
    the only defensible test is an exact sign test, and its best possible
    p-value is 1/32 = 0.031 -- reported as such, with no dressing up.
"""
import csv
import json
import math
import os
import statistics
import sys
from collections import defaultdict

SEED_FLOOR = 5


def load(results):
    runs = {}          # (target, sched, seed) -> summary dict
    curves = {}        # (target, sched, seed) -> (execs[], edges[])
    for fn in sorted(os.listdir(results)):
        path = os.path.join(results, fn)
        stem, ext = os.path.splitext(fn)
        parts = stem.split(".")
        if len(parts) != 3 or not parts[2].startswith("s"):
            continue
        target, sched, seed = parts[0], parts[1], int(parts[2][1:])
        key = (target, sched, seed)
        if ext == ".json":
            # A run killed mid-flight leaves a zero-byte or truncated summary.
            # Skip it rather than crashing: the seed-count gate below is what
            # decides whether the remaining runs are enough, and a hard crash
            # here would throw away every other result in the directory.
            try:
                with open(path) as f:
                    runs[key] = json.load(f)
            except (json.JSONDecodeError, ValueError):
                print(f"warning: ignoring incomplete summary {fn}", file=sys.stderr)
        elif ext == ".csv":
            ex, ed = [], []
            with open(path) as f:
                rows = csv.reader(r for r in f if not r.startswith("#"))
                header = next(rows, None)
                for r in rows:
                    if len(r) < 3:
                        continue
                    ex.append(int(r[0]))
                    ed.append(int(r[2]))
            curves[key] = (ex, ed)
    return runs, curves


def sign_test(pairs):
    """Exact two-sided sign test on (arm, baseline) pairs. Ties dropped."""
    wins = sum(1 for a, b in pairs if a > b)
    losses = sum(1 for a, b in pairs if a < b)
    n = wins + losses
    if n == 0:
        return wins, losses, 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1))
    p = min(1.0, 2.0 * tail / (2 ** n))
    return wins, losses, p


def main(results="results"):
    runs, curves = load(results)
    if not runs:
        print(f"no results in {results}/", file=sys.stderr)
        return 1

    targets = sorted({k[0] for k in runs})
    scheds = sorted({k[1] for k in runs}, key=lambda s: (s != "baseline", s))

    gate_ok = True
    lines = []
    lines.append("## Results\n")

    for target in targets:
        by_sched = {s: {seed: runs[(target, s, seed)]
                        for (t, ss, seed) in runs if t == target and ss == s}
                    for s in scheds}
        n_seeds = {s: len(v) for s, v in by_sched.items()}
        # Budget is reported PER TARGET: targets are not necessarily benchmarked
        # at the same budget, and a single global figure silently mislabels one
        # of them. Within a target it MUST be identical across schedulers, so a
        # spread is called out loudly instead of being averaged away.
        budget = sorted({r["execs"] for (t, _, _), r in runs.items() if t == target})
        budget_str = (f"{budget[0]:,}" if len(budget) == 1
                      else f"**MIXED {budget} — NOT COMPARABLE**")

        lines.append(f"### `{target}` — {budget_str} executions per run\n")
        lines.append("| scheduler | seeds | median edges | range | vs baseline (median) "
                     "| paired W-L | sign-test p | median execs/s |")
        lines.append("|---|---|---|---|---|---|---|---|")

        base = by_sched.get("baseline", {})
        base_med = statistics.median(r["edges"] for r in base.values()) if base else None

        for s in scheds:
            rs = by_sched[s]
            if n_seeds[s] < SEED_FLOOR:
                gate_ok = False
            if not rs:
                continue
            edges = sorted(r["edges"] for r in rs.values())
            med = statistics.median(edges)
            rate = statistics.median(r["execs"] / (r["t_ms"] / 1000) for r in rs.values())

            if s == "baseline" or not base:
                delta, wl, pstr = "—", "—", "—"
            else:
                d = med - base_med
                delta = f"{d:+g} ({d / base_med * 100:+.1f}%)" if base_med else f"{d:+g}"
                pairs = [(rs[k]["edges"], base[k]["edges"])
                         for k in sorted(set(rs) & set(base))]
                w, l, p = sign_test(pairs)
                wl = f"{w}-{l}"
                pstr = f"{p:.3f}"

            flag = "" if n_seeds[s] >= SEED_FLOOR else "  **UNDER SEED FLOOR**"
            lines.append(f"| `{s}` | {n_seeds[s]}{flag} | {med:g} | "
                         f"{edges[0]}–{edges[-1]} | {delta} | {wl} | {pstr} | {rate:.0f} |")
        lines.append("")

        # Adaptation evidence: did the learned arms actually move off the
        # hand-tuned weights, or just sample them forever?
        lines.append("Did the learned schedulers actually adapt? Total-variation "
                     "distance, from actual operator-selection counts. The baseline row "
                     "is the sampling-noise floor: it cannot adapt by construction, so "
                     "anything near its value is noise.\n")
        lines.append("| scheduler | TV(first 1k, last 1k) median | range "
                     "| TV(run, hand-tuned weights) median | range |")
        lines.append("|---|---|---|---|---|")
        for s in scheds:
            rs = by_sched[s]
            if not rs:
                continue
            late = sorted(r["tv_early_vs_late"] for r in rs.values())
            hand = sorted(r["tv_vs_handweights"] for r in rs.values())
            lines.append(
                f"| `{s}` | {statistics.median(late):.4f} | {late[0]:.4f}–{late[-1]:.4f} "
                f"| {statistics.median(hand):.4f} | {hand[0]:.4f}–{hand[-1]:.4f} |")
        lines.append("")

    table = "\n".join(lines)
    print(table)
    with open(os.path.join(results, "summary.md"), "w") as f:
        f.write(table + "\n")

    plot(results, targets, scheds, curves)

    if not gate_ok:
        print(f"\nGATE FAIL: a configuration has fewer than {SEED_FLOOR} seeds.",
              file=sys.stderr)
        return 1
    print(f"\nseed gate OK; wrote {results}/summary.md and {results}/coverage.png")
    return 0


def plot(results, targets, scheds, curves):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    colors = {"baseline": "#5b6b7a", "bandit": "#c1662f", "linucb": "#2f6f8f"}
    fig, axes = plt.subplots(1, len(targets), figsize=(6.2 * len(targets), 4.6),
                             squeeze=False)
    for ax, target in zip(axes[0], targets):
        for s in scheds:
            series = [curves[k] for k in curves if k[0] == target and k[1] == s]
            if not series:
                continue
            n = min(len(e) for e, _ in series)
            if n == 0:
                continue
            x = np.array(series[0][0][:n])
            m = np.array([ed[:n] for _, ed in series], dtype=float)
            med = np.median(m, axis=0)
            c = colors.get(s, None)
            # Median line with a min-max band: the band IS the full range across
            # seeds, not a confidence interval, matching the table.
            ax.plot(x, med, label=f"{s} (median of {m.shape[0]})", color=c, lw=1.8)
            ax.fill_between(x, m.min(axis=0), m.max(axis=0), color=c, alpha=0.15,
                            linewidth=0)
        ax.set_title(target)
        ax.set_xlabel("executions")
        ax.set_ylabel("edges covered")
        ax.grid(alpha=0.25, linewidth=0.6)
        ax.legend(loc="lower right", fontsize=8, frameon=False)
    fig.suptitle("mk-fuzz: coverage vs executions by mutation-operator scheduler\n"
                 "line = median across seeds, band = full min–max range",
                 fontsize=10)
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(os.path.join(results, "coverage.png"), dpi=150)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "results"))
