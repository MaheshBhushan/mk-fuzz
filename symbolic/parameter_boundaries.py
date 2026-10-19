"""Solve and emit the integer boundaries shared by both parser platforms."""
import argparse
import json
from pathlib import Path

import z3


def boundary_fixtures():
    fixtures = []
    number = z3.Int("parameter")
    for key, low, high in (("count", 0, 65535), ("offset", -(2**31), 2**31 - 1)):
        constraints = (
            ("below-min", number + 1 == low), ("min", number == low),
            ("above-min", number - 1 == low), ("below-max", number + 1 == high),
            ("max", number == high), ("above-max", number - 1 == high),
        )
        for label, constraint in constraints:
            solver = z3.Solver()
            solver.add(constraint)
            if solver.check() != z3.sat:
                raise RuntimeError(f"unsatisfiable boundary: {key}/{label}")
            value = solver.model().eval(number).as_long()
            expected = {"status": "ok", "count": 1, "offset": 0, "mode": "safe"}
            if key == "count" and value < 0:
                expected = {"status": "reject", "reason": "syntax"}
            elif not low <= value <= high:
                expected = {"status": "reject", "reason": "range"}
            else:
                expected[key] = value
            fixtures.append({"name": f"{key}/{label}",
                             "hex": f"{key}={value}".encode("ascii").hex(),
                             "expected": expected})
    return fixtures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", type=Path, help="verify committed fixtures without writing")
    args = parser.parse_args()
    fixtures = boundary_fixtures()
    if args.check:
        if json.loads(args.check.read_text(encoding="utf-8")) != fixtures:
            parser.error("committed parameter boundaries differ from Z3 solutions")
        print(f"verified {len(fixtures)} Z3 boundary fixtures")
    else:
        print(json.dumps(fixtures, indent=2))


if __name__ == "__main__":
    main()
