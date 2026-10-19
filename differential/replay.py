"""Compare parser semantics and retain exact inputs for cross-platform replay."""
import argparse
import hashlib
import json
import math
import platform
import subprocess
from pathlib import Path


def run_parser(command, data, timeout):
    try:
        proc = subprocess.run(command, input=data, capture_output=True, timeout=timeout,
                              check=False)
    except subprocess.TimeoutExpired as exc:
        return {"failure": "timeout", "stdout": (exc.stdout or b"").hex(),
                "stderr": (exc.stderr or b"").hex()}
    except OSError as exc:
        return {"failure": "launch", "detail": str(exc)}
    observation = {"exit_code": proc.returncode, "stdout": proc.stdout.hex(),
                   "stderr": proc.stderr.hex()}
    if proc.returncode not in (0, 2) or proc.stderr:
        return {**observation, "failure": "execution"}
    try:
        result = json.loads(proc.stdout)
    except (ValueError, UnicodeDecodeError):
        return {**observation, "failure": "protocol"}
    valid = isinstance(result, dict)
    if valid and proc.returncode == 0:
        valid = (set(result) == {"status", "count", "offset", "mode"}
                 and result["status"] == "ok"
                 and type(result["count"]) is int and 0 <= result["count"] <= 65535
                 and type(result["offset"]) is int
                 and -(2**31) <= result["offset"] < 2**31
                 and result["mode"] in ("safe", "fast"))
    elif valid:
        valid = (set(result) == {"status", "reason"} and result["status"] == "reject"
                 and result["reason"] in ("syntax", "unknown", "duplicate", "range", "size"))
    if not valid:
        return {**observation, "failure": "protocol"}
    return {**observation, "result": result}


def compare(data, legacy, migrated, timeout=1.0, expected=None):
    left = run_parser(legacy, data, timeout)
    right = run_parser(migrated, data, timeout)
    matches = ("failure" not in left and "failure" not in right
               and left["result"] == right["result"]
               and (expected is None or left["result"] == expected))
    return matches, {"legacy": left, "migrated": right}


def preserve(directory, data, report):
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    raw = directory / f"{digest}.bin"
    # Exclusive creation preserves the first observation and deduplicates inputs.
    try:
        with raw.open("xb") as stream:
            stream.write(data)
    except FileExistsError:
        if raw.read_bytes() != data:
            raise ValueError(f"counterexample hash collision: {raw}")
    metadata = directory / f"{digest}.json"
    try:
        with metadata.open("x", encoding="utf-8") as stream:
            json.dump({"platform": platform.platform(), **report}, stream,
                      indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError:
        pass
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", required=True, type=Path)
    parser.add_argument("--migrated", required=True, type=Path)
    parser.add_argument("--fixtures", type=Path, action="append", default=[])
    parser.add_argument("--replay", type=Path, help="directory of saved .bin counterexamples")
    parser.add_argument("--out", type=Path, default=Path("out_diff/counterexamples"))
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    if not args.fixtures and args.replay is None:
        parser.error("supply --fixtures or --replay")
    legacy, migrated = [str(args.legacy.resolve())], [str(args.migrated.resolve())]
    cases = []
    for fixture in args.fixtures:
        for case in json.loads(fixture.read_text(encoding="utf-8")):
            cases.append((case["name"], bytes.fromhex(case["hex"]), case["expected"]))
    if args.replay is not None:
        if not args.replay.is_dir():
            parser.error(f"replay directory does not exist: {args.replay}")
        for raw in sorted(args.replay.glob("*.bin")):
            metadata = raw.with_suffix(".json")
            expected = (json.loads(metadata.read_text(encoding="utf-8")).get("expected")
                        if metadata.exists() else None)
            cases.append((raw.name, raw.read_bytes(), expected))
    if not cases:
        parser.error("no cases found")
    failures = 0
    for name, data, expected in cases:
        matches, observations = compare(data, legacy, migrated, args.timeout, expected)
        if not matches:
            failures += 1
            raw = preserve(args.out, data, {
                "name": name, "expected": expected, "platform": platform.platform(),
                "commands": {"legacy": legacy, "migrated": migrated}, **observations})
            print(f"FAIL {name}: {raw}", flush=True)
    print(f"replayed {len(cases)} cases; {failures} failures", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
