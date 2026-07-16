#!/usr/bin/env python3
"""
mk-fuzz baby symbolic (concolic) executor.

Purpose: crack the narrow branches a coverage-guided fuzzer gets stuck on. A
fuzzer finds bugs by volume + luck; a check like `if (x == 0xCAFEBABE)` has a
1-in-4-billion chance per random try. Symbolic execution instead *reasons* about
what input satisfies the branch and asks an SMT solver (Z3) for one directly.

This is deliberately a "baby" engine over a tiny register IR (see the opcodes
below), not a full x86/LLVM lifter. It does the part that matters conceptually:

  * model each relevant input byte as an 8-bit symbolic variable,
  * interpret the IR, building Z3 expressions instead of concrete values,
  * at every conditional branch, ask Z3 which sides are *feasible* given the
    constraints accumulated so far, and explore each feasible side (this is the
    branch-negation / path-forking that fuzzing can't do),
  * when a path reaches a BUG instruction, solve the path constraints for a
    concrete input and emit it.

The emitted input is written into the fuzzer's queue directory, so the intended
workflow is hybrid (Driller-style): the fuzzer drives volume, and when it
plateaus you run this to unlock a gated branch and hand the solution back.

Run:  symbolic/venv/bin/python symbolic/symex.py [--emit <dir>]
"""
import argparse
import os
import sys

import z3


# --------------------------------------------------------------------------
# Tiny IR. A program is a flat list of instructions; control flow is by index.
# Registers and input bytes are all 8-bit bit-vectors, which is enough to model
# byte-oriented parsers (the common shape of C library fuzz targets).
#
#   ("INPUT", rd, i)      rd = symbolic input byte #i
#   ("CONST", rd, v)      rd = constant v
#   ("ADD",   rd, ra, rb) rd = ra + rb        (mod 256)
#   ("XOR",   rd, ra, rb) rd = ra ^ rb
#   ("EQ",    rd, ra, rb) rd = 1 if ra == rb else 0
#   ("ULE",   rd, ra, rb) rd = 1 if ra <=u rb else 0  (unsigned <=)
#   ("JZ",    ra, target) if ra == 0 goto target   (conditional branch)
#   ("JMP",   target)     unconditional goto
#   ("BUG",)              vulnerable state reached -> solve + emit
#   ("HALT",)             safe termination
# --------------------------------------------------------------------------


class SymEngine:
    def __init__(self, program, input_len, max_paths=10000):
        self.program = program
        self.input_len = input_len
        self.max_paths = max_paths
        # One fresh 8-bit symbol per input byte.
        self.inp = [z3.BitVec(f"b{i}", 8) for i in range(input_len)]
        self.solutions = []
        self.paths_explored = 0

    def _eval_program(self, constraints_hook):
        """Depth-first path exploration.

        Each worklist item is (pc, regs, path_constraints). At a branch we test
        each successor's feasibility with Z3 and only keep going down SAT paths,
        which is what stops the classic exponential blow-up from exploring dead
        branches.
        """
        start = (0, {}, [])
        worklist = [start]

        while worklist:
            if self.paths_explored >= self.max_paths:
                break
            pc, regs, path = worklist.pop()

            while True:
                if pc >= len(self.program):
                    break
                ins = self.program[pc]
                op = ins[0]

                if op == "INPUT":
                    _, rd, i = ins
                    regs = {**regs, rd: self.inp[i]}
                    pc += 1
                elif op == "CONST":
                    _, rd, v = ins
                    regs = {**regs, rd: z3.BitVecVal(v, 8)}
                    pc += 1
                elif op == "ADD":
                    _, rd, ra, rb = ins
                    regs = {**regs, rd: regs[ra] + regs[rb]}
                    pc += 1
                elif op == "XOR":
                    _, rd, ra, rb = ins
                    regs = {**regs, rd: regs[ra] ^ regs[rb]}
                    pc += 1
                elif op == "EQ":
                    _, rd, ra, rb = ins
                    regs = {**regs, rd: z3.If(regs[ra] == regs[rb],
                                              z3.BitVecVal(1, 8),
                                              z3.BitVecVal(0, 8))}
                    pc += 1
                elif op == "ULE":
                    _, rd, ra, rb = ins
                    regs = {**regs, rd: z3.If(z3.ULE(regs[ra], regs[rb]),
                                              z3.BitVecVal(1, 8),
                                              z3.BitVecVal(0, 8))}
                    pc += 1
                elif op == "JMP":
                    pc = ins[1]
                elif op == "JZ":
                    _, ra, target = ins
                    cond_zero = regs[ra] == 0        # taken branch
                    cond_nonzero = regs[ra] != 0     # fall-through
                    # Fork: schedule the feasible "taken" side, continue on the
                    # feasible "fall-through" side (or switch if only taken is
                    # feasible). Feasibility is a real Z3 check against `path`.
                    taken_ok = self._feasible(path + [cond_zero])
                    fall_ok = self._feasible(path + [cond_nonzero])
                    if taken_ok:
                        worklist.append((target, regs, path + [cond_zero]))
                    if fall_ok:
                        path = path + [cond_nonzero]
                        pc += 1
                    else:
                        break  # dead end; the taken side (if any) is queued
                elif op == "BUG":
                    self.paths_explored += 1
                    model_bytes = self._solve(path)
                    if model_bytes is not None:
                        self.solutions.append((list(path), model_bytes))
                    break
                elif op == "HALT":
                    self.paths_explored += 1
                    break
                else:
                    raise ValueError(f"unknown opcode {op}")

    def _feasible(self, constraints):
        s = z3.Solver()
        s.add(*constraints)
        return s.check() == z3.sat

    def _solve(self, constraints):
        s = z3.Solver()
        s.add(*constraints)
        if s.check() != z3.sat:
            return None
        m = s.model()
        out = bytearray(self.input_len)
        for i, sym in enumerate(self.inp):
            v = m.eval(sym, model_completion=True)
            out[i] = v.as_long() & 0xFF
        return bytes(out)

    def run(self):
        self._eval_program(None)
        return self.solutions


# --------------------------------------------------------------------------
# Demo program: the decision logic of targets/toy_parser.c, hand-lifted to IR.
#
#   input[0..3] must equal 'M','K','F','1'   (the 4-byte magic gate)
#   input[4]    record count N; we take the N>=1 path
#   input[5]    record 0 length L; take L>=1 path
#   input[6]    first payload byte; if it equals 0xFF -> abort()  (bug B2)
#
# Blind fuzzing needs to guess a 5-byte combination (magic + poison) by chance;
# coverage guidance helps with the magic but the exact 0xFF still takes luck.
# The symbolic engine derives all of it in one solve.
# --------------------------------------------------------------------------
def toy_parser_program():
    MAGIC = b"MKF1"
    p = []
    # Check each magic byte: INPUT -> CONST -> EQ -> JZ(mismatch -> HALT).
    # Layout is computed so jump targets are stable.
    # We build it in two passes: emit body, then patch the HALT index.
    body = []
    for i, ch in enumerate(MAGIC):
        body += [
            ("INPUT", "t", i),
            ("CONST", "c", ch),
            ("EQ", "e", "t", "c"),
            ("JZ", "e", "HALT_SAFE"),   # e==0 means mismatch -> safe exit
        ]
    # N >= 1  <=>  N != 0. Model as: if N == 0 -> safe.
    body += [
        ("INPUT", "n", 4),
        ("JZ", "n", "HALT_SAFE"),
        ("INPUT", "l", 5),
        ("JZ", "l", "HALT_SAFE"),      # L == 0 -> nothing copied -> safe
        # Guard: the target only copies when off+len <= size. Here off=6 after
        # reading N and L, and size==input_len==7, so model 6+L <= 7.
        ("CONST", "six", 6),
        ("ADD", "offlen", "l", "six"),  # off + len   (8-bit, fine for small L)
        ("CONST", "sz", 7),
        ("ULE", "fits", "offlen", "sz"),
        ("JZ", "fits", "HALT_SAFE"),   # off+len > size -> copy skipped -> safe
        # payload byte 0 == 0xFF ?  EQ then JZ(not-equal -> safe), else BUG.
        ("INPUT", "p", 6),
        ("CONST", "poison", 0xFF),
        ("EQ", "pe", "p", "poison"),
        ("JZ", "pe", "HALT_SAFE"),     # pe==0 -> not poison -> safe
        ("BUG",),
    ]
    body += [("HALT",)]  # HALT_SAFE lands here

    # Resolve the symbolic "HALT_SAFE" label to its numeric index.
    halt_index = len(body) - 1
    resolved = []
    for ins in body:
        if ins[0] == "JZ" and ins[2] == "HALT_SAFE":
            resolved.append(("JZ", ins[1], halt_index))
        else:
            resolved.append(ins)
    return resolved


def main():
    ap = argparse.ArgumentParser(description="mk-fuzz baby symbolic executor")
    ap.add_argument("--emit", metavar="DIR",
                    help="write solved inputs into DIR (e.g. out/queue) for the "
                         "fuzzer to pick up")
    args = ap.parse_args()

    prog = toy_parser_program()
    eng = SymEngine(prog, input_len=7)
    sols = eng.run()

    print(f"[symex] IR instructions : {len(prog)}")
    print(f"[symex] paths explored  : {eng.paths_explored}")
    print(f"[symex] bug inputs found: {len(sols)}")

    for idx, (path, data) in enumerate(sols):
        pretty = " ".join(f"{b:02x}" for b in data)
        print(f"[symex]   solution #{idx}: {pretty}  ({data!r})")
        if args.emit:
            os.makedirs(args.emit, exist_ok=True)
            path_out = os.path.join(args.emit, f"symex_{idx:03d}")
            with open(path_out, "wb") as f:
                f.write(data)
            print(f"[symex]   -> wrote {path_out}")

    return 0 if sols else 1


if __name__ == "__main__":
    sys.exit(main())
