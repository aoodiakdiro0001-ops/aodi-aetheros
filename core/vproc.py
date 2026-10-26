"""Aodı-AetherOS — Aether Virtual Processor (AVP): a real portable VM.

One tiny honest answer to "cross-architecture execution": instead of faking
an x86->ARM machine-code JIT (impossible without a real emitter backend, and
explicitly NOT claimed), AetherOS ships its own binary bytecode format and
register VM that runs *identically* on every node of the fleet - ARM Mac,
x86 Windows, any python3 device. Programs are encoded as compact bytes,
fingerprinted with sha256, dispatched to remote cells, and results only
count after exact cross-node agreement.
"""
import hashlib
import struct

MAGIC = b"AVP1"
OPS = {"HALT": 0, "LOAD": 1, "MOV": 2, "ADD": 3, "SUB": 4, "MUL": 5,
       "DIV": 6, "MOD": 7, "JZ": 8, "JMP": 9, "OUT": 10}
REV = {v: k for k, v in OPS.items()}
REGS = 8

# Binary format: header ">4sHH" (magic, n_instr, n_const) +
# n_instr * ">Bii" (opcode, a, b) + n_const * ">q".
# In-place arithmetic semantics (keep dst explicit, one operand register):
#   LOAD (dst, const_idx, -)   R[a] = consts[b]
#   MOV  (dst, src, -)         R[a] = R[b]
#   ADD/SUB/MUL/DIV/MOD (dst, reg, -)   R[a] = R[a] (op) R[b]
#   JZ   (reg, target, -)      if R[a] == 0: pc = b else pc += 1
#   JMP  (target, -, -)        pc = a
#   OUT  (reg, -, -)           out.append(R[a]); pc += 1
#   HALT  stop


def encode(program):
    """program dict -> deterministic compact bytes (sha256 = identity)."""
    code = program["code"]
    consts = program.get("consts", [])
    header = struct.pack(">4sHH", MAGIC, len(code), len(consts))
    body = b"".join(struct.pack(">Bii", op, a, b) for op, a, b in code)
    tail = b"".join(struct.pack(">q", int(c)) for c in consts)
    return header + body + tail


def decode(data):
    if data[:4] != MAGIC:
        raise ValueError("not an AVP program (bad magic)")
    n_code, n_const = struct.unpack(">HH", data[4:8])
    code = []
    off = 8
    for _ in range(n_code):
        op, a, b = struct.unpack(">Bii", data[off:off + 9])
        if op not in REV:
            raise ValueError("unknown opcode %d" % op)
        code.append((op, a, b))
        off += 9
    consts = [struct.unpack(">q", data[off + i * 8:off + i * 8 + 8])[0]
              for i in range(n_const)]
    return {"code": code, "consts": consts, "regs": REGS}


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def run(program, ops_budget=4096):
    """Bounded execution: hard op budget, no syscalls, no dynamic code."""
    regs = [0] * REGS
    consts = program.get("consts", [])
    code = program["code"]
    out = []
    pc = 0
    ops = 0
    n_code = len(code)
    while ops < ops_budget:
        if pc < 0 or pc >= n_code:
            raise RuntimeError("pc out of bounds")
        op, a, b = code[pc]
        ops += 1
        if op == OPS["HALT"]:
            return {"out": out, "ops": ops, "halted": True}
        if op == OPS["LOAD"]:
            regs[a] = consts[b]
        elif op == OPS["MOV"]:
            regs[a] = regs[b]
        elif op == OPS["ADD"]:
            regs[a] = regs[a] + regs[b]
        elif op == OPS["SUB"]:
            regs[a] = regs[a] - regs[b]
        elif op == OPS["MUL"]:
            regs[a] = regs[a] * regs[b]
        elif op == OPS["DIV"]:
            if regs[b] == 0:
                raise ZeroDivisionError("AVP div by zero")
            regs[a] = regs[a] // regs[b]
        elif op == OPS["MOD"]:
            if regs[b] == 0:
                raise ZeroDivisionError("AVP mod by zero")
            regs[a] = regs[a] % regs[b]
        elif op == OPS["JZ"]:
            pc = b if regs[a] == 0 else pc + 1
            continue
        elif op == OPS["JMP"]:
            pc = a
            continue
        elif op == OPS["OUT"]:
            out.append(regs[a])
        else:
            raise RuntimeError("op %s not wired" % REV.get(op, str(op)))
        pc += 1
    raise RuntimeError("ops budget exceeded (%d)" % ops_budget)


def sum_squares_program(n):
    """Compile the canonical demo kernel: sum of squares 1..n in AVP code."""
    code = [
        (OPS["LOAD"], 0, 0),     # R0 = n            (consts[0])
        (OPS["LOAD"], 1, 1),     # R1 = 0  acc       (consts[1])
        (OPS["LOAD"], 2, 2),     # R2 = 1  one       (consts[2])
        (OPS["MOV"], 3, 0),      # R3 = R0
        (OPS["MUL"], 3, 0),      # R3 = R0 * R0
        (OPS["ADD"], 1, 3),      # R1 += R3
        (OPS["SUB"], 0, 2),      # R0 -= 1
        (OPS["JZ"], 0, 9),       # if R0 == 0 -> OUT
        (OPS["JMP"], 3, 0),      # loop
        (OPS["OUT"], 1, 0),      # emit result
        (OPS["HALT"], 0, 0),
    ]
    return {"code": code, "consts": [n, 0, 1], "regs": REGS}


def reference_sum_squares(n):
    """Closed-form oracle the VM result must reproduce exactly."""
    return n * (n + 1) * (2 * n + 1) // 6


if __name__ == "__main__":
    import sys
    prog = sum_squares_program(10)
    data = encode(prog)
    assert decode(data) == prog
    r = run(decode(data))
    ok = r["out"][-1] == reference_sum_squares(10)
    print("AVP sum-squares(10) = %s (expected %s) | %s"
          % (r["out"][-1], reference_sum_squares(10), "OK" if ok else "FAIL"))
    sys.exit(0 if ok else 1)
