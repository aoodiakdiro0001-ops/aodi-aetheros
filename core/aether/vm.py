"""Portable compute kernel IR — one bytecode, every architecture.

The honest version of "cross-architecture binary morphing": instead of
rewriting machine code between ARM64 and x86_64 (which no one does at
runtime, and which we will not pretend to do), AetherOS compiles math
expressions into a tiny stack VM bytecode that runs IDENTICALLY on:

    - Python interpreter on any arch   (core/vm.py)
    - native C++ runner                (native/aether_vm.cpp)
    - any future runner (Go/Rust/WASM) — the IR is plain JSON

The same IR bytes also run in ENCRYPTED mode via Paillier homomorphic
operations (paillier.py): the remote node executes ADD/SUB/MULSCALAR on
ciphertexts without seeing any operand.

IR format: JSON  [["PUSH", 5], ["LOAD", "x"], ["ADD"], ...]
Stack machine over scaled integers (fixed-point, see SCALE).

Security: `compile_expr` parses with Python `ast` and accepts ONLY a
whitelist of nodes — no names beyond declared inputs, no calls, no
attribute access, no imports. Compiling untrusted expressions is safe
by construction.
"""
import ast
import json

# fixed-point scale shared with paillier helpers
SCALE = 10 ** int(__import__("os").environ.get("AETHER_HE_SCALE_BITS", "6"))

HE_LEGAL = ("PUSH", "LOAD", "ADD", "SUB", "NEG")   # + MUL with a constant
PLAIN_OPS = ("PUSH", "LOAD", "ADD", "SUB", "MUL", "DIV", "NEG")


class CompileError(ValueError):
    pass


class ExecError(ValueError):
    pass


def _const_value(node, scale):
    """Extract an int/float constant scaled to the integer domain."""
    v = node.value
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise CompileError("only numeric constants allowed (got %r)" % (v,))
    return int(round(v * scale))


def compile_expr(src, inputs, scale=None):
    """Compile a math expression string into IR.

    src     : e.g. "2 * x + y - 0.5"
    inputs  : ordered list of variable names, e.g. ["x", "y"]
    scale   : fixed-point scale for float constants (default SCALE)

    Returns (ir_dict, scale) where ir_dict = {"ops": [[op, arg?], ...],
    "inputs": [...], "scale": scale}.
    """
    scale = SCALE if scale is None else scale
    if not isinstance(src, str) or len(src) > 4000:
        raise CompileError("expression must be a string <= 4000 chars")
    try:
        tree = ast.parse(src, mode="eval")
    except SyntaxError as ex:
        raise CompileError("syntax error: %s" % ex)

    known = list(inputs)
    ops = []

    def emit(op, arg=None):
        ops.append([op, arg] if arg is not None else [op])

    def walk(node):
        if isinstance(node, ast.Expression):
            walk(node.body)
        elif isinstance(node, ast.Constant):
            emit("PUSH", _const_value(node, scale))
        elif isinstance(node, ast.Num):            # py<3.8 alias safety
            emit("PUSH", int(round(node.n * scale)))
        elif isinstance(node, ast.Name):
            if node.id not in known:
                raise CompileError("unknown input %r (declared: %s)"
                                   % (node.id, known))
            emit("LOAD", node.id)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            walk(node.operand)
            emit("NEG")
        elif isinstance(node, ast.BinOp) and isinstance(
                node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div)):
            walk(node.left)
            walk(node.right)
            emit({ast.Add: "ADD", ast.Sub: "SUB",
                  ast.Mult: "MUL", ast.Div: "DIV"}[type(node.op)])
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            raise CompileError("exponentiation not in v1 IR (keep kernels "
                               "linear so they stay homomorphic-friendly)")
        else:
            raise CompileError("forbidden syntax: %s (%s)"
                               % (type(node).__name__,
                                  getattr(node, "lineno", "?")))
    walk(tree)
    if not ops:
        raise CompileError("empty expression")
    return {"ops": ops, "inputs": known, "scale": scale}


def encode_inputs(ir, values):
    """Map python numbers (int/float) to scaled integers per IR inputs."""
    if len(values) != len(ir["inputs"]):
        raise ExecError("expected %d inputs %s, got %d"
                        % (len(ir["inputs"]), ir["inputs"], len(values)))
    out = []
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ExecError("inputs must be numbers, got %r" % (v,))
        out.append(int(round(float(v) * ir["scale"])))
    return out


def decode_result(scaled, ir):
    return float(scaled) / ir["scale"]


def run_plain(ir, values):
    """Execute IR in cleartext. values = raw python numbers (unscaled)."""
    stack = []
    env = {}
    regs = encode_inputs(ir, values)
    names = ir["inputs"]
    for step in ir["ops"]:
        op = step[0]
        if op == "PUSH":
            stack.append(int(step[1]))
        elif op == "LOAD":
            stack.append(regs[names.index(step[1])])
        elif op == "ADD":
            b, a = stack.pop(), stack.pop()
            stack.append(a + b)
        elif op == "SUB":
            b, a = stack.pop(), stack.pop()
            stack.append(a - b)
        elif op == "MUL":
            b, a = stack.pop(), stack.pop()
            # fixed-point: a*b is scale^2 -> bring back to scale
            s = ir["scale"]
            stack.append(int(round(a * b / float(s))))
        elif op == "DIV":
            b, a = stack.pop(), stack.pop()
            if b == 0:
                raise ExecError("division by zero")
            # integer division on scaled domain; caller scales constants
            stack.append(int(round(a * ir["scale"] / float(b))))
        elif op == "NEG":
            stack.append(-stack.pop())
        else:
            raise ExecError("unknown op %r" % op)
        if len(stack) > 64:
            raise ExecError("stack overflow (kernel too deep)")
    if len(stack) != 1:
        raise ExecError("unbalanced kernel (stack depth %d)" % len(stack))
    return stack[0]


def run_plain_decoded(ir, values):
    """Convenience: takes raw numbers, returns a python float/int result."""
    scaled = run_plain(ir, values)
    # DIV already re-scales; treat result as scaled integer
    out = float(scaled) / ir["scale"]
    return int(out) if float(out).is_integer() and abs(out) > 0 else out


def check_he_compatible(ir):
    """Verify every MUL multiplies by a PUSHed constant (left const right
    var, i.e. the stack order produced by `2 * x` style source).

    Returns list of offending op indexes (empty = HE-safe).
    """
    # simulate stack with symbolic leaves: 'C' constant, 'V' variable
    stack, bad = [], []
    for i, step in enumerate(ir["ops"]):
        op = step[0]
        if op == "PUSH":
            stack.append("C")
        elif op == "LOAD":
            stack.append("V")
        elif op == "NEG":
            if stack:
                pass  # NEG keeps kind
        elif op in ("ADD", "SUB"):
            if len(stack) < 2:
                bad.append(i)
                stack and stack.pop()
                continue
            b, a = stack.pop(), stack.pop()
            stack.append("C" if a == b == "C" else "V")
        elif op == "MUL":
            if len(stack) < 2:
                bad.append(i)
                continue
            b, a = stack.pop(), stack.pop()
            if a == "C" and b in ("C", "V"):
                stack.append("C" if (a == b == "C") else "V")
            elif a == "V" and b == "C":
                stack.append("V")
            else:
                bad.append(i)          # var * var — needs cleartext
                stack.append("V")
        elif op == "DIV":
            # integer division is not a scalar multiplication on the
            # ciphertext exponent — Paillier cannot do it. Reject honestly.
            bad.append(i)
            if len(stack) >= 2:
                stack.pop()
                stack.pop()
            stack.append("V")
        else:
            bad.append(i)
    return bad


def run_he(pk, sk, ir, enc_values):
    """Execute IR homomorphically over Paillier ciphertexts.

    enc_values: list of ciphertexts ordered like ir['inputs'].
    Requires check_he_compatible(ir) == [] (only constant multiplication).
    Returns a ciphertext. Only the key holder ever decrypts.
    """
    from . import paillier as he

    if ir.get("scale", 1) != 1:
        raise ExecError(
            "HE kernels run at scale=1 (integer arithmetic) — fixed-point "
            "scaling is not homomorphically divisible. Recompile with "
            "scale=1 or use paillier.enc_float for fixed-point aggregates.")
    bad = check_he_compatible(ir)
    if bad:
        raise ExecError(
            "kernel not homomorphic-compatible at ops %s — encrypted x "
            "encrypted multiply or division needs full FHE (out of scope "
            "for Paillier; see README honest scope)" % bad)

    stack = []
    names = ir["inputs"]
    for step in ir["ops"]:
        op = step[0]
        if op == "PUSH":
            stack.append(("C", int(step[1])))
        elif op == "LOAD":
            idx = names.index(step[1])
            stack.append(("V", enc_values[idx]))
        elif op in ("ADD", "SUB", "MUL", "DIV", "NEG"):
            if op == "NEG":
                kind, c = stack.pop()
                # E(-a) = E(a)^-1
                stack.append((kind, he.scalar_mul(pk, c, -1)))
                continue
            (k2, b), (k1, a) = stack.pop(), stack.pop()
            if op == "ADD":
                if k1 == "C" and k2 == "C":
                    stack.append(("C", a + b))
                elif k1 == "C":                 # E(a) * E(b)
                    stack.append(("V", he.add(pk, he.encrypt(pk, a), b)))
                elif k2 == "C":
                    stack.append(("V", he.add(pk, a, he.encrypt(pk, b))))
                else:
                    stack.append(("V", he.add(pk, a, b)))
            elif op == "SUB":
                if k1 == "C" and k2 == "C":
                    stack.append(("C", a - b))
                elif k2 == "C":                 # E(x) - const
                    stack.append(("V", he.sub(pk, a, he.encrypt(pk, b))))
                elif k1 == "C":                 # const - E(x)
                    stack.append(("V", he.sub(pk, he.encrypt(pk, a), b)))
                else:
                    stack.append(("V", he.sub(pk, a, b)))
            elif op == "MUL":
                if k1 == "C" and k2 == "C":
                    stack.append(("C", a * b))       # plaintext constants
                elif k2 == "C":                      # E(x) * const
                    stack.append(("V", he.scalar_mul(pk, a, b)))
                elif k1 == "C":                      # const * E(x)
                    stack.append(("V", he.scalar_mul(pk, b, a)))
                else:
                    raise ExecError("encrypted x encrypted not supported")
            elif op == "DIV":
                if k2 != "C":
                    raise ExecError("division by non-constant")
                # (a / b) with scale: a_scaled/b -> multiply by SCALE/b
                num = int(round(ir["scale"] * ir["scale"] / float(b)))
                if k1 == "C":
                    stack.append(("C", int(round(a / float(b)))))
                else:
                    stack.append(("V", he.scalar_mul(pk, a, num)))
    if len(stack) != 1:
        raise ExecError("unbalanced HE kernel")
    kind, val = stack[0]
    if kind == "C":                       # all-constant kernel -> encrypt
        return he.encrypt(pk, int(val) % pk.n)
    return val


def kind_of(k1, k2):
    return "C" if k1 == k2 == "C" else "V"


def ir_to_json(ir):
    return json.dumps(ir, separators=(",", ":"))


def ir_from_json(s):
    try:
        d = json.loads(s)
    except Exception as ex:
        raise CompileError("bad IR json: %s" % ex)
    if not isinstance(d, dict) or "ops" not in d:
        raise CompileError("bad IR json")
    return d
