"""Orchestrator: dispatch kernels across the mesh, encrypted or plain.

Two job modes:

plain — send the IR bytecode + cleartext inputs to N nodes, compare the
        results (consensus by verification), fail over on dead nodes.

he    — the ORCHESTRATOR encrypts with the secret key that never leaves
        this machine. Nodes receive ONLY (public key, IR, ciphertexts),
        run homomorphic ADD/SUB/MULSCALAR on opaque integers, return a
        ciphertext. The orchestrator decrypts. A compromised node learns
        nothing about the operands.
"""
import json
import os
import urllib.request

from . import mesh, paillier as he, vm

RUN_TIMEOUT = float(os.environ.get("AETHER_RUN_TIMEOUT", "30"))


def _post_json(url, obj, timeout=RUN_TIMEOUT):
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "aetheros/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def run_on_node(node, job):
    url = node["base_url"].rstrip("/") + "/run"
    return _post_json(url, job)


# ---------------- cleartext distributed kernel -------------------------
def dispatch_plain(ir, values, nodes, probes=None, job_tags=None,
                   redundancy=2):
    """Run a kernel on `redundancy` live nodes, cross-check, fail over."""
    if probes is None:
        probes = mesh.probe_all(nodes)
    job = {"mode": "plain", "ir": ir, "inputs": list(values)}

    def fn(node):
        out = run_on_node(node, job)
        if "error" in out:
            raise RuntimeError(out["error"])
        return out.get("scaled")

    verdict = mesh.run_verified(fn, nodes, probes, job_tags, redundancy)
    verdict["decoded"] = vm.decode_result(verdict["result"], ir) \
        if verdict.get("result") is not None else None
    return verdict


# ---------------- homomorphic distributed kernel -----------------------
def compile_he(expr, inputs):
    """HE kernels are integer kernels (scale=1) — see vm.check docs."""
    return vm.compile_expr(expr, inputs, scale=1)


def he_encrypt_inputs(sk, values):
    return [he.encrypt(sk, int(v)) for v in values]


def dispatch_he(ir, enc_values, pk, nodes, probes=None, job_tags=None):
    """Send ciphertexts + public key; node computes on encrypted data."""
    if probes is None:
        probes = mesh.probe_all(nodes)
    job = {"mode": "he", "ir": ir,
           "pk": pk.to_dict(),
           "ciphertexts": [str(c) for c in enc_values]}

    def fn(node):
        out = run_on_node(node, job)
        if "error" in out:
            raise RuntimeError(out["error"])
        return str(out["ciphertext"])

    verdict = mesh.run_verified(fn, nodes, probes, job_tags, redundancy=1)
    # consensus on ciphertext equality: deterministic scheme (fixed r is
    # not used, so identical results mean identical inputs+ops) — we
    # compare only when a second node actually ran.
    verdict["ciphertext"] = int(verdict["result"]) if verdict["result"] \
        else None
    return verdict


def he_demo(sk, pk, ir, values, nodes=None, probes=None):
    """Full round trip: encrypt here → (optionally) compute remotely →
    decrypt here. Returns a readable dict for CLI/dashboard."""
    enc = he_encrypt_inputs(sk, values)
    remote = None
    if nodes:
        try:
            remote = dispatch_he(ir, enc, pk, nodes, probes)
        except Exception as ex:
            remote = {"error": "%s: %s" % (type(ex).__name__, ex)}

    # local reference computation (same homomorphic ops, this machine)
    c_local = vm.run_he(pk, sk, ir, enc)
    plain_total = he.decrypt_signed(sk, c_local)

    node_ct = None
    if remote and remote.get("ciphertext") is not None:
        node_ct = int(remote["ciphertext"])
        remote_agrees = (node_ct == c_local)
    else:
        remote_agrees = None

    return {
        "inputs": list(values),
        "kernel": " ".join(str(s) for s in ir["ops"]),
        "decrypted_result": plain_total,
        "remote_ciphertext_matches_local": remote_agrees,
        "remote_nodes_used": [e["node"] for e in (remote or {}).get(
            "executions", [])] if remote else [],
        "remote_error": (remote or {}).get("error") if remote else None,
        "note": ("ciphertexts compared byte-for-byte: identical => the "
                 "remote node executed exactly the same arithmetic"),
    }


def load_keypair(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return he.PublicKey.from_dict(d["pk"]), he.SecretKey.from_dict(d["sk"])


def save_keypair(path, pk, sk, bits):
    import stat
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"pk": pk.to_dict(), "sk": sk.to_dict(), "bits": bits},
                  f, indent=2)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 600
    except Exception:
        pass
