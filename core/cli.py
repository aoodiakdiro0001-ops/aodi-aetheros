#!/usr/bin/env python3
"""Aodı-AetherOS — aectl operator CLI (stdlib only).

  aectl status                     protocols + consensus + cells + ledger
  aectl keygen [bits]              paillier ring (threshold-split lam)
  aectl kernel                     live additive-homomorphic bench
  aectl infer 12                   privacy loop: client encrypt -> node
                                   evaluates on ciphertext -> client decrypt
  aectl collect                    encrypted fleet sum through the core
  aectl vproc [n]                  AVP program local + fanout to cells
  aectl morph PATH...              real Mach-O/PE/ELF forensics report
  aectl spawn 9465 [9466...]       ouroboros self-replication onto cells
  aectl cells                      live self-replicated registry
  aectl fabric 48                  measured frame bench + live route
  aectl vote                       seal + rally + quorum commit
  aectl ledger                     seal chain
  aectl serve [port]               hypervisor core
"""
import base64
import json
import os
import sys
import urllib.request

CORE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CORE)
import config  # noqa: E402


def _req(method, path, payload=None, timeout=120):
    url = "http://127.0.0.1:%d%s" % (config.DEFAULT_PORT, path)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _client_key():
    """Operator-side keyring (owner device) - documented demo seam."""
    import fhe as fh
    stored = config.load_json(config.KEY_DIR / "paillier.json")
    if not stored:
        print("[fail] no keyring - run: aectl keygen")
        return None
    key = _full_from(stored, fh)
    return key


def _full_from(stored, fh):
    shares = stored["lam_shamir"]
    mod = int(shares["modulus_hex"], 16)
    pts = [(s["x"], int(s["y_hex"], 16)) for s in shares["shares"]]
    lam = fh.shamir_combine(pts, mod)
    return {"bits": stored["bits"], "n": int(stored["n_hex"], 16),
            "mu": int(stored["mu_hex"], 16), "lam": lam}


def cmd_status():
    print(config.banner())
    try:
        st = _req("GET", "/api/state")
        print("fhe:", st["fhe"]["scheme"], st["fhe"]["bits"], "bits")
        print("consensus:", json.dumps(st.get("consensus"), ensure_ascii=False))
        print("cells:", st.get("cells"), "| ledger:", st.get("ledger"))
    except Exception as e:
        print("[core down]", type(e).__name__, str(e)[:80])
    vh_cells = None
    try:
        import storage
        print("spawns table:", storage.list_cells())
    except Exception:
        pass
    return vh_cells


def cmd_keygen(bits):
    out = _req("POST", "/api/fhe/keygen", {"bits": int(bits or 0)})
    print(json.dumps(out, ensure_ascii=False))


def cmd_kernel():
    out = _req("POST", "/api/fhe/kernel")
    print(json.dumps(out, ensure_ascii=False, indent=1))


def cmd_infer(dims):
    import fhe as fh
    import random
    key = _client_key()
    if key is None:
        return 1
    n = key["n"]
    rng = random.Random(42)
    secret_vec = [rng.randrange(0, 900000) for _ in range(int(dims or 12))]
    t0 = None
    import time as _t
    t0 = _t.perf_counter()
    encs = [fh.encrypt(key, v) for v in secret_vec]
    enc_ms = (_t.perf_counter() - t0) * 1000
    out = _req("POST", "/api/private/dot", {"enc_values":
               [fh.enc_hex(key, e) for e in encs]})
    enc_score = fh.from_enc_hex(key, out["enc_score_hex"])
    score = fh.decrypt(key, enc_score)
    w_ints = fh.public_weights_fixed(
        [(((i * 37) % 13) - 6) / 4.0 for i in range(len(secret_vec))],
        key, config.FHE_SCALE)
    ref = sum(w_ints[i] * secret_vec[i] for i in range(len(secret_vec))) % key["n"]
    print("client-encrypted %d dims (%.1fms) -> node computed E(dot) in "
          "%sms" % (len(secret_vec), enc_ms, out["linear_ms"]))
    print("plaintext score recovered by client:", score, "| reference:", ref,
          "| exact:", score == ref)
    print("privacy: node saw only %d ciphertext hex strings" % len(secret_vec))
    return 0


def cmd_collect(count):
    import fhe as fh
    import random
    import time as _t
    key = _client_key()
    if key is None:
        return 1
    rng = random.Random(77)
    secrets_vals = [rng.randrange(1000, 900000) for _ in range(int(count or 3))]
    t0 = _t.perf_counter()
    encs = [fh.encrypt(key, v) for v in secrets_vals]
    enc_ms = (_t.perf_counter() - t0) * 1000
    out = _req("POST", "/api/private/collect",
               {"enc_values": [fh.enc_hex(key, e) for e in encs]})
    got = fh.decrypt(key, fh.from_enc_hex(key, out["enc_sum_hex"]))
    ref = sum(secrets_vals) % key["n"]
    print("fleet-sum: %d inputs, client enc %.1fms, node additive combine "
          "%sms" % (len(secrets_vals), enc_ms, out["add_ms"]))
    print("recovered sum %s | reference %s | exact %s"
          % (got, ref, got == ref))
    return 0


def cmd_vproc(n):
    out = _req("POST", "/api/vproc/run", {"n": int(n or 1024)},
               timeout=180)
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def cmd_morph(paths):
    for p in paths:
        try:
            out = _req("POST", "/api/morph", {"path": p})
            print(json.dumps(out, ensure_ascii=False)[:360])
        except Exception as e:
            print(p[:40], "->", type(e).__name__, str(e)[:80])
    return 0


def cmd_spawn(ports):
    for port in (ports or ["9465"]):
        out = _req("POST", "/api/ouroboros/spawn", {"port": int(port)},
                   timeout=120)
        print(json.dumps({k: out.get(k) for k in
                          ("spawned", "spawn_ms", "join_seconds",
                           "registered_by")}, ensure_ascii=False),
              "| id:", (out.get("cell") or {}).get("id"),
              "| file bytes:", (out.get("cell") or {}).get("manifest", {})
              .get("bytes"))
    return 0


def cmd_fabric(kb):
    out = _req("POST", "/api/fabric/net", {"payload_kb": int(kb or 48)})
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def cmd_vote():
    out = _req("POST", "/api/vote/propose")
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


def cmd_ledger():
    out = _req("GET", "/api/ledger")
    print("verify:", out["verify"])
    for r in out["rows"][:10]:
        print("%3d %-20s %s" % (r["idx"], r["kind"], r["hash"][:16]))


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="aectl",
                                 description="Aodı-AetherOS control plane")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    kg = sub.add_parser("keygen"); kg.add_argument("bits", nargs="?",
                                                   default=None)
    sub.add_parser("kernel")
    inf = sub.add_parser("infer"); inf.add_argument("dims", nargs="?",
                                                    default="12")
    cl = sub.add_parser("collect"); cl.add_argument("count", nargs="?",
                                                    default="3")
    vp = sub.add_parser("vproc"); vp.add_argument("n", nargs="?", default="1024")
    mo = sub.add_parser("morph"); mo.add_argument("paths", nargs="+")
    sp = sub.add_parser("spawn"); sp.add_argument("ports", nargs="*")
    sub.add_parser("cells")
    fb = sub.add_parser("fabric"); fb.add_argument("kb", nargs="?", default="48")
    sub.add_parser("vote"); sub.add_parser("ledger")
    sv = sub.add_parser("serve"); sv.add_argument("port", nargs="?",
                                                  default=None)
    a = ap.parse_args()
    if a.cmd == "status":
        return cmd_status()
    if a.cmd == "keygen":
        return cmd_keygen(a.bits)
    if a.cmd == "kernel":
        return cmd_kernel()
    if a.cmd == "infer":
        return cmd_infer(a.dims)
    if a.cmd == "collect":
        return cmd_collect(a.count)
    if a.cmd == "vproc":
        return cmd_vproc(a.n)
    if a.cmd == "morph":
        return cmd_morph(a.paths)
    if a.cmd == "spawn":
        return cmd_spawn(a.ports)
    if a.cmd == "cells":
        print(json.dumps(_req("GET", "/api/cells"), ensure_ascii=False,
                         indent=1))
        return 0
    if a.cmd == "fabric":
        return cmd_fabric(a.kb)
    if a.cmd == "vote":
        return cmd_vote()
    if a.cmd == "ledger":
        return cmd_ledger()
    if a.cmd == "serve":
        import server
        if a.port:
            config.DEFAULT_PORT = int(a.port)
        server.main()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
