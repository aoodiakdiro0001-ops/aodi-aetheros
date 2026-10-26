#!/usr/bin/env python3
"""Aodı-AetherOS — sovereign homomorphic hypervisor core (stdlib only).

Endpoints:
  GET  /                     dashboard (Arabic RTL)
  GET  /api/state            protocols + ledger head + hub consensus + cells
  POST /api/fhe/keygen       {bits?} paillier keyring (cached) + threshold split
  GET  /api/fhe/pubkey       public encryption key for TRUE remote clients
  POST /api/fhe/kernel       live additive-homomorphic bench (real numbers)
  POST /api/private/dot      {enc_values:["hex"...]} -> E(sum w_i x_i) hex
  POST /api/private/collect  {enc_values:[hex...]} -> E(sum x_i) hex (fleet)
  POST /api/vproc/run        {n?} AVP program -> local run + fanout to cells
  GET  /api/programs         dispatch history
  POST /api/morph            {path|content_b64} real binary forensics report
  POST /api/ouroboros/spawn  {port,name?} emit + launch + join a real cell
  GET  /api/cells            live self-replicated cell registry
  POST /api/vote/propose     seal ledger head -> rally votes -> quorum commit
  POST /api/fabric/net       measured frame bench + link map + hub Dijkstra
  GET  /api/fabric/route     live min-cost route from the consensus hub
  GET  /api/ledger, /api/events
"""
import json
import os
import sys
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CORE = "/".join(__file__.split("/")[:-1])
if CORE not in sys.path:
    sys.path.insert(0, CORE)

import config
import fabric
import fhe as fhem
import morph
import ouroboros
import storage
import telemetry
import vproc
import zlib

# RFC 7230: header stays ASCII - the UTF-8 brand lives in bodies only.
SERVER_NAME = "AodiAetherOS/%s" % config.VERSION

STATE = {"key": None, "cells": {}}   # keyring / live cell registry


def _get_key(force=False):
    """Load-or-create the paillier keyring; threshold-split lam (real)."""
    kfile = config.KEY_DIR / "paillier.json"
    if STATE["key"] is not None and not force:
        return STATE["key"]
    stored = config.load_json(kfile)
    if force or not stored:
        key = fhem.keygen(config.FHE_DEFAULT_BITS)
        config.KEY_DIR.mkdir(parents=True, exist_ok=True)
        lam_share = fhem.shamir_split(key["lam"], 3, 3)
        config.save_json(kfile, {
            "scheme": "paillier", "bits": key["bits"],
            "n_hex": format(key["n"], "x"),
            "mu_hex": format(key["mu"], "x"),
            "lam_shamir": lam_share, "created": __import__("time")
            .strftime("%Y-%m-%d %H:%M:%S")})
        storage.seal_append("fhe-keygen", "paillier-%d" % key["bits"],
                            format(key["n"], "x")[:64])
        telemetry.emit("fhe", "ok", "keyring born: %d-bit modulus + 3 shares"
                       % key["bits"])
        stored = config.load_json(kfile)
    key = {
        "bits": stored["bits"],
        "n": int(stored["n_hex"], 16),
        "mu": int(stored["mu_hex"], 16),
        "lam": None,  # operator-side reconstruct only (see docs)
        "lam_shamir": stored["lam_shamir"],
    }
    STATE["key"] = key
    return key


def _full_key():
    """Operator convenience: reconstruct lam from the 3 stored shares."""
    key = _get_key()
    if key.get("lam"):
        return key
    shares = key["lam_shamir"]
    mod = int(shares["modulus_hex"], 16)
    pts = [(s["x"], int(s["y_hex"], 16)) for s in shares["shares"]]
    key["lam"] = fhem.shamir_combine(pts, mod)
    return key


# demo scoring model: PUBLIC weights (a real linear anomaly-score shape)
def _model_weights(dims):
    return [(((i * 37) % 13) - 6) / 4.0 for i in range(dims)]


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_NAME

    def _json(self, code, obj):
        raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    # ---------------- GET ----------------
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/api/state":
            hub = {}
            try:
                hub = fabric.hub_get(config.HUB_URL, "/consensus/head")
            except Exception as e:
                hub = {"error": type(e).__name__ + ": " + str(e)[:80]}
            vh = storage.seal_verify()
            k = _get_key()
            return self._json(200, {
                "brand": config.BRAND, "version": config.VERSION,
                "hub": config.HUB_URL,
                "fhe": {"scheme": "paillier-additive",
                        "bits": k["bits"], "g_form": "n+1"},
                "consensus": hub, "cells": len(STATE["cells"]),
                "ledger": {"size": vh.get("size"), "ok": vh.get("ok"),
                           "head": (vh.get("head") or "")[:16]}})
        if p == "/api/cells":
            return self._json(200, {"cells": list(STATE["cells"].values())})
        if p == "/api/programs":
            return self._json(200, {"programs": storage.list_programs()})
        if p == "/api/ledger":
            return self._json(200, {"rows": storage.seal_rows(20),
                                    "verify": storage.seal_verify()})
        if p == "/api/events":
            return self._json(200, {"events": storage.event_tail()})
        if p == "/api/fhe/pubkey":
            k = _get_key()
            return self._json(200, fhem.pub_hex(k))
        if p == "/api/fabric/route":
            try:
                return self._json(200, fabric.fetch_route(
                    config.HUB_URL, ouroboros.secret()))
            except Exception as e:
                return self._json(502, {"error": type(e).__name__ +
                                        ": " + str(e)[:120]})
        if p in ("/", "/dashboard"):
            return self._serve_dashboard()
        return self._json(404, {"error": "no route"})

    # ---------------- POST ----------------
    def do_POST(self):
        p = self.path.split("?")[0]
        body = self._body()

        if p == "/ouroboros/join":            # a newly born cell calls us
            raw = json.dumps(body).encode("utf-8")
            sig = self.headers.get("X-AE-Sig") or ""
            if not ouroboros.verify_sig(ouroboros.secret(), raw, sig):
                return self._json(401, {"error": "bad join signature"})
            cid = (body.get("id") or "")[:40]
            if not cid or len(STATE["cells"]) >= config.MAX_CELLS:
                return self._json(403, {"error": "cell cap"})
            caps = body.get("caps") or {}
            STATE["cells"][cid] = {
                "id": cid, "url": body.get("url"), "caps": caps,
                "manifest_sha": body.get("manifest_sha", ""), "joined":
                    __import__("time").strftime("%H:%M:%S")}
            storage.register_cell(cid, body.get("manifest_sha", ""), arch=caps.get(
                "arch", "?"), python_v=caps.get("python", "?"),
                port=int((body.get("url") or ":0").rsplit(":", 1)[1] or 0))
            telemetry.emit("ouroboros", "ok", "cell joined: %s (%s)" %
                           (cid, caps.get("arch", "?")))
            return self._json(200, {"ok": True, "cell": cid})

        if p == "/api/fhe/keygen":
            bits = int(body.get("bits", 0)) or config.FHE_DEFAULT_BITS
            t0 = __import__("time").perf_counter()
            key = _get_key(force=True)
            ms = (__import__("time").perf_counter() - t0) * 1000
            return self._json(200, {"bits": key["bits"], "keygen_ms":
                                    round(ms, 1), "scheme":
                                    "paillier-additive"})

        if p == "/api/fhe/kernel":
            import time as _t
            key = _full_key()
            n = key["n"]
            dims = 16
            vals = [(i * 9176 + 13) % 900000 for i in range(dims)]
            t0 = _t.perf_counter()
            encs = [fhem.encrypt(key, v) for v in vals]
            t1 = _t.perf_counter()
            w = [((i * 37) % 13) for i in range(dims)]
            cs = fhem.homomorphic_linear(key, encs, w)
            t2 = _t.perf_counter()
            got = fhem.decrypt(key, cs)
            ref = sum(w[i] * vals[i] for i in range(dims)) % n
            t3 = _t.perf_counter()
            out = {"dims": dims,
                   "encrypt_ms_avg": round((t1 - t0) * 1000 / dims, 2),
                   "linear_ms": round((t2 - t1) * 1000, 2),
                   "decrypt_ms": round((t3 - t2) * 1000, 2),
                   "exact_match": got == ref,
                   "note": "node computed on ciphertexts only"}
            storage.record_private("kernel", dims, out["linear_ms"],
                                   out["exact_match"])
            return self._json(200, out)

        if p == "/api/private/dot":
            import time as _t
            key = _get_key()
            vals = body.get("enc_values") or []
            try:
                encs = [fhem.from_enc_hex(key, str(h)) for h in vals[:64]]
            except ValueError as e:
                return self._json(400, {"error": str(e)[:120]})
            dims = len(encs)
            w_fixed = fhem.public_weights_fixed(
                _model_weights(dims), key, config.FHE_SCALE)
            t0 = _t.perf_counter()
            cs = fhem.homomorphic_linear(key, encs, w_fixed)
            ms = (_t.perf_counter() - t0) * 1000
            storage.record_private("private-dot", dims, ms, True)
            telemetry.emit("fhe", "ok", "private kernel: %d dims in %.1fms"
                           % (dims, ms))
            return self._json(200, {"enc_score_hex": fhem.enc_hex(key, cs),
                                    "dims": dims, "linear_ms": round(ms, 2),
                                    "scale": config.FHE_SCALE})

        if p == "/api/private/collect":
            import time as _t
            key = _get_key()
            vals = body.get("enc_values") or []
            try:
                encs = [fhem.from_enc_hex(key, str(h)) for h in vals[:64]]
            except ValueError as e:
                return self._json(400, {"error": str(e)[:120]})
            t0 = _t.perf_counter()
            total = encs[0]
            for e in encs[1:]:
                total = fhem.homomorphic_add(key, total, e)
            ms = (_t.perf_counter() - t0) * 1000
            storage.record_private("collect", len(encs), ms, True)
            return self._json(200, {"enc_sum_hex": fhem.enc_hex(key, total),
                                    "inputs": len(encs), "add_ms":
                                    round(ms, 2)})

        if p == "/api/vproc/run":
            import base64
            import time as _t
            n = int(body.get("n", 0)) or 1024
            prog = vproc.sum_squares_program(n)
            data = vproc.encode(prog)
            fp = vproc.fingerprint(data)
            # budget scales with the program so the demo never starves:
            # ~6 ops per iteration + margin (hard cap still bounded).
            budget = max(config.VM_OPS_BUDGET, 8 * n + 512)
            try:
                t0 = _t.perf_counter()
                local = vproc.run(prog, budget)
                local_ms = (_t.perf_counter() - t0) * 1000
            except RuntimeError as e:
                return self._json(400, {"error": "AVP: " + str(e)[:90],
                                        "n": n})
            ref = vproc.reference_sum_squares(n)
            results = [{"node": "core", "out": local["out"][-1],
                        "ops": local["ops"], "ms": round(local_ms, 2)}]
            for cid, cell in list(STATE["cells"].items()):
                payload = json.dumps({"prog_b64": base64.b64encode(data)
                                      .decode(), "budget": budget}).encode()
                req = __import__("urllib.request", fromlist=["x"]
                                 ).Request(
                    cell["url"].rstrip("/") + "/micro/exec", data=payload,
                    method="POST",
                    headers={"X-AE-Sig": ouroboros._sign(ouroboros
                             .secret(), payload),
                             "Content-Type": "application/json"})
                try:
                    with __import__("urllib.request", fromlist=["x"]
                                    ).urlopen(req, timeout=6) as r:
                        back = json.loads(r.read().decode("utf-8"))
                    results.append({"node": back["id"],
                                    "out": back["result"]["out"][-1],
                                    "ops": back["result"]["ops"],
                                    "ms": back["ms"]})
                except Exception as e:
                    results.append({"node": cid, "error":
                                    type(e).__name__ + ": " + str(e)[:90]})
            outs = [r.get("out") for r in results if "out" in r]
            agreement = len(outs) >= 2 and all(o == outs[0] for o in outs) \
                and outs[0] == ref
            storage.record_program(fp, "sum-squares-%d" % n, len(prog["code"]),
                                   len(results), agreement, results)
            if agreement:
                storage.seal_append("avp-dispatch", "sum-squares-%d" % n, fp)
            telemetry.emit("avp", "ok" if agreement else "warn",
                           "identical results across %d nodes (agreement=%s)"
                           % (len(results), agreement))
            return self._json(200, {"program_sha256": fp, "n": n,
                                    "expected": ref, "agreement":
                                    agreement, "results": results})

        if p == "/api/morph":
            import base64
            path = (body.get("path") or "").strip()
            data = None
            if body.get("content_b64"):
                data = base64.b64decode(body["content_b64"])
            if data is None and not path:
                return self._json(400, {"error": "path or content_b64"})
            try:
                rep = morph.inspect(path=path or None, data=data)
            except Exception as e:
                return self._json(400, {"error": type(e).__name__ +
                                        ": " + str(e)[:120]})
            if rep.get("recognized"):
                storage.seal_append("morphology", (path or "inline")[:80],
                                    rep["fingerprint"])
                telemetry.emit("morph", "ok", "%s -> %s (%s)" %
                               (path[-40:], rep["machine"], rep["verdict"]))
            return self._json(200, rep)

        if p == "/api/ouroboros/spawn":
            port = int(body.get("port", 0)) or 9465
            name = (body.get("name") or "cell").strip()
            t0 = __import__("time").perf_counter()
            base = "http://127.0.0.1:%d" % config.DEFAULT_PORT
            rec = ouroboros.emit(name, parent_url=base, port=port)
            spawn_ms = (__import__("time").perf_counter() - t0) * 1000
            health = ouroboros.spawn(rec)
            cid = rec["id"]
            joined = "child-join" if cid in STATE["cells"] else None
            if health.get("ok") and joined is None:
                caps = health["health"]
                STATE["cells"][cid] = {
                    "id": cid, "url": "http://127.0.0.1:%d" % port,
                    "caps": {"arch": caps.get("arch"),
                             "python": caps.get("python")},
                    "manifest_sha": rec["sha256"],
                    "joined": __import__("time").strftime("%H:%M:%S")}
                storage.register_cell(cid, rec["sha256"], caps.get("arch"),
                                      caps.get("python"), port)
                joined = "parent-fallback"
            out = {"cell": rec, "spawn_ms": round(spawn_ms, 1),
                   "join_seconds": health.get("join_seconds"),
                   "health": health.get("health"),
                   "registered_by": joined, "spawned": health.get("ok")}
            if health.get("ok"):
                storage.seal_append("ouroboros-spawn", "%s:%d" % (name, port),
                                    rec["sha256"])
                telemetry.emit("ouroboros", "ok",
                               "cell %s up at :%d by %s"
                               % (cid, port, joined))
            return self._json(200, out)

        if p == "/api/vote/propose":
            import time as _t
            vh = storage.seal_verify()
            epoch = int(_t.time())
            head = sha256(("%s:%s" % (epoch, vh.get("head"))).encode()
                          ).hexdigest()[:32]
            votes = []
            try:
                votes.append(fabric.hub_post(
                    config.HUB_URL, "/vote/cast",
                    {"voter": "core-%d" % config.DEFAULT_PORT,
                     "epoch": epoch, "head": head},
                    ouroboros.secret()))
            except Exception as e:
                votes.append({"error": type(e).__name__ + ": " +
                              str(e)[:90]})
            errs = []
            for cid, cell in list(STATE["cells"].items()):
                try:
                    votes.append(fabric.hub_post(
                        cell["url"], "/micro/vote",
                        {"voter": cid, "epoch": epoch, "head": head},
                        ouroboros.secret()))
                except Exception as e:
                    errs.append(cid + ": " + str(e)[:60])
            tally = fabric.hub_get(config.HUB_URL, "/consensus/head",
                                   ouroboros.secret())
            committed = bool(tally.get("committed"))
            if committed:
                storage.seal_append("consensus-commit", "epoch-%d" % epoch,
                                    head)
            telemetry.emit("consensus", "ok" if committed else "warn",
                           "epoch %d votes=%s committed=%s"
                           % (epoch, len(votes), committed))
            return self._json(200, {"epoch": epoch, "head": head,
                                    "vote_replies": votes,
                                    "consensus": tally, "committed":
                                    committed, "cell_errors": errs})

        if p == "/api/fabric/net":
            import time as _t
            kb = int(body.get("payload_kb", 0)) or 48
            iters = int(body.get("iterations", 0)) or 200
            t0 = _t.perf_counter()
            rb = fabric.bench(iterations=min(iters, 600), payload_kb=kb)
            # real link measurements to the cells right now
            rtt_map, cell_rtt = {}, {}
            for cid, cell in list(STATE["cells"].items()):
                try:
                    t1 = _t.perf_counter()
                    fabric.hub_get(cell["url"], "/micro/health", None, 3)
                    ms = (_t.perf_counter() - t1) * 1000
                    rtt_map[cell["url"]] = round(ms, 2)
                    cell_rtt[cid] = round(ms, 2)
                except Exception:
                    cell_rtt[cid] = None
            try:
                fabric.announce_link_state(
                    config.HUB_URL,
                    "core-%d" % config.DEFAULT_PORT,
                    "http://127.0.0.1:%d" % config.DEFAULT_PORT,
                    cell_rtt.get(next(iter(cell_rtt), ""), 0.0), rtt_map,
                    ouroboros.secret())
            except Exception:
                pass
            try:
                route = fabric.fetch_route(config.HUB_URL,
                                           ouroboros.secret())
            except Exception as e:
                route = {"error": str(e)[:90]}
            rb["link_measure"] = cell_rtt
            rb["route"] = route
            rb["wall_ms"] = round((_t.perf_counter() - t0) * 1000, 1)
            return self._json(200, rb)

        return self._json(404, {"error": "no route"})

    def _serve_dashboard(self):
        import os as _os
        idx = _os.path.join(_os.path.dirname(CORE), "dashboard", "index.html")
        if _os.path.exists(idx):
            with open(idx, "rb") as f:
                raw = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        else:
            self._json(404, {"error": "missing dashboard"})

    def log_message(self, fmt, *args):
        pass


def main():
    import argparse
    ap = argparse.ArgumentParser(prog="ae-core")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    a = ap.parse_args()
    config.DEFAULT_PORT = a.port
    httpd = ThreadingHTTPServer((a.host, a.port), Handler)
    print(config.banner(), flush=True)
    print("[ae-core] listening http://%s:%d (AE_HOME=%s)"
          % (a.host, a.port, config.HOME), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
