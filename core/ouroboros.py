"""Aodı-AetherOS — Ouroboros self-replication core (real, single file).

The honest version of "the system copies itself onto your devices":

  - AetherOS EMITS a real, self-contained micro-daemon (AE_CELL/1.0): one
    Python file, stdlib only, embedding a compact AVP virtual processor.
    No pip, no installer, no files beyond itself.
  - The cell registers back with its parent (HMAC-signed join), exports
    /micro/health /micro/exec /micro/vote, and executes dispatched AVP
    programs with byte-exact results (cross-checked by the parent).
  - LOCAL spawn = write + launch. REMOTE spawn = copy the file and run
    one bootstrap line (documented); "install without any user action"
    is impossible on a stock phone and is never claimed.

Supplied identity: every cell shares a pre-shared fleet token (HMAC-SHA256
per request); parent-child traffic is authenticated, and spawn manifests
record the cell's sha256 fingerprint in the ledger.
"""
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request

import config

TEMPLATE = r'''#!/usr/bin/env python3
"""AE_CELL/1.0 — Aodı-AetherOS self-replicated micro-daemon (stdlib only).

Emitted by the Ouroboros core. Endpoints:
  GET  /micro/health   identity + platform capabilities
  POST /micro/exec     run an AVP program (HMAC-signed body)
  POST /micro/vote     relay a consensus vote to the fleet hub (HMAC-signed)
Env: AE_ID, AE_PORT, AE_PARENT (join target), AE_HUB (consensus), AE_SECRET_HEX
"""
import hashlib, hmac, json, os, platform, struct, sys, time, urllib.request, zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AE_ID = os.environ.get("AE_ID", "cell-anon")
AE_PORT = os.environ.get("AE_PORT", "9465")
AE_PARENT = os.environ.get("AE_PARENT", "")
AE_HUB = os.environ.get("AE_HUB", "")
SECRET = os.environ.get("AE_SECRET_HEX", "")

# ---- compact AVP virtual processor (same semantics as core/vproc.py) ----
MAGIC = b"AVP1"
_OPS = {"HALT": 0, "LOAD": 1, "MOV": 2, "ADD": 3, "SUB": 4, "MUL": 5,
        "DIV": 6, "MOD": 7, "JZ": 8, "JMP": 9, "OUT": 10}


def _decode(data):
    if data[:4] != MAGIC:
        raise ValueError("bad magic")
    n_code, n_const = struct.unpack(">HH", data[4:8])
    code, off = [], 8
    for _ in range(n_code):
        op, a, b = struct.unpack(">Bii", data[off:off + 9])
        code.append((op, a, b))
        off += 9
    consts = [struct.unpack(">q", data[off + i * 8:off + i * 8 + 8])[0]
              for i in range(n_const)]
    return {"code": code, "consts": consts}


def _run(prog, budget=4096):
    regs = [0] * 8
    consts, code = prog["consts"], prog["code"]
    out, pc, ops = [], 0, 0
    n_code = len(code)
    while ops < budget:
        if pc < 0 or pc >= n_code:
            raise RuntimeError("pc out of bounds")
        op, a, b = code[pc]
        ops += 1
        if op == _OPS["HALT"]:
            return {"out": out, "ops": ops}
        if op == _OPS["LOAD"]:
            regs[a] = consts[b]
        elif op == _OPS["MOV"]:
            regs[a] = regs[b]
        elif op == _OPS["ADD"]:
            regs[a] = regs[a] + regs[b]
        elif op == _OPS["SUB"]:
            regs[a] = regs[a] - regs[b]
        elif op == _OPS["MUL"]:
            regs[a] = regs[a] * regs[b]
        elif op == _OPS["JZ"]:
            pc = b if regs[a] == 0 else pc + 1
            continue
        elif op == _OPS["JMP"]:
            pc = a
            continue
        elif op == _OPS["OUT"]:
            out.append(regs[a])
        else:
            raise RuntimeError("op %d not wired" % op)
        pc += 1
    raise RuntimeError("ops budget exceeded")


def _sign(body):
    return hmac.new(bytes.fromhex(SECRET), body, hashlib.sha256).hexdigest()


class H(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if SECRET:
            got = self.headers.get("X-AE-Sig") or ""
            if not hmac.compare_digest(_sign(raw), got):
                raise PermissionError("bad signature")
        return json.loads(raw.decode("utf-8")) if raw else {}

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/micro/health":
            try:
                load = round(min(os.getloadavg()[0] / max(os.cpu_count() or 1, 1), 1.0), 2)
            except Exception:
                load = -1
            return self._json(200, {
                "service": "ae-cell", "id": AE_ID, "port": int(AE_PORT),
                "arch": platform.machine(),
                "python": sys.version.split()[0],
                "load": load, "vm": "avp-compact"})

    def do_POST(self):
        p = self.path.split("?")[0]
        try:
            body = self._body()
        except PermissionError:
            return self._json(401, {"error": "bad signature"})
        if p == "/micro/exec":
            import base64
            prog = _decode(base64.b64decode(body["prog_b64"]))
            budget = int(body.get("budget", 4096))
            t0 = time.time()
            res = _run(prog, budget)
            return self._json(200, {"id": AE_ID, "result": res,
                                    "ms": int((time.time() - t0) * 1000)})
        if p == "/micro/vote":
            out = {}
            try:
                req = urllib.request.Request(
                    AE_HUB.rstrip("/") + "/vote/cast",
                    data=json.dumps(body).encode("utf-8"), method="POST",
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    out = json.loads(r.read().decode("utf-8"))
            except Exception as e:
                out = {"error": type(e).__name__ + ": " + str(e)[:100]}
            return self._json(200, {"id": AE_ID, "vote": out})
        return self._json(404, {"error": "no route"})

    def log_message(self, *a):
        pass


def _join():
    if not AE_PARENT:
        return
    manifest = {"id": AE_ID, "url": "http://127.0.0.1:%s" % AE_PORT,
                "manifest_sha": os.environ.get("AE_MANIFEST_SHA", ""),
                "caps": {"arch": platform.machine(),
                         "python": sys.version.split()[0]},
                "service": "ae-cell-1.0"}
    payload = json.dumps(manifest).encode("utf-8")
    for _ in range(10):
        try:
            req = urllib.request.Request(
                AE_PARENT.rstrip("/") + "/ouroboros/join", data=payload,
                method="POST",
                headers={"X-AE-Sig": _sign(payload),
                         "Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=4).read()
            return
        except Exception:
            time.sleep(0.6)


if __name__ == "__main__":
    import threading
    threading.Thread(target=_join, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", int(AE_PORT)), H)
    srv.serve_forever()
'''


def _secret_hex():
    sfile = config.KEY_DIR / "fabric.secret"
    if sfile.exists():
        return sfile.read_text(encoding="utf-8").strip()
    config.KEY_DIR.mkdir(parents=True, exist_ok=True)
    hx = secrets.token_hex(32)
    sfile.write_text(hx + "\n", encoding="utf-8")
    return hx


def emit(name="cell", parent_url="", hub_url=None, port=9465, cell_id=None,
         secret_hex=None):
    """Write the self-contained micro-daemon + manifest; return paths."""
    config.CELLS_DIR.mkdir(parents=True, exist_ok=True)
    cell_id = cell_id or hashlib.sha256(
        ("%s:%s:%f" % (name, port, time.time())).encode()).hexdigest()[:10]
    target = config.CELLS_DIR / cell_id
    target.mkdir(parents=True, exist_ok=True)
    hub_url = hub_url or config.HUB_URL
    secret_hex = secret_hex or _secret_hex()
    body = (TEMPLATE
            .replace("@@ID@@", cell_id)
            .replace("@@PORT@@", str(port))
            .replace("@@PARENT@@", parent_url)
            .replace("@@HUB@@", hub_url)
            .replace("@@SECRET@@", secret_hex))
    fpath = target / "microd.py"
    fpath.write_text(body, encoding="utf-8")
    sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
    config.save_json(target / "manifest.json", {
        "id": cell_id, "name": name, "file": str(fpath), "port": port,
        "sha256": sha, "bytes": fpath.stat().st_size,
        "parent": parent_url, "hub": hub_url, "secret": secret_hex,
        "emitted": time.strftime("%H:%M:%S")})
    return {"id": cell_id, "file": str(fpath), "manifest":
            config.load_json(target / "manifest.json"), "sha256": sha}


def spawn(record, wait_s=None):
    """Launch the emitted cell as a real distinct process."""
    wait_s = wait_s or config.MAX_SPAWN_WAIT_S
    env = dict(os.environ)
    env.update({
        "AE_ID": record["id"],
        "AE_PORT": str(record["manifest"]["port"]),
        "AE_PARENT": record["manifest"]["parent"],
        "AE_HUB": record["manifest"]["hub"],
        "AE_SECRET_HEX": record["manifest"]["secret"],
        "AE_MANIFEST_SHA": record["sha256"],
    })
    log = open(record["file"] + ".log", "ab")
    proc = subprocess.Popen(
        [sys.executable, record["file"]], env=env, stdout=log, stderr=log,
        start_new_session=True)
    t0 = time.time()
    url = "http://127.0.0.1:%s" % record["manifest"]["port"]
    import urllib.error
    while time.time() - t0 < wait_s:
        try:
            with urllib.request.urlopen(url + "/micro/health",
                                        timeout=2) as r:
                health = json.loads(r.read().decode("utf-8"))
            return {"ok": True, "pid": proc.pid, "health": health,
                    "join_seconds": round(time.time() - t0, 2)}
        except Exception:
            time.sleep(0.4)
    return {"ok": False, "pid": proc.pid, "reason": "health never answered"}


def secret():
    return _secret_hex()


def _sign(secret_hex, body):
    """Module-side HMAC for dispatching signed jobs to cells."""
    return hmac.new(bytes.fromhex(secret_hex), body, hashlib.sha256) \
        .hexdigest()


def verify_sig(secret_hex, body, sig):
    return hmac.compare_digest(
        hmac.new(bytes.fromhex(secret_hex), body, hashlib.sha256).hexdigest(),
        sig or "")


if __name__ == "__main__":
    print(json.dumps(emit("selftest", port=9499), ensure_ascii=False)[:240])
