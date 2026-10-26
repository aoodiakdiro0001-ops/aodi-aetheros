"""AetherOS node agent — the tiny daemon installed on EVERY device.

One stdlib HTTP server per machine (Mac / Windows / Linux / Termux):

    GET  /healthz           liveness
    GET  /status            arch, load, battery, tags — honest nulls when
                            a platform cannot report (no invented values)
    POST /run               execute a portable kernel (IR bytecode)
                            mode=plain  -> cleartext math
                            mode=he     -> homomorphic ops on ciphertexts
                                           (agent NEVER sees plaintext:
                                            it only has the public key)

Run:  python3 -m aether.agent --port 8790 --id mac-local --tags gpu,fast
"""
import argparse
import json
import os
import platform
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import vm

HERE = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.0.0"
START = time.time()
BUSY = {"n": 0}


_BATT_CACHE = {"at": 0.0, "val": None}
_BATT_TTL = 60.0  # seconds — pmset costs ~15ms; cache keeps RTT honest


def battery_percent():
    """Best-effort battery reading (cached 60s); None when the platform
    can't say — reported as null, never invented."""
    import time as _t
    now = _t.time()
    if now - _BATT_CACHE["at"] < _BATT_TTL:
        return _BATT_CACHE["val"]
    val = None
    try:
        if sys.platform == "darwin":
            out = subprocess.check_output(
                ["pmset", "-g", "batt"], timeout=2,
                stderr=subprocess.DEVNULL).decode("utf-8", "replace")
            if "%" in out:
                val = int(out.split("(")[-1].split("%")[0].strip())
        elif os.path.exists("/sys/class/power_supply/BAT0/capacity"):
            with open("/sys/class/power_supply/BAT0/capacity") as f:
                val = int(f.read().strip())
        elif sys.platform.startswith("win"):
            out = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-WmiObject Win32_Battery).EstimatedChargeRemaining"],
                timeout=3, stderr=subprocess.DEVNULL).decode().strip()
            val = int(out) if out.isdigit() else None
    except Exception:
        val = None
    _BATT_CACHE["at"], _BATT_CACHE["val"] = now, val
    return val


def load_avg():
    try:
        return round(os.getloadavg()[0], 2)
    except Exception:
        return None


def node_status(node_id, tags):
    return {
        "id": node_id,
        "arch": platform.machine(),          # arm64 / x86_64 — real
        "os": "%s-%s" % (platform.system(), platform.release()),
        "python": platform.python_version(),
        "load_1m": load_avg(),
        "battery": battery_percent(),
        "tags": tags,
        "busy": BUSY["n"] > 0,
        "uptime_s": int(time.time() - START),
        "version": VERSION,
        "pid": os.getpid(),
    }


def execute_job(job):
    """Run one job dict -> result dict (raises on invalid jobs)."""
    mode = job.get("mode", "plain")
    ir = vm.ir_from_json(json.dumps(job["ir"])) if isinstance(job["ir"], str) \
        else job["ir"]
    if mode == "plain":
        values = job.get("inputs", [])
        scaled = vm.run_plain(ir, values)
        return {"mode": "plain", "scaled": scaled,
                "value": vm.decode_result(scaled, ir)}
    if mode == "he":
        from . import paillier as he
        pk = he.PublicKey.from_dict(job["pk"])
        cts = [int(c) for c in job["ciphertexts"]]
        out = vm.run_he(pk, None, ir, cts)
        return {"mode": "he", "ciphertext": str(out)}
    raise ValueError("unknown mode %r" % mode)


class Handler(BaseHTTPRequestHandler):
    node_id = "node"
    tags = []

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Aether-Version", VERSION)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):        # quiet by default
        if os.environ.get("AETHER_LOG"):
            sys.stderr.write("[agent] %s\n" % (fmt % args))

    def do_GET(self):
        if self.path in ("/", "/healthz"):
            return self._send(200, {"ok": True, "id": self.node_id,
                                    "version": VERSION})
        if self.path == "/status":
            return self._send(200, node_status(self.node_id, self.tags))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/run":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            job = json.loads(self.rfile.read(n).decode("utf-8"))
            if "ir" not in job:
                raise ValueError("missing 'ir'")
            BUSY["n"] += 1
            try:
                t0 = time.time()
                out = execute_job(job)
            finally:
                BUSY["n"] -= 1
            out["node"] = self.node_id
            out["ms"] = round((time.time() - t0) * 1000, 3)
            return self._send(200, out)
        except Exception as ex:
            return self._send(400, {"error": "%s: %s"
                                    % (type(ex).__name__, ex)})


def serve(node_id, port=8790, tags=None, host="0.0.0.0"):
    Handler.node_id = node_id
    Handler.tags = list(tags or [])
    httpd = ThreadingHTTPServer((host, port), Handler)
    print("[aether-agent] %s listening on %s:%d arch=%s tags=%s"
          % (node_id, host, port, platform.machine(), Handler.tags))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[aether-agent] bye")
    finally:
        httpd.server_close()


def main(argv=None):
    p = argparse.ArgumentParser(prog="aether-agent",
                                description="AetherOS node agent")
    p.add_argument("--id", default=os.environ.get("AETHER_NODE_ID",
                                                  platform.node() or "node"))
    p.add_argument("--port", type=int,
                   default=int(os.environ.get("AETHER_PORT", "8790")))
    p.add_argument("--tags", default=os.environ.get("AETHER_TAGS", ""))
    p.add_argument("--host", default="0.0.0.0")
    a = p.parse_args(argv)
    tags = [t.strip() for t in a.tags.split(",") if t.strip()]
    serve(a.id, a.port, tags, a.host)


if __name__ == "__main__":
    main()
