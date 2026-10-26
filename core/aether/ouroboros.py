"""Ouroboros adoption — grow the mesh with YOUR OWN devices, consensually.

One command bootstraps a remote machine you already control (SSH access
= consent) into an AetherOS node:

    aether adopt dev@100.x.y.z --id win-gpu --port 8790 --tags gpu

What it really does (nothing hidden, nothing self-installing):
  1. preflight  : ssh BatchMode echo — fails fast without your key
  2. copy       : scp the single Python package to ~/.aether/
  3. start      : nohup python3 -m aether.agent ... (systemd/Termux friendly)
  4. verify     : GET /healthz until healthy (bounded retries)
  5. register   : append http://host:port to the local node registry

HONEST BOUNDARY: this adopts machines YOU own/have SSH keys for. It does
not propagate to third-party devices, needs no exploit, and can be
revoked in one line (kill the agent + delete ~/.aether).
"""
import json
import os
import subprocess
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))       # .../core/aether
CORE = os.path.dirname(HERE)                            # .../core
from . import mesh                                       # noqa: E402


def _ssh(args, host, timeout=25, check=True):
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=accept-new"] + args + [host]
    r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError("ssh failed: %s"
                           % (r.stderr.decode("utf-8", "replace").strip()
                              or "exit %d" % r.returncode))
    return r


def adopt(target, node_id, port=8790, tags=(), nodes_file=None,
           key_file=None, dry_run=False):
    """Adopt `target` (user@host) as a mesh node. Returns status dict."""
    if "@" not in target:
        raise ValueError("target must be user@host (SSH access required)")
    steps = []

    def step(name, detail=""):
        steps.append({"step": name, "detail": detail})
        print("[adopt] %-10s %s" % (name, detail))

    ssh_base = ["-o", "BatchMode=yes"]
    if key_file:
        ssh_base += ["-i", os.path.expanduser(key_file)]

    # 1) preflight — consent is your own SSH key
    step("preflight", "ssh %s" % target)
    if dry_run:
        return {"ok": True, "dry_run": True, "steps": steps}
    r = _ssh(ssh_base, target + " echo aether-ok")
    if b"aether-ok" not in r.stdout:
        raise RuntimeError("preflight mismatch: %r" % r.stdout[:80])

    # 2) copy package
    step("copy", "scp package -> ~/.aether/aether")
    _ssh(ssh_base, target + " mkdir -p ~/.aether")
    scp = ["scp", "-q", "-o", "BatchMode=yes", "-r",
           os.path.join(CORE, "aether"), target + ":.aether/"]
    if key_file:
        scp[3:3] = ["-i", os.path.expanduser(key_file)]
    r = subprocess.run(scp, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("scp failed: %s"
                           % r.stderr.decode("utf-8", "replace").strip())

    # 3) start agent (idempotent: kill previous instance first)
    step("start", "nohup python3 -m aether.agent --port %d" % port)
    tag_str = ",".join(tags)
    start_cmd = (
        "cd ~/.aether && "
        "(pkill -f 'aether.agent --port %d' || true) && "
        "nohup python3 -m aether.agent --id %s --port %d --tags '%s' "
        "> agent.log 2>&1 & sleep 1"
        % (port, node_id, port, tag_str))
    _ssh(ssh_base, target + " " + start_cmd)

    # 4) verify (bounded retries)
    url = "http://%s:%d/healthz" % (target.split("@", 1)[1], port)
    healthy = False
    for _ in range(8):
        try:
            with urllib.request.urlopen(url, timeout=4) as resp:
                if resp.status == 200:
                    healthy = True
                    break
        except Exception:
            time.sleep(1.0)
    step("verify", "GET %s -> %s" % (url, "healthy" if healthy else "FAILED"))
    if not healthy:
        raise RuntimeError("agent did not come up — check ~/.aether/agent.log "
                           "on %s" % target)

    # 5) register
    node = {"id": node_id,
            "base_url": "http://%s:%d" % (target.split("@", 1)[1], port),
            "tags": list(tags), "adopted": int(time.time())}
    if nodes_file:
        nodes = mesh.load_nodes(nodes_file)
        nodes = [n for n in nodes if n.get("id") != node_id] + [node]
        mesh.save_nodes(nodes_file, nodes)
        step("register", "%s -> %s" % (node_id, nodes_file))
    return {"ok": True, "node": node, "steps": steps}


def revoke(target, port=8790):
    """One-line removal of a node you adopted (kill + delete)."""
    if "@" not in target:
        raise ValueError("target must be user@host")
    _ssh([], target + " pkill -f 'aether.agent --port %d' ; "
                      "rm -rf ~/.aether" % port)
    return {"ok": True, "revoked": target}
