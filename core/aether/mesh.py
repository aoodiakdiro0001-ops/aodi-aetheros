"""Topology-aware mesh: measure, score, place, verify.

Honest version of "topological mesh consensus" (TEP):

1. MEASURE  — real HTTP round-trip probes to every node (no mythic
   sub-millisecond transport claims: we report the milliseconds we
   actually observe over your Tailscale/LAN).
2. SCORE    — each candidate gets a placement score from measured RTT,
   reported load and capability tags (lower is better).
3. PLACE    — the scheduler picks the best node (or top-K).
4. VERIFY   — "consensus" = run the SAME kernel on 2+ nodes and compare
   results byte-for-byte; disagreement is reported, never hidden.

If a node is dead, its score becomes infinite and placement falls to the
next candidate — bounded retries, never an infinite loop.
"""
import json
import time
import urllib.error
import urllib.request

PROBE_TIMEOUT = float(__import__("os").environ.get("AETHER_PROBE_TIMEOUT", "3"))
RETRY_BUDGET = int(__import__("os").environ.get("AETHER_RETRY_BUDGET", "2"))


def _get_json(url, timeout=PROBE_TIMEOUT):
    t0 = time.time()
    req = urllib.request.Request(url, headers={"User-Agent": "aetheros/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read()
    rtt = (time.time() - t0) * 1000.0
    return json.loads(body.decode("utf-8")), rtt


def probe(node):
    """Probe one node: {"ok":bool,"rtt_ms":float,"status":dict|None,"err":str}"""
    url = node["base_url"].rstrip("/") + "/status"
    try:
        status, rtt = _get_json(url)
        return {"ok": True, "rtt_ms": round(rtt, 2),
                "status": status, "err": None}
    except Exception as ex:
        return {"ok": False, "rtt_ms": None, "status": None,
                "err": "%s: %s" % (type(ex).__name__, ex)}


def probe_all(nodes, parallel=True):
    """Probe every node; returns {node_id: probe_result}."""
    results = {}
    if parallel and len(nodes) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(8, len(nodes))) as pool:
            futs = {pool.submit(probe, n): n for n in nodes}
            for fut, n in futs.items():
                results[n["id"]] = fut.result()
    else:
        for n in nodes:
            results[n["id"]] = probe(n)
    return results


def score_node(node, probe_result, job_tags=None):
    """Placement score (lower = better). Dead node -> +inf."""
    if not probe_result or not probe_result["ok"]:
        return float("inf")
    rtt = probe_result["rtt_ms"] or 0.0
    st = probe_result.get("status") or {}
    load = float(st.get("load_1m") or 0.0)
    battery = st.get("battery")            # None on desktops (honest)
    score = rtt + 12.0 * load              # latency dominates, load hurts
    if battery is not None:
        if battery <= 10:
            score += 5000.0                # near-dead device: do not use
        elif battery <= 20:
            score += 800.0                 # heavily deprioritize
    want = set(job_tags or [])
    have = set(st.get("tags") or node.get("tags") or [])
    if want and (want & have):
        score -= 250.0                     # capability match reward
    if st.get("busy"):
        score += 300.0
    return round(score, 3)


def schedule(nodes, probes, job_tags=None, top_k=1):
    """Rank nodes for a job. Returns ranked list of
    {"node":..., "score":..., "rtt_ms":...} (alive first)."""
    ranked = []
    for n in nodes:
        pr = probes.get(n["id"], {"ok": False})
        ranked.append({"node": n, "probe": pr,
                       "score": score_node(n, pr, job_tags),
                       "rtt_ms": pr.get("rtt_ms")})
    ranked.sort(key=lambda x: (x["score"] == float("inf"), x["score"]))
    alive = [r for r in ranked if r["score"] != float("inf")]
    dead = [r for r in ranked if r["score"] == float("inf")]
    return (alive[:max(1, top_k)] + dead)[:max(1, top_k)]


def run_verified(fn, nodes, probes, job_tags=None, redundancy=2):
    """Execute `fn(node) -> result` on the top `redundancy` live nodes and
    cross-check results (consensus by verification).

    Returns {"result":..., "agreed":bool, "executions":[...]}.
    Raises RuntimeError when no live node remains or budget is exhausted.
    """
    if redundancy < 1:
        raise ValueError("redundancy must be >= 1")
    picks = schedule(nodes, probes, job_tags, top_k=redundancy)
    picks = [p for p in picks if p["score"] != float("inf")]
    if not picks:
        raise RuntimeError("no live node available (probed: %s)"
                           % [n["id"] for n in nodes])

    executions, last_err = [], None
    attempts = 0
    remaining = list(picks)
    while remaining and attempts < max(RETRY_BUDGET * len(picks), len(picks)):
        cand = remaining.pop(0)
        attempts += 1
        t0 = time.time()
        try:
            value = fn(cand["node"])
            executions.append({"node": cand["node"]["id"], "ok": True,
                               "ms": round((time.time() - t0) * 1000, 1),
                               "value": value})
        except Exception as ex:
            last_err = "%s: %s" % (type(ex).__name__, ex)
            executions.append({"node": cand["node"]["id"], "ok": False,
                               "ms": round((time.time() - t0) * 1000, 1),
                               "error": last_err})
            # failover: promote the next live candidate
            extra = schedule(nodes, probes, job_tags, top_k=len(nodes))
            for p in extra:
                if (p["score"] != float("inf")
                        and p["node"]["id"] not in
                        [e["node"] for e in executions]
                        and p["node"]["id"] not in
                        [c["node"]["id"] for c in remaining]):
                    remaining.append(p)
        if len([e for e in executions if e["ok"]]) >= redundancy:
            break

    ok_vals = [e["value"] for e in executions if e["ok"]]
    if not ok_vals:
        raise RuntimeError("all executions failed: %s" % last_err)
    agreed = all(v == ok_vals[0] for v in ok_vals)
    return {"result": ok_vals[0], "agreed": agreed,
            "executions": executions,
            "verified": len(ok_vals) >= 2}


def topology_report(nodes, probes):
    """Human/dashboard-friendly mesh report."""
    rows = []
    for n in nodes:
        pr = probes.get(n["id"], {"ok": False, "err": "not probed"})
        rows.append({
            "id": n["id"],
            "up": bool(pr.get("ok")),
            "rtt_ms": pr.get("rtt_ms"),
            "err": pr.get("err"),
            "score": score_node(n, pr),
            "arch": (pr.get("status") or {}).get("arch") or n.get("arch"),
            "load_1m": (pr.get("status") or {}).get("load_1m"),
            "battery": (pr.get("status") or {}).get("battery"),
        })
    rows.sort(key=lambda r: (not r["up"], r["score"]))
    return {"generated_at": int(time.time()), "nodes": rows,
            "up": sum(1 for r in rows if r["up"]), "total": len(rows)}


def save_nodes(path, nodes):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"nodes": nodes}, f, indent=2)
    import os
    os.replace(tmp, path)


def load_nodes(path):
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d.get("nodes", [])
    except Exception:
        return []
