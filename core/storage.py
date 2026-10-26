"""Aodı-AetherOS — SQLite storage (stdlib sqlite3) + sha256 seal chain.

    ledger        sha256 hash chain of every epoch commit / spawn / morphology
    programs      dispatched AVP programs: fingerprint + nodes + agreement
    spawns        ouroboros cells: id, manifest sha, caps, join moment
    private_runs  encrypted-compute record (NO plaintext ever, only shapes)
    events        telemetry tail
"""
import hashlib
import json
import sqlite3
import threading
import time

import config

_LOCK = threading.Lock()
_CONN = None


def _db():
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(str(config.DB_FILE), check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
        _CONN.executescript("""
        CREATE TABLE IF NOT EXISTS ledger(
            idx INTEGER PRIMARY KEY, ts REAL, kind TEXT, label TEXT,
            payload_sha256 TEXT, prev_hash TEXT, hash TEXT);
        CREATE TABLE IF NOT EXISTS programs(
            prog_sha256 TEXT PRIMARY KEY, name TEXT, n_instr INTEGER,
            nodes INTEGER, agreement INTEGER, results TEXT, ts REAL);
        CREATE TABLE IF NOT EXISTS spawns(
            cell_id TEXT PRIMARY KEY, manifest_sha TEXT, arch TEXT,
            python TEXT, port INTEGER, joined REAL);
        CREATE TABLE IF NOT EXISTS private_runs(
            prid INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, dims INTEGER,
            op_ms REAL, privacy_ok INTEGER, ts REAL);
        CREATE TABLE IF NOT EXISTS events(
            ts REAL, gen TEXT, level TEXT, message TEXT);
        """)
        _CONN.commit()
    return _CONN


def _sha(*parts):
    h = hashlib.sha256()
    h.update(b"".join(p.encode("utf-8") for p in parts))
    return h.hexdigest()


# ---------------- seal chain (tamper-evident, offline-verifiable) ----------
def seal_append(kind, label, payload_sha256):
    with _LOCK:
        row = _db().execute("SELECT MAX(idx), hash FROM ledger").fetchone()
        idx = (row[0] or 0) + 1
        prev = row[1] if idx > 1 else "GENESIS"
        h = _sha(prev or "", payload_sha256, kind, label)[:64]
        _db().execute(
            "INSERT INTO ledger(idx,ts,kind,label,payload_sha256,prev_hash,"
            "hash) VALUES(?,?,?,?,?,?,?)",
            (idx, time.time(), kind, label[:160], payload_sha256, prev, h))
        _CONN.commit()
    return {"idx": idx, "kind": kind, "label": label, "payload_sha256":
            payload_sha256, "prev_hash": prev, "hash": h}


def seal_rows(limit=50):
    with _LOCK:
        cur = _db().execute(
            "SELECT idx,ts,kind,label,payload_sha256,prev_hash,hash FROM "
            "ledger ORDER BY idx DESC LIMIT ?", (limit,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def seal_verify():
    with _LOCK:
        cur = _db().execute(
            "SELECT idx,payload_sha256,kind,label,prev_hash,hash FROM ledger "
            "ORDER BY idx ASC")
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    prev = "GENESIS"
    for r in rows:
        expect = _sha(prev, r["payload_sha256"], r["kind"], r["label"])
        if expect != r["hash"]:
            return {"ok": False, "broken_at_idx": r["idx"], "size": len(rows)}
        prev = r["hash"]
    return {"ok": True, "broken_at_idx": None, "size": len(rows),
            "head": prev}


# ---------------- programs (AVP dispatch ledger) ---------------------------
def record_program(prog_sha, name, n_instr, nodes, agreement, results):
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO programs(prog_sha256,name,n_instr,nodes,"
            "agreement,results,ts) VALUES(?,?,?,?,?,?,?)",
            (prog_sha, name[:80], n_instr, nodes, 1 if agreement else 0,
             json.dumps(results[:12]), time.time()))
        _CONN.commit()


def list_programs(limit=20):
    with _LOCK:
        cur = _db().execute(
            "SELECT prog_sha256,name,n_instr,nodes,agreement,results,ts FROM "
            "programs ORDER BY ts DESC LIMIT ?", (limit,))
        cols = [d[0] for d in cur.description]
        out = []
        for r in cur.fetchall():
            d = dict(zip(cols, r))
            try:
                d["results"] = json.loads(d.get("results") or "[]")
            except Exception:
                d["results"] = []
            out.append(d)
        return out


# ---------------- cells (ouroboros spawn registry) -------------------------
def register_cell(cell_id, manifest_sha, arch, python_v, port):
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO spawns(cell_id,manifest_sha,arch,python,"
            "port,joined) VALUES(?,?,?,?,?,?)",
            (cell_id, manifest_sha, arch, python_v, port, time.time()))
        _CONN.commit()


def list_cells():
    with _LOCK:
        cur = _db().execute(
            "SELECT cell_id,manifest_sha,arch,python,port,joined FROM spawns "
            "ORDER BY joined DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


# ---------------- private runs (shapes only, never plaintext) --------------
def record_private(kind, dims, op_ms, privacy_ok):
    with _LOCK:
        cur = _db().execute(
            "INSERT INTO private_runs(kind,dims,op_ms,privacy_ok,ts) "
            "VALUES(?,?,?,?,?)",
            (kind, dims, op_ms, 1 if privacy_ok else 0, time.time()))
        _CONN.commit()
        return cur.lastrowid


# ---------------- events ---------------------------------------------------
def log_event(gen, level, message):
    with _LOCK:
        _db().execute(
            "INSERT INTO events(ts,gen,level,message) VALUES(?,?,?,?)",
            (time.time(), gen or "", level, message[:400]))
        _CONN.commit()


def event_tail(limit=40):
    with _LOCK:
        cur = _db().execute(
            "SELECT ts,gen,level,message FROM events ORDER BY ts DESC LIMIT ?",
            (limit,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
