# AetherOS Fleet Guide — examples

Everything below runs against the live stack (hub :9463 + core :9461).

## 1. Privacy loop, by hand (curl + python on your side)

```bash
# server publishes the PUBLIC ring (encryption needs no secret):
curl -s http://127.0.0.1:9461/api/fhe/pubkey
```

```python
# on YOUR device (owner): encrypt two features, node scores them blind
import sys; sys.path.insert(0, "core")
import fhe, json, urllib.request
key = fhe.keygen(512)                      # owner-side demo ring (fast)
enc = [fhe.enc_hex(key, fhe.encrypt(key, v)) for v in (140, 88)]
req = urllib.request.Request("http://127.0.0.1:9461/api/private/dot",
        data=json.dumps({"enc_values": enc}).encode(), method="POST")
out = json.loads(urllib.request.urlopen(req).read())
score = fhe.decrypt(key, fhe.from_enc_hex(key, out["enc_score_hex"]))
print("score:", score, "| node saw only:", [e[:12] + "…" for e in enc])
```

The node computed `E(Σ wᵢxᵢ)` on values it could never read, and
`/api/private/dot` returns the raw encrypted score hex for any remote
client that arrives with its own ring.

## 2. Self-replication tour

```bash
python3 core/cli.py spawn 9465 9466
 AFFINITY/cells/$(ls AFFINITY/cells | head -1)/microd.py   # ~9 KB, self-contained
curl -s http://127.0.0.1:9465/micro/health                 # the child answers
python3 core/cli.py cells                                  # join provenance
```

Each cell: `AE_ID` identity, manifest sha256 in the ledger, embedded AVP.

## 3. Consensus tour

```bash
python3 core/cli.py vproc 1024   # fanout: 3 nodes must agree byte-exact
python3 core/cli.py vote         # epoch → votes → quorum commit → sealed
curl -s http://127.0.0.1:9461/api/ledger | python3 -m json.tool | head
```

## 4. Morph tour

```bash
python3 core/cli.py morph /bin/ls /bin/bash
 Aodı-fat [arm64, x86_64] → "runs"; try any .exe → verdict "incompatible" + honest reasons
```

## 5. Fabric tour

```bash
python3 core/cli.py fabric 48
# → pack 0.176 ms · unpack 0.076 ms · bit-flip rejected ✓
# → chunk_at_0p3ms 512 → chunk_at_8ms 978 · live Dijkstra routes
```

## 6.煮 Everything at once (the dashboard)

`open http://127.0.0.1:9461/` — Arabic RTL, every button fires a real
endpoint; state cards refresh every 4 s from `/api/state`.

## 7.ylland Seal exploration

```bash
sqlite3 AFFINITY/aetheros.db "SELECT idx,kind,label FROM ledger ORDER BY idx DESC LIMIT 12;"
```

MIT © 2026 Baran Avisat.
