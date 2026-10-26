# Setup — Aodı-AetherOS (zero dependencies)

## Prerequisites
- **python3 ≥ 3.8** (only for core + cells)
- **Go ≥ 1.21** (optional — only to build the hub; a prebuilt `bin/ae-mesh` is attached to the GitHub release)
- **node ≥ 16** (optional — only for the Telegram relay)

Nothing else. No pip, no npm, no Docker, no internet required after clone.

## 1) Start the three services

```bash
cd mesh && go build -o ../bin/ae-mesh . && cd ..
./bin/ae-mesh &                     # consensus hub   :9463
python3 core/server.py &            # hypervisor core :9461
node relay/relay.js &               # (optional)      :7462
```

## 2) First fleet demo

```bash
python3 core/cli.py keygen 1024     # 88 ms class
python3 core/cli.py spawn 9465 9466 # two self-replicated cells
python3 core/cli.py vproc 1024      # AVP fanout + cross-node agreement
python3 core/cli.py vote            # quorum commit → sealed
python3 core/cli.py fabric 48       # frame bench + live Dijkstra route
```

## Environment (all optional)

| Var | Default | Meaning |
|---|---|---|
| `AE_HOME` | `~/.aetheros` | all state: SQLite ledger, keys, cells |
| `AE_PORT` | 9461 | core bind port |
| `AE_HUB_URL` | `http://127.0.0.1:9463` | consensus hub |
| `AE_FHE_BITS` | 1024 | Paillier size default |
| `AE_VM_BUDGET` | 4096 | AVP op budget |
| `AE_MAX_CELLS` | 12 | spawn cap |
| `AE_SECRET` / `AE_SECRET_HEX` | *(unset → open demo)* | hub auth / cell fleet token |
| `TELEGRAM_TOKEN`, `TELEGRAM_CHAT` | unset | relay notifications |

## Remote growth (documented bootstrap)

```bash
scp AFFINITY/cells/<id>/microd.py you@other-box:/tmp/microd.py
AE_ID=cell-x AE_PORT=9465 AE_PARENT=http://<this-host>:9461 \
AE_HUB=http://<hub-host>:9463 AE_SECRET_HEX=$(cat AFFINITY/keys/fabric.secret) \
python3 /tmp/microd.py
```

(The cell file is self-contained; the secret is your one shared token.)

## Troubleshooting
- Port busy → set `AE_PORT` / `AE_ADDR`; cells pick their own ports.
- Hub shows `auth: open (demo)` → export `AE_SECRET` for both hub and core.
- 35 offline tests: `python3 -m unittest discover tests` (never writes
  outside `AE_HOME` — point it at a temp dir to keep your state pristine).
