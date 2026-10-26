# BENCHMARKS — Aodı-AetherOS v1.0.0

**Machine:** Apple MacBook (Apple Silicon, arm64, macOS, Darwin) · **Python:** 3.8.10 ·
**Go:** 1.25 (hub) · **Node:** v26.12.1 (relay) · **Date of run:** 2026-10-26 ·
**Scope:** every number below is from the LIVE services (`ae-mesh :9463`, `ae-core
:9461`, `relay :7462`) in one continuous session; nothing is estimated or
simulated. Zero third-party dependencies throughout.

## Layer I — Additive FHE (real Paillier, `core/fhe.py`)

| Operation | Measured |
|---|---|
| Keygen 1024-bit ring (server, `/api/fhe/keygen`) | **140.8 ms** |
| Keygen 1024-bit (module selftest) | **88 ms** |
| Encrypt a pair | **34.1 ms** (16.3–16.8 ms avg per value at 16 dims) |
| Private live kernel 16 dims (`/api/fhe/kernel`) | encrypt 16.7 ms/dim · linear **0.84 ms** · decrypt 16.8 ms · **exact_match=true** |
| Fleet additive combine ×4 (`aectl collect`) | **0.05 ms** node-side; recovered sum exact ✓ |
| Client privacy loop 12 dims (`aectl infer`) | client enc 199.2 ms · node blind E(Σwᵢxᵢ) **87.6 ms** · client decrypt → **exact: True** |
| Homomorphic add / scalar-mul / negative weights | verified exact (unit tests) ✓ |
| Threshold custody (Shamir 3-of-3, RFC3526 P) | exact reconstruction; 2-of-3 refused by construction ✓ |
| Semantic security | two encryptions of the same plaintext differ ✓ |

## Layer II — Portable execution

| Operation | Measured |
|---|---|
| AVP local run, n=1024 (`/api/vproc/run`) | **358,438,400 = closed-form oracle** in **2.05 ms**, 6,148 ops |
| Fleet fanout (core + 2 self-replicated cells) | 3 nodes → `out` **byte-identical** → `agreement: true` ✓ |
| Cell-side AVP execution | 1.0 ms each (embedded compact VM) |
| Ouroboros emission | single file **6,153 bytes**; manifest stores its sha256 |
| Emission + real process spawn | **0.6–1.2 ms** emit · health handshake **0.41 s** |
| HMAC self-join of the child | verified (`registered_by: child-join`) ✓ |
| Morph on `/bin/ls` | mach-o-fat [x86_64, arm64, **arm64e**] → verdict **runs** ( fingerprint c60cbb46bf001fb6… ) |
| Morph on python3 | mach-o-fat [x86_64, arm64] → verdict **runs** |
| Synthetic PE / ELF refusals | recognized + honest verdicts ✓ (35/35 tests) |

## Layer III — Topological fabric + consensus

| Operation | Measured |
|---|---|
| AEFR pack (48 KB payload, 200 iters) | **0.167–0.176 ms** avg |
| AEFR unpack | **0.074–0.076 ms** avg |
| Pack-rate estimate | **4.6–4.8 MB/s** |
| Corruption defense | single bit-flip → **detected & rejected** ✓ |
| Frame overhead bytes | 101 B frame @48KB payload |
| Adaptive chunk math | 512 B @ 0.3 ms RTT → 978–1004 B @ 8 ms RTT |
| Live RTT to cells | **1.02 ms** (:9465) · **0.96 ms** (:9466) |
| Dijkstra over live graph | 4 nodes · 3 edges · route hub→core-9461 0 ms; hub→cell via core at **2.04 / 1.98 ms** |
| Whole-fabric wall time | **55–57 ms** (bench + probe + announce + route) |

## Consensus (majority quorum over the live fleet)

| Operation | Measured |
|---|---|
| Epoch propose → 3 signed votes (core + 2 cells) | hub tallies → **quorum_required 2, votes 3 → committed: true** |
| Consensus policy | latest-epoch-only (stale epochs can never out-commit) |
| Commit consequence | sealed into the ledger chain ✓ |

## Integrity (seal chain, `core/storage.py`)

| Operation | Measured |
|---|---|
| Live ledger after the full demo | **11 sealed rows** — verify `ok=true` |
| Row kinds in order | 4× ouroboros-spawn · 2× avp-dispatch · morphology · consensus-commit · fhe-keygen… |
| Tamper story | rewritten row → `ok=false` + **broken_at_idx pinpoints the forgery** (unit-proven) |

## Executables

| Binary | Size |
|---|---|
| `bin/ae-mesh` (Go hub) | ~3.4 MB (see release) |
| `microd.py` emitted cell | **6,153 bytes** |

## Reproduce

```bash
./bin/ae-mesh & python3 core/server.py & node relay/relay.js &
python3 core/cli.py spawn 9465 9466 && python3 core/cli.py vproc 1024 \
  && python3 core/cli.py fabric 48 && python3 core/cli.py vote
```

29 files checked clean in this repo before publishing (no plaintext
secrets, no leaked key material, no stray binaries) — see the release
notes for the exact gates.
