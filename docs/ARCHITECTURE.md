# Architecture — Aodı-AetherOS v1.0.0

## Process topology (one laptop, zero cloud)

```
                 ┌────────────────────────────┐
                 │  ae-core (Python)   :9461  │  hypervisor state,
                 │  server.py + sqlite seal   │  keys, cells, ledger
                 └────┬───────────────┬───────┘
        signed spawns │               │ link-state announce + votes
                      ▼               ▼
     ┌──────────────────────┐   ┌──────────────────────────┐
     │ AE_CELL/1.0a  :9465  │   │ ae-mesh (Go)      :9463  │
     │ AE_CELL/1.0b  :9466  │   │ Dijkstra + quorum votes  │
     │ single-file cells    │   │ link-state DB + epochs   │
     └──────────┬───────────┘   └──────────────────────────┘
                │ HMAC-signed /micro/exec (AVP bytes) ──▲
                └── self-join /ouroboros/join ──────────┘

     relay.js :7462 (optional) — telemetry digests to Telegram
     dashboard :9461/ (same process) — Arabic RTL control panel
```

## Module map (core/, all stdlib)

| Module | Responsibility | Key guarantees |
|---|---|---|
| `config.py` | `AE_*` env, paths, caps | AE_HOME built at import; constants single-source |
| `fhe.py` | Paillier + Shamir | exact `μ` via `L()`; randomized `r`; 2-of-3 refuses |
| `vproc.py` | AVP VM + binary format | deterministic; budget; oracle agreement |
| `morph.py` | Mach-O/PE/ELF forensics | arm64e aware; strict run-verdict |
| `fabric.py` | AEFR frames + hub client | CRC rejects bit-flips; math publishes chunk size |
| `ouroboros.py` | emit + spawn cells | sha256 manifests; HMAC joins & dispatch |
| `storage.py` | SQLite: seal chain et al. | tamper → `broken_at_idx` |
| `telemetry.py` | fire-and-forget events | daemon threads; never blocks |
| `server.py` | HTTP endpoints (table below) | stdlib only; ASCII Server header |
| `cli.py` | `aectl` operator surface | client-side decrypt = owner-only |

## Endpoints

| Method | Path | Real work performed |
|---|---|---|
| GET | `/`, `/api/state`, `/api/cells`, `/api/programs`, `/api/ledger`, `/api/events`, `/api/fhe/pubkey`, `/api/fabric/route` | state, seal head, live route |
| POST | `/api/fhe/keygen` | new ring + Shamir split + seal |
| POST | `/api/fhe/kernel` | live homomorphic bench (exact-match asserted) |
| POST | `/api/private/dot` | remote-client ciphertext scoring |
| POST | `/api/private/collect` | fleet additive-sum on ciphertexts |
| POST | `/api/vproc/run` | AVP local run + signed fanout + agreement |
| POST | `/api/morph` | real forensics + seal + verdict |
| POST | `/api/ouroboros/spawn` | emit + launch + self-join |
| POST | `/ouroboros/join` | HMAC-verified cell registration |
| POST | `/api/vote/propose` | epoch head + quorum rally + commit seal |
| POST | `/api/fabric/net` | frame bench + RTT map + Dijkstra route |

## Data flow: one private inference

1. `aectl infer 12` — client side builds the keyring from the *operator
   copy* (three Shamir shares live on the operator device, not the server).
2. Client encrypts 12 fixed-point values → hex ciphertexts.
3. Core applies public integer weights to ciphertexts (`E(Σ wᵢxᵢ)`).
4. Client decrypts and asserts equality with its own plaintext reference.
5. Run recorded **shape-only** (dims, ms, privacy flag) in `private_runs`.

## Data flow: one AVP fanout

1. Program compiled to bytes → sha256 identity.
2. Core runs locally; each live cell receives signed `prog_b64`.
3. Every node (incl. cells' embedded VM) reports `out[]` + op counts.
4. Exact agreement required; pass → dispatched to `programs` + sealed.
