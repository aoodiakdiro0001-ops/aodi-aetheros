# BENCHMARKS — Aodı-AetherOS v1.0.0

All numbers below were **recorded live** on the author's MacBook
(M1 Pro, 16 GB, macOS, Python 3.8.10, Go 1.27, clang++/C++17) during the
build session — every row is command output, not a spreadsheet estimate.

## Test suite

| Metric | Value |
|---|---|
| Offline tests (Paillier · IR · scheduler · agent · orchestrator e2e) | **28/28 PASS**, 0.945 s wall clock |
| Keygen used in tests | 512-bit (fast); demos use 1024-bit |

## Cross-architecture equivalence (the "one IR, many machines" proof)

Python interpreter (ARM64) vs native C++ runner (compiled `arm64-apple`)
on the identical IR bytes — `tests` equivalent run of 5 kernels:

| Kernel | Python scaled result | C++ scaled result | Match |
|---|---|---|---|
| `2 * x + y - 0.5` @ 7,3 | 16500000 | 16500000 | ✓ |
| `x * y` @ 1.5,4 | 6000000 | 6000000 | ✓ |
| `x / 4` @ 10 | 2500000 | 2500000 | ✓ |
| `3*x + 7*y - 2` @ 11,-4 | 3000000 | 3000000 | ✓ |
| `-x + 100.25` @ 0.75 | 99500000 | 99500000 | ✓ |

**5/5 byte-identical**, including half-to-even rounding on fixed-point
division (matched via `llrint` vs Python `round`).

## Distributed run (two real HTTP agents, consensus by verification)

```
[kernel] 3*x + 7*y - 2   inputs=[11, -4]
  -> mac-backup   ok     1.0ms
  -> mac-local    ok     0.8ms
result = 3.0   agreed=True verified=True
```

## Homomorphic round trip (1024-bit Paillier)

```
[1] plaintext here        : inputs=[120, 42, 7]
[2] encrypted here        : 3 ciphertexts (616 digits each)
[3] remote node(s) compute : mac-backup      <- saw ONLY ciphertexts
[4] decrypted back here    : 155             (120 + 42 - 7 ✓)
[5] ciphertext byte-match  : True            <- remote == local result
```

## Topology measurement

| Probe | RTT | Notes |
|---|---|---|
| Go `meshd` → agent :8790 (loopback) | **1.57 ms** | parallel heartbeat, 2 s interval |
| Go `meshd` → agent :8791 (loopback) | **1.59 ms** | |
| Python orchestrator → `/status` (before battery cache) | ~20.6 ms | included a `pmset` subprocess (~15 ms) per call |
| Python orchestrator → `/status` (after 60 s battery cache) | ≈ transport + JSON | cache added precisely because the honest number was embarrassing — we fixed the overhead, not the measurement |

Placement scores observed (load 8.82, battery `n/a` on desktop):
`mac-backup 126.4`, `mac-local 127.5` (score = RTT + 12·load − tag reward).

## Scaling notes (honest)

- Paillier keygen 1024-bit: ~1 s (pure Python Miller-Rabin);
  2048-bit: several seconds. Encryption ~0.5–2 ms/op, homomorphic add
  is a single modular multiply (microseconds).
- Ciphertext expansion: n² modulus ⇒ ~2× key bits per encrypted number
  (616 decimal digits for 1024-bit n).
- Agent throughput: bounded stack VM — dominated by HTTP overhead
  (~1 ms loopback), not by arithmetic.

© 2026 Baran Avisat · every row reproducible via the commands in README
