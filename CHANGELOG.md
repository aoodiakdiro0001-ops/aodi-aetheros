# Changelog — Aodı-AetherOS

## 1.0.0 — 2026-10-25

First public release.

### Added
- **Paillier homomorphic engine** (`core/aether/paillier.py`): keygen
  (Miller-Rabin), encrypt/decrypt (signed), homomorphic add/sub/scalar,
  fixed-point float helpers, JSON key serialization (files written `0600`).
- **Portable kernel IR** (`core/aether/vm.py`): safe AST-whitelisted
  expression compiler, bounded stack VM, fixed-point semantics,
  `check_he_compatible` guard that **rejects** encrypted×encrypted and
  division with explicit errors, JSON serialization.
- **Topology scheduler** (`core/aether/mesh.py`): concurrent RTT probes,
  placement scoring (latency · load · battery penalty · capability tag
  reward), verified-consensus execution with bounded failover.
- **Node agent** (`core/aether/agent.py`): stdlib HTTP server —
  `/healthz`, `/status` (honest nulls), `/run` (plain & HE modes; the
  agent never receives the secret key).
- **Orchestrator** (`core/aether/orchestrator.py`): distributed plain
  dispatch, HE dispatch, full encrypt→remote→decrypt demo, keypair I/O.
- **Ouroboros adoption** (`core/aether/ouroboros.py`): SSH-based bootstrap
  of your own devices (preflight → copy → start → verify → register) and
  one-command `revoke`.
- **CLI** (`core/cli.py`): `keygen · nodes · probe · run · he-demo ·
  adopt · revoke · agent · status` with owner credit in `--help`.
- **Go topology beacon** (`meshd/`): parallel heartbeats, RTT, last-seen
  view, `/mesh/status` JSON. `gofmt` + `go vet` clean.
- **Native C++ runner** (`native/aether_vm.cpp`): dependency-free runner
  for the same IR — cross-architecture equivalence verified 5/5 against
  the Python interpreter (identical rounding semantics).
- Tests: **28 offline tests**, all passing (crypto, IR safety, scheduler,
  failover, live HTTP end-to-end).
- Docs: README (EN/AR), SECURITY.md (threat model), BENCHMARKS.md (live
  numbers), Telegram sales post, CI workflow (tests + go vet + C++ build).

### Fixed during build (kept for honesty)
- Homomorphic `const ± ciphertext` paths initially treated constants as
  ciphertexts — corrected and covered by 5 mixed-operand tests.
- `/status` battery probe (`pmset`, ~15 ms) inflated every RTT reading —
  added a 60 s cache so measurements reflect transport, not telemetry.

© 2026 Baran Avisat · baranavisat@gmail.com
