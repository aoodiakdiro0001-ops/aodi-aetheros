# Aodı-AetherOS

**The Sovereign Homomorphic Neural Hypervisor** — compute on data that
never gets decrypted, on machines you own, with one portable kernel
format across every architecture. **Zero cloud, zero paid APIs, nothing
leaves your tailnet.**

| Layer | Language | Role |
|---|---|---|
| `core/` | Python 3.8+ (stdlib only) | Paillier HE engine · portable kernel IR (VM) · topology scheduler · node agent · orchestrator · Ouroboros adoption · CLI |
| `meshd/` | Go 1.21+ (stdlib only) | topology beacon: parallel heartbeats, real RTT, last-seen mesh view |
| `native/` | C++17 | native runner for the **same** IR — ARM64 and x86_64 execute identical semantics |
| `tests/` | Python | 28 offline tests: crypto, IR safety, scheduler, failover, live HTTP e2e |

- **License:** MIT © 2026 Baran Avisat
- **Support:** baranavisat@gmail.com · WhatsApp +90 531 326 37 22 (wa.me/905313263722)
- **Stack:** 100% free · local · dependency-free (Python stdlib + Go stdlib + clang)

## The problem it kills

- Cloud AI means your code, your data and your findings leave your
  machine the moment you paste them into someone else's server.
- Your devices sit idle and disconnected: a strong Windows GPU box, an
  always-on Mac, a phone — each alone, none coordinated.

**AetherOS merges them into one sovereign compute plane**, and adds the
property clouds charge for: *the remote machine computes without seeing
your data.*

## Live numbers (recorded on the author's M1 Pro)

Full dataset in [BENCHMARKS.md](BENCHMARKS.md):

| Metric | Value |
|---|---|
| Test suite (crypto · IR · scheduler · e2e HTTP) | **28/28 pass** in 0.9 s |
| Cross-architecture equivalence (Python vs native C++ runner) | **5/5 kernels byte-identical** |
| Distributed run, redundancy=2, consensus | `3*x+7*y-2` → **agreed=True verified=True** (0.8–1.0 ms/exec) |
| Homomorphic round trip (1024-bit Paillier) | encrypt here → **remote node computes blind** → decrypt `155` ✓, ciphertext byte-match ✓ |
| Go meshd heartbeat RTT (loopback, 2 peers) | **1.57 ms** / 1.59 ms |
| Ciphertext size (1024-bit n) | 616 digits per encrypted number |

## Architecture

```
        [ you: secret key stays HERE, always ]
                     │  (plaintext never leaves)
   ┌─────────────────┼──────────────────────┐
   ▼                 ▼                      ▼
[ Mac agent :8790 ] [ Windows GPU agent :8790 ] [ phone/Termux agent ]
  ARM64 · Python      x86_64 · Python             aarch64 · Python
   │  same IR bytecode (JSON)  │  same IR bytecode │
   ▼                           ▼                   ▼
[ native C++ runner — same IR, compiled per-arch (arm64 / x86_64) ]
                     │
        [ meshd (Go) heartbeats: real RTT, honest last-seen ]
                     │
        [ orchestrator: schedule → run redundant → compare → decrypt ]
```

## What is REAL vs what we honestly do NOT claim

| Pitched idea | What AetherOS actually ships |
|---|---|
| "Full FHE — train neural nets on encrypted data at full speed" | **Real Paillier additively-homomorphic engine**: encrypted `+`, `-`, `×constant` executed by nodes that see only opaque integers. Enough for secure aggregation & private analytics. Full FHE (TFHE/CKKS) needs heavyweight libraries — documented as roadmap, never faked. |
| "Binary morphing between ARM and x86 at runtime" | **One portable IR + one runner per architecture.** Python runner and native C++ runner verified byte-identical (5/5 kernels). This is how cross-arch actually works; runtime machine-code rewriting between ISAs is not a thing we pretend to do. |
| "Sub-millisecond consensus replacing TCP" | **Measured RTT scheduling** (Go beacon: 1.57 ms observed on loopback) + **consensus by verification**: the same kernel runs on 2+ nodes and results are compared byte-for-byte. Disagreement is reported loudly, never hidden. |
| "Self-replicating daemon that installs itself anywhere" | **Ouroboros adoption**: one command bootstraps a device **you own** over **your** SSH key (`aether adopt dev@host`). Consent-based by design; one-command revocation. No third-party propagation, no exploits. |
| "100% security" | No system claims 100%. Here: plaintext never leaves the orchestrator, nodes hold only the public key, agent processes run unprivileged, key files are `0600`. Threat model documented in [SECURITY.md](SECURITY.md). |

## Run in 60 seconds (no pip, no npm)

```bash
# 1) start two local nodes (or one per machine you own)
python3 core/cli.py agent --id mac-local  --port 8790 --tags local,fast &
python3 core/cli.py agent --id mac-backup --port 8791 --tags local &

# 2) register + measure the topology (real RTT, real load, honest battery)
python3 core/cli.py nodes add mac-local  http://127.0.0.1:8790 --tags local,fast
python3 core/cli.py nodes add mac-backup http://127.0.0.1:8791 --tags local
python3 core/cli.py probe

# 3) distributed kernel with redundancy + consensus
python3 core/cli.py run "3*x + 7*y - 2" --inputs 11,-4 --redundancy 2

# 4) homomorphic round trip: encrypt -> remote computes blind -> decrypt
python3 core/cli.py keygen --bits 1024 --out he_key.json
python3 core/cli.py he-demo "a + b - c" --inputs 120,42,7 --remote

# 5) optional: Go topology beacon over the mesh
cd meshd && go build -o ../bin/aether-meshd . && cd ..
./bin/aether-meshd -id mac-local -addr :8795 \
    -peers http://127.0.0.1:8790,http://127.0.0.1:8791

# 6) grow the mesh with YOUR devices (SSH = consent)
python3 core/cli.py adopt dev@100.x.y.z --id win-gpu --tags gpu
python3 core/cli.py revoke dev@100.x.y.z        # one-line removal
```

Native runner (same IR, your CPU):

```bash
c++ -O2 -std=c++17 -o native/aether_vm native/aether_vm.cpp
python3 -c "import sys; sys.path.insert(0,'core'); \
from aether import vm; import json; \
print(json.dumps(vm.compile_expr('2*x + y - 0.5', ['x','y'])))" > /tmp/k.json
./native/aether_vm /tmp/k.json 7,3        # -> 16500000 (== Python)
```

## Portable kernel IR (the cross-architecture contract)

Kernels are math expressions compiled to a tiny stack VM bytecode:

```python
from aether import vm
ir = vm.compile_expr("2 * x + y - 0.5", ["x", "y"])   # {"ops":[["PUSH",2000000],...]}
vm.run_plain(ir, [7, 3])                               # scaled integer
```

Safety: expressions are parsed with a strict AST whitelist — no imports,
no attribute access, no calls, no `**`, no unknown names. Compiling
untrusted expressions cannot reach your filesystem or interpreter.

Homomorphic mode (`scale=1`) additionally rejects anything Paillier
cannot honestly do (`x*y` encrypted, division) with an explicit error —
the engine refuses to lie about its capabilities.

## Tests

```bash
python3 tests/test_aether.py -v     # 28 tests, offline
gofmt -l meshd && go vet ./meshd/   # Go layer
c++ -O2 -std=c++17 -o /tmp/vm native/aether_vm.cpp   # native layer
```

## Security & consent boundary

See [SECURITY.md](SECURITY.md). Short version:

- Secret key never leaves the orchestrator; nodes receive `pk` only.
- `adopt` requires *your* SSH key to a machine *you* control — it is a
  bootstrap tool, not a propagation worm. `revoke` kills and cleans up.
- Agents bind `0.0.0.0` by default (tailnet usage); restrict with
  `--host 127.0.0.1` for single-machine runs. No auth layer yet — run
  inside your Tailscale network, which is the documented v1 posture.

## لماذا Aodı-AetherOS؟

يوفّر Aodı-AetherOS بنية تحتية متقدمة للسيادة الرقمية، حيث يدمج بين
الخصوصية المطلقة وقوة الحوسبة الموزعة:

* **محرك التشفير المتجانس (Homomorphic Engine):** خوارزمية `Paillier`
  تُبقي البيانات مشفرة بالكامل أثناء العمليات الحسابية (الجمع والطرح
  والضرب على الثوابت) على العقد البعيدة، ولا يُفك التشفير إلا من المالك.
* **نوى برمجية متنابل (Portable Kernels):** `Bytecode IR` واحد يُنفَّذ
  بشكل متطابق على `ARM64` و`x86_64` دون تعديل الكود لكل منصة.
* **مجدول مدرك للطوبولوجيا (Topology-aware Scheduler):** قياس حقيقي
  لزمن الاستجابة `RTT` لتوزيع المهام على الأنسب مع تنفيذ مكرر وتوافق
  عبر العقد.
* **بروتوكول Ouroboros:** ربط أجهزتك الخاصة عبر `SSH` بأمر واحد —
  بموافقتك وضماناتك، مع إلغاء بأمر واحد.
* **بيئة مغلقة تمامًا:** لا سحابات خارجية، لا واجهات `APIs` مدفوعة،
  وكل الاتصالات محلية عبر شبكة `Tailscale`.

كل ما يُعرض مبني فعليًا ومفتوح للفحص — لا وعود سحرية.

## Honest disclosure

- Additive homomorphism ≠ full FHE. Encrypted × encrypted and division
  are rejected at runtime with a clear error, not silently approximated.
- "Consensus" here is result-comparison across redundant executions
  (Byzantine-tolerant in the trivial n-of-n sense), not a BFT chain.
- The IR is a linear-arithmetic VM by design (no branches yet) so it
  stays homomorphic-friendly; general kernels run in `plain` mode.
- Node agents have no TLS/auth in v1 — operate them on your tailnet.
- Battery/load fields report `null` when the OS cannot tell us; we never
  invent telemetry.

© 2026 Baran Avisat · Professional Programmer · MIT
📧 baranavisat@gmail.com · 📞 +90 531 326 37 22 · WhatsApp wa.me/905313263722
BTC `bc1q8dhtdrndxsl70e97t8grydfe6pjue37zrhzf6c` · USDT-TRC20 `TLWdTjqqogkXNEXGiPWsGdjFP6ioycxeWW`
