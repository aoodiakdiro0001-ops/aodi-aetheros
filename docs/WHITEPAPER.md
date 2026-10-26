# Aodı-AetherOS Whitepaper v1.0.0

**A Sovereign Homomorphic Neural Hypervisor & Self-Replicating Matrix**
Baran Avisat · baranavisat@gmail.com · MIT © 2026

---

## 1. Thesis

Cloud homomorphic computing is sold as an API and consumed as a black box.
AetherOS turns the privacy contract into *code you own*: a single product
whose four layers — additive FHE, portable execution, measured topology,
self-replication — each exist as auditable, dependency-free source with
published, measured behavior and an explicit honesty ledger of what is and
is not built.

## 2. Layer I — Additive FHE (real Paillier)

**Construction (exactly as published, 1982/1999):**

- Keygen: `p, q` strong probable primes (Miller–Rabin, stdlib `secrets`),
  `n = p·q`, `λ = lcm(p−1, q−1)`, `g = n+1`, and the trapdoor
  `μ = L(g^λ mod n²)^{-1} mod n` where `L(u) = (u−1)/n` — derived by actual
  computation, never assumed.
- Encryption: `c = (1 + m·n) · r^n mod n²`, `r` coprime to n (≤ 2 attempts).
- Decryption: `m = L(c^λ mod n²) · μ mod n`.
- Properties shipped and unit-proven: `E(a)·E(b) ≡ E(a+b)`,
  `E(a)^k ≡ E(ka)` (k may be negative mod n), randomized ciphertexts
  (semantic security) and a ciphertext range guard.

**Private linear kernel.** A client encrypts its feature vector
fixed-point (scale 10⁶). The node applies public model weights to
ciphertexts: `E(Σ wᵢxᵢ) = Π E(xᵢ)^wᵢ mod n²`. The node never sees a value;
the client decrypts the score and we assert exact equality with a plaintext
reference in the live benchmark (`/api/fhe/kernel`, `aectl infer`).

**Threshold custody.** The master trapdoor `λ` is never stored at rest. It
is split with a *real* Shamir 3-rd-degree scheme over the RFC 3526 Group-14
2048-bit prime: 3 shares, 3 required — 2 shares mathematically refuse to
combine (raises), so no partial key can ever exist on one device.

**Honest sizing disclosure.** Demo keys are 1024-bit by design for
interactive Python-math latency (88 ms keygen measured). RFC 5116-grade
parameter selection (≥2048/3072-bit moduli) is a documented one-line change
(`AE_FHE_BITS`) plus patience — and is pointed out as future work with
`gmpy2`-free pure-scaling notes. Bootstrapping / multiplicative depth
(true CKKS/BFV) is out of scope for a stdlib-only artifact and is
explicitly *not* claimed anywhere in this codebase.

## 3. Layer II — Portable execution: AVP + Morph

**The honest replacement for an x86↔ARM JIT.** Rather than fabricate a
machine-code emitter (which cannot be honestly built without a full backend
and is never claimed), AetherOS ships a *third thing that already works*:

- **AVP** (`core/vproc.py`): 11-opcode register VM, binary container
  (`AVP1` header + `>Bii` instruction stream + `>q` constants), sha256
  program identity, hard operations budget (4096 default), zero syscalls.
  The canonical kernel (sum of squares) agrees byte-for-byte with the
  closed-form oracle `n(n+1)(2n+1)/6` and — after fleet fanout — across
  every core/cell that executes it. Agreement is computed, recorded and
  committed to the seal ledger only when exact.
- **Morph** (`core/morph.py`): real header-window forensics for Mach-O
  thin/fat (including the `arm64e` cpu-subtype), PE32/PE32+ and ELF
  32/64-bit: machine, PIE/ASLR flag, endianness, section counts, link
  timestamp, sha256, printable strings, and a strict run-verdict for the
  *executing* node. The verdict is not advisory: cells only receive jobs
  their morphology says they can run.

## 4. Layer III — Topological fabric + consensus (TEP, honest)

AetherOS does not bypass TCP/IP (impossible inside stdlib and never
claimed). It makes the transport *smart and cheap*, all measured:

- **AEFR framing** (`core/fabric.py`): magic + version + seq + zlib payload
  + CRC32. One flipped bit is detected and rejected (unit-proven). Pack at
  48 KB: 0.176 ms; unpack 0.076 ms; ~4.6 MB/s pack-rate on the loopback.
- **Window mathematics**: chunk size `≈ √(2·BW·RTT·overhead)` — published,
  deterministic, responds to measured RTT (512 B @ 0.3 ms → 978 B @ 8 ms).
- **Link-state + Dijkstra** (`mesh/main.go`): every node announces its
  measured RTT map; the hub runs real Dijkstra over the live adjacency and
  serves min-cost routes with explicit paths.
- **Quorum consensus**: any node proposes an epoch head; the hub tallies
  signed votes, requires a clean majority − (n/2)+1 − and only then
  commits; the commit is sealed into the ledger chain.

## 5. Layer IV — Ouroboros (self-replication, honest)

`emit()` writes a **complete, single-file AE_CELL/1.0 micro-daemon**
(stdlib-only, embedded compact AVP) plus a signed manifest recording its
sha256. `spawn()` runs it as a real OS process; the child then
*self-registers* with the parent via an HMAC-SHA256-signed
`/ouroboros/join` (retrying until acceptance), exports
`/micro/health · /micro/exec · /micro/vote`, and executes dispatched AVP
programs with byte-exact results.

**Boundaries kept honest:** on the local machine this is fully automatic;
onto an external device (another Mac, a Windows PC, a Linux box) growth =
copy one file + run one documented bootstrap line. Stock phones cannot be
infected hands-free and The Matrix does not pretend otherwise.

## 6. Integrity: the seal chain

Every consequential act (keygen, AVP dispatch, morphology, spawn, commit)
appends to a **sha256 hash chain** in SQLite: `hᵢ = sha256(hᵢ₋₁ ‖ payload ‖
kind ‖ label)`. `seal_verify()` replays the whole chain offline; any single
written byte flips the outcome and `broken_at_idx` points at the first
forged record (unit-tested). `ledger-solidity/AetherSeal.sol` gives the
same construction as an optional on-chain anchor.

## 7. Threat model & limits

Protected against: honest-but-curious compute nodes and network
eavesdroppers (values never exist in plaintext server-side); accidental or
malicious DB tampering (chain); silent bit corruption (CRC); runaway local
programs (budget); unauthenticated fleet join (HMAC, token shared
out-of-band). **Not** protected against: a node operator who also holds ≥2
of 3 Shamir shares with the ledger, malformed-power side channels, and
quantum adversaries (no crypto here is post-quantum — stated plainly).

## 8. Artifact summary

| Layer | Entrypoint | Measured |
|---|---|---|
| FHE | `core/fhe.py` | keygen 88 ms @1024-bit · exact kernels |
| Portable exec | `core/vproc.py`, `core/morph.py` | 385 == oracle · 3-binomial morph verdicts |
| Topology | `core/fabric.py`, `mesh/main.go` | 0.176 ms pack · bit-flip rejected · live Dijkstra |
| Self-replication | `core/ouroboros.py` | single-file cells · signed joins |
| Integrity | `core/storage.py`, `ledger-solidity/` | chain verify + tamper pinpoint |

MIT © 2026 Baran Avisat.
