# SECURITY.md — Aodı-AetherOS threat model (v1.0)

**Owner / security contact:** Baran Avisat · baranavisat@gmail.com ·
WhatsApp +90 531 326 37 22

## What the design guarantees

1. **Plaintext never leaves the orchestrator.** Only ciphertexts and the
   *public* key travel to nodes. The secret key lives in
   `he_key.json` (created `0600`) or your memory.
2. **Nodes cannot read operands.** A Paillier ciphertext is
   indistinguishable from a random residue; a node that logs every job
   still learns nothing about the numbers without `sk`.
3. **Kernel compilation is sandboxed by construction.** `vm.compile_expr`
   accepts a whitelist AST only (no imports, calls, attributes, `**`,
   f-strings, comprehensions or unknown names). IR execution is a bounded
   stack machine (depth ≤ 64) over integers — no filesystem, no process,
   no network primitives exist in the ISA.
4. **Consent-based adoption.** `aether adopt` uses *your* SSH key against
   a host *you* specify. There is no discovery, no scanning, no
   self-propagation and no exploit usage anywhere in the codebase.
5. **Revocation.** `aether revoke user@host` kills the agent and deletes
   `~/.aether` in one command.

## Known limitations (v1.0 — stated, not hidden)

- **No TLS/auth on agent ports (8790/8795).** Run agents inside your
  Tailscale network or bind `--host 127.0.0.1`. Anyone who can reach the
  port can submit *kernels to execute* (bounded integer VM) and read
  node status — they still cannot see your plaintext inputs.
- **Side channels are out of scope.** Paillier here is a compact
  dependency-free implementation for personal sovereign computing; it is
  not hardened against power/EM/timing attacks on shared physical hosts.
- **Integrity of results** comes from redundant execution + comparison.
  A compromised node cannot *read* data, but two compromised nodes could
  agree on a wrong result — that is the honest limit of n-of-n checks.
- **Key strength:** default demo key is 1024-bit (fast); use
  `keygen --bits 2048` (or 3072) for anything that matters.

## Reporting

Found an issue? Email baranavisat@gmail.com with the subject
`[AetherOS security]`. Credit given in CHANGELOG unless you prefer
 anonymity.

© 2026 Baran Avisat
