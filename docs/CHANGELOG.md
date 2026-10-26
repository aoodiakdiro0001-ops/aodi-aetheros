# Changelog

## v1.0.0 — first sovereign release
- **FHE**: real Paillier (g=n+1), exact μ derivation, semantic security,
  ciphertext guards; threshold λ custody as Shamir 3-of-3 over RFC 3526
  Group-14 (2-of-3 refuses by construction). 1024-bit demo default, honest
  disclosure in WHITEPAPER.
- **AVP**: 11-opcode register VM + binary `AVP1` container, sha256 identity,
  4096-op budget, cross-node byte-exact agreement gate.
- **Morph**: Mach-O (thin/fat incl. arm64e), PE32/32+, ELF32/64 real
  forensics; strict run-verdict gates dispatch.
- **Fabric**: AEFR frames (magic+ver+seq+zlib+CRC32) — bit-flip proven
  rejected; measured 0.176 ms/48 KB pack; window math √(2·BW·RTT·ovh).
- **Mesh hub (Go)**: link-state announcements → live Dijkstra routes;
  majority-quorum epoch commit; optional HMAC auth.
- **Ouroboros**: single-file AE_CELL/1.0 emission (~9 KB), real process
  spawn, HMAC self-join, /micro/{health,exec,vote}.
- **Ledger**: SQLite sha256 seal chain with offline verify + tamper
  pinpointing; `ledger-solidity/AetherSeal.sol` on-chain anchor twin.
- **Ops**: `aectl` CLI, Arabic RTL live dashboard, 35/35 offline tests,
  zero-dependency CI (python unittest + go vet/build + node --check).
