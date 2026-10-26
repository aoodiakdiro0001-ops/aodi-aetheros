# Contributing — Aodı-AetherOS

Designed & built by **Baran Avisat** (Professional Programmer).
📧 baranavisat@gmail.com · 📞 +90 531 326 37 22 · WhatsApp wa.me/905313263722

## Ground rules

1. **Honesty is a feature.** Every benchmark must be reproducible from a
   documented command. No simulated numbers, no aspirational claims
   written as if shipped.
2. **stdlib-only** for Python and Go layers (the whole point is zero
   dependency / zero cloud). `native/` may use the C++ standard library
   only.
3. **The IR is the contract.** Any change to `vm.py` semantics must be
   mirrored in `native/aether_vm.cpp` and covered by an equivalence test.
4. **Never break the safety whitelist** in `compile_expr` — new AST node
   types require a security note in SECURITY.md.
5. **Consent boundary:** no discovery/scanning/propagation code, ever.

## Workflow

```bash
python3 tests/test_aether.py -v     # must stay 28/28 (or better)
gofmt -l meshd && go vet ./meshd/
c++ -O2 -std=c++17 -Wall -Werror -o /tmp/vm native/aether_vm.cpp
```

Commit message style: `area: what changed (why)` — see CHANGELOG.

## Credit

Substantial contributions are listed in CHANGELOG.md. The project's
authorship and support block (OWNER credit in README/LICENSE) stay intact.

© 2026 Baran Avisat · MIT
