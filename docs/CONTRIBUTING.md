# Contributing

**Rules of the house (non-negotiable):**

1. **Stdlib-only.** No pip, npm, CGo, cgo, vendored blobs or network
   services. Every new dependency breaks the sovereignty contract.
2. **Honesty contract.** Any feature that *sounds* bigger than it is must
   carry a code-level disclosure (see docstrings) and a line in
   `docs/WHITEPAPER.md` §honesty. Never fake JIT, bootstrapping, or
   network replacement.
3. **Measured or silent.** Benchmark numbers must come from real runs on
   real machines (`BENCHMARKS.md`), never estimates.
4. **Bounded autonomy.** New daemons get budgets, caps (`AE_MAX_CELLS`),
   HMAC auth and route-timeouts by default.
5. **Tests.** `python3 -m unittest discover tests` must stay green; new
   behavior earns a test.
6. **Style.** PascalCase types, `snake_case` funcs, ASCII identifiers in
   shipped bytes (Arabic lives in dashboard bodies, not headers/py files).

Pull requests: keep diffs surgical, explain the measured claim, and update
`docs/CHANGELOG.md` under `unreleased`.

MIT © 2026 Baran Avisat · baranavisat@gmail.com
