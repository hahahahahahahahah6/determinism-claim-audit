# determinism-claim-audit

Offline static CLI comparing a Python project's documented determinism promises
with source patterns that may violate them. Python 3.9+, standard library only,
no runtime dependencies. Target code is parsed, never imported or executed.
No network access is used. Files named exactly `.env` are never opened, and
symlinks are skipped.

Install with `python3 -m pip install .` in a prepared environment, then run:

```sh
determinism-claim-audit ./project
determinism-claim-audit ./project --json
determinism-claim-audit ./project --fail-on HIGH --verbose
python3 -m determinism_claim_audit --version
```

The path defaults to the current directory. Exit 0 means no finding meets the
threshold, 2 means findings meet it, and 1 means an input or usage error.
The default threshold is MEDIUM. `--ignore RULE,...` removes matching rules.
JSON includes `status`, `findings`, and `verified_claims`; records contain only
classification labels, paths, and line numbers, never source contents.
Human findings use `SEVERITY rule file:line evidence-kind doc-file:line`.
`--verbose` lists claims for which no evidence was found.

Root README/README.md names are case insensitive; docs/**/*.md is also read.
Fenced code is excluded, and sentence-level negations suppress claims.
Claims cover deterministic, reproducible, and same-output phrases.
TIME, RANDOM, UUID, and ORDER evidence produces HIGH
`documented-deterministic-false` findings. Evidence exclusively in tests or
fixtures produces MEDIUM `documented-deterministic-false-test-only` findings.
Examples are excluded. Silent docs produce no finding. Claims with no Python
source produce HIGH findings, one per claim family. A fixed literal integer or
string `random.seed(...)` suppresses RANDOM evidence in the same source file.
Sorted set consumption and name-based UUID versions 3/5 do not count.

## Limitations

Static pattern/AST matching is not semantic analysis: dead code and values that
never reach output still count. Dynamic construction such as
`getattr(random, name)` and eval of source strings is missed. Module aliases,
re-exports, and data flow are not resolved. The seed guard is per-file and
literal-only; cross-file seeding is missed. Any builtin-shaped `hash()` call
counts, including deterministic integer hashes, as a deliberate
over-approximation for the common str/bytes case. Shadowed builtin/module names
can produce false positives. Thread, process, and asyncio scheduling are out of
scope. Only direct set iteration is detected; sets assigned to variables are
not tracked. Unparseable Python files produce input errors. A passing audit is
not proof of deterministic behavior.

## Neighbours

- bandit and ruff check code issues rather than documented promises.
- privacy-claim-audit checks network/telemetry evidence rather than determinism.
- readonly-claim-audit checks filesystem writes rather than output stability.
- security-claim-audit checks execution safety rather than determinism.
- config-claim-audit checks defaults rather than run-to-run stability.
- Property-based and snapshot tools such as hypothesis and pytest-regressions
  observe runtime behavior rather than statically auditing docs against code.

## Development

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 -m build --no-isolation
```

The sdist includes the unittest suite and fixtures. MIT licensed.
