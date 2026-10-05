# Verification — October 5, 2026

Local Windows, Python 3.13.7. All checks below ran against the completed implementation.

| Check | Result |
| --- | --- |
| `python -m unittest discover -s tests -v` | 22 tests pass |
| Same suite with `python -O` | 22 tests pass |
| Pinned external data | 18 original artifacts match SHA256, byte lengths and Git blob IDs; 17 proof probes, 10 positive and 7 negative |
| Independent forest oracle | Every index and positive prefix for trees 1–32; maximum 4096-leaf tree, selected boundary indices and 4095→4096 growth |
| RFC symbolic example / fixed hashes | Seven-leaf paths and empty-tree/empty-leaf/known leaf checks pass |
| Controlled mutations | All five isolated weakenings detected; original source hashes unchanged |
| `python scripts/demo_reports.py --check` | Eight exact synthetic artifacts match |
| CLI samples | Inclusion 0; growth 0; changed leaf 1; empty prior 3 |
| `python -m compileall -q merkle_lab scripts tests` | Pass |
| Bandit 1.9.4, `merkle_lab scripts` | Zero findings, 465 lines, zero suppressions or skipped tests |

The five mutations remove leaf domain separation, omit the first consistency
root, accept extra inclusion nodes, weaken the proof bound and disable the output
bound. Each selected behavioral test fails on its isolated modified copy. This
is focused sensitivity evidence, not comprehensive mutation coverage.

Other tests exercise duplicate/empty records, false indexed statements, reordered,
truncated and extra paths, both roots, equal positive identity, unsupported empty
history, shrinking trees, strict JSON types/fields, malformed encodings, every
resource bound, missing anchors, log identity, unchanged evidence, exclusive
output and same-file/hardlink aliases. Split-view and stale-head controls show
that a mathematically valid proof supplies neither cross-client agreement nor
freshness. The oracle has a different iterative carry/forest structure and does
not import production tree code; it remains code written by the same agent.

Private full evidence is under `.private/verification/`: normal/optimized test
logs and exit records, Bandit JSON, CLI outputs, mutation results and repository
checks. The first sandbox run failed because Windows denied hardlink creation;
both final suites passed outside the sandbox, including that test. No skipped
hardlink test or inferred platform success is reported.

Workflow configuration and targeted credential signatures are checked separately
against tracked changes and this repository's Git blobs. A narrow signature scan
reported zero current/history hits; workflow structure, immutable pins, schedule,
manual dispatch and checkout credential settings passed. A narrow signature scan
cannot prove absence of secrets. Prepared CI/CodeQL has not run on GitHub. Linux,
hosted security eligibility/protections and independent cryptographic review are
not verified. No production/live log was tested or modified.
