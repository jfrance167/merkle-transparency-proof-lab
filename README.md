# Merkle transparency proof lab

An offline Python lab that generates and verifies **indexed inclusion** and
**append-only consistency** relationships against separately supplied roots.
SHA-256 follows RFC 9162 tree/proof algorithms; no custom cryptographic primitive.
Python 3.13+, standard library only at runtime. Synthetic bytes, no live log,
certificates, signatures, keys, network calls or trust-store changes.

```powershell
python -m merkle_lab verify-inclusion samples/inclusion.json --anchors samples/operator-anchors.json
python -m merkle_lab verify-consistency samples/consistency.json --anchors samples/operator-anchors.json --format json
python -m merkle_lab verify-inclusion samples/tampered-inclusion.json --anchors samples/operator-anchors.json
python -m merkle_lab verify-consistency samples/empty-prior.json --anchors samples/operator-anchors.json
```

Expected exits in order: **0**, **0**, **1**, **3**. Invalid input/I/O exits **2**.
Exit 0 verifies the stated relationship under the supplied commitment assumptions;
it never authenticates roots, certifies event truth or proves freshness.

## Generate a synthetic statement

```powershell
python -m merkle_lab root samples/entries.json --format json
python -m merkle_lab prove-inclusion samples/entries.json --index 1 --format json --output my-inclusion.json
python -m merkle_lab prove-consistency samples/entries.json --old-size 3 --format json --output my-consistency.json
python -m unittest discover -v
python -O -m unittest discover -v
python scripts/demo_reports.py --check
```

Output files are created exclusively. Use `--format json` for machine-readable
proof files; default text is a teaching display, not input JSON. Generators emit
proofs without claimed roots and warn on stderr that nothing is authenticated.
They never update anchor files. A root report is a generated commitment; to verify
a proof, deliberately supply an independent anchors envelope. Demo operator
anchors are generated synthetic assertions, not externally authenticated heads.
Hardlink/same-file proof/anchor aliases are rejected; separate files alone do not
establish trust. Private record material should stay outside tracked samples.

## Demonstration and meaning

[JSON results](samples/demo-report.json) and [text results](samples/demo-report.txt)
show valid inclusion, tampered leaf rejection, prefix growth, equal positive heads
and unsupported empty-prior consistency. Eight exact synthetic artifacts are
reproducible with `scripts/demo_reports.py`; write mode intentionally replaces
only those fixed demo files. `--check` reads and compares exact bytes. No server
or browser is required.

| Statement | What a valid result establishes under accepted roots |
| --- | --- |
| Inclusion | The exact leaf digest occurs at the stated zero-based index in the committed tree |
| Consistency growth | The earlier committed sequence is an unchanged prefix of the later sequence |
| Equal positive heads | Same commitment/size, empty proof; identity with no growth |
| Empty prior tree | Unsupported meaningful history evidence; empty root taught separately |

Empty byte records and duplicates are valid. In a two-leaf tree containing two
empty records, the same sibling digest can prove membership at either index.
Index mutation tests reject only independently false changed statements; the
tool makes no uniqueness claim. Empty **tree** hash differs from one empty **leaf**
hash. Odd tree shapes split at the largest lower power of two; no last-leaf
duplication. Every path node must be consumed in RFC order, with sides determined
by sizes/indexes. Both roots are checked for consistency growth.

Roots are **operator-supplied anchors**. Their authenticity is always reported as
unverified. A malicious actor replacing an anchor can present another consistent
history. Isolated clients can each accept an internally valid fork. Without fresh,
independently retained commitments, the tool cannot identify every stale/partial
or split view. It establishes no event truth/completeness or record availability.
Hash collision/second-preimage assumptions remain part of interpreting results.

## Architecture and contract

```text
bounded files → strict JSON → immutable entries / anchors / proofs
            → RFC SHA-256 tree + exact path verifier → bounded JSON/text
```

Four exact version-1 envelope shapes are defined in [PLAN.md](PLAN.md); examples
are in `samples/`. Algorithm is fixed `sha256-rfc9162`. `log_id` is 1–64 visible
ASCII `[A-Za-z0-9_.:-]`. Anchor sizes are unique. JSON duplicate keys/unknown
fields, bool-as-int, floats/exponents/nonfinite values, malformed hex and null
paths are rejected. Values and proof nodes use lowercase hex; raw records are
hashed once at the CLI boundary. Digest-level verification is a separate API.

Limits: entries file 2 MiB; anchors/proofs 64 KiB; nesting 8; integer lexemes 10
characters; tree/record count 4,096; each leaf 2,048 bytes, aggregate 512 KiB;
path 13 digests; anchors 32 heads; output 256 KiB. File reads are bounded and
regular-file-only, before/after opening. Inputs are unchanged by the CLI.

Public API: `contract.parse(bytes, kind)` / `load(Path, kind)` validate envelopes
or raise `InputError` (load may raise `OSError`). Tree APIs accept bounded bytes/
tuples, with exact uint-like integer/digest checks. `verify_inclusion` accepts
a **leaf digest**; call `leaf_hash(raw_bytes)` exactly once for raw records.
`verify_consistency` returns typed valid/invalid/unsupported results. Algorithm
details and licensing are in tree.py and [NOTICE.md](NOTICE.md).

## Verification and attribution

[VALIDATION.md](VALIDATION.md) records tests, independently sourced fixtures,
reference oracle, mutations, SAST and platform limits. [REVIEW.md](REVIEW.md) is
the implementing agent's ECC self-review, not independent cryptographic review.
Manual review precedes consequential reliance. No hosted CodeQL/CI, production
audit, Linux execution or public service is claimed.

Original harness MIT; RFC-derived code components retain IETF Revised BSD notice;
18 pinned upstream source artifacts retain Apache-2.0 provenance, including
17 JSON probes (10 positive/7 negative) and original LICENSE. Actual original
bytes match pinned Git blob IDs and SHA256 manifest. Test adaptation changes
base64/null representation in memory only; expected roots/outcomes come from
originals. No Go implementation executed or GPL Python code copied.
[Research](RESEARCH.md) assesses dependencies, alternatives, issues and limits.

AI assistance: Codex implemented and reviewed algorithms/security boundaries;
local qwen3.5:2b extracted three bounded learning labels. No remote worker inference
or new runtime dependencies used. Prepared CI actions reuse same-day verified
immutable upstream SHAs from the completed predecessor; no remote publication,
hosted eligibility or protections have been configured.

Optional exercise: explain why two clients accepting different rooted histories
can each receive a valid inclusion result. Which missing evidence links their views?

## Publication status

See [publication review](PUBLICATION.md) for the October 5 source snapshot, fresh local checks, evidence boundaries and current hosted-check distinction.
