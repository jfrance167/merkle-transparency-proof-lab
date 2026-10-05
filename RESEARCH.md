# Research assessment — October 5, 2026

Connected GitHub repository search plus direct public repository/source access
used. Official RFCs and primary project/research documentation read via web.
Firecrawl account readiness was unverified; it was not used for this research.
No third-party source installed/executed. Findings are scoped to inspected files.

## Reuse and gap

Read local file-integrity-monitor README and vault File Integrity Monitoring /
Evidence Integrity. Existing SHA-256/HMAC baselines detect changed file bytes
and metadata; they are not ordered-tree membership or prefix proofs. Searched
workspace public Markdown and file names, and relevant vault project/research
notes for merkle/hash-chain/append-only/transparency proof terms: no reusable
matching implementation found. This is not an exhaustive search. Preserve the
older projects; reuse their bounded-input/exclusive-output/evidence conventions.

## Strongest candidate: transparency-dev/merkle

[Repository](https://github.com/transparency-dev/merkle), Go, Apache-2.0.
API metadata reports not archived, pushed September 28, 2026. Inspected pinned
revision `fbbcd741c3d1c69d8498487baa8edc9e5824847c`: README, LICENSE, go.mod,
RFC6962 hasher/tests, proof verifier/tests, testonly tree and Go test workflow.
Library constructs/verifies tree proofs without needing a log service. go.mod
requires Go 1.22.7 and go-cmp 0.7.0 (test comparison usage); no runtime platform
installation or vulnerability-free claim inferred.

Source checks exact proof length, indexes and leaf digest width, compares roots,
and rejects prior size zero. Tests walk inclusion/consistency JSON probes including
positive, tampered root/size/index, leading/trailing garbage and truncation cases.
Five positive probes of each kind inspected; expected bytes are independent
of the proposed Python implementation. Null empty-path fields must be adapted
to the stricter product [] convention only in test loading, with preserved raw
source and modification record. The hasher tests have fixed empty/leaf known
answers and domain-separation/order checks.

Workflow uses pinned actions, go test -race on Linux/macOS Go 1.22/1.23;
CodeQL/govulncheck/Scorecard/fuzz workflow files exist in the tree. This is evidence
of configuration, not passing results. GitHub fetch rejected the workflow-runs
endpoint; no current CI conclusion retrieved. Scorecard API fetch failed; no
score or security judgment inferred from the badge. Open
[issue 230](https://github.com/transparency-dev/merkle/issues/230) tracks cleanup,
Go versions, old coverage baselines and reference test signatures; not proof of
a verifier vulnerability. No independent supply-chain audit was performed.

Recommendation: use as algorithm cross-check and adopt selected Apache test
vectors with license/attribution, original bytes, commit/path/hash manifest and
explicit modifications. No Go implementation copy/port or execution proposed.
The bounded Python tool's main risk remains algorithm correctness, addressed by
external fixtures, an independent small-tree oracle and mandatory manual review.

Key pinned sources:
- [Hasher](https://github.com/transparency-dev/merkle/blob/fbbcd741c3d1c69d8498487baa8edc9e5824847c/rfc6962/rfc6962.go)
- [Verifier](https://github.com/transparency-dev/merkle/blob/fbbcd741c3d1c69d8498487baa8edc9e5824847c/proof/verify.go)
- [Probe tests](https://github.com/transparency-dev/merkle/blob/fbbcd741c3d1c69d8498487baa8edc9e5824847c/proof/verify_test.go)
- [Known hashes](https://github.com/transparency-dev/merkle/blob/fbbcd741c3d1c69d8498487baa8edc9e5824847c/rfc6962/rfc6962_test.go)
- [Test fixtures](https://github.com/transparency-dev/merkle/tree/fbbcd741c3d1c69d8498487baa8edc9e5824847c/testdata)

## Python alternative: pymerkle

[Repository](https://github.com/fmerg/pymerkle), not archived; metadata last push
October 13, 2025. Pinned develop revision
`53d938f0122b1788731dee5f1cfb8fac7ce25bd5`. Inspected README, proof.py,
consistency tests, setup.py, requirements.txt and actual GPLv3 license.
Setup labels GPLv3-or-later, version 6.1.0 and cachetools==5.3.1 dependency.
README points to external GitLab CI; no current CI result retrieved.

Proof serialization uses metadata/algorithm/security, rule bits/subset/path;
it is not the proposed RFC ordered sibling-array envelope. Source verification
resolves that custom path, while tests cover matching and invalid roots.
README permits disabling domain separation for testing and explicitly requests
security review. We will not expose such a downgrade option. These are API/scope
fit observations, not a verified vulnerability or assertion that the library is
unsafe. Open [issue 29](https://github.com/fmerg/pymerkle/issues/29) reports a
concurrent stress get_state IndexError; not reproduced. License/dependency/custom
format considerations make adoption unnecessary here. Do not copy GPL source
into an MIT project or imply an audit/advisory scan was completed.

## Primary specification and alternate architecture

[RFC 9162 §2](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1) specifies
tree construction, domain separation, path algorithms and a seven-leaf example.
SHA-256 is the fixed lab profile; no TLS wire protocol or algorithm agility.
[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html) is historical context for
the reference library. Exact path/empty/equal boundaries are documented in PLAN.
Copies/translations of RFC code components must retain applicable Revised BSD
text; stage 1 resolves notices using [IETF Trust legal provisions](https://trustee.ietf.org/documents/trust-legal-provisions/).
Do not represent copied algorithms/vectors as exclusively original MIT work.

[Transparency.dev explanation](https://transparency.dev/verifiable-data-structures/)
separates inclusion, consistency and separately authenticated tree heads.
The lab excludes signing and authenticates no anchors. Operator-supplied roots
are inputs to relationships, not facts established by this program.

[Crosby/Wallach, USENIX Security 2009](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf)
compares tree proofs with linear hash-chain audit costs and discusses diverse
commitment views. Anchored chains are a reasonable later learning alternative
but do not supply compact tree inclusion/prefix proofs or remove the need for
trusted head distribution. No performance numbers from the paper are claimed
for the proposed lab. No chain/hash scheme is invented in this proposal.

Remaining uncertainties: independent cryptographic review and implementation
proof correctness are pending; current upstream CI/Scorecard results unavailable;
no dependency advisory preflight needed because no third-party runtime adoption
is proposed. If the coordinator instead chooses a dependency, reassess identity,
license, version/artifact/advisory provenance before installation.
