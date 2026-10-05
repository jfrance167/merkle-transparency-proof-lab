# Threat model and limitations

Inputs: synthetic local JSON entries/proofs and separately supplied operator
anchor roots/sizes. Adversary can tamper with records, indexes, sizes, path nodes,
metadata, encoding or nesting. CLI never executes records, deserializes pickles,
uses a network, collects a log, signs heads or changes a trust store.

Mitigations: fixed SHA-256/domain separation, bounded strict decoding, no unknown
fields or duplicate keys, visible ASCII log_id allowlist, unique anchor sizes,
fixed digest widths, exact path consumption and both-root consistency checks.
Empty prior consistency is unsupported; equal positive sizes require equal
roots and an empty path. Empty and duplicate leaves are valid. No uniqueness
assumption is used to turn true alternative indexed statements into failures.

The caller must establish anchor trust outside this tool. A separate file does
not authenticate its contents. Someone able to replace it can choose a different
consistent history. No implicit TOFU or anchor update happens after verification.
Reports expose exact compared digests and explicitly unverified authenticity.
The tool does not prove freshness, event truth/completeness, availability,
retention elsewhere, or absence of split views. Hash security is assumed, not
proved by tests. No production cryptographic or independent audit claim.

Input checks use bounded regular-file reads before/after opening; POSIX
nonblocking opening guards FIFO substitution, but Linux behavior wasn't tested
here. Alias checks reject identical files/hardlinks for proofs versus anchors.
This is not protection against malicious concurrent local filesystem processes
or a compromised OS/Python/hashlib. Exclusive output refuses existing files and
aliases; after disk failure a newly created report may be incomplete. No automatic
cleanup could delete original evidence. Report output is bounded before creation.

Decoded leaves are capped individually and in aggregate; tree/proof work is
bounded. JSON/text output uses ASCII escaping and never prints raw control bytes.
Digests do not make private records anonymous, especially low-entropy events.
No encryption or confidentiality enforcement; keep actual sensitive evidence
outside tracked artifacts. Samples are wholly synthetic.

Runtime has no third-party packages. Development Bandit pins are not an artifact
hash lock or supply-chain certificate. Upstream fixtures are licensed inert data,
not executable dependencies; actual bytes/revisions/digests are retained. Future
dependency selection/install requires its own provenance/advisory review.
No remote means hosted secret scanning/push protection/CodeQL/protections unknown.
Report defects privately to the owner; publication/merge requires Jake's approval.
