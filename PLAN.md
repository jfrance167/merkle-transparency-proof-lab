# Proposed offline Merkle inclusion and consistency lab

Status: stages 1–4 approved October 5, 2026, 01:12 Eastern by the coordinator.
Approval provenance and mandatory addendum recorded in STATE.md.
Tier 3 educational security tool. Source assessment is in RESEARCH.md.

## Problem and success criteria

Teach three distinct statements: inclusion connects an indexed byte record to a
specified root/size; consistency links two committed ordered histories; matching
digests do not authenticate roots. Produce repeatable offline synthetic examples
where valid proofs pass and independently false changed statements fail.
Empty/duplicate leaves are valid: an index mutation is negative only when the
fixture independently makes membership at that index false. No uniqueness claim.
Reports must state the precise verified relationship and all trust assumptions.
No claim of production log security or prevention/detection of every split view.

Recommended candidate: **merkle-transparency-proof-lab**. Build an original Python
standard-library harness for SHA-256 RFC 9162 Merkle algorithms, borrowing pinned
known-answer vectors with their Apache notices. Do not create a new hash/signature
scheme. No live CT, certificates, keys, signing, blockchain, network target,
monitoring service, external commitments or publication. This is distinct from
HMAC file baselines, counter observations and TLS/TUF verification projects.

Alternate: anchored append-only hash-chain verification. It is easier to explain
sequential replay but typically needs every intermediate record between anchors,
and lacks the same compact indexed inclusion/consistency exercises. It still
needs separately trusted anchors and fails to establish completeness/freshness.
Defer it rather than invent an ad hoc chain format; a later plan would select a
specific published construction. Adopting transparency-dev/merkle Go directly
is a maintained-library alternative; it adds Go/adapter overhead for this small
Python learning lab. Pymerkle's custom proof format and GPL obligations are a
poor fit for the proposed explicit RFC-path/MIT harness. No suitable existing
local implementation was identified in the searches performed.

## Exact proof and trust contract

Fixed hashing profile: SHA-256. Empty tree is hash of empty bytes; singleton leaf
hashes a 0x00 prefix plus exact record bytes. Interior hashing uses 0x01 and two
32-byte child digests. Split at the largest power of two strictly below length;
never duplicate the final leaf. This is the RFC construction, not Bitcoin trees.

Indices are zero-based: 0 <= index < size. Inclusion has one empty path for a
singleton; an empty tree has no inclusion proof. Path nodes are in RFC order from
the leaf/subtree toward the root; sides derive from index and tree size, not
untrusted direction flags. Verify expected shape and consume every node, rejecting
missing, leading/trailing or reordered nodes. For non-power-of-two trees, don't
pretend all paths have the same length.

Consistency: support 0 < old_size <= new_size. Growth verifies both roots and
exact path exhaustion using the RFC verifier. Equal positive sizes require equal
roots and an empty path; label this identity/no-growth, not proof of new entries.
Reject old_size 0 as unsupported meaningful prior-history evidence, including
0->0; demonstrate the empty-tree hash separately. This conservative boundary
matches the inspected Go verifier and avoids vacuous claims. Reject shrinkage.
Inclusion does not show append-only evolution; consistency does not show a
particular record's content unless it is independently included/recomputed.

Trusted roots/sizes come from a **separate explicitly supplied anchors file**,
not a root advertised inside the proof. Match an opaque log_id and tree size to
one unambiguous anchor; require both old and new anchors for consistency. Separate
file/path is only a data boundary, not authenticated trust. Reports say
operator-supplied anchors, authenticity not verified. Neither signatures nor
implicit trust-on-first-use are added. Demo-generated anchors are synthetic
assertions; the generator cannot certify them as trusted.

Under collision/second-preimage assumptions and accepted anchors, inclusion
establishes membership at the specified position in that committed tree.
Consistency establishes the earlier committed sequence as an unchanged prefix
of the later sequence. Neither proves who supplied records, their truth, whether
all events were logged, current freshness/availability, retention elsewhere, or
absence of alternate views. A shorter head than a supplied earlier anchor is
rejectable rollback, but an old self-consistent head without a fresh anchor is
not automatically detectable. Two isolated clients can accept separate anchored
forks; comparing suitable independently retained heads is needed to expose that
conflict. Synthetic demo illustrates this limit without a gossip/signing service.

## Architecture and bounded data

Immutable records/heads/proofs -> strict JSON validator -> RFC hash/proof engine
-> typed result (valid/invalid/unsupported) -> terminal and JSON reports.
Runtime dependency: Python 3.13 hashlib/json/dataclasses/pathlib only. Original
orchestration MIT; preserve IETF Revised BSD notices for extracted/translated
RFC code components and Apache-2.0 license/attribution for selected vectors.
Record transformations and source hashes; do not port/copy GPL Python code.

Proposed strict JSON contracts (exact fields; version 1):

- Entries: schema_version, algorithm=`sha256-rfc9162`, log_id and entries_hex
  (ordered array of exact byte encodings; duplicates/empty records valid).
- Anchors: schema_version, algorithm, log_id, heads array of size/root_hex pairs.
  Sizes unique per log; no timestamps/signature/claimed authenticated flag.
- Inclusion proof: schema_version, algorithm, log_id, kind=`inclusion`,
  tree_size, leaf_index, leaf_hex, path (array of digest hex). No claimed root.
- Consistency proof: same common fields, kind=`consistency`, old_size,
  new_size, path. No roots in the untrusted proof envelope.

Limits, enforced before expensive work/output:

| Resource | Hard bound |
| --- | --- |
| Entries JSON | 2 MiB regular file, bounded read |
| Anchors/proof JSON each | 64 KiB regular file, bounded read |
| JSON nesting / numeric text | 8 levels outside strings / 10 integer characters |
| Tree size, generated or verified | 0–4096; inclusion/old consistency size positive |
| Entries | <=4096, each <=2048 decoded bytes, aggregate <=512 KiB |
| Hash encoding | exactly 64 lowercase hex characters / 32 bytes |
| Entry hex | even length, lowercase only, <=4096 characters before decode |
| Path | <=13 digest nodes (ceil(log2(4096))+1); exact shape still required |
| Anchors | <=32 heads, unique sizes; log_id 1–64 ASCII [A-Za-z0-9_.:-] |
| Generator recursion | <=13 levels, trees bounded; no unbounded append service |
| Output | <=256 KiB UTF-8 per artifact; summaries never echo all entries |

Reject duplicate JSON keys, unknown fields, bool-as-int, floats/exponents,
nonfinite numbers, negative/oversized integers, malformed hex and ambiguous
anchors. Reject null paths in product schema (use []); external fixtures' null
paths are normalized in a documented test-only adapter. JSON ensure_ascii and
visible terminal escaping protect display. CLI exclusively creates outputs;
no force overwrite. Inputs are never mutated. Output limit violations fail
before file creation. No HTML needed for initial scope; inert HTML would require
a separate reviewed refinement after CLI correctness.

## Threat model and limitations

Adversary controls proof/entries, malformed JSON, claimed metadata and proposed
path nodes; can try record mutation, index/size substitution, missing/extra nodes,
order reversal, wrong roots, anchor ambiguity or resource exhaustion. Root
authenticity is outside the tool and remains an explicit operator assumption.
An adversary who can replace the trusted anchor file can supply a whole new
consistent history; separate paths do not stop this. Filesystem ownership, OS,
Python/hashlib and confidentiality are outside containment. No byte record is
executed, serialized as a pickle or forwarded to a service.

Mitigate shape/encoding/resource errors with strict parser + fixed algorithm,
exact indexed proof logic, both-root checks, unique anchored heads, bounded
output, mutation tests and ECC review. Never auto-update anchors after a pass.
Independent vectors and a separate small-tree reference oracle reduce shared
generator/verifier bugs; tests do not create a production cryptographic audit.
Retain original vector bytes and licensing; synthetic/private evidence only.

## Stages and definitions of done

1. **Contract and provenance.** Record concrete approval in STATE/DECISIONS;
   retrieve/pin Apache known-answer fixtures and license with hashes; preserve
   original bytes, document base64/null-to-hex/array adaptation. Add IETF notice
   handling before translating code components. Implement strict JSON/regular
   file/resource contracts with admission/rejection boundary tests.
2. **Hash/tree and proof engine.** Empty vs empty leaf, odd/full tree shapes,
   root reconstruction and inclusion/consistency generation/verification. Pass
   all ten independently sourced positive fixtures and selected negative probes;
   separately test raw leaf hashing so digest-level fixtures cannot hide a
   double-hash bug. Verify full sizes/indexes for synthetic trees 1 through 32
   with an independently structured reference oracle; all prefix pairs. Include
   wrong-byte/index/size/root/path, extra/missing nodes, growth from a power-of-two
   and non-power-of-two prefix, equal heads and zero/shrinking prior size.
3. **Offline CLI and teaching evidence.** Commands root/prove-inclusion/
   prove-consistency/verify-inclusion/verify-consistency. Generators compute
   synthetic commitments but never authenticate them. Verifiers require anchors.
   Exit 0 valid relationship, 1 invalid proof, 2 input/I/O errors, 3 unsupported
   prior-history case. JSON/text state exact relationship, synthetic/operator
   anchors and authenticity/freshness/split-view limitations. End-to-end tests
   cover separated anchors, same-file rejection, evidence preservation/output
   limits, unknown anchor IDs, ambiguous heads and tamper-repaired controls.
4. **Portfolio and review.** README/demo/mutation matrix, MIT + notices + AI
   disclosure, SECURITY/STATE/DECISIONS/LEARNING. Mandatory ECC self-review,
   affected rechecks, Bandit, compilation, sample reproducibility, targeted
   secret/history checks and pinned CI/CodeQL preparation. Save exact logs/exits;
   update relevant Obsidian milestone. No hosted checks claimed without execution;
   manual review precedes consequential use, publication/merge needs authorization.

## Source-independent acceptance evidence

Pinned transparency-dev/merkle revision
`fbbcd741c3d1c69d8498487baa8edc9e5824847c` has five inclusion happy paths
(size/index: 1/0, 8/0, 8/5, 3/2, 5/1) and five consistency happy paths
(old/new: 1/1, 1/8, 6/8, 2/5, 6/7). Fetch and retain their expected roots/nodes;
never regenerate expected values with this project's implementation. Negative
fixtures include wrong roots, reversed/swapped commitments and extra/truncated
paths. The RFC's seven-leaf symbolic example independently fixes sibling order
for index 0/3/4/6 and consistency 3/4/6 ->7. Hash known answers distinguish
empty tree, empty leaf and L123456. Actual source/tests were inspected; no tests
are claimed run during research. Stage 1 pins original fixture byte hashes.

Worker choice: local qwen3.5:2b extracted three bounded labels in 6.576 seconds;
reviewed labels inform the opening learning statements only. Cryptographic
semantics, sources, threat model and decisions remain with Codex. No remote
inference needed; no new provider discovery, downloads or spending.

Implementation may proceed within all four approved local stages. Mandatory
addendum: preserve actual pinned vector bytes/revision/path/hashes/license before
adaptation; don't assert universal index-mutation failure for duplicate leaves;
use the visible-ASCII log_id allowlist above. Preserve exact path consumption,
both-root checks, separate unauthenticated operator anchors, all reviewed bounds,
empty-old/equal-positive conventions and input-alias/output protections.
