# Approved decisions

- Prefer original bounded stdlib harness, implementing published RFC Merkle
  algorithms and adopting independently pinned Apache vectors with attribution.
- Do not fork/copy GPL Python source or run a live Go log service.
- Trust anchors are explicitly separate operator-supplied roots and sizes; no
  signature, freshness, truth, completeness or split-view guarantee inferred.
- Empty-root hashing is taught, but consistency from prior size zero is rejected
  as unsupported meaningful prior-history evidence. Equal positive heads are
  identity/no-growth; extra nodes still fail.
- Synthetic records only; no signing, certificates, keys, blockchain or service.
- Stages 1–4 approved at October 5, 01:12 Eastern by coordinator; provenance in
  STATE. Read and recorded mandatory addendum before code. Empty/duplicate leaves
  valid; no uniqueness or universal index-mutation rejection claim. log_id uses
  [A-Za-z0-9_.:-] allowlist, length 1–64. Original artifact provenance before reuse.
  Parent/counter-window/fwrule stay unchanged.
- Report exact leaf/root digests for auditability without printing raw leaves.
- Independent iterative forest oracle supplements pinned expected results and
  recursive generators; targeted mutation checks establish guard sensitivity.
- CLI creates output exclusively. Fixed synthetic demo regeneration is a separate
  documented script with an exact read-only `--check` mode.
