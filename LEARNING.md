# Learning goals from research

An inclusion proof concerns one indexed record and a committed tree; consistency
concerns two committed histories. These are different proof statements.

An accepted digest relationship does not authenticate the source of its roots.
External trust, freshness, completeness and multi-client view reconciliation are
separate system problems. Small offline proofs cannot silently solve them.

Empty trees and empty byte records differ; domain separation makes that explicit.
Odd tree shapes, singleton paths and equal/zero prior sizes are contract choices
that need source-backed known answers and explicit tests, not intuition.

Verified: two identical empty leaves can accept the same sibling proof at either
index. Changing an index is not universally a false statement. The tests retain
that counterexample and use unique leaves for negative indexed statements.

The five controlled mutations all caused selected tests to fail, including one
that checked only the newer root. A generator/verifier round trip alone can hide
shared mistakes; pinned expected roots and a differently structured oracle help.
Hardlink creation failed inside the Windows sandbox; an authorized outside-sandbox
run established alias rejection without pretending the skipped environment worked.
