# Coding Standards

Read at review time. Two judgement-call rules no linter can check. Everything
mechanical — gofmt, vet, golangci-lint, the commit-msg conflict-trailer
hook — is already automated; do not re-check those by hand in review.

## Comments describe current contracts, not history

A comment states the constraint the code maintains, plus whatever rationale
must survive with it, beside the code it constrains. It never tells the
story of how the code came to be.

**Flag** (recognition patterns, exemplar trim: `git show 9bc254c`):

- Provenance narrative: "the former X", "restoring the pre-extraction
  relative order", "extracted from the servlet", "formerly"
- Change-dating labels: incident timelines, "audit-run-1 fix"
- Any sentence whose subject is a past state of the code rather than a
  property of the current code

**Do not flag** — these are contracts, not history, and they stay:

- Spec references carrying a constraint's rationale (FID-69's 200-noop
  rule, §6.2(e)'s reconnect push, "VERBATIM" wire-shape clauses)
- Security, persistence, firmware-compatibility, and test rationale

Rule of thumb: delete the history clause; if what remains still constrains
a reader of the current code, keep the rest. If nothing remains, the whole
comment goes.

## After conflict resolution, comments must match the merged code

Git merges text, not meaning: an auto-merged comment can describe a
structure that neither parent — nor the merged result — has. When
reviewing a merge or cherry-pick:

1. List every comment in the merged hunks that describes structure,
   ordering, function shape, or a file/module overview.
2. Re-derive each against the **merged** tree, not either parent.
3. Fix the comment to the merged reality (or delete it). A resolved
   conflict that leaves a structural comment stale is an unresolved
   conflict.

Real case: a cherry-pick auto-merged `absorbInform` carrying "Both steps
share one function so their ordering cannot drift" while the merge split
those steps apart; a file-header overview kept naming
`inform.StationMACs` after the code had moved to `inform.Stations`.
