# Plans index

Every planning document in this repository, oldest first.

This is a small library, so the list is short and is likely to stay
that way: most of what happens here is a change to one of three
modules rather than a piece of work worth planning. A plan lands here
when a change spans the library and its consumers, because that is the
case where the decision needs to be written down somewhere both ends
can read it.

Status cells use the shared vocabulary from
[development's plan-status-vocabulary block](https://github.com/shakenfist/development/blob/main/templates/shared-blocks/plan-status-vocabulary.md),
which is the same list the `plan-index` audit enforces across the
fleet: one of `Proposed`, `Not started`, `In progress`, `Blocked`,
`Complete`, `Abandoned` or `Superseded`, and nothing else. The reasons
behind a status belong in the plan, not in this column.

| Date | Plan | Intent | Status |
|------|------|--------|--------|
| 2026-06-19 | [Loki log shipping](PLAN-loki.md) | A library-side Loki handler with an in-memory queue; superseded by the on-disk spool that shipped in the shakenfist package instead | Superseded |
