# Merging and releasing

## Merging

Pull requests merge through a merge queue on `develop`, not with the
merge button directly. A pull request can be queued once its "Can
enqueue" check passes. The queue then runs `ci.yml` again on the
commit it is about to merge, and merges only when "Can merge" passes.
That second run is the one a release counts (see below), so a change
merged around the queue, by an administrator bypassing it, cannot be
released until a later commit has gone through the queue.

The queue builds one entry at a time (`max_entries_to_build: 1` in the
`develop` ruleset). `ci.yml`'s concurrency group depends on that: a
queue run shares a group with whatever the queue builds next, so that
a superseded run is cancelled. Raising the setting would make each
entry cancel the one ahead of it, so revisit that group first.

A new job in `ci.yml` goes in the `needs:` of both "Can enqueue" and
"Can merge", or the queue will not wait for it.

There is no `push` trigger on `ci.yml`: every commit on `develop` came
through the queue, so a push run would only test the exact commit
its merge queue run already tested.
`pr-retest.yml` can still dispatch the workflow by hand, but a
dispatched run does not count towards a release.

## Releasing

Pushing a `v*` tag triggers `release.yml`. Its jobs, in order:

1. `ci-gate` checks that `ci.yml` succeeded on the tagged commit, in
   its merge queue run. A run started by hand with `workflow_dispatch`
   does not count, so to recover from a flaky queue run, use "Re-run
   jobs" on that merge queue run itself. How the gate decides is
   documented with the action, as
   [`require-ci-success`](https://github.com/shakenfist/actions/blob/main/docs/actions.md#require-ci-success).
   It has no override.
2. `build` builds the sdist and wheel, then runs `twine check` and
   [`check-dist`](https://github.com/shakenfist/actions/blob/main/docs/actions.md#check-dist),
   which fails if the wheel holds a test directory or nothing at all.
   It runs only if the gate passed.
3. The publishing jobs wait for approval in the `release`
   environment, re-sign the tag with gitsign, and publish to PyPI with
   attestations.

So tag a commit that is on `develop` and went through the merge
queue, and wait for its `ci.yml` run to finish first. A gate failure
means nothing was signed or published, so every failure is
recoverable: the template's
[recovery table](https://github.com/shakenfist/development/blob/main/templates/release-automation/README.md#recovering-from-a-gate-failure)
says what to do for each cause, which is usually moving the tag or
re-running CI and then the `ci-gate` job.

Running `release.yml` by hand with `workflow_dispatch` skips the gate
and the publishing jobs, and only builds and checks the packages.

The version comes from the tag through setuptools_scm. The one-time
setup, and how to verify a release, are in `RELEASE-SETUP.md`.

## What the wheel contains

The wheel holds the `shakenfist_utilities` package and nothing else:
the tests are excluded, and `include-package-data` is off so that
setuptools_scm's file finder cannot bring git-tracked files back in as
package data. Nothing in the package reads a data file at runtime. If
that ever changes, declare the file under `[tool.setuptools.package-data]`
rather than turning the setting back on.
