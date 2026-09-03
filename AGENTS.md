# Working on shakenfist-utilities

This is a small library -- three modules, no daemons, no services --
whose consumers are the other Shaken Fist projects. That shape is the
thing to keep in mind: almost nothing here is used only here, so a
change that looks local usually is not. `ARCHITECTURE.md` has the
component map; this file is the conventions and the traps.

## Code style

* Single quotes for all strings, except docstrings, which use triple
  double quotes. Never triple single quotes.
* Wrap at 120 characters, and trim trailing whitespace.
* `flake8` is the arbiter and runs at `--max-line-length=120`.

## The log field names are a published contract

`logs.ENABLED_FIELDS` and the JSON it produces are documented in
`docs/log-record-fields.md`, and that document is a contract rather
than a description. The Shaken Fist Loki shipper reads the field list
from this module precisely so it does not keep a copy in step by hand,
and the Loki queries built on those names do not get a migration when
they change.

So: renaming a field, reordering `ENABLED_FIELDS`, or changing what
`with_fields()` normalisation does is a breaking change to another
repository. Update `docs/log-record-fields.md` in the same commit, and
say in the commit message what downstream has to do about it.

Two related invariants worth stating because they are easy to undo:

* `message` holds exactly what the caller logged. The
  `proctitle[pid:thread]` prefix was removed deliberately; `program`,
  `pid` and `thread_name` carry that information as discrete fields.
* The `Z` timestamp really is UTC. It used to be local time wearing a
  `Z`, which nothing downstream could compensate for. Only `setup()`
  asks for `Z`; any other `datefmt` keeps `logging`'s local-time
  convention, which is fine and should stay that way.

## Credentials never reach a log line

`api.generic_wrapper` redacts `key`, `password` and the `Authorization`
header before logging a request, and it logs the JWT *identity* rather
than the token. This is load bearing: Shaken Fist log lines go to
syslog and on to Loki, so a credential in a log line is a credential in
log aggregation.

If you add a field to what that wrapper logs, decide explicitly whether
it can carry a secret. Request and response bodies on credential-bearing
routes are the case most often missed, because the logging that catches
them is generic request tracing written long before the route existed.

## Tests and linting

* `tox` runs the unit tests through `stestr`; `tox -eflake8` lints only
  what changed since `HEAD~1`, via `tools/flake8wrap.sh`.
* `stestr` captures stdout, so tests set `SHAKENFIST_LOG_TO_STDOUT=1`
  to pull daemon logging away from syslog and into that capture. A test
  that logs and does not set it will try to write to `/dev/log`.
* `logging` is process-global state and `setup()` mutates it -- it sets
  the logger class, the root level, and strips the named logger's own
  handlers. Tests that call it need to put that back, or the next test
  in the same process inherits it.
* Run `pre-commit run --all-files` before proposing a commit. It runs
  `actionlint` over the workflows and `shellcheck` over `tools/`.

## Versions come from tags, not from a file

`setuptools_scm` derives the version from the most recent `v*` tag and
writes `shakenfist_utilities/_version.py`, which is generated and not
committed. There is no version string to bump by hand; a release is a
signed tag, and `RELEASE-SETUP.md` describes the one-time PyPI and
GitHub configuration that tag relies on.

## Where the documentation lives

* `docs/log-record-fields.md` -- the JSON field-name contract above.
* `docs/plans/index.md` -- the planning documents, such as they are.
