# Architecture

`shakenfist-utilities` is a library of things more than one Shaken Fist
project needs and none of them should own. It runs no processes and
holds no state of its own: every component here is imported into
somebody else's daemon or CLI and does its work inside that process.

That is the constraint the whole shape follows from. The package has no
opinion about deployment, no configuration file, and no dependency on
any other Shaken Fist project -- the arrows all point inward.
`AGENTS.md` covers the conventions for changing it.

## The three modules

| Module | Responsibility | Consumers |
|--------|----------------|-----------|
| `logs` | Structured JSON logging for daemons, and a separate human-readable path for CLI tools | Every Shaken Fist daemon and CLI |
| `api` | Flask/flask-restful/JWT helpers: error rendering, request parsing and the logging wrapper | The projects that serve an HTTP API |
| `random` | A short random identifier for queue entries | Anything with a work queue |

`logs` is where nearly all of the code and all of the subtlety is.
`api` is a thin layer over Flask that happens to be shared. `random` is
seven lines and exists so that identifier does not get reinvented at
three different lengths.

## How a daemon log line is assembled

`setup()` returns an adapter, not a logger, and the pipeline behind it
has four stages, each of which adds something the next cannot:

1. **`SyslogLogger`** -- a `logging.Logger` subclass, installed as the
   logger class, so that `with_fields()` and `with_prefix()` exist on
   any logger the application fetches.
2. **`SyslogAdapter`** -- a `LoggingAdapter` carrying the caller's
   accumulated fields. This is where `with_fields()` normalisation
   happens: keys are lower-cased, objects with a `.uuid` are unwrapped
   to it, `uuid.UUID` values are stringified, and a Flask
   `request-id` is picked up from the request environment when there is
   one. Chaining produces a new adapter rather than mutating the old,
   so a per-request logger cannot leak fields into an unrelated one.
3. **`JsonFormatter`** -- maps `LogRecord` attributes onto the JSON
   field names in `ENABLED_FIELDS` and emits one object per line. The
   `Z` date format resolves UTC.
4. **A handler** -- syslog by default, a `WatchedFileHandler` for a log
   path, `ConsoleLoggingHandler` for `stdout`, or a plain stream
   handler when `SHAKENFIST_LOG_TO_STDOUT` is set for test capture.

The field names that fall out of stage 3 are a published interface,
specified in `docs/log-record-fields.md`.

`setup_console()` is a deliberate parallel stack -- `ConsoleLogger`,
`ConsoleAdapter`, `ConsoleLogFormatter` -- for CLI tools, where the
reader is a person at a terminal rather than a log aggregator. It is
not covered by the JSON contract and should not grow toward it.

## Where the responsibility stops

The library produces structured JSON and nothing else. It does not
ship logs anywhere, and it does not know about Loki.

Shipping lives in the `shakenfist` package: an on-disk SQLite spool, a
background drainer and an HTTP push, which is where it has to be,
because surviving a daemon restart needs storage a library cannot
assume. The Loki stream labels `{job, daemon, host}` are applied there
too. Nothing in the JSON body is a label, and the high-cardinality
identifiers in it -- object UUIDs, `request-id`, addresses -- must stay
out of the label set.

An earlier draft put a Loki handler with an in-memory queue in this
library instead. It is recorded as superseded in `docs/plans/index.md`;
the queue would have lost whatever it held whenever a daemon died,
which is the moment the logs matter most.

## Dependencies, and the ones that were removed

The install dependency is `setproctitle`, for the `program` field.
`api` additionally needs Flask, flask-restful and flask-jwt-extended,
which are not declared as install requirements: a project that imports
`shakenfist_utilities.api` is a web service and brings its own web
stack, while the many consumers that only want `logs` should not
inherit one.

Two dependencies were deliberately dropped rather than upgraded.
`pylogrus` supplied the JSON formatter until it was reimplemented here
-- it was last released in 2018 and was the only reason `six` was
installed anywhere in the fleet, and what we used of it was small
enough to own. `oslo.concurrency` was carried without being imported.

## Versioning

There is no version constant. `setuptools_scm` derives the version from
the most recent `v*` tag and generates
`shakenfist_utilities/_version.py` at build time; the file is not
committed. Releases are cut by pushing a signed tag, which is what the
release workflow keys on.
