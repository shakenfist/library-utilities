# Log record field-name contract

`shakenfist_utilities.logs.setup()` configures daemon logging to emit one
structured JSON object per log line, via this library's own
`logs.JsonFormatter`. This is the only daemon log format -- there is no text
format. This document is the stable contract for the field names that appear in
that JSON, so downstream consumers (notably the Shaken Fist Loki log shipper)
can rely on them.

The field list is exported as `logs.ENABLED_FIELDS`, so a consumer that needs
to build a matching formatter reads it from here rather than keeping its own
copy in step by hand.

`setup_console()` is a separate, human-readable path for CLI tools and is not
covered by this contract.

## Base fields

Every daemon log line contains these base fields, mapped from the Python
`LogRecord` by `JsonFormatter`'s `enabled_fields`, which defaults to
`logs.ENABLED_FIELDS`:

| JSON field         | Source `LogRecord` attribute | Notes |
|--------------------|------------------------------|-------|
| `logger_name`      | `name`                       | The logger name, i.e. the `name` passed to `setup()` (usually `__name__`). |
| `ts`               | `asctime`                    | Timestamp in Zulu/UTC ISO-8601 form (e.g. `2026-06-19T17:58:00.234Z`). Genuinely UTC -- see the note below. |
| `level`            | `levelname`                  | `DEBUG`, `INFO`, `WARNING`, `ERROR`, etc. |
| `pid`              | `process`                    | Operating-system process id of the emitter. |
| `thread_name`      | `threadName`                 | Name of the emitting thread (e.g. `MainThread`). |
| `message`          | `getMessage()`               | The caller's message only -- no process/pid/thread prefix. |
| `exception_class`  | `exc_info[0].__name__`       | Class name of the active exception, or `null`. |
| `stack_trace`      | `exc_text`                   | Formatted traceback when logging an exception, else `null`. |
| `module`           | `module`                     | The module that emitted the record. |
| `function`         | `funcName`                   | The function that emitted the record. |

In addition, the adapter injects one field that is not a raw `LogRecord`
attribute:

| JSON field | Source | Notes |
|------------|--------|-------|
| `program`  | `setproctitle.getproctitle()` | The process title of the emitter. This used to be prepended to `message`; it is now a discrete field so `message` stays clean and indexable. |

### `ts` is UTC, and did not used to be

Until this was fixed, `ts` was resolved with `time.localtime` and then labelled
`Z`. On a host in a non-UTC timezone that meant the timestamp was wrong by the
host's offset -- on an Australian host, ten hours in the future -- while
claiming to be Zulu. Nothing downstream could compensate, because the offset is
invisible once the line is written.

This matters when reading logs from before the fix. Lines shipped by an older
release carry local time under a `Z`, so correlating them against anything else
means knowing which host wrote them and what its offset was. Lines written after
it are UTC and need no correction.

Only the `Z` format is UTC. `setup()` is the only caller that asks for it, and
any other `datefmt` keeps `logging`'s own convention of local time.

### Clean message

The `message` field contains exactly the string the caller logged. Earlier
versions of this library prepended `proctitle[pid:thread] ` to every message;
that prefix has been removed. The same information is now available as the
`program`, `pid`, and `thread_name` fields.

## `with_fields()` conventions

`LOG.with_fields({...})` adds caller-supplied key/value pairs to the JSON body.
The following normalisation rules apply:

- **Keys are lower-cased.** `with_fields({'Instance': ...})` emits the field as
  `instance`.
- **Objects with a `.uuid` attribute are unwrapped** to that attribute's value.
  Passing a Shaken Fist object unwraps to its uuid string.
- **`uuid.UUID` values are stringified.** A `uuid.UUID` instance is emitted as
  its canonical string form.
- **Flask `request-id` is auto-injected.** When logging inside a Flask request
  context, the adapter adds a `request-id` field from the request environment
  (`FLASK_REQUEST_ID`). Outside a request context it is absent.

These body keys are free-form; the library does not enumerate or constrain them
beyond the normalisation above.

### Values JSON cannot encode

A field value that `json` cannot encode natively no longer costs the record.
Earlier releases raised inside the handler, `logging` printed
`--- Logging error ---` and a traceback to stderr, and the line was lost.
`JsonFormatter` now renders such values instead:

| Value | Rendered as |
|-------|-------------|
| `bytes` / `bytearray` | Decoded as UTF-8, with undecodable bytes replaced by U+FFFD. |
| An `enum.Enum` member | Its name, e.g. `RED`. Enums mixing in `str` or `int` encode as their value, as `json` always did. |
| `uuid.UUID` (nested, where `with_fields()` did not reach it) | Its canonical string. |
| Anything with a `model_dump()`, such as a pydantic v2 model | `model_dump(mode='json')`, so its fields stay structured and queryable. |
| Anything else | `str(value)`. |

This applies at any depth, so a list of bytes inside a dict renders too. Two
things a renderer cannot fix -- a dict with a non-string key, and a circular
reference -- cause only the affected top-level field to be emitted as
`str(value)`; every other field in the record is unchanged.

Callers should still log meaningful values: this is a guarantee that a record
survives, not a recommended way to serialise an object.

## Labels are downstream, not here

The Loki **stream labels** `{job, daemon, host}` are applied by the Shaken Fist
log shipper downstream -- they are **not** added by this library, and none of
the JSON body fields above is a label. See
`shakenfist/docs/plans/PLAN-remove-syslog-forwarding.md` for the label contract.

High-cardinality identifiers (object UUIDs, `request-id`, IP addresses, etc.)
deliberately stay in the JSON **body** and must never be promoted to Loki
labels, to avoid label-cardinality explosion. This library's responsibility
ends at producing the structured JSON described above.
