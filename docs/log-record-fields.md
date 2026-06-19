# Log record field-name contract

`shakenfist_utilities.logs.setup()` configures daemon logging to emit one
structured JSON object per log line (via pylogrus's `JsonFormatter`). This is
the only daemon log format -- there is no text format. This document is the
stable contract for the field names that appear in that JSON, so downstream
consumers (notably the Shaken Fist Loki log shipper) can rely on them.

`setup_console()` is a separate, human-readable path for CLI tools and is not
covered by this contract.

## Base fields

Every daemon log line contains these base fields, mapped from the Python
`LogRecord` by `JsonFormatter`'s `enabled_fields`:

| JSON field         | Source `LogRecord` attribute | Notes |
|--------------------|------------------------------|-------|
| `logger_name`      | `name`                       | The logger name, i.e. the `name` passed to `setup()` (usually `__name__`). |
| `ts`               | `asctime`                    | Timestamp in Zulu/UTC ISO-8601 form (e.g. `2026-06-19T17:58:00.234Z`). |
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

## Labels are downstream, not here

The Loki **stream labels** `{job, daemon, host}` are applied by the Shaken Fist
log shipper downstream -- they are **not** added by this library, and none of
the JSON body fields above is a label. See
`shakenfist/docs/plans/PLAN-remove-syslog-forwarding.md` for the label contract.

High-cardinality identifiers (object UUIDs, `request-id`, IP addresses, etc.)
deliberately stay in the JSON **body** and must never be promoted to Loki
labels, to avoid label-cardinality explosion. This library's responsibility
ends at producing the structured JSON described above.
