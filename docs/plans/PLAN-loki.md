# Plan: Loki Log Shipping Support

## Status: Superseded

This draft proposed a library-side `LokiHandler` with an in-memory queue. It has
been superseded. The Loki log shipper (on-disk SQLite spool + background drainer
+ HTTP push) lives in the `shakenfist` package, not this library -- see
`shakenfist/docs/plans/PLAN-remove-syslog-forwarding.md`. This library's role is
limited to structured-JSON formatting and the field-name contract (see
`docs/log-record-fields.md`).
