import copy
import datetime
import logging
import sys
import importlib
import os
import uuid

import json
import time

from logging import handlers as logging_handlers
import setproctitle


FLASK = None
FLASK_ATTEMPTED = False


#: The LogRecord attributes daemon logging emits, and the JSON field
#: names they are emitted under. A bare string is emitted under its own
#: name; a tuple renames. This is the contract documented in
#: docs/log-record-fields.md, and it is exported because consumers need
#: it: shakenfist's Loki shipper carried a hand-maintained copy with a
#: comment asking for exactly this.
ENABLED_FIELDS = [
    ('name', 'logger_name'),
    ('asctime', 'ts'),
    ('levelname', 'level'),
    ('process', 'pid'),
    ('threadName', 'thread_name'),
    'message',
    ('exception', 'exception_class'),
    ('stacktrace', 'stack_trace'),
    'module',
    ('funcName', 'function'),
]


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single JSON object.

    Formerly pylogrus.JsonFormatter, reimplemented here. pylogrus was
    last released in June 2018 and was the only reason `six` was
    installed anywhere in the fleet; this is the whole of what we used
    of it, and it is small enough to own.

    The field names and their order are deliberately identical to what
    pylogrus produced, because docs/log-record-fields.md is a stated
    contract and the Loki queries built on it do not get a migration.

    Two things differ, both on purpose. pylogrus defaulted
    `enabled_fields` to six basic fields; this defaults to
    ENABLED_FIELDS, so a bare JsonFormatter() emits the documented
    contract rather than a subset of it -- nothing constructed one
    without an explicit list, so the change is invisible today. And
    formatTime resolves a 'Z' timestamp in UTC rather than local time;
    see there for why that was worth changing rather than preserving.

    :param datefmt: passed to formatTime; 'Z' selects the ISO 8601 form
    :param enabled_fields: which record attributes to emit, and under
                           what names; defaults to ENABLED_FIELDS
    :param indent: json.dumps indent, for pretty printing
    :param sort_keys: json.dumps sort_keys
    """

    def __init__(self, datefmt=None, enabled_fields=None, indent=None,
                 sort_keys=False):
        super(JsonFormatter, self).__init__(fmt=None, datefmt=datefmt)
        self._indent = indent
        self._sort_keys = sort_keys
        self._enabled_fields = (
            ENABLED_FIELDS if enabled_fields is None else enabled_fields)

    def formatTime(self, record, datefmt=None):
        """Format the record's creation time.

        A datefmt of 'Z' means ISO 8601 with milliseconds and a literal
        Z, which is what setup() asks for and what the field contract
        documents as `ts`. It is resolved in UTC, because that is what
        the Z says.

        pylogrus resolved it with logging.Formatter.converter, which is
        time.localtime, so the Z was a claim rather than a fact: on an
        Australian host every daemon stamped its logs ten hours in the
        future and said they were Zulu. Nothing downstream could
        correct for it either, because the offset is invisible once the
        line is written.

        Every other datefmt keeps the converter, and so keeps local
        time. That is logging's own convention, and a caller asking for
        '%H:%M:%S' has not asked for UTC.
        """
        if datefmt == 'Z':
            return '{}.{:03.0f}Z'.format(
                time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(record.created)),
                record.msecs)
        created = self.converter(record.created)
        if datefmt:
            return time.strftime(datefmt, created)
        return self.default_msec_format % (
            time.strftime(self.default_time_format, created), record.msecs)

    def _record_fields(self, record):
        """Every attribute a caller may name, in emission order.

        Built whole and then filtered, rather than built from the
        enabled list, so that the order of the output is a property of
        this table rather than of whatever order a caller happened to
        pass. pylogrus behaved the same way and the field contract
        quietly depends on it.
        """
        message = record.getMessage()
        prefix = getattr(record, 'prefix', None)
        if prefix:
            message = '{} {}'.format(prefix, message)

        return {
            'name': record.name,
            'asctime': self.formatTime(record, self.datefmt),
            'created': record.created,
            'msecs': record.msecs,
            'relativeCreated': record.relativeCreated,
            'levelno': record.levelno,
            'levelname': record.levelname,
            'thread': record.thread,
            'threadName': record.threadName,
            'process': record.process,
            'pathname': record.pathname,
            'filename': record.filename,
            'module': record.module,
            'lineno': record.lineno,
            'funcName': record.funcName,
            'message': message,
            'exception': (
                record.exc_info[0].__name__ if record.exc_info else None),
            'stacktrace': record.exc_text,
        }

    def _enabled(self):
        """The enabled field list as {attribute: emitted name}."""
        enabled = self._enabled_fields
        if not isinstance(enabled, list):
            enabled = [str(enabled)]

        names = {}
        for item in enabled:
            if isinstance(item, tuple):
                names[item[0]] = item[1]
            elif isinstance(item, str):
                names[item] = item
        return names

    def format(self, record):
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)

        names = self._enabled()
        obj = {names[key]: value
               for key, value in self._record_fields(record).items()
               if key in names}

        extra_fields = getattr(record, 'extra_fields', None)
        if isinstance(extra_fields, dict):
            obj.update(extra_fields)

        return json.dumps(obj, indent=self._indent,
                          sort_keys=self._sort_keys)


# These classes began as extensions of the work in
# https://github.com/vmig/pylogrus
class SyslogLogger(logging.Logger):

    def __init__(self, *args, **kwargs):
        extra = kwargs.pop('extra', None)
        self._extra_fields = extra or {}
        super(SyslogLogger, self).__init__(*args, **kwargs)

    def withPrefix(self, prefix=None):
        return self.with_prefix(prefix)

    def withFields(self, fields=None):
        return self.with_fields(fields)

    def with_prefix(self, prefix=None):
        return SyslogAdapter(self, None, prefix)

    def with_fields(self, fields=None):
        return SyslogAdapter(self, fields)


class SyslogAdapter(logging.LoggerAdapter):

    def __init__(self, logger, extra=None, prefix=None):
        """Logger modifier.

        :param logger: Logger instance
        :type logger: PyLogrus
        :param extra: Custom fields
        :type extra: dict | None
        :param prefix: Prefix of log message
        :type prefix: str | None
        """
        global FLASK, FLASK_ATTEMPTED

        self._logger = logger

        self._extra = self._normalize(extra)
        self._prefix = prefix

        # Attempt to lookup a request id for a flask request
        try:
            if not FLASK_ATTEMPTED:
                try:
                    FLASK = importlib.import_module('flask')
                except Exception:
                    pass
                FLASK_ATTEMPTED = True

            if FLASK:
                self._extra['request-id'] = FLASK.request.environ.get(
                    'FLASK_REQUEST_ID')
        except RuntimeError:
            pass

        super(SyslogAdapter, self).__init__(
            self._logger, {'extra_fields': self._extra, 'prefix': self._prefix})

    @staticmethod
    def _normalize(fields):
        return {k.lower(): v for k, v in fields.items()} if isinstance(fields, dict) else {}

    def withPrefix(self, prefix=None):
        return self.with_prefix(prefix)

    def withFields(self, fields=None):
        return self.with_fields(fields)

    def with_fields(self, fields=None):
        extra = copy.deepcopy(self._extra)
        fields = self._normalize(fields)

        for field in fields:
            # The field might be an object and therefore have a .uuid attribute?
            try:
                fields[field] = fields[field].uuid
            except AttributeError:
                ...

            # The field might be a uuid object not a string?
            if isinstance(fields[field], uuid.UUID):
                fields[field] = str(fields[field])

        extra.update(fields)
        return SyslogAdapter(self._logger, extra, self._prefix)

    def with_prefix(self, prefix=None):
        return self if prefix is None else SyslogAdapter(self._logger, self._extra, prefix)

    def process(self, msg, kwargs):
        # The message field must contain only the caller's message. The process
        # identity (process title) that used to be prepended to the message is
        # now surfaced as a structured 'program' field instead, so the JSON
        # 'message' field stays clean and indexable. pid and thread_name are
        # emitted by the JsonFormatter directly from the LogRecord.
        extra = copy.copy(self.extra)
        extra_fields = dict(extra.get('extra_fields') or {})
        extra_fields['program'] = setproctitle.getproctitle()
        extra['extra_fields'] = extra_fields
        kwargs['extra'] = extra
        return msg, kwargs


class ConsoleLogger(logging.Logger):

    def __init__(self, *args, **kwargs):
        extra = kwargs.pop('extra', None)
        self._extra_fields = extra or {}
        super(ConsoleLogger, self).__init__(*args, **kwargs)

    def withPrefix(self, prefix=None):
        return self.with_prefix(prefix)

    def withFields(self, fields=None):
        return self.with_fields(fields)

    def with_prefix(self, prefix=None):
        return ConsoleAdapter(self, None, prefix)

    def with_fields(self, fields=None):
        return ConsoleAdapter(self, fields)


class ConsoleAdapter(SyslogAdapter):
    def process(self, msg, kwargs):
        extra_string = ''
        for key in self.extra.get('extra_fields', {}):
            extra_string += '\n\t%s: %s' % (key,
                                            self.extra['extra_fields'][key])
        msg = '%s%s' % (msg, extra_string)
        return msg, kwargs


class ConsoleLogFormatter(logging.Formatter):
    def format(self, record):
        level_to_color = {
            logging.DEBUG: '\033[34m',    # blue
            logging.INFO: '',
            logging.WARNING: '\033[033m',  # yellow
            logging.ERROR: '\033[031m'     # red
        }
        reset_color = '\033[0m'

        timestamp = str(datetime.datetime.now())
        if not record.exc_info:
            return '%s %s%s%s: %s' % (timestamp, level_to_color[record.levelno],
                                      logging._levelToName[record.levelno],
                                      reset_color, record.getMessage())
        return logging.Formatter.format(self, record)


class ConsoleLoggingHandler(logging.Handler):
    # Deliberately no level of its own, so it inherits NOTSET from
    # logging.Handler and passes everything it is given. Filtering is the
    # logger's job (setup_console sets logging.root to INFO), and doing it
    # here as well is what caused the bug this note exists to prevent.
    #
    # emit() used to assign self.level from the record it was emitting.
    # Handler.level is what Logger.callHandlers filters on, so that made
    # the level a one-way ratchet: the first WARNING silently dropped every
    # INFO after it, and the first ERROR then dropped the WARNINGs too. The
    # more trouble a daemon was in, the less it logged -- and nothing
    # anywhere reported that records were being discarded.

    def emit(self, record):
        try:
            print(self.format(record))
        except Exception:
            self.handleError(record)


def setup(name, syslog=True, json=False, logpath=None):
    """Setup log formatter for a daemon.

    Daemon logging is always structured JSON now: the ``JsonFormatter`` is
    installed on the syslog / file / stdout handler unconditionally. See
    ``docs/log-record-fields.md`` for the emitted field-name contract.

    The ``json`` parameter is deprecated and ignored -- it is retained only for
    source compatibility with callers that still pass ``json=True``/
    ``json=False``. JSON is now the only daemon format.

    If the environment variable SHAKENFIST_LOG_TO_STDOUT is set to '1', logging
    will be redirected to stdout instead of syslog. This is useful for unit
    tests where stestr captures stdout and only displays it for failing tests.
    """
    del json  # Deprecated/no-op: JSON is now the only daemon format.

    logging.setLoggerClass(SyslogLogger)

    # Set root log level - higher handlers can set their own filter level
    logging.root.setLevel(logging.DEBUG)
    log = logging.getLogger(name)

    handler = None
    # Ensure our requested configuration is the one we have by removing
    # this logger's own pre-existing handlers. Note: check ``log.handlers``
    # (this logger's own handlers) rather than ``log.hasHandlers()``, which
    # returns True when any *ancestor* (e.g. the root logger) has a handler.
    # If a root handler is installed before setup() runs for a child logger
    # -- as happens once the Shaken Fist Loki shipper attaches its handler
    # to the root logger -- ``hasHandlers()`` is True while ``log.handlers``
    # is empty, so ``log.handlers[0]`` would raise IndexError.
    while log.handlers:
        log.removeHandler(log.handlers[0])

    # Allow tests to redirect logging to stdout for capture by test runners
    if os.environ.get('SHAKENFIST_LOG_TO_STDOUT') == '1':
        handler = logging.StreamHandler(sys.stdout)
    elif syslog:
        handler = logging_handlers.SysLogHandler(address='/dev/log')
    elif logpath == 'stdout':
        handler = ConsoleLoggingHandler()
    else:
        handler = logging_handlers.WatchedFileHandler(logpath)

    handler.setFormatter(JsonFormatter(
        datefmt='Z', enabled_fields=ENABLED_FIELDS))

    log.addHandler(handler)
    return log.with_prefix(), handler


def setup_console(name):
    """ Setup log formatter for a console script. """
    logging.setLoggerClass(ConsoleLogger)

    logging.root.setLevel(logging.INFO)
    log = logging.getLogger(name)

    handler = ConsoleLoggingHandler()
    handler.formatter = ConsoleLogFormatter()
    log.handlers = [handler]

    return log.with_prefix()
