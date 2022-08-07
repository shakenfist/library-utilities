import copy
import datetime
from lib2to3.pytree import Base
import logging
from logging import handlers as logging_handlers
import importlib
import os
from pylogrus import TextFormatter
from pylogrus.base import PyLogrusBase
import setproctitle


FLASK = None
FLASK_ATTEMPTED = False


# These classes are extensions of the work in https://github.com/vmig/pylogrus
class SyslogLogger(logging.Logger, PyLogrusBase):

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


class SyslogAdapter(logging.LoggerAdapter, PyLogrusBase):

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

        # Handle "special fields" which might be internal objects
        for key in ['artifact', 'blob', 'instance', 'network', 'networkinterface', 'node']:
            if key in fields:
                value = fields[key]
                if not isinstance(value, str):
                    fields[key] = value.uuid

        extra.update(fields)
        return SyslogAdapter(self._logger, extra, self._prefix)

    def with_prefix(self, prefix=None):
        return self if prefix is None else SyslogAdapter(self._logger, self._extra, prefix)


    def process(self, msg, kwargs):
        msg = '%s[%s] %s' % (setproctitle.getproctitle(), os.getpid(), msg)
        kwargs['extra'] = self.extra
        return msg, kwargs


class ConsoleLogger(logging.Logger, PyLogrusBase):

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
    level = logging.INFO

    def emit(self, record):
        try:
            # NOTE(mikal): level looks unused, but is used by the python
            # logging handler
            self.level = logging._nameToLevel[record.levelname.upper()]
            print(self.format(record))
        except Exception:
            self.handleError(record)


def setup(name):
    """ Setup log formatter for a daemon. """
    logging.setLoggerClass(SyslogLogger)

    # Set root log level - higher handlers can set their own filter level
    logging.root.setLevel(logging.DEBUG)
    log = logging.getLogger(name)

    handler = None
    if log.hasHandlers():
        # The parent logger might have the handler, not this lower logger
        if len(log.handlers) > 0:
            # TODO(andy): Remove necessity to return handler or
            # correctly obtain the handler without causing an exception
            handler = log.handlers[0]
    else:
        # Add our handler
        handler = logging_handlers.SysLogHandler(address='/dev/log')
        handler.setFormatter(TextFormatter(
            fmt='%(levelname)s %(message)s', colorize=False))
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
