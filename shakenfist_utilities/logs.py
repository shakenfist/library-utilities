import copy
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
class SFPyLogrus(logging.Logger, PyLogrusBase):

    def __init__(self, *args, **kwargs):
        extra = kwargs.pop('extra', None)
        self._extra_fields = extra or {}
        super(SFPyLogrus, self).__init__(*args, **kwargs)

    def withPrefix(self, prefix=None):
        return self.with_prefix(prefix)

    def withFields(self, fields=None):
        return self.with_fields(fields)

    def with_prefix(self, prefix=None):
        return SFCustomAdapter(self, None, prefix)

    def with_fields(self, fields=None):
        return SFCustomAdapter(self, fields)


class SFCustomAdapter(logging.LoggerAdapter, PyLogrusBase):

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

        super(SFCustomAdapter, self).__init__(
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
        return SFCustomAdapter(self._logger, extra, self._prefix)

    def with_prefix(self, prefix=None):
        return self if prefix is None else SFCustomAdapter(self._logger, self._extra, prefix)

    def process(self, msg, kwargs):
        msg = '%s[%s] %s' % (setproctitle.getproctitle(), os.getpid(), msg)
        kwargs["extra"] = self.extra

        return msg, kwargs


def setup(name):
    logging.setLoggerClass(SFPyLogrus)

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
