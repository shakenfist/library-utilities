import io
import json
import logging
import uuid

import testtools

from shakenfist_utilities import logs


class _Thing(object):
    """A stand-in for a Shaken Fist object with a .uuid attribute."""

    def __init__(self, value):
        self.uuid = value


class LogsTestCase(testtools.TestCase):
    def _capture(self, log):
        """Attach an in-memory StreamHandler and return its buffer.

        The buffer mirrors what the configured JsonFormatter emits, without
        depending on syslog or the filesystem.
        """
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        # The logger returned by setup() is an adapter; reach the real logger
        # to find the formatter setup() installed and reuse it.
        real_logger = logging.getLogger(log.logger.name)
        handler.setFormatter(real_logger.handlers[0].formatter)
        real_logger.addHandler(handler)
        self.addCleanup(real_logger.removeHandler, handler)
        return buf

    def test_setup_emits_valid_json_with_base_fields(self):
        log, _ = logs.setup('test-base-fields')
        buf = self._capture(log)
        log.info('a message')

        obj = json.loads(buf.getvalue().strip())
        for field in ('logger_name', 'ts', 'level', 'pid', 'thread_name',
                      'message', 'module', 'function'):
            self.assertIn(field, obj)
        self.assertEqual('test-base-fields', obj['logger_name'])
        self.assertEqual('INFO', obj['level'])

    def test_message_is_clean_and_pid_present(self):
        log, _ = logs.setup('test-clean-message')
        buf = self._capture(log)
        log.info('hello world')

        obj = json.loads(buf.getvalue().strip())
        # No setproctitle[pid:thread] prefix -- the message is exactly what was
        # logged.
        self.assertEqual('hello world', obj['message'])
        self.assertIn('pid', obj)
        self.assertIsInstance(obj['pid'], int)
        # The process title is surfaced as a discrete field instead.
        self.assertIn('program', obj)

    def test_with_fields_lowercases_keys(self):
        log, _ = logs.setup('test-lowercase')
        buf = self._capture(log)
        log.with_fields({'Foo': 'bar'}).info('msg')

        obj = json.loads(buf.getvalue().strip())
        self.assertIn('foo', obj)
        self.assertNotIn('Foo', obj)
        self.assertEqual('bar', obj['foo'])

    def test_with_fields_unwraps_object_uuid(self):
        log, _ = logs.setup('test-unwrap')
        buf = self._capture(log)
        thing = _Thing('11111111-2222-3333-4444-555555555555')
        log.with_fields({'instance': thing}).info('msg')

        obj = json.loads(buf.getvalue().strip())
        self.assertEqual('11111111-2222-3333-4444-555555555555',
                         obj['instance'])

    def test_with_fields_stringifies_uuid(self):
        log, _ = logs.setup('test-uuid')
        buf = self._capture(log)
        value = uuid.UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        log.with_fields({'network': value}).info('msg')

        obj = json.loads(buf.getvalue().strip())
        self.assertEqual('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                         obj['network'])
        self.assertIsInstance(obj['network'], str)

    def test_deprecated_json_param_still_yields_json(self):
        # Passing the deprecated json=False must not raise and must still
        # produce JSON output (the parameter is now a no-op).
        log, _ = logs.setup('test-deprecated', json=False)
        buf = self._capture(log)
        log.info('still json')

        obj = json.loads(buf.getvalue().strip())
        self.assertEqual('still json', obj['message'])

    def test_setup_with_root_handler_present(self):
        # Regression: when a handler is attached to the root logger before
        # setup() runs for a child logger (as the Shaken Fist Loki shipper
        # does), setup() must not raise. log.hasHandlers() is True via the
        # root ancestor while the child logger's own handlers list is empty,
        # so the old `while log.hasHandlers(): removeHandler(log.handlers[0])`
        # raised IndexError.
        root = logging.getLogger()
        root_handler = logging.StreamHandler(io.StringIO())
        root.addHandler(root_handler)
        self.addCleanup(root.removeHandler, root_handler)

        # Must not raise IndexError.
        log, _ = logs.setup('test-root-handler-present')

        # The root handler is left intact (setup only strips the child
        # logger's own handlers).
        self.assertIn(root_handler, root.handlers)

        # And the logger still works.
        buf = self._capture(log)
        log.info('after root handler')
        obj = json.loads(buf.getvalue().strip())
        self.assertEqual('after root handler', obj['message'])

    def test_setup_console_is_not_json(self):
        log = logs.setup_console('test-console')
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        real_logger = logging.getLogger(log.logger.name)
        handler.setFormatter(real_logger.handlers[0].formatter)
        real_logger.addHandler(handler)
        self.addCleanup(real_logger.removeHandler, handler)

        log.info('human readable')
        line = buf.getvalue().strip()

        self.assertRaises(json.JSONDecodeError, json.loads, line)
        # The colorised console format ends with "<LEVEL><reset>: <message>".
        self.assertIn('INFO', line)
        self.assertIn('human readable', line)
