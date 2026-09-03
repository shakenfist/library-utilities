import contextlib
import io
import json
import logging
import sys
import time
import uuid

import testtools

from shakenfist_utilities import logs


class _Thing(object):
    """A stand-in for a Shaken Fist object with a .uuid attribute."""

    def __init__(self, value):
        self.uuid = value


class JsonFormatterTestCase(testtools.TestCase):
    """The formatter that replaced pylogrus.JsonFormatter.

    docs/log-record-fields.md is a stated contract that the Loki
    shipper and every saved query depend on, so these assert the shape
    of the output rather than merely that it is JSON.
    """

    def _record(self, **kwargs):
        record = logging.LogRecord(
            'a.logger', kwargs.pop('level', logging.INFO), '/path/mod.py',
            42, kwargs.pop('msg', 'hello %s'), kwargs.pop('args', ('world',)),
            kwargs.pop('exc_info', None), func='do_thing')
        for key, value in kwargs.items():
            setattr(record, key, value)
        return record

    def _format(self, record, **kwargs):
        kwargs.setdefault('datefmt', 'Z')
        return json.loads(logs.JsonFormatter(**kwargs).format(record))

    def test_the_contract_fields_are_emitted_in_order(self):
        obj = self._format(self._record())
        self.assertEqual(
            ['logger_name', 'ts', 'level', 'thread_name', 'pid', 'module',
             'function', 'message', 'exception_class', 'stack_trace'],
            list(obj))

    def test_the_default_field_list_is_the_contract(self):
        """A bare JsonFormatter() emits what the documentation promises."""
        self.assertEqual(self._format(self._record()),
                         self._format(self._record(),
                                      enabled_fields=logs.ENABLED_FIELDS))

    def test_a_zulu_timestamp_has_milliseconds_and_a_z(self):
        obj = self._format(self._record())
        self.assertRegex(
            obj['ts'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$')

    def test_a_zulu_timestamp_is_actually_utc(self):
        """The Z has to be a fact, not a claim.

        pylogrus resolved it with time.localtime, so on an Australian
        host every daemon stamped its logs ten hours in the future and
        called them Zulu. Asserted against gmtime rather than against
        "not localtime", so the test means the same thing on a host
        that happens to run UTC.
        """
        record = self._record()
        obj = self._format(record)
        expected = time.strftime('%Y-%m-%dT%H:%M:%S',
                                 time.gmtime(record.created))
        self.assertTrue(obj['ts'].startswith(expected), obj['ts'])

    def test_other_date_formats_stay_local(self):
        """Only 'Z' means UTC; logging's own convention is local time."""
        record = self._record()
        obj = self._format(record, datefmt='%Y-%m-%dT%H:%M:%S',
                           enabled_fields=[('asctime', 'ts')])
        self.assertEqual(
            time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(record.created)),
            obj['ts'])

    def test_arguments_are_interpolated_into_the_message(self):
        self.assertEqual('hello world',
                         self._format(self._record())['message'])

    def test_a_prefix_is_prepended_to_the_message(self):
        obj = self._format(self._record(prefix='PFX'))
        self.assertEqual('PFX hello world', obj['message'])

    def test_an_empty_prefix_is_not_prepended(self):
        self.assertEqual('hello world',
                         self._format(self._record(prefix=''))['message'])

    def test_no_prefix_attribute_is_not_an_error(self):
        self.assertEqual('hello world',
                         self._format(self._record())['message'])

    def test_extra_fields_are_merged_into_the_body(self):
        obj = self._format(self._record(extra_fields={'instance': 'abc'}))
        self.assertEqual('abc', obj['instance'])

    def test_extra_fields_that_are_not_a_dict_are_ignored(self):
        obj = self._format(self._record(extra_fields='nope'))
        self.assertNotIn('nope', obj)

    def test_an_exception_populates_the_exception_fields(self):
        try:
            raise ValueError('boom')
        except ValueError:
            record = self._record(exc_info=sys.exc_info())
        obj = self._format(record)
        self.assertEqual('ValueError', obj['exception_class'])
        self.assertIn('boom', obj['stack_trace'])

    def test_no_exception_leaves_the_exception_fields_null(self):
        obj = self._format(self._record())
        self.assertIsNone(obj['exception_class'])
        self.assertIsNone(obj['stack_trace'])

    def test_an_explicit_field_list_selects_and_renames(self):
        obj = self._format(self._record(),
                           enabled_fields=['message', ('funcName', 'fn')])
        self.assertEqual({'fn': 'do_thing', 'message': 'hello world'}, obj)

    def test_an_unknown_field_name_is_ignored(self):
        obj = self._format(self._record(),
                           enabled_fields=['message', 'nosuchthing'])
        self.assertEqual({'message': 'hello world'}, obj)

    def test_a_bare_string_field_list_is_tolerated(self):
        self.assertEqual({'message': 'hello world'},
                         self._format(self._record(), enabled_fields='message'))

    def test_output_order_follows_the_record_not_the_request(self):
        """pylogrus behaved this way and the contract depends on it."""
        obj = self._format(
            self._record(),
            enabled_fields=[('funcName', 'function'), ('name', 'logger_name')])
        self.assertEqual(['logger_name', 'function'], list(obj))



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

    def _console_output(self, log, emit):
        """Run ``emit`` and return what the console handler printed.

        Deliberately captures stdout rather than attaching a second
        StreamHandler the way the tests above do. ConsoleLoggingHandler
        prints directly, and a substitute handler has its own level -- so
        adding one bypasses the very filtering these tests are about.
        """
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            emit(log)
        return buf.getvalue()

    def test_console_keeps_logging_info_after_a_warning(self):
        """A WARNING must not silence the INFOs that follow it.

        emit() used to assign self.level from each record it emitted, and
        Handler.level is what Logger.callHandlers filters on. So the first
        WARNING raised the handler to WARNING and every later INFO was
        dropped without a word; the first ERROR then dropped the WARNINGs
        too, leaving a failing daemon quieter than a healthy one. Found in
        conductor on 2026-08-20, where an unrelated startup warning
        silenced the rest of the process's INFO logging.
        """
        log = logs.setup_console('test-console-ratchet')

        def emit(log):
            log.info('first info')
            log.warning('a warning')
            log.info('info after the warning')
            log.error('an error')
            log.warning('warning after the error')
            log.info('info after the error')

        out = self._console_output(log, emit)

        for message in ('first info', 'a warning', 'info after the warning',
                        'an error', 'warning after the error',
                        'info after the error'):
            self.assertIn(message, out)

    def test_console_handler_level_is_not_mutated_by_emitting(self):
        """The handler's level is fixed, whatever passes through it."""
        log = logs.setup_console('test-console-handler-level')
        handler = logging.getLogger(log.logger.name).handlers[0]
        before = handler.level

        self._console_output(log, lambda log: log.error('an error'))

        self.assertEqual(before, handler.level)

    def test_console_still_honours_the_logger_level(self):
        """Removing the handler's filtering must not remove filtering.

        The logger is where the level belongs, so raising it still works.
        """
        log = logs.setup_console('test-console-logger-level')
        real_logger = logging.getLogger(log.logger.name)
        real_logger.setLevel(logging.WARNING)
        self.addCleanup(real_logger.setLevel, logging.NOTSET)

        def emit(log):
            log.info('filtered out')
            log.warning('let through')

        out = self._console_output(log, emit)

        self.assertNotIn('filtered out', out)
        self.assertIn('let through', out)

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
