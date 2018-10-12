# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import unittest

from swh.model.exceptions import ValidationError
from swh.model.fields import simple


class ValidateSimple(unittest.TestCase):
    def setUp(self):
        self.valid_str = 'I am a valid string'

        self.valid_bytes = b'I am a valid bytes object'

        self.enum_values = {'an enum value', 'other', 'and another'}
        self.invalid_enum_value = 'invalid enum value'

        self.valid_int = 42

        self.valid_real = 42.42

        self.valid_datetime = datetime.datetime(1999, 1, 1, 12, 0, 0,
                                                tzinfo=datetime.timezone.utc)
        self.invalid_datetime_notz = datetime.datetime(1999, 1, 1, 12, 0, 0)

    def test_validate_int(self):
        self.assertTrue(simple.validate_int(self.valid_int))

    def test_validate_int_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_int(self.valid_str)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'Integral')
        self.assertEqual(exc.params['type'], 'str')

    def test_validate_str(self):
        self.assertTrue(simple.validate_str(self.valid_str))

    def test_validate_str_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_str(self.valid_int)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'str')
        self.assertEqual(exc.params['type'], 'int')

        with self.assertRaises(ValidationError) as cm:
            simple.validate_str(self.valid_bytes)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'str')
        self.assertEqual(exc.params['type'], 'bytes')

    def test_validate_bytes(self):
        self.assertTrue(simple.validate_bytes(self.valid_bytes))

    def test_validate_bytes_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_bytes(self.valid_int)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'bytes')
        self.assertEqual(exc.params['type'], 'int')

        with self.assertRaises(ValidationError) as cm:
            simple.validate_bytes(self.valid_str)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'bytes')
        self.assertEqual(exc.params['type'], 'str')

    def test_validate_datetime(self):
        self.assertTrue(simple.validate_datetime(self.valid_datetime))
        self.assertTrue(simple.validate_datetime(self.valid_int))
        self.assertTrue(simple.validate_datetime(self.valid_real))

    def test_validate_datetime_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_datetime(self.valid_str)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'one of datetime, Real')
        self.assertEqual(exc.params['type'], 'str')

    def test_validate_datetime_invalide_tz(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_datetime(self.invalid_datetime_notz)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'datetime-without-tzinfo')

    def test_validate_enum(self):
        for value in self.enum_values:
            self.assertTrue(simple.validate_enum(value, self.enum_values))

    def test_validate_enum_invalid_value(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_enum(self.invalid_enum_value, self.enum_values)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'unexpected-value')
        self.assertEqual(exc.params['value'], self.invalid_enum_value)
        self.assertEqual(exc.params['expected_values'],
                         ', '.join(sorted(self.enum_values)))
