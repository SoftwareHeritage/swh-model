# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import unittest

from nose.tools import istest

from swh.model.exceptions import ValidationError
from swh.model.fields import simple


class ValidateHash(unittest.TestCase):
    def setUp(self):
        self.valid_str = 'I am a valid string'

        self.enum_values = {'an enum value', 'other', 'and another'}
        self.invalid_enum_value = 'invalid enum value'

        self.valid_int = 42

        self.valid_real = 42.42

        self.valid_datetime = datetime.datetime(1999, 1, 1, 12, 0, 0,
                                                tzinfo=datetime.timezone.utc)
        self.invalid_datetime_notz = datetime.datetime(1999, 1, 1, 12, 0, 0)

    @istest
    def validate_int(self):
        self.assertTrue(simple.validate_int(self.valid_int))

    @istest
    def validate_int_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_int(self.valid_str)

        exc = cm.exception
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'Integral')
        self.assertEqual(exc.params['type'], 'str')

    @istest
    def validate_str(self):
        self.assertTrue(simple.validate_str(self.valid_str))

    @istest
    def validate_str_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_str(self.valid_int)

        exc = cm.exception
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'str')
        self.assertEqual(exc.params['type'], 'int')

    @istest
    def validate_datetime(self):
        self.assertTrue(simple.validate_datetime(self.valid_datetime))
        self.assertTrue(simple.validate_datetime(self.valid_int))
        self.assertTrue(simple.validate_datetime(self.valid_real))

    @istest
    def validate_datetime_invalid_type(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_datetime(self.valid_str)

        exc = cm.exception
        self.assertEqual(exc.code, 'unexpected-type')
        self.assertEqual(exc.params['expected_type'], 'one of datetime, Real')
        self.assertEqual(exc.params['type'], 'str')

    @istest
    def validate_datetime_invalide_tz(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_datetime(self.invalid_datetime_notz)

        exc = cm.exception
        self.assertEqual(exc.code, 'datetime-without-tzinfo')

    @istest
    def validate_enum(self):
        for value in self.enum_values:
            self.assertTrue(simple.validate_enum(value, self.enum_values))

    @istest
    def validate_enum_invalid_value(self):
        with self.assertRaises(ValidationError) as cm:
            simple.validate_enum(self.invalid_enum_value, self.enum_values)

        exc = cm.exception
        self.assertEqual(exc.code, 'unexpected-value')
        self.assertEqual(exc.params['value'], self.invalid_enum_value)
        self.assertEqual(exc.params['expected_values'],
                         ', '.join(sorted(self.enum_values)))
