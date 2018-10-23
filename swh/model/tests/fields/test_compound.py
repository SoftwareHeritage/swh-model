# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import unittest

from swh.model.exceptions import NON_FIELD_ERRORS, ValidationError
from swh.model.fields import compound, simple


class ValidateCompound(unittest.TestCase):
    def setUp(self):
        def validate_always(model):
            return True

        def validate_never(model):
            return False

        self.test_model = 'test model'
        self.test_schema = {
            'int': (True, simple.validate_int),
            'str': (True, simple.validate_str),
            'str2': (True, simple.validate_str),
            'datetime': (False, simple.validate_datetime),
            NON_FIELD_ERRORS: validate_always,
        }

        self.test_schema_shortcut = self.test_schema.copy()
        self.test_schema_shortcut[NON_FIELD_ERRORS] = validate_never

        self.test_schema_field_failed = self.test_schema.copy()
        self.test_schema_field_failed['int'] = (True, [simple.validate_int,
                                                       validate_never])

        self.test_value = {
            'str': 'value1',
            'str2': 'value2',
            'int': 42,
            'datetime': datetime.datetime(1990, 1, 1, 12, 0, 0,
                                          tzinfo=datetime.timezone.utc),
        }

        self.test_value_missing = {
            'str': 'value1',
        }

        self.test_value_str_error = {
            'str': 1984,
            'str2': 'value2',
            'int': 42,
            'datetime': datetime.datetime(1990, 1, 1, 12, 0, 0,
                                          tzinfo=datetime.timezone.utc),
        }

        self.test_value_missing_keys = {'int'}

        self.test_value_wrong_type = 42

        self.present_keys = set(self.test_value)
        self.missing_keys = {'missingkey1', 'missingkey2'}

    def test_validate_any_key(self):
        self.assertTrue(
            compound.validate_any_key(self.test_value, self.present_keys))

        self.assertTrue(
            compound.validate_any_key(self.test_value,
                                      self.present_keys | self.missing_keys))

    def test_validate_any_key_missing(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_any_key(self.test_value, self.missing_keys)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'missing-alternative-field')
        self.assertEqual(exc.params['missing_fields'],
                         ', '.join(sorted(self.missing_keys)))

    def test_validate_all_keys(self):
        self.assertTrue(
            compound.validate_all_keys(self.test_value, self.present_keys))

    def test_validate_all_keys_missing(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_all_keys(self.test_value, self.missing_keys)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'missing-mandatory-field')
        self.assertEqual(exc.params['missing_fields'],
                         ', '.join(sorted(self.missing_keys)))

        with self.assertRaises(ValidationError) as cm:
            compound.validate_all_keys(self.test_value,
                                       self.present_keys | self.missing_keys)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'missing-mandatory-field')
        self.assertEqual(exc.params['missing_fields'],
                         ', '.join(sorted(self.missing_keys)))

    def test_validate_against_schema(self):
        self.assertTrue(
            compound.validate_against_schema(self.test_model, self.test_schema,
                                             self.test_value))

    def test_validate_against_schema_wrong_type(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(self.test_model, self.test_schema,
                                             self.test_value_wrong_type)

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(exc.code, 'model-unexpected-type')
        self.assertEqual(exc.params['model'], self.test_model)
        self.assertEqual(exc.params['type'],
                         self.test_value_wrong_type.__class__.__name__)

    def test_validate_against_schema_mandatory_keys(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(self.test_model, self.test_schema,
                                             self.test_value_missing)

        # The exception should be of the form:
        # ValidationError({
        #     'mandatory_key1': [ValidationError('model-field-mandatory')],
        #     'mandatory_key2': [ValidationError('model-field-mandatory')],
        # })
        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        for key in self.test_value_missing_keys:
            nested_key = exc.error_dict[key]
            self.assertIsInstance(nested_key, list)
            self.assertEqual(len(nested_key), 1)
            nested = nested_key[0]
            self.assertIsInstance(nested, ValidationError)
            self.assertEqual(nested.code, 'model-field-mandatory')
            self.assertEqual(nested.params['field'], key)

    def test_validate_whole_schema_shortcut_previous_error(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(
                self.test_model,
                self.test_schema_shortcut,
                self.test_value_missing,
            )

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertNotIn(NON_FIELD_ERRORS, exc.error_dict)

    def test_validate_whole_schema(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(
                self.test_model,
                self.test_schema_shortcut,
                self.test_value,
            )

        # The exception should be of the form:
        # ValidationError({
        #     NON_FIELD_ERRORS: [ValidationError('model-validation-failed')],
        # })

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(set(exc.error_dict.keys()), {NON_FIELD_ERRORS})

        non_field_errors = exc.error_dict[NON_FIELD_ERRORS]
        self.assertIsInstance(non_field_errors, list)
        self.assertEqual(len(non_field_errors), 1)

        nested = non_field_errors[0]
        self.assertIsInstance(nested, ValidationError)
        self.assertEqual(nested.code, 'model-validation-failed')
        self.assertEqual(nested.params['model'], self.test_model)
        self.assertEqual(nested.params['validator'], 'validate_never')

    def test_validate_against_schema_field_error(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(self.test_model, self.test_schema,
                                             self.test_value_str_error)

        # The exception should be of the form:
        # ValidationError({
        #     'str': [ValidationError('unexpected-type')],
        # })

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(set(exc.error_dict.keys()), {'str'})

        str_errors = exc.error_dict['str']
        self.assertIsInstance(str_errors, list)
        self.assertEqual(len(str_errors), 1)

        nested = str_errors[0]
        self.assertIsInstance(nested, ValidationError)
        self.assertEqual(nested.code, 'unexpected-type')

    def test_validate_against_schema_field_failed(self):
        with self.assertRaises(ValidationError) as cm:
            compound.validate_against_schema(self.test_model,
                                             self.test_schema_field_failed,
                                             self.test_value)

        # The exception should be of the form:
        # ValidationError({
        #     'int': [ValidationError('field-validation-failed')],
        # })

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(set(exc.error_dict.keys()), {'int'})

        int_errors = exc.error_dict['int']
        self.assertIsInstance(int_errors, list)
        self.assertEqual(len(int_errors), 1)

        nested = int_errors[0]
        self.assertIsInstance(nested, ValidationError)
        self.assertEqual(nested.code, 'field-validation-failed')
        self.assertEqual(nested.params['validator'], 'validate_never')
        self.assertEqual(nested.params['field'], 'int')
