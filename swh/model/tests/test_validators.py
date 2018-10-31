# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import unittest

from swh.model import exceptions, hashutil, validators


def hash_data(raw_content):
    return hashutil.MultiHash.from_data(raw_content).digest()


class TestValidators(unittest.TestCase):
    def setUp(self):
        self.valid_visible_content = {
            'status': 'visible',
            'length': 5,
            'data': b'1984\n',
            'ctime': datetime.datetime(2015, 11, 22, 16, 33, 56,
                                       tzinfo=datetime.timezone.utc),
        }

        self.valid_visible_content.update(
            hash_data(self.valid_visible_content['data']))

        self.valid_absent_content = {
            'status': 'absent',
            'length': 5,
            'ctime': datetime.datetime(2015, 11, 22, 16, 33, 56,
                                       tzinfo=datetime.timezone.utc),
            'reason': 'Content too large',
            'sha1_git': self.valid_visible_content['sha1_git'],
            'origin': 42,
        }

        self.invalid_content_hash_mismatch = self.valid_visible_content.copy()
        self.invalid_content_hash_mismatch.update(
            hash_data(b"this is not the data you're looking for"))

    def test_validate_content(self):
        self.assertTrue(
            validators.validate_content(self.valid_visible_content))

        self.assertTrue(
            validators.validate_content(self.valid_absent_content))

    def test_validate_content_hash_mismatch(self):
        with self.assertRaises(exceptions.ValidationError) as cm:
            validators.validate_content(self.invalid_content_hash_mismatch)

        # All the hashes are wrong. The exception should be of the form:
        # ValidationError({
        #     NON_FIELD_ERRORS: [
        #         ValidationError('content-hash-mismatch', 'sha1'),
        #         ValidationError('content-hash-mismatch', 'sha1_git'),
        #         ValidationError('content-hash-mismatch', 'sha256'),
        #     ]
        # })

        exc = cm.exception
        self.assertIsInstance(str(exc), str)
        self.assertEqual(set(exc.error_dict.keys()),
                         {exceptions.NON_FIELD_ERRORS})

        hash_mismatches = exc.error_dict[exceptions.NON_FIELD_ERRORS]
        self.assertIsInstance(hash_mismatches, list)
        self.assertEqual(len(hash_mismatches), 4)
        self.assertTrue(all(mismatch.code == 'content-hash-mismatch'
                            for mismatch in hash_mismatches))
        self.assertEqual(set(mismatch.params['hash']
                             for mismatch in hash_mismatches),
                         {'sha1', 'sha1_git', 'sha256', 'blake2s256'})
