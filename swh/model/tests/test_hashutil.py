# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import io
import tempfile
import unittest

from nose.tools import istest

from swh.model import hashutil


class Hashutil(unittest.TestCase):
    def setUp(self):
        self.data = b'1984\n'
        self.hex_checksums = {
            'sha1': '62be35bf00ff0c624f4a621e2ea5595a049e0731',
            'sha1_git': '568aaf43d83b2c3df8067f3bedbb97d83260be6d',
            'sha256': '26602113b4b9afd9d55466b08580d3c2'
                      '4a9b50ee5b5866c0d91fab0e65907311',
        }

        self.checksums = {
            type: bytes.fromhex(cksum)
            for type, cksum in self.hex_checksums.items()
        }

        self.git_hex_checksums = {
            'blob': self.hex_checksums['sha1_git'],
            'tree': '5b2e883aa33d2efab98442693ea4dd5f1b8871b0',
            'commit': '79e4093542e72f0fcb7cbd75cb7d270f9254aa8f',
            'tag': 'd6bf62466f287b4d986c545890716ce058bddf67',
        }

        self.git_checksums = {
            type: bytes.fromhex(cksum)
            for type, cksum in self.git_hex_checksums.items()
        }

    @istest
    def hash_data(self):
        checksums = hashutil.hash_data(self.data)
        self.assertEqual(checksums, self.checksums)

    @istest
    def hash_data_unknown_hash(self):
        with self.assertRaises(ValueError) as cm:
            hashutil.hash_data(self.data, ['unknown-hash'])

        self.assertIn('Unexpected hashing algorithm', cm.exception.args[0])
        self.assertIn('unknown-hash', cm.exception.args[0])

    @istest
    def hash_git_data(self):
        checksums = {
            git_type: hashutil.hash_git_data(self.data, git_type)
            for git_type in self.git_checksums
        }

        self.assertEqual(checksums, self.git_checksums)

    @istest
    def hash_git_data_unknown_git_type(self):
        with self.assertRaises(ValueError) as cm:
            hashutil.hash_git_data(self.data, 'unknown-git-type')

        self.assertIn('Unexpected git object type', cm.exception.args[0])
        self.assertIn('unknown-git-type', cm.exception.args[0])

    @istest
    def hash_file(self):
        fobj = io.BytesIO(self.data)

        checksums = hashutil.hash_file(fobj, length=len(self.data))
        self.assertEqual(checksums, self.checksums)

    @istest
    def hash_file_missing_length(self):
        fobj = io.BytesIO(self.data)

        with self.assertRaises(ValueError) as cm:
            hashutil.hash_file(fobj, algorithms=['sha1_git'])

        self.assertIn('Missing length', cm.exception.args[0])

    @istest
    def hash_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(self.data)
            f.close()
            hashes = hashutil.hash_path(f.name)

        self.assertEquals(self.checksums, hashes)

    @istest
    def hash_to_hex(self):
        for type in self.checksums:
            hex = self.hex_checksums[type]
            hash = self.checksums[type]
            self.assertEquals(hashutil.hash_to_hex(hex), hex)
            self.assertEquals(hashutil.hash_to_hex(hash), hex)

    @istest
    def hash_to_bytes(self):
        for type in self.checksums:
            hex = self.hex_checksums[type]
            hash = self.checksums[type]
            self.assertEquals(hashutil.hash_to_bytes(hex), hash)
            self.assertEquals(hashutil.hash_to_bytes(hash), hash)
