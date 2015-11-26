# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
import unittest

from nose.tools import istest

from swh.model import hashutil, identifiers


class UtilityFunctionsIdentifier(unittest.TestCase):
    def setUp(self):
        self.str_id = 'c2e41aae41ac17bd4a650770d6ee77f62e52235b'
        self.bytes_id = binascii.unhexlify(self.str_id)
        self.bad_type_id = object()

    @istest
    def identifier_to_bytes(self):
        for id in [self.str_id, self.bytes_id]:
            self.assertEqual(identifiers.identifier_to_bytes(id),
                             self.bytes_id)

            # wrong length
            with self.assertRaises(ValueError) as cm:
                identifiers.identifier_to_bytes(id[:-2])

            self.assertIn('length', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            identifiers.identifier_to_bytes(self.bad_type_id)

        self.assertIn('type', str(cm.exception))

    @istest
    def identifier_to_str(self):
        for id in [self.str_id, self.bytes_id]:
            self.assertEqual(identifiers.identifier_to_str(id),
                             self.str_id)

            # wrong length
            with self.assertRaises(ValueError) as cm:
                identifiers.identifier_to_str(id[:-2])

            self.assertIn('length', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            identifiers.identifier_to_str(self.bad_type_id)

        self.assertIn('type', str(cm.exception))


class UtilityFunctionsDateOffset(unittest.TestCase):
    def setUp(self):
        self.date = datetime.datetime(
            2015, 11, 22, 16, 33, 56, tzinfo=datetime.timezone.utc)
        self.date_int = int(self.date.timestamp())
        self.date_repr = b'1448210036'

        self.date_microseconds = datetime.datetime(
            2015, 11, 22, 16, 33, 56, 2342, tzinfo=datetime.timezone.utc)
        self.date_microseconds_float = self.date_microseconds.timestamp()
        self.date_microseconds_repr = b'1448210036.002342'

        self.offsets = {
            0: b'+0000',
            -630: b'-1030',
            800: b'+1320',
        }

    @istest
    def format_date(self):
        for date in [self.date, self.date_int]:
            self.assertEqual(identifiers.format_date(date), self.date_repr)

        for date in [self.date_microseconds, self.date_microseconds_float]:
            self.assertEqual(identifiers.format_date(date),
                             self.date_microseconds_repr)

    @istest
    def format_offset(self):
        for offset, res in self.offsets.items():
            self.assertEqual(identifiers.format_offset(offset), res)


class ContentIdentifier(unittest.TestCase):
    def setUp(self):
        self.content = {
            'status': 'visible',
            'length': 5,
            'data': b'1984\n',
            'ctime': datetime.datetime(2015, 11, 22, 16, 33, 56,
                                       tzinfo=datetime.timezone.utc),
        }

        self.content.update(
            hashutil.hash_data(self.content['data']))

    @istest
    def content_identifier(self):
        self.assertEqual(identifiers.content_identifier(self.content),
                         self.content['sha1'])


class DirectoryIdentifier(unittest.TestCase):
    def setUp(self):
        self.directory = {
            'id': 'c2e41aae41ac17bd4a650770d6ee77f62e52235b',
            'entries': [
                {
                    'type': 'file',
                    'perms': 33188,
                    'name': b'README',
                    'target': '37ec8ea2110c0b7a32fbb0e872f6e7debbf95e21'
                },
                {
                    'type': 'file',
                    'perms': 33188,
                    'name': b'Rakefile',
                    'target': '3bb0e8592a41ae3185ee32266c860714980dbed7'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'app',
                    'target': '61e6e867f5d7ba3b40540869bc050b0c4fed9e95'
                },
                {
                    'type': 'file',
                    'perms': 33188,
                    'name': b'1.megabyte',
                    'target': '7c2b2fbdd57d6765cdc9d84c2d7d333f11be7fb3'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'config',
                    'target': '591dfe784a2e9ccc63aaba1cb68a765734310d98'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'public',
                    'target': '9588bf4522c2b4648bfd1c61d175d1f88c1ad4a5'
                },
                {
                    'type': 'file',
                    'perms': 33188,
                    'name': b'development.sqlite3',
                    'target': 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'doc',
                    'target': '154705c6aa1c8ead8c99c7915373e3c44012057f'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'db',
                    'target': '85f157bdc39356b7bc7de9d0099b4ced8b3b382c'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'log',
                    'target': '5e3d3941c51cce73352dff89c805a304ba96fffe'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'script',
                    'target': '1b278423caf176da3f3533592012502aa10f566c'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'test',
                    'target': '035f0437c080bfd8711670b3e8677e686c69c763'
                },
                {
                    'type': 'dir',
                    'perms': 16384,
                    'name': b'vendor',
                    'target': '7c0dc9ad978c1af3f9a4ce061e50f5918bd27138'
                },
                {
                    'type': 'rev',
                    'perms': 57344,
                    'name': b'will_paginate',
                    'target': '3d531e169db92a16a9a8974f0ae6edf52e52659e'
                }
            ],
        }

        self.empty_directory = {
            'id': '4b825dc642cb6eb9a060e54bf8d69288fbee4904',
            'entries': [],
        }

    @istest
    def dir_identifier(self):
        self.assertEqual(
            identifiers.directory_identifier(self.directory),
            self.directory['id'])

    @istest
    def dir_identifier_empty_directory(self):
        self.assertEqual(
            identifiers.directory_identifier(self.empty_directory),
            self.empty_directory['id'])


class RevisionIdentifier(unittest.TestCase):
    def setUp(self):
        self.revision = {
            'id': 'bc0195aad0daa2ad5b0d76cce22b167bc3435590',
            'directory': '85a74718d377195e1efd0843ba4f3260bad4fe07',
            'parents': ['01e2d0627a9a6edb24c37db45db5ecb31e9de808'],
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
                'date': datetime.datetime(2015, 7, 12, 22, 10, 30,
                                          tzinfo=datetime.timezone.utc),
                'date_offset': -420,

            },
            'committer': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
                'date': datetime.datetime(2015, 7, 12, 22, 10, 30,
                                          tzinfo=datetime.timezone.utc),
                'date_offset': -420,

            },
            'message': b'Linux 4.2-rc2\n',
        }

        self.synthetic_revision = {
            'id': b'\xb2\xa7\xe1&\x04\x92\xe3D\xfa\xb3\xcb\xf9\x1b\xc1<\x91'
                  b'\xe0T&\xfd',
            'author': {
                'name': b'Software Heritage',
                'email': b'robot@softwareheritage.org',
                'date': datetime.datetime(2015, 7, 16, 11, 51, 35,
                                          tzinfo=datetime.timezone.utc),
                'date_offset': 0,
            },
            'type': 'tar',
            'committer': {
                'name': b'Software Heritage',
                'date': datetime.datetime(2015, 7, 16, 11, 51, 35,
                                          tzinfo=datetime.timezone.utc),
                'email': b'robot@softwareheritage.org',
                'date_offset': 0,
            },
            'synthetic': True,
            'parents': [None],
            'message': b'synthetic revision message\n',
            'directory': b'\xd1\x1f\x00\xa6\xa0\xfe\xa6\x05SA\xd2U\x84\xb5\xa9'
                         b'e\x16\xc0\xd2\xb8',
            'metadata': {'original_artifact': [
                {'archive_type': 'tar',
                 'name': 'gcc-5.2.0.tar.bz2',
                 'sha1_git': '39d281aff934d44b439730057e55b055e206a586',
                 'sha1': 'fe3f5390949d47054b613edc36c557eb1d51c18e',
                 'sha256': '5f835b04b5f7dd4f4d2dc96190ec1621b8d89f'
                           '2dc6f638f9f8bc1b1014ba8cad'}]},

        }

    @istest
    def revision_identifier(self):
        self.assertEqual(
            identifiers.revision_identifier(self.revision),
            identifiers.identifier_to_str(self.revision['id']),
        )

    @istest
    def revision_identifier_synthetic(self):
        self.assertEqual(
            identifiers.revision_identifier(self.synthetic_revision),
            identifiers.identifier_to_str(self.synthetic_revision['id']),
        )


class ReleaseIdentifier(unittest.TestCase):
    def setUp(self):
        self.release = {
            'id': '2b10839e32c4c476e9d94492756bb1a3e1ec4aa8',
            'revision': b't\x1b"R\xa5\xe1Ml`\xa9\x13\xc7z`\x99\xab\xe7:\x85J',
            'name': 'v2.6.14',
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@g5.osdl.org',
                'date': datetime.datetime(2005, 10, 28, 0, 2, 33,
                                          tzinfo=datetime.timezone.utc),
                'date_offset': -420,
            },
            'comment': b'''\
Linux 2.6.14 release
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.1 (GNU/Linux)

iD8DBQBDYWq6F3YsRnbiHLsRAmaeAJ9RCez0y8rOBbhSv344h86l/VVcugCeIhO1
wdLOnvj91G4wxYqrvThthbE=
=7VeT
-----END PGP SIGNATURE-----
''',
            'synthetic': False,
        }

        self.release_no_author = {
            'id': b'&y\x1a\x8b\xcf\x0em3\xf4:\xefv\x82\xbd\xb5U#mV\xde',
            'revision': '9ee1c939d1cb936b1f98e8d81aeffab57bae46ab',
            'name': 'v2.6.12',
            'comment': b'''\
This is the final 2.6.12 release
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.2.4 (GNU/Linux)

iD8DBQBCsykyF3YsRnbiHLsRAvPNAJ482tCZwuxp/bJRz7Q98MHlN83TpACdHr37
o6X/3T+vm8K3bf3driRr34c=
=sBHn
-----END PGP SIGNATURE-----
''',
            'synthetic': False,
        }

    @istest
    def release_identifier(self):
        self.assertEqual(
            identifiers.release_identifier(self.release),
            identifiers.identifier_to_str(self.release['id'])
        )

    @istest
    def release_identifier_no_author(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_no_author),
            identifiers.identifier_to_str(self.release_no_author['id'])
        )
