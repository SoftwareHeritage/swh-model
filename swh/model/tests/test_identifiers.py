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

        self.content_id = hashutil.hash_data(self.content['data'])

    @istest
    def content_identifier(self):
        self.assertEqual(identifiers.content_identifier(self.content),
                         self.content_id)


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

        linus_tz = datetime.timezone(datetime.timedelta(minutes=-420))

        gpgsig = b'''\
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1.4.13 (Darwin)

iQIcBAABAgAGBQJVJcYsAAoJEBiY3kIkQRNJVAUQAJ8/XQIfMqqC5oYeEFfHOPYZ
L7qy46bXHVBa9Qd8zAJ2Dou3IbI2ZoF6/Et89K/UggOycMlt5FKV/9toWyuZv4Po
L682wonoxX99qvVTHo6+wtnmYO7+G0f82h+qHMErxjP+I6gzRNBvRr+SfY7VlGdK
wikMKOMWC5smrScSHITnOq1Ews5pe3N7qDYMzK0XVZmgDoaem4RSWMJs4My/qVLN
e0CqYWq2A22GX7sXl6pjneJYQvcAXUX+CAzp24QnPSb+Q22Guj91TcxLFcHCTDdn
qgqMsEyMiisoglwrCbO+D+1xq9mjN9tNFWP66SQ48mrrHYTBV5sz9eJyDfroJaLP
CWgbDTgq6GzRMehHT3hXfYS5NNatjnhkNISXR7pnVP/obIi/vpWh5ll6Gd8q26z+
a/O41UzOaLTeNI365MWT4/cnXohVLRG7iVJbAbCxoQmEgsYMRc/pBAzWJtLfcB2G
jdTswYL6+MUdL8sB9pZ82D+BP/YAdHe69CyTu1lk9RT2pYtI/kkfjHubXBCYEJSG
+VGllBbYG6idQJpyrOYNRJyrDi9yvDJ2W+S0iQrlZrxzGBVGTB/y65S8C+2WTBcE
lf1Qb5GDsQrZWgD+jtWTywOYHtCBwyCKSAXxSARMbNPeak9WPlcW/Jmu+fUcMe2x
dg1KdHOa34shrKDaOVzW
=od6m
-----END PGP SIGNATURE-----'''

        self.revision = {
            'id': 'bc0195aad0daa2ad5b0d76cce22b167bc3435590',
            'directory': '85a74718d377195e1efd0843ba4f3260bad4fe07',
            'parents': ['01e2d0627a9a6edb24c37db45db5ecb31e9de808'],
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
            },
            'date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                      tzinfo=linus_tz),
            'committer': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
            },
            'committer_date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                                tzinfo=linus_tz),
            'message': b'Linux 4.2-rc2\n',
        }

        self.synthetic_revision = {
            'id': b'\xb2\xa7\xe1&\x04\x92\xe3D\xfa\xb3\xcb\xf9\x1b\xc1<\x91'
                  b'\xe0T&\xfd',
            'author': {
                'name': b'Software Heritage',
                'email': b'robot@softwareheritage.org',
            },
            'date': {
                'timestamp': 1437047495.0,
                'offset': 0,
                'negative_utc': False,
            },
            'type': 'tar',
            'committer': {
                'name': b'Software Heritage',
                'email': b'robot@softwareheritage.org',
            },
            'committer_date': 1437047495,
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

        # cat commit.txt | git hash-object -t commit --stdin
        self.revision_with_extra_headers = {
            'id': '010d34f384fa99d047cdd5e2f41e56e5c2feee45',
            'directory': '85a74718d377195e1efd0843ba4f3260bad4fe07',
            'parents': ['01e2d0627a9a6edb24c37db45db5ecb31e9de808'],
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
            },
            'date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                      tzinfo=linus_tz),
            'committer': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
            },
            'committer_date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                                tzinfo=linus_tz),
            'message': b'Linux 4.2-rc2\n',
            'metadata': {
                'extra_headers': [
                    ['svn-repo-uuid', '046f1af7-66c2-d61b-5410-ce57b7db7bff'],
                    ['svn-revision', 10],
                ]
            }
        }

        self.revision_with_gpgsig = {
            'id': '44cc742a8ca17b9c279be4cc195a93a6ef7a320e',
            'directory': 'b134f9b7dc434f593c0bab696345548b37de0558',
            'parents': ['689664ae944b4692724f13b709a4e4de28b54e57',
                        'c888305e1efbaa252d01b4e5e6b778f865a97514'],
            'author': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'metadata': {
                'extra_headers': [
                    ['gpgsig', gpgsig],
                ],
            },
            'message': b'''Merge branch 'master' of git://github.com/alexhenrie/git-po

* 'master' of git://github.com/alexhenrie/git-po:
  l10n: ca.po: update translation
'''
        }

        self.revision_no_message = {
            'id': '4cfc623c9238fa92c832beed000ce2d003fd8333',
            'directory': 'b134f9b7dc434f593c0bab696345548b37de0558',
            'parents': ['689664ae944b4692724f13b709a4e4de28b54e57',
                        'c888305e1efbaa252d01b4e5e6b778f865a97514'],
            'author': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'message': None,
        }

        self.revision_empty_message = {
            'id': '7442cd78bd3b4966921d6a7f7447417b7acb15eb',
            'directory': 'b134f9b7dc434f593c0bab696345548b37de0558',
            'parents': ['689664ae944b4692724f13b709a4e4de28b54e57',
                        'c888305e1efbaa252d01b4e5e6b778f865a97514'],
            'author': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': '1428538899',
                'offset': 480,
            },
            'message': b'',
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

    @istest
    def revision_identifier_with_extra_headers(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_with_extra_headers),
            identifiers.identifier_to_str(
                self.revision_with_extra_headers['id']),
        )

    @istest
    def revision_identifier_with_gpgsig(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_with_gpgsig),
            identifiers.identifier_to_str(
                self.revision_with_gpgsig['id']),
        )

    @istest
    def revision_identifier_no_message(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_no_message),
            identifiers.identifier_to_str(
                self.revision_no_message['id']),
        )

    @istest
    def revision_identifier_empty_message(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_empty_message),
            identifiers.identifier_to_str(
                self.revision_empty_message['id']),
        )


class ReleaseIdentifier(unittest.TestCase):
    def setUp(self):
        linus_tz = datetime.timezone(datetime.timedelta(minutes=-420))

        self.release = {
            'id': '2b10839e32c4c476e9d94492756bb1a3e1ec4aa8',
            'target': b't\x1b"R\xa5\xe1Ml`\xa9\x13\xc7z`\x99\xab\xe7:\x85J',
            'target_type': 'revision',
            'name': b'v2.6.14',
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@g5.osdl.org',
            },
            'date': datetime.datetime(2005, 10, 27, 17, 2, 33,
                                      tzinfo=linus_tz),
            'message': b'''\
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
            'target': '9ee1c939d1cb936b1f98e8d81aeffab57bae46ab',
            'target_type': 'revision',
            'name': b'v2.6.12',
            'message': b'''\
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

        self.release_no_message = {
            'id': 'b6f4f446715f7d9543ef54e41b62982f0db40045',
            'target': '9ee1c939d1cb936b1f98e8d81aeffab57bae46ab',
            'target_type': 'revision',
            'name': b'v2.6.12',
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@g5.osdl.org',
            },
            'date': datetime.datetime(2005, 10, 27, 17, 2, 33,
                                      tzinfo=linus_tz),
            'message': None,
        }

        self.release_empty_message = {
            'id': '71a0aea72444d396575dc25ac37fec87ee3c6492',
            'target': '9ee1c939d1cb936b1f98e8d81aeffab57bae46ab',
            'target_type': 'revision',
            'name': b'v2.6.12',
            'author': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@g5.osdl.org',
            },
            'date': datetime.datetime(2005, 10, 27, 17, 2, 33,
                                      tzinfo=linus_tz),
            'message': b'',
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

    @istest
    def release_identifier_no_message(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_no_message),
            identifiers.identifier_to_str(self.release_no_message['id'])
        )

    @istest
    def release_identifier_empty_message(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_empty_message),
            identifiers.identifier_to_str(self.release_empty_message['id'])
        )
