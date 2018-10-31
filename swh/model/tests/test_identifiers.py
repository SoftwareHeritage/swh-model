# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
import unittest

from swh.model import hashutil, identifiers
from swh.model.exceptions import ValidationError
from swh.model.identifiers import (CONTENT, DIRECTORY,
                                   PERSISTENT_IDENTIFIER_TYPES, RELEASE,
                                   REVISION, SNAPSHOT, PersistentId)


class UtilityFunctionsIdentifier(unittest.TestCase):
    def setUp(self):
        self.str_id = 'c2e41aae41ac17bd4a650770d6ee77f62e52235b'
        self.bytes_id = binascii.unhexlify(self.str_id)
        self.bad_type_id = object()

    def test_identifier_to_bytes(self):
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

    def test_identifier_to_str(self):
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
        self.dates = {
            b'1448210036': {
                'seconds': 1448210036,
                'microseconds': 0,
            },
            b'1448210036.002342': {
                'seconds': 1448210036,
                'microseconds': 2342,
            },
            b'1448210036.12': {
                'seconds': 1448210036,
                'microseconds': 120000,
            }
        }
        self.broken_dates = [
            1448210036.12,
        ]

        self.offsets = {
            0: b'+0000',
            -630: b'-1030',
            800: b'+1320',
        }

    def test_format_date(self):
        for date_repr, date in self.dates.items():
            self.assertEqual(identifiers.format_date(date), date_repr)

    def test_format_date_fail(self):
        for date in self.broken_dates:
            with self.assertRaises(ValueError):
                identifiers.format_date(date)

    def test_format_offset(self):
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

        self.content_id = hashutil.MultiHash.from_data(
            self.content['data']).digest()

    def test_content_identifier(self):
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

    def test_dir_identifier(self):
        self.assertEqual(
            identifiers.directory_identifier(self.directory),
            self.directory['id'])

    def test_dir_identifier_empty_directory(self):
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

        self.revision_none_metadata = {
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
            'metadata': None,
        }

        self.synthetic_revision = {
            'id': b'\xb2\xa7\xe1&\x04\x92\xe3D\xfa\xb3\xcb\xf9\x1b\xc1<\x91'
                  b'\xe0T&\xfd',
            'author': {
                'name': b'Software Heritage',
                'email': b'robot@softwareheritage.org',
            },
            'date': {
                'timestamp': {'seconds': 1437047495},
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
                'fullname': b'Linus Torvalds <torvalds@linux-foundation.org>',
            },
            'date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                      tzinfo=linus_tz),
            'committer': {
                'name': b'Linus Torvalds',
                'email': b'torvalds@linux-foundation.org',
                'fullname': b'Linus Torvalds <torvalds@linux-foundation.org>',
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
                'fullname': b'Jiang Xin <worldhello.net@gmail.com>',
            },
            'date': {
                'timestamp': 1428538899,
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': 1428538899,
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
                'fullname': b'Jiang Xin <worldhello.net@gmail.com>',
            },
            'date': {
                'timestamp': 1428538899,
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': 1428538899,
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
                'fullname': b'Jiang Xin <worldhello.net@gmail.com>',
            },
            'date': {
                'timestamp': 1428538899,
                'offset': 480,
            },
            'committer': {
                'name': b'Jiang Xin',
                'email': b'worldhello.net@gmail.com',
            },
            'committer_date': {
                'timestamp': 1428538899,
                'offset': 480,
            },
            'message': b'',
        }

        self.revision_only_fullname = {
            'id': '010d34f384fa99d047cdd5e2f41e56e5c2feee45',
            'directory': '85a74718d377195e1efd0843ba4f3260bad4fe07',
            'parents': ['01e2d0627a9a6edb24c37db45db5ecb31e9de808'],
            'author': {
                'fullname': b'Linus Torvalds <torvalds@linux-foundation.org>',
            },
            'date': datetime.datetime(2015, 7, 12, 15, 10, 30,
                                      tzinfo=linus_tz),
            'committer': {
                'fullname': b'Linus Torvalds <torvalds@linux-foundation.org>',
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

    def test_revision_identifier(self):
        self.assertEqual(
            identifiers.revision_identifier(self.revision),
            identifiers.identifier_to_str(self.revision['id']),
        )

    def test_revision_identifier_none_metadata(self):
        self.assertEqual(
            identifiers.revision_identifier(self.revision_none_metadata),
            identifiers.identifier_to_str(self.revision_none_metadata['id']),
        )

    def test_revision_identifier_synthetic(self):
        self.assertEqual(
            identifiers.revision_identifier(self.synthetic_revision),
            identifiers.identifier_to_str(self.synthetic_revision['id']),
        )

    def test_revision_identifier_with_extra_headers(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_with_extra_headers),
            identifiers.identifier_to_str(
                self.revision_with_extra_headers['id']),
        )

    def test_revision_identifier_with_gpgsig(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_with_gpgsig),
            identifiers.identifier_to_str(
                self.revision_with_gpgsig['id']),
        )

    def test_revision_identifier_no_message(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_no_message),
            identifiers.identifier_to_str(
                self.revision_no_message['id']),
        )

    def test_revision_identifier_empty_message(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_empty_message),
            identifiers.identifier_to_str(
                self.revision_empty_message['id']),
        )

    def test_revision_identifier_only_fullname(self):
        self.assertEqual(
            identifiers.revision_identifier(
                self.revision_only_fullname),
            identifiers.identifier_to_str(
                self.revision_only_fullname['id']),
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

        self.release_negative_utc = {
            'id': '97c8d2573a001f88e72d75f596cf86b12b82fd01',
            'name': b'20081029',
            'target': '54e9abca4c77421e2921f5f156c9fe4a9f7441c7',
            'target_type': 'revision',
            'date': {
                'timestamp': {'seconds': 1225281976},
                'offset': 0,
                'negative_utc': True,
            },
            'author': {
                'name': b'Otavio Salvador',
                'email': b'otavio@debian.org',
                'id': 17640,
            },
            'synthetic': False,
            'message': b'tagging version 20081029\n\nr56558\n',
        }

        self.release_newline_in_author = {
            'author': {
                'email': b'esycat@gmail.com',
                'fullname': b'Eugene Janusov\n<esycat@gmail.com>',
                'name': b'Eugene Janusov\n',
            },
            'date': {
                'negative_utc': None,
                'offset': 600,
                'timestamp': {
                    'microseconds': 0,
                    'seconds': 1377480558,
                },
            },
            'id': b'\\\x98\xf5Y\xd04\x16-\xe2->\xbe\xb9T3\xe6\xf8\x88R1',
            'message': b'Release of v0.3.2.',
            'name': b'0.3.2',
            'synthetic': False,
            'target': (b'\xc0j\xa3\xd9;x\xa2\x86\\I5\x17'
                       b'\x000\xf8\xc2\xd79o\xd3'),
            'target_type': 'revision',
        }

    def test_release_identifier(self):
        self.assertEqual(
            identifiers.release_identifier(self.release),
            identifiers.identifier_to_str(self.release['id'])
        )

    def test_release_identifier_no_author(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_no_author),
            identifiers.identifier_to_str(self.release_no_author['id'])
        )

    def test_release_identifier_no_message(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_no_message),
            identifiers.identifier_to_str(self.release_no_message['id'])
        )

    def test_release_identifier_empty_message(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_empty_message),
            identifiers.identifier_to_str(self.release_empty_message['id'])
        )

    def test_release_identifier_negative_utc(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_negative_utc),
            identifiers.identifier_to_str(self.release_negative_utc['id'])
        )

    def test_release_identifier_newline_in_author(self):
        self.assertEqual(
            identifiers.release_identifier(self.release_newline_in_author),
            identifiers.identifier_to_str(self.release_newline_in_author['id'])
        )


class SnapshotIdentifier(unittest.TestCase):
    def setUp(self):
        super().setUp()

        self.empty = {
            'id': '1a8893e6a86f444e8be8e7bda6cb34fb1735a00e',
            'branches': {},
        }

        self.dangling_branch = {
            'id': 'c84502e821eb21ed84e9fd3ec40973abc8b32353',
            'branches': {
                b'HEAD': None,
            },
        }

        self.unresolved = {
            'id': '84b4548ea486e4b0a7933fa541ff1503a0afe1e0',
            'branches': {
                b'foo': {
                    'target': b'bar',
                    'target_type': 'alias',
                },
            },
        }

        self.all_types = {
            'id': '6e65b86363953b780d92b0a928f3e8fcdd10db36',
            'branches': {
                b'directory': {
                    'target': '1bd0e65f7d2ff14ae994de17a1e7fe65111dcad8',
                    'target_type': 'directory',
                },
                b'content': {
                    'target': 'fe95a46679d128ff167b7c55df5d02356c5a1ae1',
                    'target_type': 'content',
                },
                b'alias': {
                    'target': b'revision',
                    'target_type': 'alias',
                },
                b'revision': {
                    'target': 'aafb16d69fd30ff58afdd69036a26047f3aebdc6',
                    'target_type': 'revision',
                },
                b'release': {
                    'target': '7045404f3d1c54e6473c71bbb716529fbad4be24',
                    'target_type': 'release',
                },
                b'snapshot': {
                    'target': '1a8893e6a86f444e8be8e7bda6cb34fb1735a00e',
                    'target_type': 'snapshot',
                },
                b'dangling': None,
            }
        }

    def test_empty_snapshot(self):
        self.assertEqual(
            identifiers.snapshot_identifier(self.empty),
            identifiers.identifier_to_str(self.empty['id']),
        )

    def test_dangling_branch(self):
        self.assertEqual(
            identifiers.snapshot_identifier(self.dangling_branch),
            identifiers.identifier_to_str(self.dangling_branch['id']),
        )

    def test_unresolved(self):
        with self.assertRaisesRegex(ValueError, "b'foo' -> b'bar'"):
            identifiers.snapshot_identifier(self.unresolved)

    def test_unresolved_force(self):
        self.assertEqual(
            identifiers.snapshot_identifier(
                self.unresolved,
                ignore_unresolved=True,
            ),
            identifiers.identifier_to_str(self.unresolved['id']),
        )

    def test_all_types(self):
        self.assertEqual(
            identifiers.snapshot_identifier(self.all_types),
            identifiers.identifier_to_str(self.all_types['id']),
        )

    def test_persistent_identifier(self):
        _snapshot_id = hashutil.hash_to_bytes(
                    'c7c108084bc0bf3d81436bf980b46e98bd338453')
        _release_id = '22ece559cc7cc2364edc5e5593d63ae8bd229f9f'
        _revision_id = '309cf2674ee7a0749978cf8265ab91a60aea0f7d'
        _directory_id = 'd198bc9d7a6bcf6db04f476d29314f157507d505'
        _content_id = '94a9ed024d3859793618152ea559a168bbcbb5e2'
        _snapshot = {'id': _snapshot_id}
        _release = {'id': _release_id}
        _revision = {'id': _revision_id}
        _directory = {'id': _directory_id}
        _content = {'sha1_git': _content_id}

        for full_type, _hash, expected_persistent_id, version, _meta in [
                (SNAPSHOT, _snapshot_id,
                 'swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453',
                 None, {}),
                (RELEASE, _release_id,
                 'swh:2:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f',
                 2, {}),
                (REVISION, _revision_id,
                 'swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d',
                 None, {}),
                (DIRECTORY, _directory_id,
                 'swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505',
                 None, {}),
                (CONTENT, _content_id,
                 'swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2',
                 1, {}),
                (SNAPSHOT, _snapshot,
                 'swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453',
                 None, {}),
                (RELEASE, _release,
                 'swh:2:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f',
                 2, {}),
                (REVISION, _revision,
                 'swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d',
                 None, {}),
                (DIRECTORY, _directory,
                 'swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505',
                 None, {}),
                (CONTENT, _content,
                 'swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2',
                 1, {}),
                (CONTENT, _content,
                 'swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2;origin=1',
                 1, {'origin': '1'}),
        ]:
            if version:
                actual_value = identifiers.persistent_identifier(
                    full_type, _hash, version, metadata=_meta)
            else:
                actual_value = identifiers.persistent_identifier(
                    full_type, _hash, metadata=_meta)

            self.assertEqual(actual_value, expected_persistent_id)

    def test_persistent_identifier_wrong_input(self):
        _snapshot_id = 'notahash4bc0bf3d81436bf980b46e98bd338453'
        _snapshot = {'id': _snapshot_id}

        for _type, _hash, _error in [
                (SNAPSHOT, _snapshot_id, 'Unexpected characters'),
                (SNAPSHOT, _snapshot, 'Unexpected characters'),
                ('foo', '', 'Wrong input: Supported types are'),
        ]:
            with self.assertRaisesRegex(ValidationError, _error):
                identifiers.persistent_identifier(_type, _hash)

    def test_parse_persistent_identifier(self):
        for pid, _type, _version, _hash in [
                ('swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2',
                 CONTENT, 1, '94a9ed024d3859793618152ea559a168bbcbb5e2'),
                ('swh:1:dir:d198bc9d7a6bcf6db04f476d29314f157507d505',
                 DIRECTORY, 1, 'd198bc9d7a6bcf6db04f476d29314f157507d505'),
                ('swh:1:rev:309cf2674ee7a0749978cf8265ab91a60aea0f7d',
                 REVISION, 1, '309cf2674ee7a0749978cf8265ab91a60aea0f7d'),
                ('swh:1:rel:22ece559cc7cc2364edc5e5593d63ae8bd229f9f',
                 RELEASE, 1, '22ece559cc7cc2364edc5e5593d63ae8bd229f9f'),
                ('swh:1:snp:c7c108084bc0bf3d81436bf980b46e98bd338453',
                 SNAPSHOT, 1, 'c7c108084bc0bf3d81436bf980b46e98bd338453'),
        ]:
            expected_result = PersistentId(
                namespace='swh',
                scheme_version=_version,
                object_type=_type,
                object_id=_hash,
                metadata={}
            )
            actual_result = identifiers.parse_persistent_identifier(pid)
            self.assertEqual(actual_result, expected_result)

        for pid, _type, _version, _hash, _metadata in [
                ('swh:1:cnt:9c95815d9e9d91b8dae8e05d8bbc696fe19f796b;lines=1-18;origin=https://github.com/python/cpython', # noqa
                 CONTENT, 1, '9c95815d9e9d91b8dae8e05d8bbc696fe19f796b',
                 {
                     'lines': '1-18',
                     'origin': 'https://github.com/python/cpython'
                 }),
                 ('swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;origin=deb://Debian/packages/linuxdoc-tools', # noqa
                  DIRECTORY, 1, '0b6959356d30f1a4e9b7f6bca59b9a336464c03d',
                 {
                     'origin': 'deb://Debian/packages/linuxdoc-tools'
                 })
        ]:
            expected_result = PersistentId(
                namespace='swh',
                scheme_version=_version,
                object_type=_type,
                object_id=_hash,
                metadata=_metadata
            )
            actual_result = identifiers.parse_persistent_identifier(pid)
            self.assertEqual(actual_result, expected_result)

    def test_parse_persistent_identifier_parsing_error(self):
        for pid, _error in [
                ('swh:1:cnt',
                 'Wrong format: There should be 4 mandatory values'),
                ('swh:1:',
                 'Wrong format: There should be 4 mandatory values'),
                ('swh:',
                 'Wrong format: There should be 4 mandatory values'),
                ('swh:1:cnt:',
                 'Wrong format: Identifier should be present'),
                ('foo:1:cnt:abc8bc9d7a6bcf6db04f476d29314f157507d505',
                 'Wrong format: Supported namespace is \'swh\''),
                ('swh:2:dir:def8bc9d7a6bcf6db04f476d29314f157507d505',
                 'Wrong format: Supported version is 1'),
                ('swh:1:foo:fed8bc9d7a6bcf6db04f476d29314f157507d505',
                 'Wrong format: Supported types are %s' % (
                     ', '.join(PERSISTENT_IDENTIFIER_TYPES))),
                ('swh:1:dir:0b6959356d30f1a4e9b7f6bca59b9a336464c03d;invalid;'
                 'malformed',
                 'Contextual data is badly formatted, form key=val expected'),
                ('swh:1:snp:gh6959356d30f1a4e9b7f6bca59b9a336464c03d',
                 'Wrong format: Identifier should be a valid hash'),
                ('swh:1:snp:foo',
                 'Wrong format: Identifier should be a valid hash')
        ]:
            with self.assertRaisesRegex(
                    ValidationError, _error):
                identifiers.parse_persistent_identifier(pid)
