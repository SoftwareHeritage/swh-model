# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import unittest

from nose.tools import istest

from swh.model import hashutil, identifiers


class Identifiers(unittest.TestCase):
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

        print(self.directory)

    @istest
    def content_identifier(self):
        self.assertEqual(identifiers.content_identifier(self.content),
                         self.content['sha1'])

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
