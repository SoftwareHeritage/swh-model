# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import unittest

from nose.tools import istest

from swh.model import git


class GitHashlib(unittest.TestCase):
    def setUp(self):
        self.tree_data = b''.join([b'40000 barfoo\0',
                                   bytes.fromhex('c3020f6bf135a38c6df'
                                                 '3afeb5fb38232c5e07087'),
                                   b'100644 blah\0',
                                   bytes.fromhex('63756ef0df5e4f10b6efa'
                                                 '33cfe5c758749615f20'),
                                   b'100644 hello\0',
                                   bytes.fromhex('907b308167f0880fb2a'
                                                 '5c0e1614bb0c7620f9dc3')])

        self.commit_data = """tree 1c61f7259dcb770f46b194d941df4f08ff0a3970
author Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200
committer Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200

initial
""".encode('utf-8')  # NOQA
        self.tag_data = """object 24d012aaec0bc5a4d2f62c56399053d6cc72a241
type commit
tag 0.0.1
tagger Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444225145 +0200

blah
""".encode('utf-8')  # NOQA

        self.checksums = {
            'tree_sha1_git': bytes.fromhex('ac212302c45eada382b27bfda795db'
                                           '121dacdb1c'),
            'commit_sha1_git': bytes.fromhex('e960570b2e6e2798fa4cfb9af2c399'
                                             'd629189653'),
            'tag_sha1_git': bytes.fromhex('bc2b99ba469987bcf1272c189ed534'
                                          'e9e959f120'),
        }

    @istest
    def compute_directory_git_sha1(self):
        # given
        dirpath = 'some-dir-path'
        hashes = {
            dirpath: [{'perms': git.GitPerm.TREE,
                       'type': git.GitType.TREE,
                       'name': b'barfoo',
                       'sha1_git': bytes.fromhex('c3020f6bf135a38c6df'
                                                 '3afeb5fb38232c5e07087')},
                      {'perms': git.GitPerm.BLOB,
                       'type': git.GitType.BLOB,
                       'name': b'hello',
                       'sha1_git': bytes.fromhex('907b308167f0880fb2a'
                                                 '5c0e1614bb0c7620f9dc3')},
                      {'perms': git.GitPerm.BLOB,
                       'type': git.GitType.BLOB,
                       'name': b'blah',
                       'sha1_git': bytes.fromhex('63756ef0df5e4f10b6efa'
                                                 '33cfe5c758749615f20')}]
        }

        # when
        checksum = git.compute_directory_git_sha1(dirpath, hashes)

        # then
        self.assertEqual(checksum, self.checksums['tree_sha1_git'])

    @istest
    def compute_revision_sha1_git(self):
        # given
        tree_hash = bytes.fromhex('1c61f7259dcb770f46b194d941df4f08ff0a3970')
        revision = {
            'author': {
                'name': b'Antoine R. Dumont (@ardumont)',
                'email': b'antoine.romain.dumont@gmail.com',
            },
            'date': {
                'timestamp': 1444054085,
                'offset': 120,
            },
            'committer': {
                'name': b'Antoine R. Dumont (@ardumont)',
                'email': b'antoine.romain.dumont@gmail.com',
            },
            'committer_date': {
                'timestamp': 1444054085,
                'offset': 120,
            },
            'message': b'initial\n',
            'type': 'tar',
            'directory': tree_hash,
            'parents': [],
        }

        # when
        checksum = git.compute_revision_sha1_git(revision)

        # then
        self.assertEqual(checksum, self.checksums['commit_sha1_git'])

    @istest
    def compute_release_sha1_git(self):
        # given
        revision_hash = bytes.fromhex('24d012aaec0bc5a4d2f62c56399053'
                                      'd6cc72a241')
        release = {
            'name': b'0.0.1',
            'author': {
                'name': b'Antoine R. Dumont (@ardumont)',
                'email': b'antoine.romain.dumont@gmail.com',
            },
            'date': {
                'timestamp': 1444225145,
                'offset': 120,
            },
            'message': b'blah\n',
            'target_type': 'revision',
            'target': revision_hash,
        }

        # when
        checksum = git.compute_release_sha1_git(release)

        # then
        self.assertEqual(checksum, self.checksums['tag_sha1_git'])
