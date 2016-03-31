# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import shutil
import subprocess
import tempfile
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


class GitHashArborescenceTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.tmp_root_path = tempfile.mkdtemp().encode('utf-8')

        start_path = os.path.dirname(__file__).encode('utf-8')
        sample_folder_archive = os.path.join(start_path,
                                             b'../../../..',
                                             b'swh-storage-testdata',
                                             b'dir-folders',
                                             b'sample-folder.tgz')

        cls.root_path = os.path.join(cls.tmp_root_path, b'sample-folder')

        # uncompress the sample folder
        subprocess.check_output(
            ['tar', 'xvf', sample_folder_archive, '-C', cls.tmp_root_path])

    @classmethod
    def tearDown(cls):
        if os.path.exists(cls.tmp_root_path):
            shutil.rmtree(cls.tmp_root_path)

    @istest
    def walk_and_compute_sha1_from_directory(self):
        # make a temporary arborescence tree to hash without ignoring anything
        # same as previous behavior
        walk0 = git.walk_and_compute_sha1_from_directory(self.tmp_root_path)

        keys0 = list(walk0.keys())
        path_excluded = os.path.join(self.tmp_root_path,
                                     b'sample-folder',
                                     b'foo')
        self.assertTrue(path_excluded in keys0)  # it is not excluded here

        # make the same temporary arborescence tree to hash with ignoring one
        # folder foo
        walk1 = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path,
            dir_ok_fn=lambda dirpath: b'sample-folder/foo' not in dirpath)
        keys1 = list(walk1.keys())
        self.assertTrue(path_excluded not in keys1)

        # remove the keys that can't be the same (due to hash definition)
        # Those are the top level folders
        keys_diff = [self.tmp_root_path,
                     os.path.join(self.tmp_root_path, b'sample-folder'),
                     git.ROOT_TREE_KEY]
        for k in keys_diff:
            self.assertNotEquals(walk0[k], walk1[k])

        # The remaining keys (bottom path) should have exactly the same hashes
        # as before
        keys = set(keys1) - set(keys_diff)
        actual_walk1 = {}
        for k in keys:
            self.assertEquals(walk0[k], walk1[k])
            actual_walk1[k] = walk1[k]

        expected_checksums = {
            os.path.join(self.tmp_root_path, b'sample-folder/empty-folder'): [],                                            # noqa
            os.path.join(self.tmp_root_path, b'sample-folder/bar/barfoo'): [{                                               # noqa
                'type': git.GitType.BLOB,                                                                                   # noqa
                'sha256': b'=\xb5\xae\x16\x80U\xbc\xd9:M\x08(]\xc9\x9f\xfe\xe2\x883\x03\xb2?\xac^\xab\x85\x02s\xa8\xeaUF',  # noqa
                'name': b'another-quote.org',                                                                               # noqa
                'path': os.path.join(self.tmp_root_path, b'sample-folder/bar/barfoo/another-quote.org'),                    # noqa
                'perms': git.GitPerm.BLOB,                                                                                  # noqa
                'sha1': b'\x90\xa6\x13\x8b\xa5\x99\x15&\x1e\x17\x99H8j\xa1\xcc*\xa9"\n',                                    # noqa
                'sha1_git': b'\x136\x93\xb1%\xba\xd2\xb4\xac1\x855\xb8I\x01\xeb\xb1\xf6\xb68'}],                            # noqa
            os.path.join(self.tmp_root_path, b'sample-folder/bar'): [{                                                      # noqa
                'type': git.GitType.TREE,                                                                                   # noqa
                'perms': git.GitPerm.TREE,                                                                                  # noqa
                'name': b'barfoo',                                                                                          # noqa
                'path': os.path.join(self.tmp_root_path, b'sample-folder/bar/barfoo'),                                      # noqa
                'sha1_git': b'\xc3\x02\x0fk\xf15\xa3\x8cm\xf3\xaf\xeb_\xb3\x822\xc5\xe0p\x87'}]}                            # noqa

        self.assertEquals(actual_walk1, expected_checksums)
