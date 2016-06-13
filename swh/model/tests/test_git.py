# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import shutil
import subprocess
import tempfile
import unittest

from nose.plugins.attrib import attr
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


@attr('fs')
class GitHashWalkArborescenceTree:
    """Root class to ease walk and git hash testing without side-effecty
    problems.

    """
    def setUp(self):
        super().setUp()
        self.tmp_root_path = tempfile.mkdtemp().encode('utf-8')
        self.maxDiff = None

        start_path = os.path.dirname(__file__).encode('utf-8')
        sample_folder = os.path.join(start_path,
                                     b'../../../..',
                                     b'swh-storage-testdata',
                                     b'dir-folders',
                                     b'sample-folder.tgz')

        self.root_path = os.path.join(self.tmp_root_path, b'sample-folder')

        # uncompress the sample folder
        subprocess.check_output(
            ['tar', 'xvf', sample_folder, '-C', self.tmp_root_path])

    def tearDown(self):
        if os.path.exists(self.tmp_root_path):
            shutil.rmtree(self.tmp_root_path)


class GitHashFromScratch(GitHashWalkArborescenceTree, unittest.TestCase):
    """Test the main `walk_and_compute_sha1_from_directory` algorithm that
    scans and compute the disk for checksums.

    """
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
                'length': 72,
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

    @istest
    def walk_and_compute_sha1_from_directory_without_root_tree(self):
        # compute the full checksums
        expected_hashes = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # except for the key on that round
        actual_hashes = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path,
            with_root_tree=False)

        # then, removing the root tree hash from the first round
        del expected_hashes[git.ROOT_TREE_KEY]

        # should give us the same checksums as the second round
        self.assertEquals(actual_hashes, expected_hashes)


class WithSampleFolderChecksums:
    def setUp(self):
        super().setUp()

        self.rootkey = b'/tmp/tmp7w3oi_j8'
        self.objects = {
            b'/tmp/tmp7w3oi_j8': {
                'children': {b'/tmp/tmp7w3oi_j8/sample-folder'},
                'checksums': {
                    'type': git.GitType.TREE,
                    'name': b'tmp7w3oi_j8',
                    'sha1_git': b'\xa7A\xfcM\x96\x8c{\x8e<\x94\xff\x86\xe7\x04\x80\xc5\xc7\xe5r\xa9',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8',
                    'perms': git.GitPerm.TREE
                },
            },
            b'/tmp/tmp7w3oi_j8/sample-folder': {
                'children': {
                    b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder',
                    b'/tmp/tmp7w3oi_j8/sample-folder/link-to-binary',
                    b'/tmp/tmp7w3oi_j8/sample-folder/link-to-another-quote',
                    b'/tmp/tmp7w3oi_j8/sample-folder/link-to-foo',
                    b'/tmp/tmp7w3oi_j8/sample-folder/some-binary',
                    b'/tmp/tmp7w3oi_j8/sample-folder/bar',
                    b'/tmp/tmp7w3oi_j8/sample-folder/foo',
                },
                'checksums': {
                    'type': git.GitType.TREE,
                    'name': b'sample-folder',
                    'sha1_git': b'\xe8\xb0\xf1Fj\xf8`\x8c\x8a?\xb9\x87\x9d\xb1r\xb8\x87\xe8\x07Y',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder',
                    'perms': git.GitPerm.TREE}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder': {
                'children': {},
                'checksums': {
                    'type': git.GitType.TREE,
                    'name': b'empty-folder',
                    'sha1_git': b'K\x82]\xc6B\xcbn\xb9\xa0`\xe5K\xf8\xd6\x92\x88\xfb\xeeI\x04',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder',
                    'perms': git.GitPerm.TREE
                }
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/link-to-binary': {
                'checksums': {
                    'name': b'link-to-binary',
                    'sha1': b'\xd0$\x87\x14\x94\x8b:H\xa2T8#*o\x99\xf01\x8fY\xf1',  # noqa
                    'data': b'some-binary',
                    'sha1_git': b'\xe8kE\xe58\xd9\xb6\x88\x8c\x96\x9c\x89\xfb\xd2*\x85\xaa\x0e\x03f',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-binary',
                    'sha256': b'\x14\x12n\x97\xd8?}&\x1cZh\x89\xce\xe76\x19w\x0f\xf0\x9e@\xc5I\x86\x85\xab\xa7E\xbe\x88.\xff',  # noqa
                    'perms': git.GitPerm.LINK,
                    'type': git.GitType.BLOB,
                    'length': 11
                }
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/link-to-another-quote': {
                'checksums': {
                    'name': b'link-to-another-quote',
                    'sha1': b'\xcb\xee\xd1^yY\x9c\x90\xdes\x83\xf4 \xfe\xd7\xac\xb4\x8e\xa1q',  # noqa
                    'data': b'bar/barfoo/another-quote.org',
                    'sha1_git': b'}\\\x08\x11\x1e!\xc8\xa9\xf7\x15@\x93\x99\x98U\x16\x837_\xad',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-another-quote',  # noqa
                    'sha256': b'\xe6\xe1}\x07\x93\xaau\n\x04@\xeb\x9a\xd5\xb8\x0b%\x80vc~\xf0\xfbh\xf3\xac.Y\xe4\xb9\xac;\xa6',  # noqa
                    'perms': git.GitPerm.LINK,
                    'type': git.GitType.BLOB,
                    'length': 28
                }
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/link-to-foo': {
                'checksums': {
                    'name': b'link-to-foo',
                    'sha1': b'\x0b\xee\xc7\xb5\xea?\x0f\xdb\xc9]\r\xd4\x7f<[\xc2u\xda\x8a3',  # noqa
                    'data': b'foo',
                    'sha1_git': b'\x19\x10(\x15f=#\xf8\xb7ZG\xe7\xa0\x19e\xdc\xdc\x96F\x8c',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-foo',
                    'sha256': b',&\xb4kh\xff\xc6\x8f\xf9\x9bE<\x1d0A4\x13B-pd\x83\xbf\xa0\xf9\x8a^\x88bf\xe7\xae',  # noqa
                    'perms': git.GitPerm.LINK,
                    'type': git.GitType.BLOB,
                    'length': 3
                }
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/some-binary': {
                'checksums': {
                    'name': b'some-binary',
                    'sha1': b'\x0b\xbc\x12\xd7\xf4\xa2\xa1[\x14=\xa8F\x17\xd9\\\xb2#\xc9\xb2<',  # noqa
                    'sha1_git': b'hv\x95y\xc3\xea\xad\xbeUSy\xb9\xc3S\x8ef(\xba\xe1\xeb',  # noqa
                    'path': b'/tmp/tmp7w3oi_j8/sample-folder/some-binary',
                    'sha256': b'\xba\xc6P\xd3Jv8\xbb\n\xebSBdm$\xe3\xb9\xadkD\xc9\xb3\x83b\x1f\xaaH+\x99\n6}',  # noqa
                    'perms': git.GitPerm.EXEC,
                    'type': git.GitType.BLOB,
                    'length': 5}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/bar': {
                'children': {b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo'},
                'checksums': {'type': git.GitType.TREE,
                              'name': b'bar',
                              'sha1_git': b'<\x1fW\x83\x94\xf4b?t\xa0\xba\x7f\xe7ar\x9fY\xfcn\xc4',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar',
                              'perms': git.GitPerm.TREE},
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo': {
                'children': {b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo/another-quote.org'},  # noqa
                'checksums': {'type': git.GitType.TREE,
                              'name': b'barfoo',
                              'sha1_git': b'\xc3\x02\x0fk\xf15\xa3\x8cm\xf3\xaf\xeb_\xb3\x822\xc5\xe0p\x87',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo',  # noqa
                              'perms': git.GitPerm.TREE},
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo/another-quote.org': {
                'checksums': {'name': b'another-quote.org',
                              'sha1': b'\x90\xa6\x13\x8b\xa5\x99\x15&\x1e\x17\x99H8j\xa1\xcc*\xa9"\n',  # noqa
                              'sha1_git': b'\x136\x93\xb1%\xba\xd2\xb4\xac1\x855\xb8I\x01\xeb\xb1\xf6\xb68',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo/another-quote.org',  # noqa
                              'sha256': b'=\xb5\xae\x16\x80U\xbc\xd9:M\x08(]\xc9\x9f\xfe\xe2\x883\x03\xb2?\xac^\xab\x85\x02s\xa8\xeaUF',  # noqa
                              'perms': git.GitPerm.BLOB,
                              'type': git.GitType.BLOB,
                              'length': 72}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/foo': {
                'children': {
                    b'/tmp/tmp7w3oi_j8/sample-folder/foo/barfoo',
                    b'/tmp/tmp7w3oi_j8/sample-folder/foo/rel-link-to-barfoo',
                    b'/tmp/tmp7w3oi_j8/sample-folder/foo/quotes.md',
                },
                'checksums': {'type': git.GitType.TREE,
                              'name': b'foo',
                              'sha1_git': b'+A\xc4\x0f\r\x1f\xbf\xfc\xba\x12I}\xb7\x1f\xba\x83\xfc\xca\x96\xe5',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo',
                              'perms': git.GitPerm.TREE}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/foo/barfoo': {
                'checksums': {'name': b'barfoo',
                              'sha1': b'\x90W\xeem\x01bPn\x01\xc4\xd9\xd5E\x9az\xdd\x1f\xed\xac7',  # noqa
                              'data': b'bar/barfoo',
                              'sha1_git': b'\x81\x85\xdf\xb2\xc0\xc2\xc5\x97\xd1ou\xa8\xa0\xc3vhV|=~',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/barfoo',  # noqa
                              'sha256': b')\xad?W%2\x1b\x94\x032\xc7\x8e@6\x01\xaf\xffa\xda\xea\x85\xe9\xc8\x0bJpc\xb6\x88~\xadh',  # noqa
                              'perms': git.GitPerm.LINK,
                              'type': git.GitType.BLOB,
                              'length': 10}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/foo/rel-link-to-barfoo': {
                'checksums': {'name': b'rel-link-to-barfoo',
                              'sha1': b'\xdcQ"\x1d0\x8f:\xeb\'T\xdbH9\x1b\x85h|(i\xf4',  # noqa
                              'data': b'../bar/barfoo',
                              'sha1_git': b'\xac\xac2m\xddc\xb0\xbcp\x84\x06Y\xd4\xacCa\x94\x84\xe6\x9f',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/rel-link-to-barfoo',  # noqa
                              'sha256': b'\x80\x07\xd2\r\xb2\xaf@C_B\xdd\xefK\x8a\xd7k\x80\xad\xbe\xc2k$\x9f\xdf\x04s5?\x8d\x99\xdf\x08',  # noqa
                              'perms': git.GitPerm.LINK,
                              'type': git.GitType.BLOB,
                              'length': 13}
            },
            b'/tmp/tmp7w3oi_j8/sample-folder/foo/quotes.md': {
                'checksums': {'name': b'quotes.md',
                              'sha1': b'\x1b\xf0\xbbr\x1a\xc9,\x18\xa1\x9b\x13\xc0\xeb=t\x1c\xbf\xad\xeb\xfc',  # noqa
                              'sha1_git': b'|LW\xba\x9f\xf4\x96\xad\x17\x9b\x8fe\xb1\xd2\x86\xed\xbd\xa3L\x9a',  # noqa
                              'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/quotes.md',  # noqa
                              'sha256': b'\xca\xca\x94*\xed\xa7\xb3\x08\x85\x9e\xb5o\x90\x9e\xc9m\x07\xa4\x99I\x16\x90\xc4S\xf7;\x98\x00\xa9;\x16Y',  # noqa
                              'perms': git.GitPerm.BLOB,
                              'type': git.GitType.BLOB,
                              'length': 66}
            },
        }


class TestObjectsPerType(WithSampleFolderChecksums, unittest.TestCase):
    @istest
    def objects_per_type_blob(self):
        # given
        expected_blobs = [
            {
                'name': b'another-quote.org',
                'sha1': b'\x90\xa6\x13\x8b\xa5\x99\x15&\x1e\x17\x99H8j\xa1\xcc*\xa9"\n',  # noqa
                'sha1_git': b'\x136\x93\xb1%\xba\xd2\xb4\xac1\x855\xb8I\x01\xeb\xb1\xf6\xb68',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo/another-quote.org',  # noqa
                'sha256': b'=\xb5\xae\x16\x80U\xbc\xd9:M\x08(]\xc9\x9f\xfe\xe2\x883\x03\xb2?\xac^\xab\x85\x02s\xa8\xeaUF',  # noqa
                'perms': git.GitPerm.BLOB,
                'type': git.GitType.BLOB,
                'length': 72
            },
            {
                'name': b'link-to-binary',
                'sha1': b'\xd0$\x87\x14\x94\x8b:H\xa2T8#*o\x99\xf01\x8fY\xf1',
                'data': b'some-binary',
                'sha1_git': b'\xe8kE\xe58\xd9\xb6\x88\x8c\x96\x9c\x89\xfb\xd2*\x85\xaa\x0e\x03f',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-binary',
                'sha256': b'\x14\x12n\x97\xd8?}&\x1cZh\x89\xce\xe76\x19w\x0f\xf0\x9e@\xc5I\x86\x85\xab\xa7E\xbe\x88.\xff',  # noqa
                'perms': git.GitPerm.LINK,
                'type': git.GitType.BLOB,
                'length': 11
            },
            {
                'name': b'link-to-another-quote',
                'sha1': b'\xcb\xee\xd1^yY\x9c\x90\xdes\x83\xf4 \xfe\xd7\xac\xb4\x8e\xa1q',  # noqa
                'data': b'bar/barfoo/another-quote.org',
                'sha1_git': b'}\\\x08\x11\x1e!\xc8\xa9\xf7\x15@\x93\x99\x98U\x16\x837_\xad',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-another-quote',  # noqa
                'sha256': b'\xe6\xe1}\x07\x93\xaau\n\x04@\xeb\x9a\xd5\xb8\x0b%\x80vc~\xf0\xfbh\xf3\xac.Y\xe4\xb9\xac;\xa6',  # noqa
                'perms': git.GitPerm.LINK,
                'type': git.GitType.BLOB,
                'length': 28
            },
            {
                'name': b'link-to-foo',
                'sha1': b'\x0b\xee\xc7\xb5\xea?\x0f\xdb\xc9]\r\xd4\x7f<[\xc2u\xda\x8a3',  # noqa
                'data': b'foo',
                'sha1_git': b'\x19\x10(\x15f=#\xf8\xb7ZG\xe7\xa0\x19e\xdc\xdc\x96F\x8c',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/link-to-foo',
                'sha256': b',&\xb4kh\xff\xc6\x8f\xf9\x9bE<\x1d0A4\x13B-pd\x83\xbf\xa0\xf9\x8a^\x88bf\xe7\xae',  # noqa
                'perms': git.GitPerm.LINK,
                'type': git.GitType.BLOB,
                'length': 3
            },
            {
                'name': b'some-binary',
                'sha1': b'\x0b\xbc\x12\xd7\xf4\xa2\xa1[\x14=\xa8F\x17\xd9\\\xb2#\xc9\xb2<',  # noqa
                'sha1_git': b'hv\x95y\xc3\xea\xad\xbeUSy\xb9\xc3S\x8ef(\xba\xe1\xeb',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/some-binary',
                'sha256': b'\xba\xc6P\xd3Jv8\xbb\n\xebSBdm$\xe3\xb9\xadkD\xc9\xb3\x83b\x1f\xaaH+\x99\n6}',  # noqa
                'perms': git.GitPerm.EXEC,
                'type': git.GitType.BLOB,
                'length': 5
            },
            {
                'name': b'barfoo',
                'sha1': b'\x90W\xeem\x01bPn\x01\xc4\xd9\xd5E\x9az\xdd\x1f\xed\xac7',  # noqa
                'data': b'bar/barfoo',
                'sha1_git': b'\x81\x85\xdf\xb2\xc0\xc2\xc5\x97\xd1ou\xa8\xa0\xc3vhV|=~',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/barfoo',
                'sha256': b')\xad?W%2\x1b\x94\x032\xc7\x8e@6\x01\xaf\xffa\xda\xea\x85\xe9\xc8\x0bJpc\xb6\x88~\xadh',  # noqa
                'perms': git.GitPerm.LINK,
                'type': git.GitType.BLOB,
                'length': 10
            },
            {
                'name': b'rel-link-to-barfoo',
                'sha1': b'\xdcQ"\x1d0\x8f:\xeb\'T\xdbH9\x1b\x85h|(i\xf4',
                'data': b'../bar/barfoo',
                'sha1_git': b'\xac\xac2m\xddc\xb0\xbcp\x84\x06Y\xd4\xacCa\x94\x84\xe6\x9f',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/rel-link-to-barfoo',  # noqa
                'sha256': b'\x80\x07\xd2\r\xb2\xaf@C_B\xdd\xefK\x8a\xd7k\x80\xad\xbe\xc2k$\x9f\xdf\x04s5?\x8d\x99\xdf\x08',  # noqa
                'perms': git.GitPerm.LINK,
                'type': git.GitType.BLOB,
                'length': 13
            },
            {
                'name': b'quotes.md',
                'sha1': b'\x1b\xf0\xbbr\x1a\xc9,\x18\xa1\x9b\x13\xc0\xeb=t\x1c\xbf\xad\xeb\xfc',  # noqa
                'sha1_git': b'|LW\xba\x9f\xf4\x96\xad\x17\x9b\x8fe\xb1\xd2\x86\xed\xbd\xa3L\x9a',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo/quotes.md',
                'sha256': b'\xca\xca\x94*\xed\xa7\xb3\x08\x85\x9e\xb5o\x90\x9e\xc9m\x07\xa4\x99I\x16\x90\xc4S\xf7;\x98\x00\xa9;\x16Y',  # noqa
                'perms': git.GitPerm.BLOB,
                'type': git.GitType.BLOB,
                'length': 66
            },
        ]

        expected_sha1_blobs = set(
            ((c['sha1_git'], git.GitType.BLOB) for c in expected_blobs))

        # when
        actual_sha1_blobs = set(
            ((c['sha1_git'], c['type'])
             for c in git.objects_per_type(git.GitType.BLOB, self.objects)))

        # then
        self.assertEqual(actual_sha1_blobs, expected_sha1_blobs)

    @istest
    def objects_per_type_tree(self):
        def __children_hashes(path, objects=self.objects):
            return set((c['sha1_git']
                       for c in git.children_hashes(
                           objects[path]['children'], objects)))

        expected_trees = [
            {
                'type': git.GitType.TREE,
                'name': b'tmp7w3oi_j8',
                'sha1_git': b'\xa7A\xfcM\x96\x8c{\x8e<\x94\xff\x86\xe7\x04\x80\xc5\xc7\xe5r\xa9',  # noqa
                'path': b'/tmp/tmp7w3oi_j8',
                'perms': git.GitPerm.TREE,
                # we only add children's sha1_git here, in reality,
                # it's a full dict of hashes.
                'children': __children_hashes(b'/tmp/tmp7w3oi_j8')
            },
            {
                'type': git.GitType.TREE,
                'name': b'sample-folder',
                'sha1_git': b'\xe8\xb0\xf1Fj\xf8`\x8c\x8a?\xb9\x87\x9d\xb1r\xb8\x87\xe8\x07Y',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder',
                'perms': git.GitPerm.TREE,
                'children': __children_hashes(
                    b'/tmp/tmp7w3oi_j8/sample-folder')
            },
            {
                'type': git.GitType.TREE,
                'name': b'empty-folder',
                'sha1_git': b'K\x82]\xc6B\xcbn\xb9\xa0`\xe5K\xf8\xd6\x92\x88\xfb\xeeI\x04',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder',
                'perms': git.GitPerm.TREE,
                'children': __children_hashes(
                    b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder')
            },
            {
                'type': git.GitType.TREE,
                'name': b'bar',
                'sha1_git': b'<\x1fW\x83\x94\xf4b?t\xa0\xba\x7f\xe7ar\x9fY\xfcn\xc4',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar',
                'perms': git.GitPerm.TREE,
                'children': __children_hashes(
                    b'/tmp/tmp7w3oi_j8/sample-folder/bar')
            },
            {
                'type': git.GitType.TREE,
                'name': b'barfoo',
                'sha1_git': b'\xc3\x02\x0fk\xf15\xa3\x8cm\xf3\xaf\xeb_\xb3\x822\xc5\xe0p\x87',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo',
                'perms': git.GitPerm.TREE,
                'children': __children_hashes(
                    b'/tmp/tmp7w3oi_j8/sample-folder/bar/barfoo'),
            },
            {
                'type': git.GitType.TREE,
                'name': b'foo',
                'sha1_git': b'+A\xc4\x0f\r\x1f\xbf\xfc\xba\x12I}\xb7\x1f\xba\x83\xfc\xca\x96\xe5',  # noqa
                'path': b'/tmp/tmp7w3oi_j8/sample-folder/foo',
                'perms': git.GitPerm.TREE,
                'children': __children_hashes(
                    b'/tmp/tmp7w3oi_j8/sample-folder/foo')
            },
        ]
        expected_sha1_trees = list(
            ((c['sha1_git'], git.GitType.TREE, c['children'])
             for c in expected_trees))

        # when
        actual_sha1_trees = list(
            ((c['sha1_git'], c['type'], __children_hashes(c['path']))
             for c in git.objects_per_type(git.GitType.TREE, self.objects)))

        self.assertEquals(len(actual_sha1_trees), len(expected_sha1_trees))
        for e in actual_sha1_trees:
            self.assertTrue(e in expected_sha1_trees)


class TestComputeHashesFromDirectory(WithSampleFolderChecksums,
                                     GitHashWalkArborescenceTree,
                                     unittest.TestCase):

    def __adapt_object_to_rootpath(self, rootpath):
        def _replace_slash(s,
                           rootpath=self.rootkey,
                           newrootpath=rootpath):
            return s.replace(rootpath, newrootpath)

        def _update_children(children):
            return set((_replace_slash(c) for c in children))

        # given
        expected_objects = {}
        for path, v in self.objects.items():
            p = _replace_slash(path)
            v['checksums']['path'] = _replace_slash(v['checksums']['path'])
            v['checksums']['name'] = os.path.basename(v['checksums']['path'])
            if 'children' in v:
                v['children'] = _update_children(v['children'])
            expected_objects[p] = v

        return expected_objects

    @istest
    def compute_hashes_from_directory_default(self):
        # given
        expected_objects = self.__adapt_object_to_rootpath(self.tmp_root_path)

        # when
        actual_hashes = git.compute_hashes_from_directory(self.tmp_root_path)

        # then
        self.assertEquals(actual_hashes, expected_objects)

    @istest
    def compute_hashes_from_directory_no_empty_folder(self):
        # given
        def _replace_slash(s,
                           rootpath=self.rootkey,
                           newrootpath=self.tmp_root_path):
            return s.replace(rootpath, newrootpath)

        expected_objects = self.__adapt_object_to_rootpath(self.tmp_root_path)

        # when
        actual_hashes = git.compute_hashes_from_directory(
            self.tmp_root_path,
            remove_empty_folder=True)

        # then

        # One folder less, so plenty of hashes are different now
        self.assertNotEquals(actual_hashes, expected_objects)
        keys = set(actual_hashes.keys())

        assert (b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder'
                in self.objects.keys())
        new_empty_folder_path = _replace_slash(
            b'/tmp/tmp7w3oi_j8/sample-folder/empty-folder')
        self.assertNotIn(new_empty_folder_path, keys)

        self.assertEqual(len(keys), len(expected_objects.keys()) - 1)

    @istest
    def compute_hashes_from_directory_ignore_some_folder(self):
        # given
        def _replace_slash(s,
                           rootpath=self.rootkey,
                           newrootpath=self.tmp_root_path):
            return s.replace(rootpath, newrootpath)

        ignore_path = b'/tmp/tmp7w3oi_j8/sample-folder'

        # when
        actual_hashes = git.compute_hashes_from_directory(
            self.tmp_root_path,
            dir_ok_fn=lambda dirpath: b'sample-folder' not in dirpath)

        # then

        # One entry less, so plenty of hashes are different now
        # self.assertNotEquals(actual_hashes, expected_objects)
        keys = set(actual_hashes.keys())

        assert ignore_path in self.objects.keys()

        new_ignore_path = _replace_slash(ignore_path)
        self.assertNotIn(new_ignore_path, keys)

        # top level directory contains the folder to ignore
        self.assertEqual(len(keys), 1)
