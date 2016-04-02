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


class GitHashWalkArborescenceTree(unittest.TestCase):
    """Root class to ease walk and git hash testing without side-effecty problems.

    """
    def setUp(self):
        self.tmp_root_path = tempfile.mkdtemp().encode('utf-8')

        start_path = os.path.dirname(__file__).encode('utf-8')
        sample_folder_archive = os.path.join(start_path,
                                             b'../../../..',
                                             b'swh-storage-testdata',
                                             b'dir-folders',
                                             b'sample-folder.tgz')

        self.root_path = os.path.join(self.tmp_root_path, b'sample-folder')

        # uncompress the sample folder
        subprocess.check_output(
            ['tar', 'xvf', sample_folder_archive, '-C', self.tmp_root_path])

    def tearDown(self):
        if os.path.exists(self.tmp_root_path):
            shutil.rmtree(self.tmp_root_path)


class GitHashFromScratch(GitHashWalkArborescenceTree):
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


class GitHashUpdate(GitHashWalkArborescenceTree):
    """Test `walk and git hash only on modified fs` functions.

    """
    @istest
    def update_checksums_from_add_new_file(self):
        # make a temporary arborescence tree to hash without ignoring anything
        # update the disk in some way (add a new file)
        # update the actual git checksums from the deeper tree modified

        # when
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # update the existing file
        changed_path = os.path.join(self.tmp_root_path,
                                    b'sample-folder/bar/barfoo/new')
        with open(changed_path, 'wb') as f:
            f.write(b'new line')

        # walk1 (this will be our expectation)
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'A'}],
            objects)

        self.assertEquals(expected_dict, actual_dict)

    @istest
    def update_checksums_from_modify_existing_file(self):
        # make a temporary arborescence tree to hash without ignoring anything
        # update the disk in some way ()
        # update the actual git checksums where only the modification is needed

        # when
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # update existing file
        changed_path = os.path.join(
            self.tmp_root_path,
            b'sample-folder/bar/barfoo/another-quote.org')
        with open(changed_path, 'wb+') as f:
            f.write(b'I have a dream')

        # walk1 (this will be our expectation)
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'M'}],
            objects)

        self.assertEquals(expected_dict, actual_dict)

    @istest
    def update_checksums_no_change(self):
        # when
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # nothing changes on disk

        # then
        actual_dict = git.update_checksums_from([], expected_dict)

        self.assertEquals(actual_dict, expected_dict)

    @istest
    def update_checksums_delete_existing_file(self):
        # make a temporary arborescence tree to hash without ignoring anything
        # update the disk in some way (delete a file)
        # update the actual git checksums from the deeper tree modified

        # when
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # Remove folder
        changed_path = os.path.join(self.tmp_root_path,
                                    b'sample-folder/bar/barfoo')
        shutil.rmtree(changed_path)

        # Actually walking the fs will be the resulting expectation
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'D'}],
            objects)

        self.assertEquals(actual_dict, expected_dict)

    @istest
    def update_checksums_from_multiple_fs_modifications(self):
        # make a temporary arborescence tree to hash without ignoring anything
        # update the disk in some way (modify a file, add a new, delete one)
        # update the actual git checksums from the deeper tree modified

        # when
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # Actions on disk (imagine a checkout of some form)

        # 1. Create a new file
        changed_path = os.path.join(self.tmp_root_path,
                                    b'sample-folder/bar/barfoo/new')
        with open(changed_path, 'wb') as f:
            f.write(b'new line')

        # 2. update the existing file
        changed_path1 = os.path.join(
            self.tmp_root_path,
            b'sample-folder/bar/barfoo/another-quote.org')
        with open(changed_path1, 'wb') as f:
            f.write(b'new line')

        # 3. Remove some folder
        changed_path2 = os.path.join(self.tmp_root_path,
                                     b'sample-folder/foo')
        shutil.rmtree(changed_path2)

        # Actually walking the fs will be the resulting expectation
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'A'},
             {'path': changed_path1, 'action': 'M'},
             {'path': changed_path2, 'action': 'D'}],
            objects)

        self.assertEquals(expected_dict, actual_dict)

    @istest
    def update_checksums_from_common_ancestor(self):
        # when
        # Add some new arborescence below a folder destined to be removed
        # want to check that old keys does not remain
        future_folder_to_remove = os.path.join(self.tmp_root_path,
                                               b'sample-folder/bar/barfoo')

        # add .../barfoo/hello/world under (.../barfoo which will be destroyed)
        new_folder = os.path.join(future_folder_to_remove, b'hello')
        os.makedirs(new_folder, exist_ok=True)
        with open(os.path.join(future_folder_to_remove, b'world'), 'wb') as f:
            f.write(b"i'm sad 'cause i'm destined to be removed...")

        # now we scan the disk
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        assert objects[future_folder_to_remove]

        # Actions on disk (to simulate a checkout of some sort)

        # 1. Create a new file
        changed_path = os.path.join(self.tmp_root_path,
                                    b'sample-folder/bar/barfoo/new')
        with open(changed_path, 'wb') as f:
            f.write(b'new line')

        # 2. update the existing file
        changed_path1 = os.path.join(
            self.tmp_root_path,
            b'sample-folder/bar/barfoo/another-quote.org')
        with open(changed_path1, 'wb') as f:
            f.write(b'new line')

        # 3. Remove folder
        shutil.rmtree(future_folder_to_remove)

        # Actually walking the fs will be the resulting expectation
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'A'},
             {'path': changed_path1, 'action': 'M'},
             {'path': future_folder_to_remove, 'action': 'D'}],
            objects)

        self.assertEquals(expected_dict, actual_dict)

    @istest
    def update_checksums_detects_recomputation_from_all_is_needed(self):
        # when
        objects = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # Actions on disk (imagine a checkout of some form)

        # 1. Create a new file
        changed_path = os.path.join(self.tmp_root_path,
                                    b'new-file-at-root')
        with open(changed_path, 'wb') as f:
            f.write(b'new line')

        # 2. update the existing file
        changed_path1 = os.path.join(
            self.tmp_root_path,
            b'sample-folder/bar/barfoo/another-quote.org')
        with open(changed_path1, 'wb') as f:
            f.write(b'new line')

        # 3. Remove some folder
        changed_path2 = os.path.join(self.tmp_root_path,
                                     b'sample-folder/foo')

        # 3. Remove some folder
        changed_path2 = os.path.join(self.tmp_root_path,
                                     b'sample-folder/bar/barfoo')
        shutil.rmtree(changed_path2)

        # Actually walking the fs will be the resulting expectation
        expected_dict = git.walk_and_compute_sha1_from_directory(
            self.tmp_root_path)

        # then
        actual_dict = git.update_checksums_from(
            [{'path': changed_path, 'action': 'A'},
             {'path': changed_path1, 'action': 'M'},
             {'path': changed_path2, 'action': 'D'}],
            objects)

        self.assertEquals(expected_dict, actual_dict)

    @istest
    def commonpath(self):
        paths = ['r/0/h',
                 'r/1/d', 'r/1/i/a', 'r/1/i/b', 'r/1/i/c',
                 'r/2/e', 'r/2/f', 'r/2/g']
        self.assertEquals(git.commonpath(paths), 'r')

        paths = ['r/1/d', 'r/1/i/a', 'r/1/i/b', 'r/1/i/c']
        self.assertEquals(git.commonpath(paths), 'r/1')

        paths = ['/a/r/2/g', '/a/r/1/i/c', '/a/r/0/h']
        self.assertEquals(git.commonpath(paths), '/a/r')

        paths = [b'/a/r/2/g', b'/b/r/1/i/c', b'/c/r/0/h']
        self.assertEquals(git.commonpath(paths), b'/')

        paths = ['a/z', 'a/z', 'a/z']
        self.assertEquals(git.commonpath(paths), 'a/z')

        paths = ['0']
        self.assertEquals(git.commonpath(paths), '0')
