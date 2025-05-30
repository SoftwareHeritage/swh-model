# Copyright (C) 2017-2025  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from collections import defaultdict
from functools import partial
import os
import tarfile
import tempfile
from typing import ClassVar, Optional
import unittest

import pytest

from swh.model import from_disk, model
from swh.model.from_disk import (
    Content,
    DentryPerms,
    Directory,
    DiskBackedData,
    FromDiskType,
)
from swh.model.hashutil import DEFAULT_ALGORITHMS, hash_to_bytes, hash_to_hex

TEST_DATA = os.path.join(os.path.dirname(__file__), "data")


def mk_tree(root: bytes, tree_desc: bytes):
    """Create a directory tree under `root` with content generated from `tree_desc`

    tree_desc is a simple textual representation of the tree structure; each
    line is an element of the directory tree structure, a trailing '/' defines
    a directory, otherwise it's an (empty) file; a symlink is specified with a
    ' -> path' in the description. If the destination path starts with a slash ('/')
    it is considered as absolute, ie. relative to the 'root' directory; e.g.

      foo/bar/baz.txt
      foo/baz/
      foo/bar/toto -> baz.txt
      foo/abstoto -> /foo/bar/baz.txt

    will generate a directory structure like:

    .
    └── foo
        ├── abstoto -> bar/baz.txt
        ├── bar
        │   ├── baz.txt
        │   └── toto -> baz.txt
        └── baz

    The root directory must already exist.

    """
    if not os.path.isdir(root):
        raise EnvironmentError("The root directory must exists and be writable")

    symlinks = []
    for entry in tree_desc.splitlines():
        entry = entry.strip()
        if not entry or entry.startswith(b"#"):
            continue
        entry = entry.strip().lstrip(b"/")
        if b".." in entry:
            raise ValueError(".. in path descr is forbidden...")
        if b"->" in entry:
            dst, src = entry.split(b"->")
            symlinks.append((src.strip(), dst.strip()))
            continue
        path = os.path.join(root, entry)
        if entry.endswith(b"/"):
            os.makedirs(path, exist_ok=True)
        else:
            dirname = os.path.dirname(path)
            os.makedirs(dirname, exist_ok=True)
            open(path, "a")

    # now create symlinks
    while symlinks:
        src, dst = symlinks.pop(0)
        fp_dst = os.path.join(root, dst)
        if src.startswith(b"/"):
            rp_src = src.lstrip(b"/")
        else:
            rp_src = os.path.join(os.path.dirname(dst), src)
        fp_src = os.path.join(root, rp_src)
        if not os.path.exists(fp_src):
            symlinks.append((src, dst))
            continue
        # create the parent directory of the dst, if need be
        dirname = os.path.dirname(fp_dst)
        os.makedirs(dirname, exist_ok=True)

        rp_src = os.path.relpath(fp_src, os.path.dirname(fp_dst))
        os.symlink(rp_src, fp_dst)


def test_mk_tree(tmpdir):
    desc = b"""
      foo/bar/baz.txt
      foo/baz/
      foo/bar/toto -> baz.txt
      foo/abstoto -> /foo/bar/baz.txt
      baz/baz/baz/
      # prefix / is ignored
      /bar/a_file.txt
      # symlink to a not yet defined target is ok
      bar/baz/lnk -> /foo/bar/later.txt
      foo/bar/later.txt
      # symlink to another symlink is ok
      bar/baz/lnk2 -> /foo/bar/toto
      # even if the src of the symlink is defined after the dst
      bar/baz/lnk3 -> /foo/bar/toto2
      foo/bar/toto2 -> later.txt

    """
    from os.path import isdir, isfile, islink, realpath

    join = partial(os.path.join, tmpdir)

    mk_tree(os.fsencode(tmpdir), desc)

    assert isfile(join("foo/bar/baz.txt"))
    assert isfile(join("foo/bar/later.txt"))
    assert isfile(join("bar/a_file.txt"))

    assert isdir(join("baz/baz/baz"))

    assert islink(join("foo/bar/toto"))
    assert realpath(join("foo/bar/toto")) == join("foo/bar/baz.txt")
    assert islink(join("foo/bar/toto2"))
    assert realpath(join("foo/bar/toto2")) == join("foo/bar/later.txt")
    assert islink(join("foo/abstoto"))
    assert realpath(join("foo/abstoto")) == join("foo/bar/baz.txt")
    assert islink(join("bar/baz/lnk"))
    assert realpath(join("bar/baz/lnk")) == join("foo/bar/later.txt")
    assert islink(join("bar/baz/lnk2"))
    assert realpath(join("bar/baz/lnk2")) == join("foo/bar/baz.txt")
    assert islink(join("bar/baz/lnk3"))
    assert realpath(join("bar/baz/lnk3")) == join("foo/bar/later.txt")


class ModeToPerms(unittest.TestCase):
    def setUp(self):
        super().setUp()

        # Generate a full permissions map
        self.perms_map = {}

        # Symlinks
        for i in range(0o120000, 0o127777 + 1):
            self.perms_map[i] = DentryPerms.symlink

        # Directories
        for i in range(0o040000, 0o047777 + 1):
            self.perms_map[i] = DentryPerms.directory

        # Other file types: socket, regular file, block device, character
        # device, fifo all map to regular files
        for ft in [0o140000, 0o100000, 0o060000, 0o020000, 0o010000]:
            for i in range(ft, ft + 0o7777 + 1):
                if i & 0o111:
                    # executable bits are set
                    self.perms_map[i] = DentryPerms.executable_content
                else:
                    self.perms_map[i] = DentryPerms.content

    def test_exhaustive_mode_to_perms(self):
        for fmode, perm in self.perms_map.items():
            self.assertEqual(perm, from_disk.mode_to_perms(fmode))


class TestDiskBackedContent(unittest.TestCase):
    def test_with_data(self):
        expected_content = model.Content(
            length=42,
            status="visible",
            data=b"foo bar",
            sha1=b"foo",
            sha1_git=b"bar",
            sha256=b"baz",
            blake2s256=b"qux",
        )
        with tempfile.NamedTemporaryFile(mode="w+b") as fd:
            content = model.Content(
                length=42,
                status="visible",
                get_data=DiskBackedData(path=fd.name),
                sha1=b"foo",
                sha1_git=b"bar",
                sha256=b"baz",
                blake2s256=b"qux",
            )
            fd.write(b"foo bar")
            fd.seek(0)
            content_with_data = content.with_data()
            assert content.to_dict() == content_with_data.to_dict()

        assert expected_content == content_with_data
        assert expected_content.to_dict() == content_with_data.to_dict()

    def test_lazy_data(self):
        with tempfile.NamedTemporaryFile(mode="w+b") as fd:
            fd.write(b"foo")
            fd.seek(0)
            content = model.Content(
                length=42,
                status="visible",
                get_data=DiskBackedData(path=fd.name),
                sha1=b"foo",
                sha1_git=b"bar",
                sha256=b"baz",
                blake2s256=b"qux",
            )
            fd.write(b"bar")
            fd.seek(0)
            content_with_data = content.with_data()
            fd.write(b"baz")
            fd.seek(0)

        assert content_with_data.data == b"bar"

    def test_with_data_cannot_read(self):
        with tempfile.NamedTemporaryFile(mode="w+b") as fd:
            content = model.Content(
                length=42,
                status="visible",
                get_data=DiskBackedData(path=fd.name),
                sha1=b"foo",
                sha1_git=b"bar",
                sha256=b"baz",
                blake2s256=b"qux",
            )

        with pytest.raises(OSError):
            content.with_data()

    def test_missing_path(self):
        with pytest.raises(model.MissingData):
            c = model.Content(
                length=42,
                status="visible",
                sha1=b"foo",
                sha1_git=b"bar",
                sha256=b"baz",
                blake2s256=b"qux",
            )
            c.with_data()

        with pytest.raises(model.MissingData):
            c = model.Content(
                length=42,
                status="visible",
                get_data=lambda: None,
                sha1=b"foo",
                sha1_git=b"bar",
                sha256=b"baz",
                blake2s256=b"qux",
            )
            c.with_data()


class DataMixin:
    maxDiff: ClassVar[Optional[int]] = None

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(prefix="swh.model.from_disk")
        self.tmpdir_name = os.fsencode(self.tmpdir.name)

        self.contents = {
            b"file": {
                "data": b"42\n",
                "sha1": hash_to_bytes("34973274ccef6ab4dfaaf86599792fa9c3fe4689"),
                "sha256": hash_to_bytes(
                    "084c799cd551dd1d8d5c5f9a5d593b2e"
                    "931f5e36122ee5c793c1d08a19839cc0"
                ),
                "sha1_git": hash_to_bytes("d81cc0710eb6cf9efd5b920a8453e1e07157b6cd"),
                "blake2s256": hash_to_bytes(
                    "d5fe1939576527e42cfd76a9455a2432"
                    "fe7f56669564577dd93c4280e76d661d"
                ),
                "length": 3,
                "mode": 0o100644,
            },
        }

        self.symlinks = {
            b"symlink": {
                "data": b"target",
                "blake2s256": hash_to_bytes(
                    "595d221b30fdd8e10e2fdf18376e688e"
                    "9f18d56fd9b6d1eb6a822f8c146c6da6"
                ),
                "sha1": hash_to_bytes("0e8a3ad980ec179856012b7eecf4327e99cd44cd"),
                "sha1_git": hash_to_bytes("1de565933b05f74c75ff9a6520af5f9f8a5a2f1d"),
                "sha256": hash_to_bytes(
                    "34a04005bcaf206eec990bd9637d9fdb"
                    "6725e0a0c0d4aebf003f17f4c956eb5c"
                ),
                "length": 6,
                "perms": DentryPerms.symlink,
            }
        }

        self.specials = {
            b"fifo": os.mkfifo,
        }

        self.empty_content = {
            "data": b"",
            "length": 0,
            "blake2s256": hash_to_bytes(
                "69217a3079908094e11121d042354a7c" "1f55b6482ca1a51e1b250dfd1ed0eef9"
            ),
            "sha1": hash_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            "sha1_git": hash_to_bytes("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"),
            "sha256": hash_to_bytes(
                "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855"
            ),
            "perms": DentryPerms.content,
        }

        self.empty_directory = {
            "id": hash_to_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            "entries": [],
        }

        # Generated with generate_testdata_from_disk
        self.tarball_contents = {
            b"": {
                "entries": [
                    {
                        "name": b"bar",
                        "perms": DentryPerms.directory,
                        "target": hash_to_bytes(
                            "3c1f578394f4623f74a0ba7fe761729f59fc6ec4"
                        ),
                        "type": "dir",
                    },
                    {
                        "name": b"empty-folder",
                        "perms": DentryPerms.directory,
                        "target": hash_to_bytes(
                            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
                        ),
                        "type": "dir",
                    },
                    {
                        "name": b"foo",
                        "perms": DentryPerms.directory,
                        "target": hash_to_bytes(
                            "2b41c40f0d1fbffcba12497db71fba83fcca96e5"
                        ),
                        "type": "dir",
                    },
                    {
                        "name": b"link-to-another-quote",
                        "perms": DentryPerms.symlink,
                        "target": hash_to_bytes(
                            "7d5c08111e21c8a9f71540939998551683375fad"
                        ),
                        "type": "file",
                    },
                    {
                        "name": b"link-to-binary",
                        "perms": DentryPerms.symlink,
                        "target": hash_to_bytes(
                            "e86b45e538d9b6888c969c89fbd22a85aa0e0366"
                        ),
                        "type": "file",
                    },
                    {
                        "name": b"link-to-foo",
                        "perms": DentryPerms.symlink,
                        "target": hash_to_bytes(
                            "19102815663d23f8b75a47e7a01965dcdc96468c"
                        ),
                        "type": "file",
                    },
                    {
                        "name": b"some-binary",
                        "perms": DentryPerms.executable_content,
                        "target": hash_to_bytes(
                            "68769579c3eaadbe555379b9c3538e6628bae1eb"
                        ),
                        "type": "file",
                    },
                ],
                "id": hash_to_bytes("e8b0f1466af8608c8a3fb9879db172b887e80759"),
            },
            b"bar": {
                "entries": [
                    {
                        "name": b"barfoo",
                        "perms": DentryPerms.directory,
                        "target": hash_to_bytes(
                            "c3020f6bf135a38c6df3afeb5fb38232c5e07087"
                        ),
                        "type": "dir",
                    }
                ],
                "id": hash_to_bytes("3c1f578394f4623f74a0ba7fe761729f59fc6ec4"),
            },
            b"bar/barfoo": {
                "entries": [
                    {
                        "name": b"another-quote.org",
                        "perms": DentryPerms.content,
                        "target": hash_to_bytes(
                            "133693b125bad2b4ac318535b84901ebb1f6b638"
                        ),
                        "type": "file",
                    }
                ],
                "id": hash_to_bytes("c3020f6bf135a38c6df3afeb5fb38232c5e07087"),
            },
            b"bar/barfoo/another-quote.org": {
                "blake2s256": hash_to_bytes(
                    "d26c1cad82d43df0bffa5e7be11a60e3"
                    "4adb85a218b433cbce5278b10b954fe8"
                ),
                "length": 72,
                "perms": DentryPerms.content,
                "sha1": hash_to_bytes("90a6138ba59915261e179948386aa1cc2aa9220a"),
                "sha1_git": hash_to_bytes("133693b125bad2b4ac318535b84901ebb1f6b638"),
                "sha256": hash_to_bytes(
                    "3db5ae168055bcd93a4d08285dc99ffe"
                    "e2883303b23fac5eab850273a8ea5546"
                ),
            },
            b"empty-folder": {
                "entries": [],
                "id": hash_to_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            },
            b"foo": {
                "entries": [
                    {
                        "name": b"barfoo",
                        "perms": DentryPerms.symlink,
                        "target": hash_to_bytes(
                            "8185dfb2c0c2c597d16f75a8a0c37668567c3d7e"
                        ),
                        "type": "file",
                    },
                    {
                        "name": b"quotes.md",
                        "perms": DentryPerms.content,
                        "target": hash_to_bytes(
                            "7c4c57ba9ff496ad179b8f65b1d286edbda34c9a"
                        ),
                        "type": "file",
                    },
                    {
                        "name": b"rel-link-to-barfoo",
                        "perms": DentryPerms.symlink,
                        "target": hash_to_bytes(
                            "acac326ddd63b0bc70840659d4ac43619484e69f"
                        ),
                        "type": "file",
                    },
                ],
                "id": hash_to_bytes("2b41c40f0d1fbffcba12497db71fba83fcca96e5"),
            },
            b"foo/barfoo": {
                "blake2s256": hash_to_bytes(
                    "e1252f2caa4a72653c4efd9af871b62b"
                    "f2abb7bb2f1b0e95969204bd8a70d4cd"
                ),
                "data": b"bar/barfoo",
                "length": 10,
                "perms": DentryPerms.symlink,
                "sha1": hash_to_bytes("9057ee6d0162506e01c4d9d5459a7add1fedac37"),
                "sha1_git": hash_to_bytes("8185dfb2c0c2c597d16f75a8a0c37668567c3d7e"),
                "sha256": hash_to_bytes(
                    "29ad3f5725321b940332c78e403601af"
                    "ff61daea85e9c80b4a7063b6887ead68"
                ),
            },
            b"foo/quotes.md": {
                "blake2s256": hash_to_bytes(
                    "bf7ce4fe304378651ee6348d3e9336ed"
                    "5ad603d33e83c83ba4e14b46f9b8a80b"
                ),
                "length": 66,
                "perms": DentryPerms.content,
                "sha1": hash_to_bytes("1bf0bb721ac92c18a19b13c0eb3d741cbfadebfc"),
                "sha1_git": hash_to_bytes("7c4c57ba9ff496ad179b8f65b1d286edbda34c9a"),
                "sha256": hash_to_bytes(
                    "caca942aeda7b308859eb56f909ec96d"
                    "07a499491690c453f73b9800a93b1659"
                ),
            },
            b"foo/rel-link-to-barfoo": {
                "blake2s256": hash_to_bytes(
                    "d9c327421588a1cf61f316615005a2e9"
                    "c13ac3a4e96d43a24138d718fa0e30db"
                ),
                "data": b"../bar/barfoo",
                "length": 13,
                "perms": DentryPerms.symlink,
                "sha1": hash_to_bytes("dc51221d308f3aeb2754db48391b85687c2869f4"),
                "sha1_git": hash_to_bytes("acac326ddd63b0bc70840659d4ac43619484e69f"),
                "sha256": hash_to_bytes(
                    "8007d20db2af40435f42ddef4b8ad76b"
                    "80adbec26b249fdf0473353f8d99df08"
                ),
            },
            b"link-to-another-quote": {
                "blake2s256": hash_to_bytes(
                    "2d0e73cea01ba949c1022dc10c8a43e6"
                    "6180639662e5dc2737b843382f7b1910"
                ),
                "data": b"bar/barfoo/another-quote.org",
                "length": 28,
                "perms": DentryPerms.symlink,
                "sha1": hash_to_bytes("cbeed15e79599c90de7383f420fed7acb48ea171"),
                "sha1_git": hash_to_bytes("7d5c08111e21c8a9f71540939998551683375fad"),
                "sha256": hash_to_bytes(
                    "e6e17d0793aa750a0440eb9ad5b80b25"
                    "8076637ef0fb68f3ac2e59e4b9ac3ba6"
                ),
            },
            b"link-to-binary": {
                "blake2s256": hash_to_bytes(
                    "9ce18b1adecb33f891ca36664da676e1"
                    "2c772cc193778aac9a137b8dc5834b9b"
                ),
                "data": b"some-binary",
                "length": 11,
                "perms": DentryPerms.symlink,
                "sha1": hash_to_bytes("d0248714948b3a48a25438232a6f99f0318f59f1"),
                "sha1_git": hash_to_bytes("e86b45e538d9b6888c969c89fbd22a85aa0e0366"),
                "sha256": hash_to_bytes(
                    "14126e97d83f7d261c5a6889cee73619"
                    "770ff09e40c5498685aba745be882eff"
                ),
            },
            b"link-to-foo": {
                "blake2s256": hash_to_bytes(
                    "08d6cad88075de8f192db097573d0e82"
                    "9411cd91eb6ec65e8fc16c017edfdb74"
                ),
                "data": b"foo",
                "length": 3,
                "perms": DentryPerms.symlink,
                "sha1": hash_to_bytes("0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33"),
                "sha1_git": hash_to_bytes("19102815663d23f8b75a47e7a01965dcdc96468c"),
                "sha256": hash_to_bytes(
                    "2c26b46b68ffc68ff99b453c1d304134"
                    "13422d706483bfa0f98a5e886266e7ae"
                ),
            },
            b"some-binary": {
                "blake2s256": hash_to_bytes(
                    "922e0f7015035212495b090c27577357"
                    "a740ddd77b0b9e0cd23b5480c07a18c6"
                ),
                "length": 5,
                "perms": DentryPerms.executable_content,
                "sha1": hash_to_bytes("0bbc12d7f4a2a15b143da84617d95cb223c9b23c"),
                "sha1_git": hash_to_bytes("68769579c3eaadbe555379b9c3538e6628bae1eb"),
                "sha256": hash_to_bytes(
                    "bac650d34a7638bb0aeb5342646d24e3"
                    "b9ad6b44c9b383621faa482b990a367d"
                ),
            },
        }

    def tearDown(self):
        self.tmpdir.cleanup()

    def assertContentEqual(self, left, right, *, check_path=False):  # noqa
        if not isinstance(left, Content):
            raise ValueError("%s is not a Content" % left)
        if isinstance(right, Content):
            right = right.get_data()

        # Compare dictionaries

        keys = DEFAULT_ALGORITHMS | {
            "length",
            "perms",
        }
        if check_path:
            keys |= {"path"}

        failed = []
        for key in keys:
            try:
                lvalue = left.data[key]
                if key == "perms" and "perms" not in right:
                    rvalue = from_disk.mode_to_perms(right["mode"])
                else:
                    rvalue = right[key]
            except KeyError:
                failed.append(key)
                continue

            if lvalue != rvalue:
                failed.append(key)

        if failed:
            raise self.failureException(
                "Content mismatched:\n"
                + "\n".join(
                    "content[%s] = %r != %r" % (key, left.data.get(key), right.get(key))
                    for key in failed
                )
            )

    def assertDirectoryEqual(self, left, right):  # NoQA
        if not isinstance(left, Directory):
            raise ValueError("%s is not a Directory" % left)
        if isinstance(right, Directory):
            right = right.get_data()

        assert left.entries == right["entries"]
        assert left.hash == right["id"]

        assert left.to_model() == model.Directory.from_dict(right)

    def make_contents(self, directory):
        for filename, content in self.contents.items():
            path = os.path.join(directory, filename)
            with open(path, "wb") as f:
                f.write(content["data"])
            os.chmod(path, content["mode"])

    def make_symlinks(self, directory):
        for filename, symlink in self.symlinks.items():
            path = os.path.join(directory, filename)
            os.symlink(symlink["data"], path)

    def make_specials(self, directory):
        for filename, fn in self.specials.items():
            path = os.path.join(directory, filename)
            fn(path)

    def make_from_tarball(self, directory):
        tarball = os.path.join(TEST_DATA, "dir-folders", "sample-folder.tgz")

        with tarfile.open(tarball, "r:gz") as f:
            f.extractall(os.fsdecode(directory))


class TestContent(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()

    def test_data_to_content(self):
        for filename, content in self.contents.items():
            conv_content = Content.from_bytes(
                mode=content["mode"], data=content["data"]
            )
            self.assertContentEqual(conv_content, content)
            self.assertIn(hash_to_hex(conv_content.hash), repr(conv_content))

    def test_content_swhid(self):
        for _, content in self.contents.items():
            content_res = Content.from_bytes(mode=content["mode"], data=content["data"])
            content_swhid = "swh:1:cnt:" + hash_to_hex(content["sha1_git"])
            assert str(content_res.swhid()) == content_swhid


class TestDirectory(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()

    def test_directory_swhid(self):
        directory_swhid = "swh:1:dir:" + hash_to_hex(self.empty_directory["id"])
        directory = Directory.from_disk(path=self.tmpdir_name, max_content_length=None)
        assert str(directory.swhid()) == directory_swhid


class SymlinkToContent(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.make_symlinks(self.tmpdir_name)

    def test_symlink_to_content(self):
        for filename, symlink in self.symlinks.items():
            path = os.path.join(self.tmpdir_name, filename)
            perms = 0o120000
            conv_content = Content.from_symlink(path=path, mode=perms)
            symlink_copy = symlink.copy()
            symlink_copy["path"] = path
            self.assertContentEqual(conv_content, symlink_copy, check_path=True)

    def test_symlink_to_base_model(self):
        for filename, symlink in self.symlinks.items():
            path = os.path.join(self.tmpdir_name, filename)
            perms = 0o120000
            model_content = Content.from_symlink(path=path, mode=perms).to_model()

            right = symlink.copy()
            for key in ("perms", "path", "mode"):
                right.pop(key, None)
            right["status"] = "visible"
            assert model_content == model.Content.from_dict(right)


class FileToContent(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.make_contents(self.tmpdir_name)
        self.make_symlinks(self.tmpdir_name)
        self.make_specials(self.tmpdir_name)

    def test_symlink_to_content(self):
        for filename, symlink in self.symlinks.items():
            path = os.path.join(self.tmpdir_name, filename)
            conv_content = Content.from_file(path=path, max_content_length=None)
            self.assertContentEqual(conv_content, symlink)

    def test_file_to_content(self):
        for filename, content in self.contents.items():
            path = os.path.join(self.tmpdir_name, filename)
            conv_content = Content.from_file(path=path, max_content_length=None)
            self.assertContentEqual(conv_content, content)

    def test_special_to_content(self):
        for filename in self.specials:
            path = os.path.join(self.tmpdir_name, filename)
            conv_content = Content.from_file(path=path, max_content_length=None)
            self.assertContentEqual(conv_content, self.empty_content)

        for path in ["/dev/null", "/dev/zero"]:
            path = os.path.join(self.tmpdir_name, filename)
            conv_content = Content.from_file(path=path, max_content_length=None)
            self.assertContentEqual(conv_content, self.empty_content)

    def test_symlink_to_content_model(self):
        for filename, symlink in self.symlinks.items():
            path = os.path.join(self.tmpdir_name, filename)
            model_content = Content.from_file(
                path=path, max_content_length=None
            ).to_model()

            right = symlink.copy()
            for key in ("perms", "path", "mode"):
                right.pop(key, None)
            right["status"] = "visible"
            assert model_content == model.Content.from_dict(right)

    def test_file_to_content_model(self):
        for filename, content in self.contents.items():
            path = os.path.join(self.tmpdir_name, filename)
            model_content = Content.from_file(
                path=path, max_content_length=None
            ).to_model()

            right = content.copy()
            for key in ("perms", "mode"):
                right.pop(key, None)
            assert model_content.with_data() == model.Content.from_dict(right)

            right["get_data"] = DiskBackedData(path=path)
            del right["data"]
            assert model_content == model.Content.from_dict(right)

    def test_special_to_content_model(self):
        for filename in self.specials:
            path = os.path.join(self.tmpdir_name, filename)
            model_content = Content.from_file(
                path=path, max_content_length=None
            ).to_model()

            right = self.empty_content.copy()
            for key in ("perms", "path", "mode"):
                right.pop(key, None)
            right["status"] = "visible"
            assert model_content == model.Content.from_dict(right)

        for path in ["/dev/null", "/dev/zero"]:
            model_content = Content.from_file(
                path=path, max_content_length=None
            ).to_model()

            right = self.empty_content.copy()
            for key in ("perms", "path", "mode"):
                right.pop(key, None)
            right["status"] = "visible"
            assert model_content == model.Content.from_dict(right)

    def test_symlink_max_length(self):
        for max_content_length in [4, 10]:
            for filename, symlink in self.symlinks.items():
                path = os.path.join(self.tmpdir_name, filename)
                content = Content.from_file(path=path, max_content_length=None)
                if content.data["length"] > max_content_length:
                    with pytest.raises(Exception, match="too large"):
                        Content.from_file(
                            path=path, max_content_length=max_content_length
                        )
                else:
                    limited_content = Content.from_file(
                        path=path, max_content_length=max_content_length
                    )
                    assert content == limited_content

    def test_file_max_length(self):
        for max_content_length in [2, 4]:
            for filename, content in self.contents.items():
                path = os.path.join(self.tmpdir_name, filename)
                content = Content.from_file(path=path, max_content_length=None)
                limited_content = Content.from_file(
                    path=path, max_content_length=max_content_length
                )
                assert content.data["length"] == limited_content.data["length"]
                assert content.data["status"] == "visible"
                if content.data["length"] > max_content_length:
                    assert limited_content.data["status"] == "absent"
                    assert limited_content.data["reason"] == "Content too large"
                else:
                    assert limited_content.data["status"] == "visible"

    def test_special_file_max_length(self):
        for max_content_length in [None, 0, 1]:
            for filename in self.specials:
                path = os.path.join(self.tmpdir_name, filename)
                content = Content.from_file(path=path, max_content_length=None)
                limited_content = Content.from_file(
                    path=path, max_content_length=max_content_length
                )
                assert limited_content == content

    def test_file_to_content_with_path(self):
        for filename, content in self.contents.items():
            content_w_path = content.copy()
            path = os.path.join(self.tmpdir_name, filename)
            content_w_path["path"] = path
            conv_content = Content.from_file(path=path, max_content_length=None)
            self.assertContentEqual(conv_content, content_w_path, check_path=True)


class DirectoryToObjects(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        contents = os.path.join(self.tmpdir_name, b"contents")
        os.mkdir(contents)
        self.make_contents(contents)
        symlinks = os.path.join(self.tmpdir_name, b"symlinks")
        os.mkdir(symlinks)
        self.make_symlinks(symlinks)
        specials = os.path.join(self.tmpdir_name, b"specials")
        os.mkdir(specials)
        self.make_specials(specials)
        empties = os.path.join(self.tmpdir_name, b"empty1", b"empty2")
        os.makedirs(empties)

    def check_collect(
        self, directory, expected_directory_count, expected_content_count
    ):
        objs = directory.collect()
        contents = []
        directories = []
        for obj in objs:
            if isinstance(obj, Content):
                contents.append(obj)
            elif isinstance(obj, Directory):
                directories.append(obj)

        self.assertEqual(len(directories), expected_directory_count)
        self.assertEqual(len(contents), expected_content_count)

    def test_directory_to_objects(self):
        directory = Directory.from_disk(path=self.tmpdir_name, max_content_length=None)

        for name, value in self.contents.items():
            self.assertContentEqual(directory[b"contents/" + name], value)

        for name, value in self.symlinks.items():
            self.assertContentEqual(directory[b"symlinks/" + name], value)

        for name in self.specials:
            self.assertContentEqual(
                directory[b"specials/" + name],
                self.empty_content,
            )

        self.assertEqual(
            directory[b"empty1/empty2"].get_data(),
            self.empty_directory,
        )

        # Raise on non existent file
        with self.assertRaisesRegex(KeyError, "b'nonexistent'"):
            directory[b"empty1/nonexistent"]

        # Raise on non existent directory
        with self.assertRaisesRegex(KeyError, "b'nonexistentdir'"):
            directory[b"nonexistentdir/file"]

        self.check_collect(
            directory,
            expected_directory_count=6,
            expected_content_count=len(self.contents) + len(self.symlinks) + 1,
        )

    def test_directory_to_objects_ignore_empty(self):
        directory = Directory.from_disk(
            path=self.tmpdir_name,
            path_filter=from_disk.ignore_empty_directories,
            max_content_length=None,
        )

        for name, value in self.contents.items():
            self.assertContentEqual(directory[b"contents/" + name], value)

        for name, value in self.symlinks.items():
            self.assertContentEqual(directory[b"symlinks/" + name], value)

        for name in self.specials:
            self.assertContentEqual(
                directory[b"specials/" + name],
                self.empty_content,
            )

        # empty directories have been ignored recursively
        with self.assertRaisesRegex(KeyError, "b'empty1'"):
            directory[b"empty1"]
        with self.assertRaisesRegex(KeyError, "b'empty1'"):
            directory[b"empty1/empty2"]

        self.check_collect(
            directory,
            expected_directory_count=4,
            expected_content_count=len(self.contents) + len(self.symlinks) + 1,
        )

    def test_directory_to_objects_ignore_name(self):
        pfilter = from_disk.ignore_named_directories([b"symlinks"])
        directory = Directory.from_disk(
            path=self.tmpdir_name, path_filter=pfilter, max_content_length=None
        )
        for name, value in self.contents.items():
            self.assertContentEqual(directory[b"contents/" + name], value)

        for name in self.specials:
            self.assertContentEqual(
                directory[b"specials/" + name],
                self.empty_content,
            )

        self.assertEqual(
            directory[b"empty1/empty2"].get_data(),
            self.empty_directory,
        )

        with self.assertRaisesRegex(KeyError, "b'symlinks'"):
            directory[b"symlinks"]

        self.check_collect(
            directory,
            expected_directory_count=5,
            expected_content_count=len(self.contents) + 1,
        )

    def test_directory_to_objects_ignore_name_with_slash(self):
        self.tmpdir_name = self.tmpdir_name + b"/"
        self.test_directory_to_objects_ignore_name()

    def test_directory_to_objects_ignore_name_case(self):
        directory = Directory.from_disk(
            path=self.tmpdir_name,
            path_filter=from_disk.ignore_named_directories(
                [b"symLiNks"], case_sensitive=False
            ),
            max_content_length=None,
        )
        for name, value in self.contents.items():
            self.assertContentEqual(directory[b"contents/" + name], value)

        for name in self.specials:
            self.assertContentEqual(
                directory[b"specials/" + name],
                self.empty_content,
            )

        self.assertEqual(
            directory[b"empty1/empty2"].get_data(),
            self.empty_directory,
        )

        with self.assertRaisesRegex(KeyError, "b'symlinks'"):
            directory[b"symlinks"]

        self.check_collect(
            directory,
            expected_directory_count=5,
            expected_content_count=len(self.contents) + 1,
        )

    def test_directory_entry_order(self):
        with tempfile.TemporaryDirectory() as dirname:
            dirname = os.fsencode(dirname)
            mk_tree(
                dirname,
                b"""
              /foo.
              /foo0
              /foo/
            """,
            )
            directory = Directory.from_disk(path=dirname, max_content_length=None)

        assert [entry["name"] for entry in directory.entries] == [
            b"foo.",
            b"foo",
            b"foo0",
        ]

    def test_directory_path_filter(self):
        def filter_func(path, name, entries):
            return name.startswith(b"foo")

        with tempfile.TemporaryDirectory() as dirname:
            dirname = os.fsencode(dirname)
            mk_tree(
                dirname,
                b"""
              /foofile
              /file
              /foo/foo/
              /baz/
            """,
            )

            # No filters
            directory = Directory.from_disk(path=dirname, max_content_length=None)
            assert [entry["name"] for entry in directory.entries] == [
                b"baz",
                b"file",
                b"foo",
                b"foofile",
            ]

            # Filter paths
            directory = Directory.from_disk(
                path=dirname, path_filter=filter_func, max_content_length=None
            )
            assert [entry["name"] for entry in directory.entries] == [
                b"foo",
                b"foofile",
            ]

    def test_directory_progress_callback(self):
        total = []

        def update_info(arg):
            assert type(arg) is int
            total.append(arg)

        Directory.from_disk(
            path=self.tmpdir_name,
            progress_callback=update_info,
            max_content_length=None,
        )
        # Corresponds to the deeper files and directories plus the four top level ones
        assert total == [4, 1, 1, 1, 1]

    def test_exclude_trailing(self):
        self.test_exclude(trailing_slash=True)

    def test_exclude(self, trailing_slash=False):
        """exclude patterns"""
        with tempfile.TemporaryDirectory() as dirname:
            dirname = os.fsencode(dirname)
            mk_tree(
                dirname,
                b"""
              /foofile
              /file
              /foo/foo/
              /baz/
              /excluded_dir/file
              /excluded_dir\x96/file
              /excluded_dir2/
              /excluded_dir2\x96/
              /foo/excluded_dir/
              /foo/excluded_dir2\x96/
            """,
            )

            # no filter
            dir_path = dirname
            if trailing_slash:
                dir_path += b"/"
            directory = Directory.from_disk(path=dir_path, max_content_length=None)
            assert set(directory.keys()) == {
                b"baz",
                b"foo",
                b"excluded_dir2\x96",
                b"excluded_dir",
                b"excluded_dir\x96",
                b"excluded_dir2",
                b"foofile",
                b"file",
            }
            assert set(directory[b"foo"].keys()) == {
                b"foo",
                b"excluded_dir2\x96",
                b"excluded_dir",
            }
            assert (
                str(directory.swhid())
                == "swh:1:dir:cd4dfab9b3e160a683f036841e03855929a07286"
            )

            from swh.model.from_disk import ignore_directories_patterns

            exclude_patterns = [b"excluded_*"]
            path_filter = ignore_directories_patterns(dirname, exclude_patterns)
            directory_f = Directory.from_disk(
                path=dir_path, path_filter=path_filter, max_content_length=None
            )
            assert set(directory_f.keys()) == {b"baz", b"foo", b"foofile", b"file"}
            # XXX should foo/excluded_dir and foo/excluded_dir2 be excluded as
            # well? Currently they are not
            assert set(directory_f[b"foo"].keys()) == {
                b"foo",
                b"excluded_dir2\x96",
                b"excluded_dir",
            }
            assert (
                str(directory_f.swhid())
                == "swh:1:dir:adaeb949e1f09d28d334b7e360691ef9df934703"
            )


class TarballTest(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.make_from_tarball(self.tmpdir_name)

    def test_contents_match(self):
        directory = Directory.from_disk(
            path=os.path.join(self.tmpdir_name, b"sample-folder"),
            max_content_length=None,
        )

        for name, expected in self.tarball_contents.items():
            obj = directory[name]
            if isinstance(obj, Content):
                self.assertContentEqual(obj, expected)
            elif isinstance(obj, Directory):
                self.assertDirectoryEqual(obj, expected)
            else:
                raise self.failureException("Unknown type for %s" % obj)


class TarballIterDirectory(DataMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.make_from_tarball(self.tmpdir_name)

    def test_iter_directory(self):
        """Iter from_disk.directory should yield the full arborescence tree"""
        directory = Directory.from_disk(
            path=os.path.join(self.tmpdir_name, b"sample-folder"),
            max_content_length=None,
        )

        contents, skipped_contents, directories = from_disk.iter_directory(directory)

        expected_nb = defaultdict(int)
        for name in self.tarball_contents.keys():
            obj = directory[name]
            expected_nb[obj.object_type] += 1

        assert len(contents) == expected_nb[FromDiskType.CONTENT] and len(contents) > 0
        assert len(skipped_contents) == 0
        assert (
            len(directories) == expected_nb[FromDiskType.DIRECTORY]
            and len(directories) > 0
        )


class DirectoryManipulation(DataMixin, unittest.TestCase):
    def test_directory_access_nested(self):
        d = Directory()
        d[b"a"] = Directory()
        d[b"a/b"] = Directory()

        self.assertEqual(d[b"a/b"].get_data(), self.empty_directory)

    def test_directory_del_nested(self):
        d = Directory()
        d[b"a"] = Directory()
        d[b"a/b"] = Directory()

        with self.assertRaisesRegex(KeyError, "b'c'"):
            del d[b"a/b/c"]

        with self.assertRaisesRegex(KeyError, "b'level2'"):
            del d[b"a/level2/c"]

        del d[b"a/b"]

        self.assertEqual(d[b"a"].get_data(), self.empty_directory)

    def test_directory_access_self(self):
        d = Directory()
        self.assertIs(d, d[b""])
        self.assertIs(d, d[b"/"])
        self.assertIs(d, d[b"//"])

    def test_directory_access_wrong_type(self):
        d = Directory()
        with self.assertRaisesRegex(ValueError, "bytes from Directory"):
            d["foo"]
        with self.assertRaisesRegex(ValueError, "bytes from Directory"):
            d[42]

    def test_directory_repr(self):
        entries = [b"a", b"b", b"c"]
        d = Directory()
        for entry in entries:
            d[entry] = Directory()

        r = repr(d)
        self.assertIn(hash_to_hex(d.hash), r)

        for entry in entries:
            self.assertIn(str(entry), r)

    def test_directory_set_wrong_type_name(self):
        d = Directory()
        with self.assertRaisesRegex(ValueError, "bytes Directory entry"):
            d["foo"] = Directory()
        with self.assertRaisesRegex(ValueError, "bytes Directory entry"):
            d[42] = Directory()

    def test_directory_set_nul_in_name(self):
        d = Directory()

        with self.assertRaisesRegex(ValueError, "nul bytes"):
            d[b"\x00\x01"] = Directory()

    def test_directory_set_empty_name(self):
        d = Directory()
        with self.assertRaisesRegex(ValueError, "must have a name"):
            d[b""] = Directory()
        with self.assertRaisesRegex(ValueError, "must have a name"):
            d[b"/"] = Directory()

    def test_directory_set_wrong_type(self):
        d = Directory()
        with self.assertRaisesRegex(ValueError, "Content or Directory"):
            d[b"entry"] = object()

    def test_directory_del_wrong_type(self):
        d = Directory()
        with self.assertRaisesRegex(ValueError, "bytes Directory entry"):
            del d["foo"]
        with self.assertRaisesRegex(ValueError, "bytes Directory entry"):
            del d[42]

    def test_directory_contains(self):
        d = Directory()
        d[b"a"] = Directory()
        d[b"a/b"] = Directory()
        d[b"a/b/c"] = Directory()
        d[b"a/b/c/d"] = Content()

        self.assertIn(b"a", d)
        self.assertIn(b"a/b", d)
        self.assertIn(b"a/b/c", d)
        self.assertIn(b"a/b/c/d", d)

        self.assertNotIn(b"b", d)
        self.assertNotIn(b"b/c", d)
        self.assertNotIn(b"b/c/d", d)
