# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import hashlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from swh.model import hashutil
from swh.model.hashutil import MultiHash


class BaseHashutil(unittest.TestCase):
    def setUp(self):
        # Reset function cache
        hashutil._blake2_hash_cache = {}

        self.data = b"1984\n"
        self.hex_checksums = {
            "sha1": "62be35bf00ff0c624f4a621e2ea5595a049e0731",
            "sha1_git": "568aaf43d83b2c3df8067f3bedbb97d83260be6d",
            "sha256": "26602113b4b9afd9d55466b08580d3c2"
            "4a9b50ee5b5866c0d91fab0e65907311",
            "blake2s256": "63cfb259e1fdb485bc5c55749697a6b21ef31fb7445f6c78a"
            "c9422f9f2dc8906",
        }

        self.checksums = {
            type: bytes.fromhex(cksum) for type, cksum in self.hex_checksums.items()
        }

        self.bytehex_checksums = {
            type: hashutil.hash_to_bytehex(cksum)
            for type, cksum in self.checksums.items()
        }

        self.git_hex_checksums = {
            "blob": self.hex_checksums["sha1_git"],
            "tree": "5b2e883aa33d2efab98442693ea4dd5f1b8871b0",
            "commit": "79e4093542e72f0fcb7cbd75cb7d270f9254aa8f",
            "tag": "d6bf62466f287b4d986c545890716ce058bddf67",
        }

        self.git_checksums = {
            type: bytes.fromhex(cksum) for type, cksum in self.git_hex_checksums.items()
        }


class MultiHashTest(BaseHashutil):
    def test_multi_hash_data(self):
        checksums = MultiHash.from_data(self.data).digest()
        self.assertEqual(checksums, self.checksums)
        self.assertFalse("length" in checksums)

    def test_multi_hash_data_with_length(self):
        expected_checksums = self.checksums.copy()
        expected_checksums["length"] = len(self.data)

        algos = set(["length"]).union(hashutil.DEFAULT_ALGORITHMS)
        checksums = MultiHash.from_data(self.data, hash_names=algos).digest()

        self.assertEqual(checksums, expected_checksums)
        self.assertTrue("length" in checksums)

    def test_multi_hash_data_unknown_hash(self):
        with self.assertRaises(ValueError) as cm:
            MultiHash.from_data(self.data, ["unknown-hash"])

        self.assertIn("Unexpected hashing algorithm", cm.exception.args[0])
        self.assertIn("unknown-hash", cm.exception.args[0])

    def test_multi_hash_file(self):
        fobj = io.BytesIO(self.data)

        checksums = MultiHash.from_file(fobj, length=len(self.data)).digest()
        self.assertEqual(checksums, self.checksums)

    def test_multi_hash_file_hexdigest(self):
        fobj = io.BytesIO(self.data)
        length = len(self.data)
        checksums = MultiHash.from_file(fobj, length=length).hexdigest()
        self.assertEqual(checksums, self.hex_checksums)

    def test_multi_hash_file_bytehexdigest(self):
        fobj = io.BytesIO(self.data)
        length = len(self.data)
        checksums = MultiHash.from_file(fobj, length=length).bytehexdigest()
        self.assertEqual(checksums, self.bytehex_checksums)

    def test_multi_hash_file_missing_length(self):
        fobj = io.BytesIO(self.data)
        with self.assertRaises(ValueError) as cm:
            MultiHash.from_file(fobj, hash_names=["sha1_git"])

        self.assertIn("Missing length", cm.exception.args[0])

    def test_multi_hash_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(self.data)

        hashes = MultiHash.from_path(f.name).digest()
        os.remove(f.name)

        self.assertEqual(self.checksums, hashes)


class Hashutil(BaseHashutil):
    def test_hash_git_data(self):
        checksums = {
            git_type: hashutil.hash_git_data(self.data, git_type)
            for git_type in self.git_checksums
        }

        self.assertEqual(checksums, self.git_checksums)

    def test_hash_git_data_unknown_git_type(self):
        with self.assertRaises(ValueError) as cm:
            hashutil.hash_git_data(self.data, "unknown-git-type")

        self.assertIn("Unexpected git object type", cm.exception.args[0])
        self.assertIn("unknown-git-type", cm.exception.args[0])

    def test_hash_to_hex(self):
        for type in self.checksums:
            hex = self.hex_checksums[type]
            hash = self.checksums[type]
            self.assertEqual(hashutil.hash_to_hex(hex), hex)
            self.assertEqual(hashutil.hash_to_hex(hash), hex)

    def test_hash_to_bytes(self):
        for type in self.checksums:
            hex = self.hex_checksums[type]
            hash = self.checksums[type]
            self.assertEqual(hashutil.hash_to_bytes(hex), hash)
            self.assertEqual(hashutil.hash_to_bytes(hash), hash)

    def test_hash_to_bytehex(self):
        for algo in self.checksums:
            self.assertEqual(
                self.hex_checksums[algo].encode("ascii"),
                hashutil.hash_to_bytehex(self.checksums[algo]),
            )

    def test_bytehex_to_hash(self):
        for algo in self.checksums:
            self.assertEqual(
                self.checksums[algo],
                hashutil.bytehex_to_hash(self.hex_checksums[algo].encode()),
            )

    def test_new_hash_unsupported_hashing_algorithm(self):
        try:
            hashutil._new_hash("blake2:10")
        except ValueError as e:
            self.assertEqual(
                str(e),
                "Unexpected hashing algorithm blake2:10, "
                "expected one of blake2b512, blake2s256, "
                "sha1, sha1_git, sha256",
            )

    @patch("hashlib.new")
    def test_new_hash_blake2b_blake2b512_builtin(self, mock_hashlib_new):
        if "blake2b512" not in hashlib.algorithms_available:
            self.skipTest("blake2b512 not built-in")
        mock_hashlib_new.return_value = sentinel = object()

        h = hashutil._new_hash("blake2b512")

        self.assertIs(h, sentinel)
        mock_hashlib_new.assert_called_with("blake2b512")

    @patch("hashlib.new")
    def test_new_hash_blake2s_blake2s256_builtin(self, mock_hashlib_new):
        if "blake2s256" not in hashlib.algorithms_available:
            self.skipTest("blake2s256 not built-in")
        mock_hashlib_new.return_value = sentinel = object()

        h = hashutil._new_hash("blake2s256")

        self.assertIs(h, sentinel)
        mock_hashlib_new.assert_called_with("blake2s256")

    def test_new_hash_blake2b_builtin(self):
        removed_hash = False

        try:
            if "blake2b512" in hashlib.algorithms_available:
                removed_hash = True
                hashlib.algorithms_available.remove("blake2b512")
            if "blake2b" not in hashlib.algorithms_available:
                self.skipTest("blake2b not built in")

            with patch("hashlib.blake2b") as mock_blake2b:
                mock_blake2b.return_value = sentinel = object()

                h = hashutil._new_hash("blake2b512")

                self.assertIs(h, sentinel)
                mock_blake2b.assert_called_with(digest_size=512 // 8)
        finally:
            if removed_hash:
                hashlib.algorithms_available.add("blake2b512")

    def test_new_hash_blake2s_builtin(self):
        removed_hash = False

        try:
            if "blake2s256" in hashlib.algorithms_available:
                removed_hash = True
                hashlib.algorithms_available.remove("blake2s256")
            if "blake2s" not in hashlib.algorithms_available:
                self.skipTest("blake2s not built in")

            with patch("hashlib.blake2s") as mock_blake2s:
                mock_blake2s.return_value = sentinel = object()

                h = hashutil._new_hash("blake2s256")

                self.assertIs(h, sentinel)
                mock_blake2s.assert_called_with(digest_size=256 // 8)
        finally:
            if removed_hash:
                hashlib.algorithms_available.add("blake2s256")

    def test_new_hash_blake2b_pyblake2(self):
        if "blake2b512" in hashlib.algorithms_available:
            self.skipTest("blake2b512 built in")
        if "blake2b" in hashlib.algorithms_available:
            self.skipTest("blake2b built in")

        with patch("pyblake2.blake2b") as mock_blake2b:
            mock_blake2b.return_value = sentinel = object()

            h = hashutil._new_hash("blake2b512")

            self.assertIs(h, sentinel)
            mock_blake2b.assert_called_with(digest_size=512 // 8)

    def test_new_hash_blake2s_pyblake2(self):
        if "blake2s256" in hashlib.algorithms_available:
            self.skipTest("blake2s256 built in")
        if "blake2s" in hashlib.algorithms_available:
            self.skipTest("blake2s built in")

        with patch("pyblake2.blake2s") as mock_blake2s:
            mock_blake2s.return_value = sentinel = object()

            h = hashutil._new_hash("blake2s256")

            self.assertIs(h, sentinel)
            mock_blake2s.assert_called_with(digest_size=256 // 8)


class HashlibGit(unittest.TestCase):
    def setUp(self):
        self.blob_data = b"42\n"

        self.tree_data = b"".join(
            [
                b"40000 barfoo\0",
                bytes.fromhex("c3020f6bf135a38c6df" "3afeb5fb38232c5e07087"),
                b"100644 blah\0",
                bytes.fromhex("63756ef0df5e4f10b6efa" "33cfe5c758749615f20"),
                b"100644 hello\0",
                bytes.fromhex("907b308167f0880fb2a" "5c0e1614bb0c7620f9dc3"),
            ]
        )

        self.commit_data = b"""\
tree 1c61f7259dcb770f46b194d941df4f08ff0a3970
author Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200
committer Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200

initial
"""  # noqa
        self.tag_data = """object 24d012aaec0bc5a4d2f62c56399053d6cc72a241
type commit
tag 0.0.1
tagger Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444225145 +0200

blah
""".encode(
            "utf-8"
        )  # NOQA

        self.checksums = {
            "blob_sha1_git": bytes.fromhex(
                "d81cc0710eb6cf9efd5b920a8453e1" "e07157b6cd"
            ),
            "tree_sha1_git": bytes.fromhex(
                "ac212302c45eada382b27bfda795db" "121dacdb1c"
            ),
            "commit_sha1_git": bytes.fromhex(
                "e960570b2e6e2798fa4cfb9af2c399" "d629189653"
            ),
            "tag_sha1_git": bytes.fromhex(
                "bc2b99ba469987bcf1272c189ed534" "e9e959f120"
            ),
        }

    def test_unknown_header_type(self):
        with self.assertRaises(ValueError) as cm:
            hashutil.hash_git_data(b"any-data", "some-unknown-type")

        self.assertIn("Unexpected git object type", cm.exception.args[0])

    def test_hashdata_content(self):
        # when
        actual_hash = hashutil.hash_git_data(self.blob_data, git_type="blob")

        # then
        self.assertEqual(actual_hash, self.checksums["blob_sha1_git"])

    def test_hashdata_tree(self):
        # when
        actual_hash = hashutil.hash_git_data(self.tree_data, git_type="tree")

        # then
        self.assertEqual(actual_hash, self.checksums["tree_sha1_git"])

    def test_hashdata_revision(self):
        # when
        actual_hash = hashutil.hash_git_data(self.commit_data, git_type="commit")

        # then
        self.assertEqual(actual_hash, self.checksums["commit_sha1_git"])

    def test_hashdata_tag(self):
        # when
        actual_hash = hashutil.hash_git_data(self.tag_data, git_type="tag")

        # then
        self.assertEqual(actual_hash, self.checksums["tag_sha1_git"])
