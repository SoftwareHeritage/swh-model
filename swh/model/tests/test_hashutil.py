# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import contextlib
import hashlib
import io
import os
import tempfile
from unittest.mock import patch

import pytest

from swh.model import hashutil
from swh.model.hashutil import DEFAULT_ALGORITHMS, MultiHash, hash_to_bytehex


@contextlib.contextmanager
def patch_blake2(function_name):
    try:
        with patch(function_name) as mock:
            yield mock
    finally:
        # mocking blake2 inserts mock objects in the cache; we need
        # to clean it before the next test runs
        hashutil._blake2_hash_cache.clear()


@pytest.fixture(autouse=True)
def blake2_hash_cache_reset():
    # Reset function cache
    hashutil._blake2_hash_cache = {}


@pytest.fixture
def hash_test_data():
    class HashTestData:

        data = b"1984\n"
        hex_checksums = {
            "sha1": "62be35bf00ff0c624f4a621e2ea5595a049e0731",
            "sha1_git": "568aaf43d83b2c3df8067f3bedbb97d83260be6d",
            "sha256": "26602113b4b9afd9d55466b08580d3c2"
            "4a9b50ee5b5866c0d91fab0e65907311",
            "blake2s256": "63cfb259e1fdb485bc5c55749697a6b21ef31fb7445f6c78a"
            "c9422f9f2dc8906",
        }

        checksums = {
            type: bytes.fromhex(cksum) for type, cksum in hex_checksums.items()
        }

        bytehex_checksums = {
            type: hashutil.hash_to_bytehex(cksum) for type, cksum in checksums.items()
        }

        git_hex_checksums = {
            "blob": hex_checksums["sha1_git"],
            "tree": "5b2e883aa33d2efab98442693ea4dd5f1b8871b0",
            "commit": "79e4093542e72f0fcb7cbd75cb7d270f9254aa8f",
            "tag": "d6bf62466f287b4d986c545890716ce058bddf67",
        }

        git_checksums = {
            type: bytes.fromhex(cksum) for type, cksum in git_hex_checksums.items()
        }

    return HashTestData


def test_multi_hash_data(hash_test_data):
    checksums = MultiHash.from_data(hash_test_data.data).digest()
    assert checksums == hash_test_data.checksums
    assert "length" not in checksums


def test_multi_hash_data_with_length(hash_test_data):
    expected_checksums = hash_test_data.checksums.copy()
    expected_checksums["length"] = len(hash_test_data.data)

    algos = set(["length"]).union(hashutil.DEFAULT_ALGORITHMS)
    checksums = MultiHash.from_data(hash_test_data.data, hash_names=algos).digest()

    assert checksums == expected_checksums
    assert "length" in checksums


def test_multi_hash_data_unknown_hash(hash_test_data):
    with pytest.raises(ValueError, match="Unexpected hashing algorithm.*unknown-hash"):
        MultiHash.from_data(hash_test_data.data, ["unknown-hash"])


def test_multi_hash_file(hash_test_data):
    fobj = io.BytesIO(hash_test_data.data)

    checksums = MultiHash.from_file(fobj, length=len(hash_test_data.data)).digest()
    assert checksums == hash_test_data.checksums


def test_multi_hash_file_hexdigest(hash_test_data):
    fobj = io.BytesIO(hash_test_data.data)
    length = len(hash_test_data.data)
    checksums = MultiHash.from_file(fobj, length=length).hexdigest()
    assert checksums == hash_test_data.hex_checksums


def test_multi_hash_file_bytehexdigest(hash_test_data):
    fobj = io.BytesIO(hash_test_data.data)
    length = len(hash_test_data.data)
    checksums = MultiHash.from_file(fobj, length=length).bytehexdigest()
    assert checksums == hash_test_data.bytehex_checksums


EXTRA_HASH_ALGOS = ["md5", "sha512"]


@pytest.mark.parametrize("hash_algo", EXTRA_HASH_ALGOS)
def test_multi_hash_file_with_extra_hash_algo(hash_test_data, hash_algo):
    fobj = io.BytesIO(hash_test_data.data)

    checksums = MultiHash.from_file(
        fobj,
        hash_names=DEFAULT_ALGORITHMS | {hash_algo},
        length=len(hash_test_data.data),
    ).digest()
    checksum = {hash_algo: hashlib.new(hash_algo, hash_test_data.data).digest()}
    assert checksums == {**hash_test_data.checksums, **checksum}


@pytest.mark.parametrize("hash_algo", EXTRA_HASH_ALGOS)
def test_multi_hash_file_hexdigest_with_extra_hash_algo(hash_test_data, hash_algo):
    fobj = io.BytesIO(hash_test_data.data)
    length = len(hash_test_data.data)
    checksums = MultiHash.from_file(
        fobj, hash_names=DEFAULT_ALGORITHMS | {hash_algo}, length=length
    ).hexdigest()
    checksum = {hash_algo: hashlib.new(hash_algo, hash_test_data.data).hexdigest()}
    assert checksums == {**hash_test_data.hex_checksums, **checksum}


@pytest.mark.parametrize("hash_algo", EXTRA_HASH_ALGOS)
def test_multi_hash_file_bytehexdigest_with_extra_algo(hash_test_data, hash_algo):
    fobj = io.BytesIO(hash_test_data.data)
    length = len(hash_test_data.data)
    checksums = MultiHash.from_file(
        fobj, hash_names=DEFAULT_ALGORITHMS | {hash_algo}, length=length
    ).bytehexdigest()
    checksum = {
        hash_algo: hash_to_bytehex(hashlib.new(hash_algo, hash_test_data.data).digest())
    }
    assert checksums == {**hash_test_data.bytehex_checksums, **checksum}


def test_multi_hash_file_missing_length(hash_test_data):
    fobj = io.BytesIO(hash_test_data.data)
    with pytest.raises(ValueError, match="Missing length"):
        MultiHash.from_file(fobj, hash_names=["sha1_git"])


def test_multi_hash_path(hash_test_data):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(hash_test_data.data)

    hashes = MultiHash.from_path(f.name).digest()
    os.remove(f.name)

    assert hash_test_data.checksums == hashes


def test_hash_git_data(hash_test_data):
    checksums = {
        git_type: hashutil.hash_git_data(hash_test_data.data, git_type)
        for git_type in hash_test_data.git_checksums
    }

    assert checksums == hash_test_data.git_checksums


def test_hash_git_data_unknown_git_type(hash_test_data):
    with pytest.raises(
        ValueError, match="Unexpected git object type.*unknown-git-type"
    ):
        hashutil.hash_git_data(hash_test_data.data, "unknown-git-type")


def test_hash_to_hex(hash_test_data):
    for type in hash_test_data.checksums:
        hex = hash_test_data.hex_checksums[type]
        hash = hash_test_data.checksums[type]
        assert hashutil.hash_to_hex(hex) == hex
        assert hashutil.hash_to_hex(hash) == hex


def test_hash_to_bytes(hash_test_data):
    for type in hash_test_data.checksums:
        hex = hash_test_data.hex_checksums[type]
        hash = hash_test_data.checksums[type]
        assert hashutil.hash_to_bytes(hex) == hash
        assert hashutil.hash_to_bytes(hash) == hash


def test_hash_to_bytehex(hash_test_data):
    for algo in hash_test_data.checksums:
        hex_checksum = hash_test_data.hex_checksums[algo].encode("ascii")
        assert hex_checksum == hashutil.hash_to_bytehex(hash_test_data.checksums[algo])


def test_bytehex_to_hash(hash_test_data):
    for algo in hash_test_data.checksums:
        assert hash_test_data.checksums[algo] == hashutil.bytehex_to_hash(
            hash_test_data.hex_checksums[algo].encode()
        )


def test_new_hash_unsupported_hashing_algorithm():
    expected_message = (
        "Unexpected hashing algorithm blake2:10, "
        "expected one of blake2b512, blake2s256, "
        "md5, sha1, sha1_git, sha256"
    )
    with pytest.raises(ValueError, match=expected_message):
        hashutil._new_hash("blake2:10")


def test_new_hash_blake2b_builtin():
    with patch_blake2("hashlib.blake2b") as mock_blake2b:
        mock_blake2b.return_value = sentinel = object()

        h = hashutil._new_hash("blake2b512")

        assert h is sentinel
        mock_blake2b.assert_called_with(digest_size=512 // 8)


def test_new_hash_blake2s_builtin():
    with patch_blake2("hashlib.blake2s") as mock_blake2s:
        mock_blake2s.return_value = sentinel = object()

        h = hashutil._new_hash("blake2s256")

        assert h is sentinel
        mock_blake2s.assert_called_with(digest_size=256 // 8)


@pytest.fixture
def hashgit_test_data():
    class HashGitTestData:
        blob_data = b"42\n"

        tree_data = b"".join(
            [
                b"40000 barfoo\0",
                bytes.fromhex("c3020f6bf135a38c6df" "3afeb5fb38232c5e07087"),
                b"100644 blah\0",
                bytes.fromhex("63756ef0df5e4f10b6efa" "33cfe5c758749615f20"),
                b"100644 hello\0",
                bytes.fromhex("907b308167f0880fb2a" "5c0e1614bb0c7620f9dc3"),
            ]
        )

        commit_data = b"""\
tree 1c61f7259dcb770f46b194d941df4f08ff0a3970
author Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200
committer Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444054085 +0200

initial
"""  # noqa

        tag_data = """object 24d012aaec0bc5a4d2f62c56399053d6cc72a241
type commit
tag 0.0.1
tagger Antoine R. Dumont (@ardumont) <antoine.romain.dumont@gmail.com> 1444225145 +0200

blah
""".encode(
            "utf-8"
        )  # NOQA

        checksums = {
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

    return HashGitTestData


def test_unknown_header_type():
    with pytest.raises(ValueError, match="Unexpected git object type"):
        hashutil.hash_git_data(b"any-data", "some-unknown-type")


def test_hashdata_content(hashgit_test_data):
    # when
    actual_hash = hashutil.hash_git_data(hashgit_test_data.blob_data, git_type="blob")

    # then
    assert actual_hash == hashgit_test_data.checksums["blob_sha1_git"]


def test_hashdata_tree(hashgit_test_data):
    # when
    actual_hash = hashutil.hash_git_data(hashgit_test_data.tree_data, git_type="tree")

    # then
    assert actual_hash == hashgit_test_data.checksums["tree_sha1_git"]


def test_hashdata_revision(hashgit_test_data):
    # when
    actual_hash = hashutil.hash_git_data(
        hashgit_test_data.commit_data, git_type="commit"
    )

    # then
    assert actual_hash == hashgit_test_data.checksums["commit_sha1_git"]


def test_hashdata_tag(hashgit_test_data):
    # when
    actual_hash = hashutil.hash_git_data(hashgit_test_data.tag_data, git_type="tag")

    # then
    assert actual_hash == hashgit_test_data.checksums["tag_sha1_git"]
