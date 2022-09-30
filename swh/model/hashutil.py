# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Module in charge of hashing function definitions. This is the base
module use to compute swh's hashes.

Only a subset of hashing algorithms is supported as defined in the
ALGORITHMS set. Any provided algorithms not in that list will result
in a ValueError explaining the error.

This module defines a MultiHash class to ease the softwareheritage
hashing algorithms computation. This allows to compute hashes from
file object, path, data using a similar interface as what the standard
hashlib module provides.

Basic usage examples:

- file object: MultiHash.from_file(
                 file_object, hash_names=DEFAULT_ALGORITHMS).digest()

- path (filepath): MultiHash.from_path(b'foo').hexdigest()

- data (bytes): MultiHash.from_data(b'foo').bytehexdigest()


"Complex" usage, defining a swh hashlib instance first:

- To compute length, integrate the length to the set of algorithms to
  compute, for example:

  .. code-block:: python

     h = MultiHash(hash_names=set({'length'}).union(DEFAULT_ALGORITHMS))
     with open(filepath, 'rb') as f:
         h.update(f.read(HASH_BLOCK_SIZE))
     hashes = h.digest()  # returns a dict of {hash_algo_name: hash_in_bytes}

- Write alongside computing hashing algorithms (from a stream), example:

  .. code-block:: python

     h = MultiHash(length=length)
     with open(filepath, 'wb') as f:
         for chunk in r.iter_content():  # r a stream of sort
             h.update(chunk)
             f.write(chunk)
     hashes = h.hexdigest()  # returns a dict of {hash_algo_name: hash_in_hex}


"""

import binascii
import functools
import hashlib
from io import BytesIO
import os
from typing import Callable, Dict, Optional, Union

ALGORITHMS = set(
    ["sha1", "sha256", "sha1_git", "blake2s256", "blake2b512", "md5", "sha512"]
)
"""Hashing algorithms supported by this module"""

DEFAULT_ALGORITHMS = set(["sha1", "sha256", "sha1_git", "blake2s256"])
"""Algorithms computed by default when calling the functions from this module.

Subset of :const:`ALGORITHMS`.
"""

HASH_BLOCK_SIZE = 32768
"""Block size for streaming hash computations made in this module"""

_blake2_hash_cache = {}  # type: Dict[str, Callable]


class MultiHash:
    """Hashutil class to support multiple hashes computation.

    Args:

        hash_names (set): Set of hash algorithms (+ optionally length)
                          to compute hashes (cf. DEFAULT_ALGORITHMS)
        length (int): Length of the total sum of chunks to read

    If the length is provided as algorithm, the length is also
    computed and returned.

    """

    def __init__(self, hash_names=DEFAULT_ALGORITHMS, length=None):
        self.state = {}
        self.track_length = False
        for name in hash_names:
            if name == "length":
                self.state["length"] = 0
                self.track_length = True
            else:
                self.state[name] = _new_hash(name, length)

    @classmethod
    def from_state(cls, state, track_length):
        ret = cls([])
        ret.state = state
        ret.track_length = track_length

    @classmethod
    def from_file(cls, fobj, hash_names=DEFAULT_ALGORITHMS, length=None):
        ret = cls(length=length, hash_names=hash_names)
        while True:
            chunk = fobj.read(HASH_BLOCK_SIZE)
            if not chunk:
                break
            ret.update(chunk)
        return ret

    @classmethod
    def from_path(cls, path, hash_names=DEFAULT_ALGORITHMS):
        length = os.path.getsize(path)
        with open(path, "rb") as f:
            ret = cls.from_file(f, hash_names=hash_names, length=length)
        return ret

    @classmethod
    def from_data(cls, data, hash_names=DEFAULT_ALGORITHMS):
        length = len(data)
        fobj = BytesIO(data)
        return cls.from_file(fobj, hash_names=hash_names, length=length)

    def update(self, chunk):
        for name, h in self.state.items():
            if name == "length":
                continue
            h.update(chunk)
        if self.track_length:
            self.state["length"] += len(chunk)

    def digest(self):
        return {
            name: h.digest() if name != "length" else h
            for name, h in self.state.items()
        }

    def hexdigest(self):
        return {
            name: h.hexdigest() if name != "length" else h
            for name, h in self.state.items()
        }

    def bytehexdigest(self):
        return {
            name: hash_to_bytehex(h.digest()) if name != "length" else h
            for name, h in self.state.items()
        }

    def copy(self):
        copied_state = {
            name: h.copy() if name != "length" else h for name, h in self.state.items()
        }
        return self.from_state(copied_state, self.track_length)


def _new_blake2_hash(algo):
    """Return a function that initializes a blake2 hash."""
    if algo in _blake2_hash_cache:
        return _blake2_hash_cache[algo]()

    lalgo = algo.lower()
    if not lalgo.startswith("blake2"):
        raise ValueError("Algorithm %s is not a blake2 hash" % algo)

    blake_family = lalgo[:7]

    digest_size = None
    if lalgo[7:]:
        try:
            digest_size, remainder = divmod(int(lalgo[7:]), 8)
        except ValueError:
            raise ValueError("Unknown digest size for algo %s" % algo) from None
        if remainder:
            raise ValueError(
                "Digest size for algorithm %s must be a multiple of 8" % algo
            )

    blake2 = getattr(hashlib, blake_family)
    _blake2_hash_cache[algo] = lambda: blake2(digest_size=digest_size)

    return _blake2_hash_cache[algo]()


def _new_hashlib_hash(algo):
    """Initialize a digest object from hashlib.

    Handle the swh-specific names for the blake2-related algorithms
    """
    if algo.startswith("blake2"):
        return _new_blake2_hash(algo)
    else:
        return hashlib.new(algo)


def git_object_header(git_type: str, length: int) -> bytes:
    """Returns the header for a git object of the given type and length.

    The header of a git object consists of:
     - The type of the object (encoded in ASCII)
     - One ASCII space (\x20)
     - The length of the object (decimal encoded in ASCII)
     - One NUL byte

    Args:
        base_algo (str from :const:`ALGORITHMS`): a hashlib-supported algorithm
        git_type: the type of the git object (supposedly one of 'blob',
                  'commit', 'tag', 'tree')
        length: the length of the git object you're encoding

    Returns:
        a hashutil.hash object
    """
    git_object_types = {
        "blob",
        "tree",
        "commit",
        "tag",
        "snapshot",
        "raw_extrinsic_metadata",
        "extid",
    }

    if git_type not in git_object_types:
        raise ValueError(
            "Unexpected git object type %s, expected one of %s"
            % (git_type, ", ".join(sorted(git_object_types)))
        )

    return ("%s %d\0" % (git_type, length)).encode("ascii")


def _new_hash(algo: str, length: Optional[int] = None):
    """Initialize a digest object (as returned by python's hashlib) for
    the requested algorithm. See the constant ALGORITHMS for the list
    of supported algorithms. If a git-specific hashing algorithm is
    requested (e.g., "sha1_git"), the hashing object will be pre-fed
    with the needed header; for this to work, length must be given.

    Args:
        algo (str): a hashing algorithm (one of ALGORITHMS)
        length (int): the length of the hashed payload (needed for
          git-specific algorithms)

    Returns:
        a hashutil.hash object

    Raises:
        ValueError if algo is unknown, or length is missing for a git-specific
        hash.

    """
    if algo not in ALGORITHMS:
        raise ValueError(
            "Unexpected hashing algorithm %s, expected one of %s"
            % (algo, ", ".join(sorted(ALGORITHMS)))
        )

    if algo.endswith("_git"):
        if length is None:
            raise ValueError("Missing length for git hashing algorithm")
        base_algo = algo[:-4]
        h = _new_hashlib_hash(base_algo)
        h.update(git_object_header("blob", length))
        return h

    return _new_hashlib_hash(algo)


def hash_git_data(data, git_type, base_algo="sha1"):
    """Hash the given data as a git object of type git_type.

    Args:
        data: a bytes object
        git_type: the git object type
        base_algo: the base hashing algorithm used (default: sha1)

    Returns: a dict mapping each algorithm to a bytes digest

    Raises:
        ValueError if the git_type is unexpected.
    """
    h = _new_hashlib_hash(base_algo)
    h.update(git_object_header(git_type, len(data)))
    h.update(data)

    return h.digest()


@functools.lru_cache()
def hash_to_hex(hash: Union[str, bytes]) -> str:
    """Converts a hash (in hex or bytes form) to its hexadecimal ascii form

    Args:
      hash (str or bytes): a :class:`bytes` hash or a :class:`str` containing
        the hexadecimal form of the hash

    Returns:
      str: the hexadecimal form of the hash
    """
    if isinstance(hash, str):
        return hash
    return binascii.hexlify(hash).decode("ascii")


@functools.lru_cache()
def hash_to_bytehex(hash: bytes) -> bytes:
    """Converts a hash to its hexadecimal bytes representation

    Args:
      hash (bytes): a :class:`bytes` hash

    Returns:
      bytes: the hexadecimal form of the hash, as :class:`bytes`
    """
    return binascii.hexlify(hash)


@functools.lru_cache()
def hash_to_bytes(hash: Union[str, bytes]) -> bytes:
    """Converts a hash (in hex or bytes form) to its raw bytes form

    Args:
      hash (str or bytes): a :class:`bytes` hash or a :class:`str` containing
        the hexadecimal form of the hash

    Returns:
      bytes: the :class:`bytes` form of the hash
    """
    if isinstance(hash, bytes):
        return hash
    return bytes.fromhex(hash)


@functools.lru_cache()
def bytehex_to_hash(hex: bytes) -> bytes:
    """Converts a hexadecimal bytes representation of a hash to that hash

    Args:
      hash (bytes): a :class:`bytes` containing the hexadecimal form of the
        hash encoded in ascii

    Returns:
      bytes: the :class:`bytes` form of the hash
    """
    return hash_to_bytes(hex.decode())
