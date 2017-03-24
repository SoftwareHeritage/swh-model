# Copyright (C) 2015-2017  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Module in charge of hashing function definitions. This is the base
module use to compute swh's hashes.

Only a subset of hashing algorithms is supported as defined in the
ALGORITHMS set. Any provided algorithms not in that list will result
in a ValueError explaining the error.

This modules defines the following hashing functions:

- hash_file: Hash the contents of the given file object with the given
  algorithms (defaulting to DEFAULT_ALGORITHMS if none provided).

- hash_data: Hash the given binary blob with the given algorithms
  (defaulting to DEFAULT_ALGORITHMS if none provided).

- hash_path: Hash the contents of the file at the given path with the
  given algorithms (defaulting to DEFAULT_ALGORITHMS if none
  provided).

"""

import binascii
import functools
import hashlib
import os
import sys

from io import BytesIO

# Supported algorithms
ALGORITHMS = set(['sha1', 'sha256', 'sha1_git', 'blake2s256', 'blake2b512'])

# Default algorithms used
DEFAULT_ALGORITHMS = set(['sha1', 'sha256', 'sha1_git', 'blake2s256'])

# should be a multiple of 64 (sha1/sha256's block size)
# FWIW coreutils' sha1sum uses 32768
HASH_BLOCK_SIZE = 32768

# Prior to python3.4, only blake2 is available through pyblake2 module
# From 3.5 onwards, it's been integrated in python
if sys.version_info.major == 3 and sys.version_info.minor <= 4:
    import pyblake2
    # register those hash algorithms in hashlib
    __cache = hashlib.__builtin_constructor_cache
    __cache['blake2s256'] = pyblake2.blake2s
    __cache['blake2b512'] = pyblake2.blake2b


def _new_git_hash(base_algo, git_type, length):
    """Initialize a digest object (as returned by python's hashlib) for the
    requested algorithm, and feed it with the header for a git object of the
    given type and length.

    The header for hashing a git object consists of:
     - The type of the object (encoded in ASCII)
     - One ASCII space (\x20)
     - The length of the object (decimal encoded in ASCII)
     - One NUL byte

    Args:
        base_algo: a hashlib-supported algorithm
        git_type: the type of the git object (supposedly one of 'blob',
                  'commit', 'tag', 'tree')
        length: the length of the git object you're encoding

    Returns:
        a hashutil.hash object
    """

    h = hashlib.new(base_algo)
    git_header = '%s %d\0' % (git_type, length)
    h.update(git_header.encode('ascii'))

    return h


def _new_hash(algo, length=None):
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
            'Unexpected hashing algorithm %s, expected one of %s' %
            (algo, ', '.join(sorted(ALGORITHMS))))

    if algo.endswith('_git'):
        if length is None:
            raise ValueError('Missing length for git hashing algorithm')
        base_algo = algo[:-4]
        return _new_git_hash(base_algo, 'blob', length)

    return hashlib.new(algo)


def hash_file(fobj, length=None, algorithms=DEFAULT_ALGORITHMS, chunk_cb=None):
    """Hash the contents of the given file object with the given algorithms.

    Args:
        fobj: a file-like object
        length: the length of the contents of the file-like object (for the
                git-specific algorithms)
        algorithms: the hashing algorithms used

    Returns: a dict mapping each algorithm to a bytes digest.

    Raises:
        ValueError if algorithms contains an unknown hash algorithm.
    """
    hashes = {algo: _new_hash(algo, length) for algo in algorithms}

    while True:
        chunk = fobj.read(HASH_BLOCK_SIZE)
        if not chunk:
            break
        for hash in hashes.values():
            hash.update(chunk)
        if chunk_cb:
            chunk_cb(chunk)

    return {algo: hash.digest() for algo, hash in hashes.items()}


def hash_path(path, algorithms=DEFAULT_ALGORITHMS, chunk_cb=None):
    """Hash the contents of the file at the given path with the given
       algorithms.

    Args:
        path: the path of the file to hash
        algorithms: the hashing algorithms used
        chunk_cb: a callback

    Returns: a dict mapping each algorithm to a bytes digest.

    Raises:
        ValueError if algorithms contains an unknown hash algorithm.
        OSError on file access error

    """
    length = os.path.getsize(path)
    with open(path, 'rb') as fobj:
        hash = hash_file(fobj, length, algorithms, chunk_cb)
    hash['length'] = length
    return hash


def hash_data(data, algorithms=DEFAULT_ALGORITHMS):
    """Hash the given binary blob with the given algorithms.

    Args:
        data: a bytes object
        algorithms: the hashing algorithms used

    Returns: a dict mapping each algorithm to a bytes digest

    Raises:
        TypeError if data does not support the buffer interface.
        ValueError if algorithms contains an unknown hash algorithm.
    """
    fobj = BytesIO(data)
    return hash_file(fobj, len(data), algorithms)


def hash_git_data(data, git_type, base_algo='sha1'):
    """Hash the given data as a git object of type git_type.

    Args:
        data: a bytes object
        git_type: the git object type
        base_algo: the base hashing algorithm used (default: sha1)

    Returns: a dict mapping each algorithm to a bytes digest

    Raises:
        ValueError if the git_type is unexpected.
    """

    git_object_types = {'blob', 'tree', 'commit', 'tag'}

    if git_type not in git_object_types:
        raise ValueError('Unexpected git object type %s, expected one of %s' %
                         (git_type, ', '.join(sorted(git_object_types))))

    h = _new_git_hash(base_algo, git_type, len(data))
    h.update(data)

    return h.digest()


@functools.lru_cache()
def hash_to_hex(hash):
    """Converts a hash (in hex or bytes form) to its hexadecimal ascii form"""
    if isinstance(hash, str):
        return hash
    return binascii.hexlify(hash).decode('ascii')


@functools.lru_cache()
def hash_to_bytehex(hash):
    """Converts a hash to its hexadecimal bytes representation"""
    return binascii.hexlify(hash)


@functools.lru_cache()
def hash_to_bytes(hash):
    """Converts a hash (in hex or bytes form) to its raw bytes form"""
    if isinstance(hash, bytes):
        return hash
    return bytes.fromhex(hash)


@functools.lru_cache()
def bytehex_to_hash(hex):
    """Converts a hexadecimal bytes representation of a hash to that hash"""
    return hash_to_bytes(hex.decode())
