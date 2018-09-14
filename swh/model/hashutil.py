# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Module in charge of hashing function definitions. This is the base
module use to compute swh's hashes.

Only a subset of hashing algorithms is supported as defined in the
ALGORITHMS set. Any provided algorithms not in that list will result
in a ValueError explaining the error.

This modules defines the following hashing functions:

- hash_stream: Hash the contents of something iterable (file, stream,
  ...) with the given algorithms (defaulting to DEFAULT_ALGORITHMS if
  none provided).

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

from io import BytesIO

ALGORITHMS = set(['sha1', 'sha256', 'sha1_git', 'blake2s256', 'blake2b512'])
"""Hashing algorithms supported by this module"""

DEFAULT_ALGORITHMS = set(['sha1', 'sha256', 'sha1_git', 'blake2s256'])
"""Algorithms computed by default when calling the functions from this module.

Subset of :const:`ALGORITHMS`.
"""

HASH_BLOCK_SIZE = 32768
"""Block size for streaming hash computations made in this module"""

_blake2_hash_cache = {}

HASH_FORMATS = set(['bytes', 'bytehex', 'hex'])
"""Supported output hash formats
"""


class MultiHash:
    """Hashutil class to support multiple hashes computation.

    Args:

        hash_names (set): Set of hash algorithms (+ length) to compute
                          hashes (cf. DEFAULT_ALGORITHMS)
        length (int): Length of the total sum of chunks to read

    If the length is provided as algorithm, the length is also
    computed and returned.

    """
    def __init__(self, hash_names=DEFAULT_ALGORITHMS, length=None):
        self.state = {}
        self.track_length = False
        for name in hash_names:
            if name == 'length':
                self.state['length'] = 0
                self.track_length = True
            else:
                self.state[name] = _new_hash(name, length)

    @classmethod
    def from_state(cls, state, track_length):
        ret = cls([])
        ret.state = state
        ret.track_length = track_length

    def update(self, chunk):
        for name, h in self.state.items():
            if name == 'length':
                continue
            h.update(chunk)
        if self.track_length:
            self.state['length'] += len(chunk)

    def digest(self):
        return {
            name: h.digest() if name != 'length' else h
            for name, h in self.state.items()
        }

    def hexdigest(self):
        return {
            name: h.hexdigest() if name != 'length' else h
            for name, h in self.state.items()
        }

    def bytehexdigest(self):
        return {
            name: hash_to_bytehex(h.digest()) if name != 'length' else h
            for name, h in self.state.items()
        }

    def copy(self):
        copied_state = {
            name: h.copy() if name != 'length' else h
            for name, h in self.state.items()
        }
        return self.from_state(copied_state, self.track_length)


def _new_blake2_hash(algo):
    """Return a function that initializes a blake2 hash.

    """
    if algo in _blake2_hash_cache:
        return _blake2_hash_cache[algo]()

    lalgo = algo.lower()
    if not lalgo.startswith('blake2'):
        raise ValueError('Algorithm %s is not a blake2 hash' % algo)

    blake_family = lalgo[:7]

    digest_size = None
    if lalgo[7:]:
        try:
            digest_size, remainder = divmod(int(lalgo[7:]), 8)
        except ValueError:
            raise ValueError(
                'Unknown digest size for algo %s' % algo
            ) from None
        if remainder:
            raise ValueError(
                'Digest size for algorithm %s must be a multiple of 8' % algo
            )

    if lalgo in hashlib.algorithms_available:
        # Handle the case where OpenSSL ships the given algorithm
        # (e.g. Python 3.5 on Debian 9 stretch)
        _blake2_hash_cache[algo] = lambda: hashlib.new(lalgo)
    else:
        # Try using the built-in implementation for Python 3.6+
        if blake_family in hashlib.algorithms_available:
            blake2 = getattr(hashlib, blake_family)
        else:
            import pyblake2
            blake2 = getattr(pyblake2, blake_family)

        _blake2_hash_cache[algo] = lambda: blake2(digest_size=digest_size)

    return _blake2_hash_cache[algo]()


def _new_hashlib_hash(algo):
    """Initialize a digest object from hashlib.

    Handle the swh-specific names for the blake2-related algorithms
    """
    if algo.startswith('blake2'):
        return _new_blake2_hash(algo)
    else:
        return hashlib.new(algo)


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
        base_algo (str from :const:`ALGORITHMS`): a hashlib-supported algorithm
        git_type: the type of the git object (supposedly one of 'blob',
                  'commit', 'tag', 'tree')
        length: the length of the git object you're encoding

    Returns:
        a hashutil.hash object
    """

    h = _new_hashlib_hash(base_algo)
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

    return _new_hashlib_hash(algo)


def _read(fobj):
    """Wrapper function around reading a chunk from fobj.

    """
    return fobj.read(HASH_BLOCK_SIZE)


def hash_stream(s, readfn=_read, length=None, algorithms=DEFAULT_ALGORITHMS,
                chunk_cb=None, hash_format='bytes'):
    """Hash the contents of a stream

    Args:
        s: stream or object we can consume by successive call using `readfn`
        readfn (fn): Function to read chunk data from s
        length (int): the length of the contents of the object (for the
                      git-specific algorithms)
        algorithms (set): the hashing algorithms to be used, as an
                          iterable over strings
        hash_format (str): Format required for the output of the
                           computed hashes (cf. HASH_FORMATS)

    Returns: a dict mapping each algorithm to a digest (bytes by default).

    Raises:
        ValueError if:

            algorithms contains an unknown hash algorithm.
            hash_format is an unknown hash format

    """
    if hash_format not in HASH_FORMATS:
        raise ValueError('Unexpected hash format %s, expected one of %s' % (
            hash_format, HASH_FORMATS))

    h = MultiHash(algorithms, length)
    while True:
        chunk = readfn(s)
        if not chunk:
            break
        h.update(chunk)
        if chunk_cb:
            chunk_cb(chunk)

    if hash_format == 'bytes':
        return h.digest()
    if hash_format == 'bytehex':
        return h.bytehexdigest()
    return h.hexdigest()


def hash_file(fobj, length=None, algorithms=DEFAULT_ALGORITHMS,
              chunk_cb=None, hash_format='bytes'):
    """Hash the contents of the given file object with the given algorithms.

    Args:
        fobj: a file-like object
        length: the length of the contents of the file-like object (for the
          git-specific algorithms)
        algorithms: the hashing algorithms to be used, as an iterable over
          strings
        hash_format (str): Format required for the output of the
                           computed hashes (cf. HASH_FORMATS)

    Returns: a dict mapping each algorithm to a digest (bytes by default).

    Raises:
        ValueError if:

            algorithms contains an unknown hash algorithm.
            hash_format is an unknown hash format

    """
    return hash_stream(fobj, length=length, algorithms=algorithms,
                       chunk_cb=chunk_cb, hash_format=hash_format)


def hash_path(path, algorithms=DEFAULT_ALGORITHMS, chunk_cb=None,
              hash_format='bytes', track_length=True):
    """Hash the contents of the file at the given path with the given
       algorithms.

    Args:
        path (str): the path of the file to hash
        algorithms (set): the hashing algorithms used
        chunk_cb (def): a callback
        hash_format (str): Format required for the output of the
                           computed hashes (cf. HASH_FORMATS)

    Returns: a dict mapping each algorithm to a bytes digest.

    Raises:
        ValueError if:

            algorithms contains an unknown hash algorithm.
            hash_format is an unknown hash format

        OSError on file access error

    """
    if track_length:
        algorithms = set(['length']).union(algorithms)
    length = os.path.getsize(path)
    with open(path, 'rb') as fobj:
        return hash_file(fobj, length, algorithms, chunk_cb=chunk_cb,
                         hash_format=hash_format)


def hash_data(data, algorithms=DEFAULT_ALGORITHMS, hash_format='bytes'):
    """Hash the given binary blob with the given algorithms.

    Args:
        data (bytes): raw content to hash
        algorithms (list): the hashing algorithms used
        hash_format (str): Format required for the output of the
                           computed hashes (cf. HASH_FORMATS)

    Returns: a dict mapping each algorithm to a bytes digest

    Raises:
        TypeError if data does not support the buffer interface.
        ValueError if:

            algorithms contains an unknown hash algorithm.
            hash_format is an unknown hash format

    """
    fobj = BytesIO(data)
    length = len(data)
    return hash_file(fobj, length, algorithms, hash_format=hash_format)


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

    git_object_types = {'blob', 'tree', 'commit', 'tag', 'snapshot'}

    if git_type not in git_object_types:
        raise ValueError('Unexpected git object type %s, expected one of %s' %
                         (git_type, ', '.join(sorted(git_object_types))))

    h = _new_git_hash(base_algo, git_type, len(data))
    h.update(data)

    return h.digest()


@functools.lru_cache()
def hash_to_hex(hash):
    """Converts a hash (in hex or bytes form) to its hexadecimal ascii form

    Args:
      hash (str or bytes): a :class:`bytes` hash or a :class:`str` containing
        the hexadecimal form of the hash

    Returns:
      str: the hexadecimal form of the hash
    """
    if isinstance(hash, str):
        return hash
    return binascii.hexlify(hash).decode('ascii')


@functools.lru_cache()
def hash_to_bytehex(hash):
    """Converts a hash to its hexadecimal bytes representation

    Args:
      hash (bytes): a :class:`bytes` hash

    Returns:
      bytes: the hexadecimal form of the hash, as :class:`bytes`
    """
    return binascii.hexlify(hash)


@functools.lru_cache()
def hash_to_bytes(hash):
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
def bytehex_to_hash(hex):
    """Converts a hexadecimal bytes representation of a hash to that hash

    Args:
      hash (bytes): a :class:`bytes` containing the hexadecimal form of the
        hash encoded in ascii

    Returns:
      bytes: the :class:`bytes` form of the hash
    """
    return hash_to_bytes(hex.decode())
