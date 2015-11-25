# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from functools import lru_cache

from . import hashutil


@lru_cache()
def identifier_to_bytes(identifier):
    """Convert a text identifier to bytes.

    Args:
        identifier: an identifier, either a 40-char hexadecimal string or a
                    bytes object of length 20
    Returns:
        The length 20 bytestring corresponding to the given identifier

    Raises:
        ValueError if the identifier is of an unexpected type or length.
    """

    if isinstance(identifier, bytes):
        if len(identifier) != 20:
            raise ValueError(
                'Wrong length for bytes identifier %s, expected 20' %
                len(identifier))
        return identifier

    if isinstance(identifier, str):
        if len(identifier) != 40:
            raise ValueError(
                'Wrong length for str identifier %s, expected 40' %
                len(identifier))
        return bytes.fromhex(identifier)

    raise ValueError('Wrong type for identitfier %s, expected bytes or str' %
                     identifier.__class__.__name__)


def content_identifier(content):
    """Return the intrinsic identifier for a content.

    A content's identifier is the sha1 checksum of its data.

    Args:
        content: a content conforming to the Software Heritage schema

    Returns:
        The intrinsic identifier of the content as a text string.

    Raises:
        KeyError if the content doesn't have a data member.
    """

    hashes = hashutil.hash_data(content['data'], {'sha1'})

    return hashes['sha1']


def _sort_key(entry):
    """The sorting key for tree entries"""
    if entry['type'] == 'dir':
        return entry['name'] + b'/'
    else:
        return entry['name']


@lru_cache()
def _perms_to_bytes(perms):
    """Convert the perms value to its bytes representation"""
    oc = oct(perms)[2:]
    return oc.encode('ascii')


def directory_identifier(directory):
    """Return the intrinsic identifier for a directory.

    A directory's identifier is the tree sha1 à la git of a directory listing,
    using the following algorithm, which is equivalent to the git algorithm for
    trees:

    1. Entries of the directory are sorted using the name (or the name with '/'
    appended for directory entries) as key, in bytes order.

    2. For each entry of the directory, the following bytes are output:
        - the octal representation of the permissions for the entry
          (stored in the 'perms' member), which is a representation of the
          entry type:
            b'100644' (int 33188)for files
            b'100755' (int 33261)for executable files
            b'120000' (int 40960)for symbolic links
            b'40000' (int 16384) for directories
            b'160000' (int 57344) for references to revisions
        - an ascii space (b'\x20')
        - the entry's name (as raw bytes), stored in the 'name' member
        - a null byte (b'\x00')
        - the 20 byte long identifier of the object pointed at by the entry,
          stored in the 'target' member:
            for files or executable files: their blob sha1_git
            for symbolic links: the blob sha1_git of a file containing the
                                link destination
            for directories: their intrinsic identifier
            for revisions: their intrinsic identifier

      (Note that there is no separator between entries)

    """

    components = []

    for entry in sorted(directory['entries'], key=_sort_key):
        components.extend([
            _perms_to_bytes(entry['perms']),
            b'\x20',
            entry['name'],
            b'\x00',
            identifier_to_bytes(entry['target']),
        ])

    return hashutil.hash_git_data(b''.join(components), 'tree')
