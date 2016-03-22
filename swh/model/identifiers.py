# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
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

    raise ValueError('Wrong type for identifier %s, expected bytes or str' %
                     identifier.__class__.__name__)


@lru_cache()
def identifier_to_str(identifier):
    """Convert an identifier to an hexadecimal string.

    Args:
        identifier: an identifier, either a 40-char hexadecimal string or a
                    bytes object of length 20
    Returns:
        The length 40 string corresponding to the given identifier, hex encoded

    Raises:
        ValueError if the identifier is of an unexpected type or length.
    """

    if isinstance(identifier, str):
        if len(identifier) != 40:
            raise ValueError(
                'Wrong length for str identifier %s, expected 40' %
                len(identifier))
        return identifier

    if isinstance(identifier, bytes):
        if len(identifier) != 20:
            raise ValueError(
                'Wrong length for bytes identifier %s, expected 20' %
                len(identifier))
        return binascii.hexlify(identifier).decode()

    raise ValueError('Wrong type for identifier %s, expected bytes or str' %
                     identifier.__class__.__name__)


def content_identifier(content):
    """Return the intrinsic identifier for a content.

    A content's identifier is the sha1, sha1_git and sha256 checksums of its
    data.

    Args:
        content: a content conforming to the Software Heritage schema

    Returns:
        A dictionary with all the hashes for the data

    Raises:
        KeyError if the content doesn't have a data member.

    """

    hashes = hashutil.hash_data(
        content['data'],
        {'sha1', 'sha1_git', 'sha256'},
    )

    return hashes


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
            b'100644' (int 33188) for files
            b'100755' (int 33261) for executable files
            b'120000' (int 40960) for symbolic links
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

    return identifier_to_str(hashutil.hash_git_data(b''.join(components),
                                                    'tree'))


def format_date(date):
    """Convert a date object into an UTC timestamp encoded as ascii bytes.

    Git stores timestamps as an integer number of seconds since the UNIX epoch.

    However, Software Heritage stores timestamps as an integer number of
    microseconds (postgres type "datetime with timezone").

    Therefore, we print timestamps with no microseconds as integers, and
    timestamps with microseconds as floating point values.

    """
    if isinstance(date, datetime.datetime):
        if date.microsecond == 0:
            date = int(date.timestamp())
        else:
            date = date.timestamp()
        return str(date).encode()
    else:
        if date == int(date):
            date = int(date)
        return str(date).encode()


@lru_cache()
def format_offset(offset):
    """Convert an integer number of minutes into an offset representation.

    The offset representation is [+-]hhmm where:
        hh is the number of hours;
        mm is the number of minutes.

    A null offset is represented as +0000.
    """
    if offset >= 0:
        sign = '+'
    else:
        sign = '-'

    hours = abs(offset) // 60
    minutes = abs(offset) % 60

    t = '%s%02d%02d' % (sign, hours, minutes)
    return t.encode()


def format_date_offset(date_offset):
    """Format a date-compatible object with its timezone offset.

    A date-compatible object is either:
        - a dict with two members
            timestamp: floating point number of seconds since the unix epoch
            offset: (int) number of minutes representing the offset from UTC
        - a datetime.datetime object with a timezone
        - a numeric value (in which case the offset is hardcoded to 0)
    """

    # FIXME: move normalization to another module

    if isinstance(date_offset, dict):
        date = date_offset['timestamp']
        offset = date_offset['offset']
    elif isinstance(date_offset, datetime.datetime):
        date = date_offset
        utcoffset = date_offset.utcoffset()
        if utcoffset is None:
            raise ValueError('Received a datetime without a timezone')
        seconds_offset = utcoffset.total_seconds()
        if seconds_offset - int(seconds_offset) != 0 or seconds_offset % 60:
            raise ValueError('Offset is not an integer number of minutes')
        offset = int(seconds_offset) // 60
    else:
        date = date_offset
        offset = 0

    return b''.join([format_date(date), b' ', format_offset(offset)])


def format_author(author):
    return b''.join([author['name'], b' <', author['email'], b'>'])


def revision_identifier(revision):
    """Return the intrinsic identifier for a revision.
    """
    components = [
        b'tree ', identifier_to_str(revision['directory']).encode(), b'\n',
    ]
    for parent in revision['parents']:
        if parent:
            components.extend([
                b'parent ', identifier_to_str(parent).encode(), b'\n',
            ])

    components.extend([
        b'author ', format_author(revision['author']),
        b' ', format_date_offset(revision['date']), b'\n',
        b'committer ', format_author(revision['committer']),
        b' ', format_date_offset(revision['committer_date']), b'\n',
    ])

    metadata = revision.get('metadata', {})
    if 'extra-headers' in metadata:
        headers = metadata['extra-headers']
        keys = list(headers.keys())
        keys.sort()
        for header_key in keys:
            val = headers[header_key]
            if isinstance(val, int):
                val = str(val).encode('utf-8')
            if isinstance(val, str):
                val = val.encode('utf-8')
            if isinstance(header_key, str):
                key = header_key.encode('utf-8')
            else:
                key = header_key

            components.extend([key, b' ', val, b'\n'])

    components.extend([b'\n', revision['message']])

    commit_raw = b''.join(components)
    return identifier_to_str(hashutil.hash_git_data(commit_raw, 'commit'))


def target_type_to_git(target_type):
    """Convert a software heritage target type to a git object type"""
    return {
        'content': b'blob',
        'directory': b'tree',
        'revision': b'commit',
        'release': b'tag',
    }[target_type]


def release_identifier(release):
    """Return the intrinsic identifier for a release."""
    components = [
        b'object ', identifier_to_str(release['target']).encode(), b'\n',
        b'type ', target_type_to_git(release['target_type']), b'\n',
        b'tag ', release['name'], b'\n',
    ]

    if 'author' in release and release['author']:
        components.extend([
            b'tagger ', format_author(release['author']), b' ',
            format_date_offset(release['date']), b'\n',
        ])

    components.extend([b'\n', release['message']])

    return identifier_to_str(hashutil.hash_git_data(b''.join(components),
                                                    'tag'))
