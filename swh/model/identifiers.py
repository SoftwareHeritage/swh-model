# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
from functools import lru_cache

from .hashutil import hash_data, hash_git_data


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

    hashes = hash_data(
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

    return identifier_to_str(hash_git_data(b''.join(components), 'tree'))


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
def format_offset(offset, negative_utc=None):
    """Convert an integer number of minutes into an offset representation.

    The offset representation is [+-]hhmm where:
        hh is the number of hours;
        mm is the number of minutes.

    A null offset is represented as +0000.
    """
    if offset < 0 or offset == 0 and negative_utc:
        sign = '-'
    else:
        sign = '+'

    hours = abs(offset) // 60
    minutes = abs(offset) % 60

    t = '%s%02d%02d' % (sign, hours, minutes)
    return t.encode()


def normalize_timestamp(time_representation):
    """Normalize a time representation for processing by Software Heritage

    This function supports a numeric timestamp (representing a number of
    seconds since the UNIX epoch, 1970-01-01 at 00:00 UTC), a datetime.datetime
    object (with timezone information), or a normalized Software
    Heritage time representation (idempotency).

    Args:
        time_representation: the representation of a timestamp

    Returns: a normalized dictionary with three keys

     - timestamp: a number of seconds since the UNIX epoch (1970-01-01 at 00:00
       UTC)
     - offset: the timezone offset as a number of minutes relative to UTC
     - negative_utc: a boolean representing whether the offset is -0000 when
       offset = 0.

    """

    if time_representation is None:
        return None

    negative_utc = False

    if isinstance(time_representation, dict):
        timestamp = time_representation['timestamp']
        offset = time_representation['offset']
        if 'negative_utc' in time_representation:
            negative_utc = time_representation['negative_utc']
    elif isinstance(time_representation, datetime.datetime):
        timestamp = time_representation.timestamp()
        utcoffset = time_representation.utcoffset()
        if utcoffset is None:
            raise ValueError(
                'normalize_timestamp received datetime without timezone: %s' %
                time_representation)

        # utcoffset is an integer number of minutes
        seconds_offset = utcoffset.total_seconds()
        offset = int(seconds_offset) // 60
    else:
        timestamp = time_representation
        offset = 0

    return {
        'timestamp': timestamp,
        'offset': offset,
        'negative_utc': negative_utc,
    }


def format_author_line(header, author, date_offset):
    """Format a an author line according to git standards.

    An author line has four components:
     - a header, describing the type of author (author, committer, tagger)
     - a name, which is an arbitrary byte string
     - an email, which is an arbitrary byte string too
     - optionally, a timestamp with UTC offset specification

    The author line is formatted thus:

        `header` `name` <`email`>[ `timestamp` `utc_offset`]

    If name or email are empty, they are passed as is (so you can find author
    lines with empty square brackets or two spaces between the header and the
    opening bracket).

    The timestamp is encoded as a (decimal) number of seconds since the UNIX
    epoch (1970-01-01 at 00:00 UTC). As an extension to the git format, we
    support fractional timestamps, using a dot as the separator for the decimal
    part.

    The utc offset is a number of minutes encoded as '[+-]HHMM'. Note some
    tools can pass a negative offset corresponding to the UTC timezone
    ('-0000'), which is valid and is encoded as such.

    For convenience, this function returns the whole line with its trailing
    newline.

    Args:
        header: the header of the author line (one of 'author', 'committer',
                'tagger')
        author: an author specification (dict with two bytes values: name and
                email)
        date_offset: a normalized date/time representation as returned by
                     `normalize_timestamp`.

    Returns:
        the newline-terminated byte string containing the author line

    """

    ret = [header.encode(), b' ', author['name'], b' <', author['email'], b'>']

    date_offset = normalize_timestamp(date_offset)

    if date_offset is not None:
        date_f = format_date(date_offset['timestamp'])
        offset_f = format_offset(date_offset['offset'],
                                 date_offset['negative_utc'])

        ret.extend([b' ', date_f, b' ', offset_f])

    ret.append(b'\n')
    return b''.join(ret)


def revision_identifier(revision):
    """Return the intrinsic identifier for a revision.

    The fields used for the revision identifier computation are:
     - directory
     - parents
     - author
     - author_date
     - committer
     - committer_date
     - metadata -> extra_headers
     - message

    A revision's identifier is the 'git'-checksum of a commit manifest
    constructed as follows (newlines are a single ASCII newline character):

    ```
    tree <directory identifier>
    [for each parent in parents]
    parent <parent identifier>
    [end for each parents]
    author <author> <author_date>
    committer <committer> <committer_date>
    [for each key, value in extra_headers]
    <key> <encoded value>
    [end for each extra_headers]

    <message>
    ```

    The directory identifier is the ascii representation of its hexadecimal
    encoding.

    Author and committer are formatted with the `format_author` function.
    Dates are formatted with the `format_date_offset` function.

    Extra headers are an ordered list of [key, value] pairs. Keys are strings
    and get encoded to utf-8 for identifier computation. Values are either byte
    strings, unicode strings (that get encoded to utf-8), or integers (that get
    encoded to their utf-8 decimal representation).

    Multiline extra header values are escaped by indenting the continuation
    lines with one ascii space.

    If the message is None, the manifest ends with the last header. Else, the
    message is appended to the headers after an empty line.

    The checksum of the full manifest is computed using the 'commit' git object
    type.

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
        format_author_line('author', revision['author'], revision['date']),
        format_author_line('committer', revision['committer'],
                           revision['committer_date']),
    ])

    # Handle extra headers
    metadata = revision.get('metadata')
    if not metadata:
        metadata = {}

    for key, value in metadata.get('extra_headers', []):

        # Integer values: decimal representation
        if isinstance(value, int):
            value = str(value).encode('utf-8')

        # Unicode string values: utf-8 encoding
        if isinstance(value, str):
            value = value.encode('utf-8')

        # multi-line values: indent continuation lines
        if b'\n' in value:
            value_chunks = value.split(b'\n')
            value = b'\n '.join(value_chunks)

        # encode the key to utf-8
        components.extend([key.encode('utf-8'), b' ', value, b'\n'])

    if revision['message'] is not None:
        components.extend([b'\n', revision['message']])

    commit_raw = b''.join(components)
    return identifier_to_str(hash_git_data(commit_raw, 'commit'))


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
        components.append(
            format_author_line('tagger', release['author'], release['date'])
        )

    if release['message'] is not None:
        components.extend([b'\n', release['message']])

    return identifier_to_str(hash_git_data(b''.join(components), 'tag'))
