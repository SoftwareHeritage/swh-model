# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime

from collections import namedtuple
from functools import lru_cache

from .exceptions import ValidationError
from .fields.hashes import validate_sha1
from .hashutil import hash_git_data, hash_to_hex, MultiHash


SNAPSHOT = 'snapshot'
REVISION = 'revision'
RELEASE = 'release'
DIRECTORY = 'directory'
CONTENT = 'content'


@lru_cache()
def identifier_to_bytes(identifier):
    """Convert a text identifier to bytes.

    Args:
        identifier: an identifier, either a 40-char hexadecimal string or a
            bytes object of length 20
    Returns:
        The length 20 bytestring corresponding to the given identifier

    Raises:
        ValueError: if the identifier is of an unexpected type or length.
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
        ValueError: if the identifier is of an unexpected type or length.
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
        KeyError: if the content doesn't have a data member.

    """

    return MultiHash.from_data(content['data']).digest()


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


def escape_newlines(snippet):
    """Escape the newlines present in snippet according to git rules.

    New lines in git manifests are escaped by indenting the next line by one
    space.

    """

    if b'\n' in snippet:
        return b'\n '.join(snippet.split(b'\n'))
    else:
        return snippet


def directory_identifier(directory):
    """Return the intrinsic identifier for a directory.

    A directory's identifier is the tree sha1 à la git of a directory listing,
    using the following algorithm, which is equivalent to the git algorithm for
    trees:

    1. Entries of the directory are sorted using the name (or the name with '/'
       appended for directory entries) as key, in bytes order.

    2. For each entry of the directory, the following bytes are output:

      - the octal representation of the permissions for the entry (stored in
        the 'perms' member), which is a representation of the entry type:

        - b'100644' (int 33188) for files
        - b'100755' (int 33261) for executable files
        - b'120000' (int 40960) for symbolic links
        - b'40000'  (int 16384) for directories
        - b'160000' (int 57344) for references to revisions

      - an ascii space (b'\x20')
      - the entry's name (as raw bytes), stored in the 'name' member
      - a null byte (b'\x00')
      - the 20 byte long identifier of the object pointed at by the entry,
        stored in the 'target' member:

        - for files or executable files: their blob sha1_git
        - for symbolic links: the blob sha1_git of a file containing the link
          destination
        - for directories: their intrinsic identifier
        - for revisions: their intrinsic identifier

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
    timestamps with microseconds as floating point values. We elide the
    trailing zeroes from microsecond values, to "future-proof" our
    representation if we ever need more precision in timestamps.

    """
    if not isinstance(date, dict):
        raise ValueError('format_date only supports dicts, %r received' % date)

    seconds = date.get('seconds', 0)
    microseconds = date.get('microseconds', 0)
    if not microseconds:
        return str(seconds).encode()
    else:
        float_value = ('%d.%06d' % (seconds, microseconds))
        return float_value.rstrip('0').encode()


@lru_cache()
def format_offset(offset, negative_utc=None):
    """Convert an integer number of minutes into an offset representation.

    The offset representation is [+-]hhmm where:

    - hh is the number of hours;
    - mm is the number of minutes.

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
    seconds since the UNIX epoch, 1970-01-01 at 00:00 UTC), a
    :obj:`datetime.datetime` object (with timezone information), or a
    normalized Software Heritage time representation (idempotency).

    Args:
        time_representation: the representation of a timestamp

    Returns:
        dict: a normalized dictionary with three keys:

            - timestamp: a dict with two optional keys:

               - seconds: the integral number of seconds since the UNIX epoch
               - microseconds: the integral number of microseconds

            - offset: the timezone offset as a number of minutes relative to
              UTC
            - negative_utc: a boolean representing whether the offset is -0000
              when offset = 0.

    """

    if time_representation is None:
        return None

    negative_utc = False

    if isinstance(time_representation, dict):
        ts = time_representation['timestamp']
        if isinstance(ts, dict):
            seconds = ts.get('seconds', 0)
            microseconds = ts.get('microseconds', 0)
        elif isinstance(ts, int):
            seconds = ts
            microseconds = 0
        else:
            raise ValueError(
                'normalize_timestamp received non-integer timestamp member:'
                ' %r' % ts)
        offset = time_representation['offset']
        if 'negative_utc' in time_representation:
            negative_utc = time_representation['negative_utc']
    elif isinstance(time_representation, datetime.datetime):
        seconds = int(time_representation.timestamp())
        microseconds = time_representation.microsecond
        utcoffset = time_representation.utcoffset()
        if utcoffset is None:
            raise ValueError(
                'normalize_timestamp received datetime without timezone: %s' %
                time_representation)

        # utcoffset is an integer number of minutes
        seconds_offset = utcoffset.total_seconds()
        offset = int(seconds_offset) // 60
    elif isinstance(time_representation, int):
        seconds = time_representation
        microseconds = 0
        offset = 0
    else:
        raise ValueError(
            'normalize_timestamp received non-integer timestamp:'
            ' %r' % time_representation)

    return {
        'timestamp': {
            'seconds': seconds,
            'microseconds': microseconds,
        },
        'offset': offset,
        'negative_utc': negative_utc,
    }


def format_author(author):
    """Format the specification of an author.

    An author is either a byte string (passed unchanged), or a dict with three
    keys, fullname, name and email.

    If the fullname exists, return it; if it doesn't, we construct a fullname
    using the following heuristics: if the name value is None, we return the
    email in angle brackets, else, we return the name, a space, and the email
    in angle brackets.

    """
    if isinstance(author, bytes) or author is None:
        return author

    if 'fullname' in author:
        return author['fullname']

    ret = []
    if author['name'] is not None:
        ret.append(author['name'])
    if author['email'] is not None:
        ret.append(b''.join([b'<', author['email'], b'>']))

    return b' '.join(ret)


def format_author_line(header, author, date_offset):
    """Format a an author line according to git standards.

    An author line has three components:

    - a header, describing the type of author (author, committer, tagger)
    - a name and email, which is an arbitrary bytestring
    - optionally, a timestamp with UTC offset specification

    The author line is formatted thus::

        `header` `name and email`[ `timestamp` `utc_offset`]

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
            email, or byte value)
        date_offset: a normalized date/time representation as returned by
            :func:`normalize_timestamp`.

    Returns:
        the newline-terminated byte string containing the author line

    """

    ret = [header.encode(), b' ', escape_newlines(format_author(author))]

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
    constructed as follows (newlines are a single ASCII newline character)::

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

    The directory identifier is the ascii representation of its hexadecimal
    encoding.

    Author and committer are formatted with the :func:`format_author` function.
    Dates are formatted with the :func:`format_offset` function.

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

        # encode the key to utf-8
        components.extend([key.encode('utf-8'), b' ',
                           escape_newlines(value), b'\n'])

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


def snapshot_identifier(snapshot, *, ignore_unresolved=False):
    """Return the intrinsic identifier for a snapshot.

    Snapshots are a set of named branches, which are pointers to objects at any
    level of the Software Heritage DAG.

    As well as pointing to other objects in the Software Heritage DAG, branches
    can also be *alias*es, in which case their target is the name of another
    branch in the same snapshot, or *dangling*, in which case the target is
    unknown (and represented by the ``None`` value).

    A snapshot identifier is a salted sha1 (using the git hashing algorithm
    with the ``snapshot`` object type) of a manifest following the algorithm:

    1. Branches are sorted using the name as key, in bytes order.

    2. For each branch, the following bytes are output:

      - the type of the branch target:

        - ``content``, ``directory``, ``revision``, ``release`` or ``snapshot``
          for the corresponding entries in the DAG;
        - ``alias`` for branches referencing another branch;
        - ``dangling`` for dangling branches

      - an ascii space (``\\x20``)
      - the branch name (as raw bytes)
      - a null byte (``\\x00``)
      - the length of the target identifier, as an ascii-encoded decimal number
        (``20`` for current intrinsic identifiers, ``0`` for dangling
        branches, the length of the target branch name for branch aliases)
      - a colon (``:``)
      - the identifier of the target object pointed at by the branch,
        stored in the 'target' member:

        - for contents: their *sha1_git*
        - for directories, revisions, releases or snapshots: their intrinsic
          identifier
        - for branch aliases, the name of the target branch (as raw bytes)
        - for dangling branches, the empty string

      Note that, akin to directory manifests, there is no separator between
      entries. Because of symbolic branches, identifiers are of arbitrary
      length but are length-encoded to avoid ambiguity.

    Args:
      snapshot (dict): the snapshot of which to compute the identifier. A
        single entry is needed, ``'branches'``, which is itself a :class:`dict`
        mapping each branch to its target
      ignore_unresolved (bool): if `True`, ignore unresolved branch aliases.

    Returns:
      str: the intrinsic identifier for `snapshot`

    """

    unresolved = []
    lines = []

    for name, target in sorted(snapshot['branches'].items()):
        if not target:
            target_type = b'dangling'
            target_id = b''
        elif target['target_type'] == 'alias':
            target_type = b'alias'
            target_id = target['target']
            if target_id not in snapshot['branches'] or target_id == name:
                unresolved.append((name, target_id))
        else:
            target_type = target['target_type'].encode()
            target_id = identifier_to_bytes(target['target'])

        lines.extend([
            target_type, b'\x20', name, b'\x00',
            ('%d:' % len(target_id)).encode(), target_id,
        ])

    if unresolved and not ignore_unresolved:
        raise ValueError('Branch aliases unresolved: %s' %
                         ', '.join('%s -> %s' % x for x in unresolved),
                         unresolved)

    return identifier_to_str(hash_git_data(b''.join(lines), 'snapshot'))


_object_type_map = {
    SNAPSHOT: {
        'short_name': 'snp',
        'key_id': 'id'
    },
    RELEASE: {
        'short_name': 'rel',
        'key_id': 'id'
    },
    REVISION: {
        'short_name': 'rev',
        'key_id': 'id'
    },
    DIRECTORY: {
        'short_name': 'dir',
        'key_id': 'id'
    },
    CONTENT: {
        'short_name': 'cnt',
        'key_id': 'sha1_git'
    }
}

PERSISTENT_IDENTIFIER_TYPES = ['snp', 'rel', 'rev', 'dir', 'cnt']

PERSISTENT_IDENTIFIER_KEYS = [
    'namespace', 'scheme_version', 'object_type', 'object_id', 'metadata']

PERSISTENT_IDENTIFIER_PARTS_SEP = ';'


class PersistentId(namedtuple('PersistentId', PERSISTENT_IDENTIFIER_KEYS)):
    """
    Named tuple holding the relevant info associated to a Software Heritage
    persistent identifier.

    Args:
        namespace (str): the namespace of the identifier, defaults to 'swh'
        scheme_version (int): the scheme version of the identifier,
            defaults to 1
        object_type (str): the type of object the identifier points to,
            either 'content', 'directory', 'release', 'revision' or 'snapshot'
        object_id (dict/bytes/str): object's dict representation or
            object identifier
        metadata (dict): optional dict filled with metadata related to
            pointed object

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    Once created, it contains the following attributes:

    Attributes:
        namespace (str): the namespace of the identifier
        scheme_version (int): the scheme version of the identifier
        object_type (str): the type of object the identifier points to
        object_id (str): hexadecimal representation of the object hash
        metadata (dict): metadata related to the pointed object

    To get the raw persistent identifier string from an instance of
    this named tuple, use the :func:`str` function::

        pid = PersistentId(object_type='content', object_id='8ff44f081d43176474b267de5451f2c2e88089d0')
        pid_str = str(pid) # 'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'
    """ # noqa
    __slots__ = ()

    def __new__(cls, namespace='swh', scheme_version=1,
                object_type='', object_id='', metadata={}):
        o = _object_type_map.get(object_type)
        if not o:
            raise ValidationError('Wrong input: Supported types are %s' % (
                list(_object_type_map.keys())))
        # internal swh representation resolution
        if isinstance(object_id, dict):
            object_id = object_id[o['key_id']]
        validate_sha1(object_id)  # can raise if invalid hash
        object_id = hash_to_hex(object_id)
        return super(cls, PersistentId).__new__(
            cls, namespace, scheme_version, object_type, object_id, metadata)

    def __str__(self):
        o = _object_type_map.get(self.object_type)
        pid = '%s:%s:%s:%s' % (self.namespace, self.scheme_version,
                               o['short_name'], self.object_id)
        if self.metadata:
            for k, v in self.metadata.items():
                pid += '%s%s=%s' % (PERSISTENT_IDENTIFIER_PARTS_SEP, k, v)
        return pid


def persistent_identifier(object_type, object_id, scheme_version=1,
                          metadata={}):
    """Compute persistent identifier (stable over time) as per
       documentation.

    Documentation:
        https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html  # noqa

    Args:
        object_type (str): object's type, either 'content', 'directory',
            'release', 'revision' or 'snapshot'
        object_id (dict/bytes/str): object's dict representation or object
            identifier
        scheme_version (int): persistent identifier scheme version,
            defaults to 1
        metadata (dict): metadata related to the pointed object

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type
        or id

    Returns:
        str: the persistent identifier

    """
    pid = PersistentId(scheme_version=scheme_version, object_type=object_type,
                       object_id=object_id, metadata=metadata)
    return str(pid)


def parse_persistent_identifier(persistent_id):
    """Parse swh's :ref:`persistent-identifiers` scheme.

    Args:
        persistent_id (str): A persistent identifier

    Raises:
        swh.model.exceptions.ValidationError: in case of:

            * missing mandatory values (4)
            * invalid namespace supplied
            * invalid version supplied
            * invalid type supplied
            * missing hash
            * invalid hash identifier supplied

    Returns:
        PersistentId: a named tuple holding the parsing result

    """
    # <pid>;<contextual-information>
    persistent_id_parts = persistent_id.split(PERSISTENT_IDENTIFIER_PARTS_SEP)
    pid_data = persistent_id_parts.pop(0).split(':')

    if len(pid_data) != 4:
        raise ValidationError(
            'Wrong format: There should be 4 mandatory values')

    # Checking for parsing errors
    _ns, _version, _type, _id = pid_data
    if _ns != 'swh':
        raise ValidationError(
            'Wrong format: Supported namespace is \'swh\'')

    if _version != '1':
        raise ValidationError(
            'Wrong format: Supported version is 1')

    pid_data[1] = int(pid_data[1])

    expected_types = PERSISTENT_IDENTIFIER_TYPES
    if _type not in expected_types:
        raise ValidationError(
            'Wrong format: Supported types are %s' % (
                ', '.join(expected_types)))

    for otype, data in _object_type_map.items():
        if _type == data['short_name']:
            pid_data[2] = otype
            break

    if not _id:
        raise ValidationError(
            'Wrong format: Identifier should be present')

    try:
        validate_sha1(_id)
    except ValidationError:
        raise ValidationError(
           'Wrong format: Identifier should be a valid hash')

    persistent_id_metadata = {}
    for part in persistent_id_parts:
        try:
            key, val = part.split('=')
            persistent_id_metadata[key] = val
        except Exception:
            msg = 'Contextual data is badly formatted, form key=val expected'
            raise ValidationError(msg)
    pid_data.append(persistent_id_metadata)
    return PersistentId._make(pid_data)
