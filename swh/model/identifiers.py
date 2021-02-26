# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import binascii
import datetime
import enum
from functools import lru_cache
import hashlib
import re
from typing import (
    Any,
    Dict,
    Generic,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)
import urllib.parse
import warnings

import attr
from attrs_strict import type_validator

from .collections import ImmutableDict
from .exceptions import ValidationError
from .fields.hashes import validate_sha1
from .hashutil import MultiHash, hash_git_data, hash_to_bytes, hash_to_hex


class ObjectType(enum.Enum):
    """Possible object types of a QualifiedSWHID or CoreSWHID.

    The values of each variant is what is used in the SWHID's string representation."""

    SNAPSHOT = "snp"
    REVISION = "rev"
    RELEASE = "rel"
    DIRECTORY = "dir"
    CONTENT = "cnt"


class ExtendedObjectType(enum.Enum):
    """Possible object types of an ExtendedSWHID.

    The variants are a superset of :cls:`ObjectType`'s"""

    SNAPSHOT = "snp"
    REVISION = "rev"
    RELEASE = "rel"
    DIRECTORY = "dir"
    CONTENT = "cnt"
    ORIGIN = "ori"
    RAW_EXTRINSIC_METADATA = "emd"


# The following are deprecated aliases of the variants defined in ObjectType
# while transitioning from SWHID to QualifiedSWHID
ORIGIN = "origin"
SNAPSHOT = "snapshot"
REVISION = "revision"
RELEASE = "release"
DIRECTORY = "directory"
CONTENT = "content"
RAW_EXTRINSIC_METADATA = "raw_extrinsic_metadata"

SWHID_NAMESPACE = "swh"
SWHID_VERSION = 1
SWHID_TYPES = ["snp", "rel", "rev", "dir", "cnt"]
EXTENDED_SWHID_TYPES = SWHID_TYPES + ["ori", "emd"]
SWHID_SEP = ":"
SWHID_CTXT_SEP = ";"
SWHID_QUALIFIERS = {"origin", "anchor", "visit", "path", "lines"}

SWHID_RE_RAW = (
    f"(?P<namespace>{SWHID_NAMESPACE})"
    f"{SWHID_SEP}(?P<scheme_version>{SWHID_VERSION})"
    f"{SWHID_SEP}(?P<object_type>{'|'.join(EXTENDED_SWHID_TYPES)})"
    f"{SWHID_SEP}(?P<object_id>[0-9a-f]{{40}})"
    f"({SWHID_CTXT_SEP}(?P<qualifiers>\\S+))?"
)
SWHID_RE = re.compile(SWHID_RE_RAW)


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
                "Wrong length for bytes identifier %s, expected 20" % len(identifier)
            )
        return identifier

    if isinstance(identifier, str):
        if len(identifier) != 40:
            raise ValueError(
                "Wrong length for str identifier %s, expected 40" % len(identifier)
            )
        return bytes.fromhex(identifier)

    raise ValueError(
        "Wrong type for identifier %s, expected bytes or str"
        % identifier.__class__.__name__
    )


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
                "Wrong length for str identifier %s, expected 40" % len(identifier)
            )
        return identifier

    if isinstance(identifier, bytes):
        if len(identifier) != 20:
            raise ValueError(
                "Wrong length for bytes identifier %s, expected 20" % len(identifier)
            )
        return binascii.hexlify(identifier).decode()

    raise ValueError(
        "Wrong type for identifier %s, expected bytes or str"
        % identifier.__class__.__name__
    )


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

    return MultiHash.from_data(content["data"]).digest()


def directory_entry_sort_key(entry):
    """The sorting key for tree entries"""
    if entry["type"] == "dir":
        return entry["name"] + b"/"
    else:
        return entry["name"]


@lru_cache()
def _perms_to_bytes(perms):
    """Convert the perms value to its bytes representation"""
    oc = oct(perms)[2:]
    return oc.encode("ascii")


def escape_newlines(snippet):
    """Escape the newlines present in snippet according to git rules.

    New lines in git manifests are escaped by indenting the next line by one
    space.

    """

    if b"\n" in snippet:
        return b"\n ".join(snippet.split(b"\n"))
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

    for entry in sorted(directory["entries"], key=directory_entry_sort_key):
        components.extend(
            [
                _perms_to_bytes(entry["perms"]),
                b"\x20",
                entry["name"],
                b"\x00",
                identifier_to_bytes(entry["target"]),
            ]
        )

    return identifier_to_str(hash_git_data(b"".join(components), "tree"))


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
        raise ValueError("format_date only supports dicts, %r received" % date)

    seconds = date.get("seconds", 0)
    microseconds = date.get("microseconds", 0)
    if not microseconds:
        return str(seconds).encode()
    else:
        float_value = "%d.%06d" % (seconds, microseconds)
        return float_value.rstrip("0").encode()


@lru_cache()
def format_offset(offset, negative_utc=None):
    """Convert an integer number of minutes into an offset representation.

    The offset representation is [+-]hhmm where:

    - hh is the number of hours;
    - mm is the number of minutes.

    A null offset is represented as +0000.
    """
    if offset < 0 or offset == 0 and negative_utc:
        sign = "-"
    else:
        sign = "+"

    hours = abs(offset) // 60
    minutes = abs(offset) % 60

    t = "%s%02d%02d" % (sign, hours, minutes)
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
        ts = time_representation["timestamp"]
        if isinstance(ts, dict):
            seconds = ts.get("seconds", 0)
            microseconds = ts.get("microseconds", 0)
        elif isinstance(ts, int):
            seconds = ts
            microseconds = 0
        else:
            raise ValueError(
                "normalize_timestamp received non-integer timestamp member:" " %r" % ts
            )
        offset = time_representation["offset"]
        if "negative_utc" in time_representation:
            negative_utc = time_representation["negative_utc"]
        if negative_utc is None:
            negative_utc = False
    elif isinstance(time_representation, datetime.datetime):
        seconds = int(time_representation.timestamp())
        microseconds = time_representation.microsecond
        utcoffset = time_representation.utcoffset()
        if utcoffset is None:
            raise ValueError(
                "normalize_timestamp received datetime without timezone: %s"
                % time_representation
            )

        # utcoffset is an integer number of minutes
        seconds_offset = utcoffset.total_seconds()
        offset = int(seconds_offset) // 60
    elif isinstance(time_representation, int):
        seconds = time_representation
        microseconds = 0
        offset = 0
    else:
        raise ValueError(
            "normalize_timestamp received non-integer timestamp:"
            " %r" % time_representation
        )

    return {
        "timestamp": {"seconds": seconds, "microseconds": microseconds,},
        "offset": offset,
        "negative_utc": negative_utc,
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

    if "fullname" in author:
        return author["fullname"]

    ret = []
    if author["name"] is not None:
        ret.append(author["name"])
    if author["email"] is not None:
        ret.append(b"".join([b"<", author["email"], b">"]))

    return b" ".join(ret)


def format_manifest(
    headers: Iterable[Tuple[bytes, bytes]], message: Optional[bytes] = None,
) -> bytes:
    """Format a manifest comprised of a sequence of `headers` and an optional `message`.

    The manifest format, compatible with the git format for tag and commit
    objects, is as follows:

      - for each `key`, `value` in `headers`, emit:

        - the `key`, literally
        - an ascii space (``\\x20``)
        - the `value`, with newlines escaped using :func:`escape_newlines`,
        - an ascii newline (``\\x0a``)

      - if the `message` is not None, emit:

        - an ascii newline (``\\x0a``)
        - the `message`, literally

    Args:
      headers: a sequence of key/value headers stored in the manifest;
      message: an optional message used to trail the manifest.

    Returns:
      the formatted manifest as bytes
    """
    entries: List[bytes] = []

    for key, value in headers:
        entries.extend((key, b" ", escape_newlines(value), b"\n"))

    if message is not None:
        entries.extend((b"\n", message))

    return b"".join(entries)


def hash_manifest(
    type: str, headers: Iterable[Tuple[bytes, bytes]], message: Optional[bytes] = None,
):
    """Hash the manifest of an object of type `type`, comprised of a sequence
    of `headers` and an optional `message`.

    Before hashing, the manifest is serialized with the :func:`format_manifest`
    function.

    We then use the git "salted sha1" (:func:`swh.model.hashutil.hash_git_data`)
    with the given `type` to hash the manifest.

    Args:
      type: the type of object for which we're computing a manifest (e.g.
        "tag", "commit", ...)
      headers: a sequence of key/value headers stored in the manifest;
      message: an optional message used to trail the manifest.

    """
    manifest = format_manifest(headers, message)
    return hash_git_data(manifest, type)


def format_author_data(author, date_offset) -> bytes:
    """Format authorship data according to git standards.

    Git authorship data has two components:

    - an author specification, usually a name and email, but in practice an
      arbitrary bytestring
    - optionally, a timestamp with a UTC offset specification

    The authorship data is formatted thus::

        `name and email`[ `timestamp` `utc_offset`]

    The timestamp is encoded as a (decimal) number of seconds since the UNIX
    epoch (1970-01-01 at 00:00 UTC). As an extension to the git format, we
    support fractional timestamps, using a dot as the separator for the decimal
    part.

    The utc offset is a number of minutes encoded as '[+-]HHMM'. Note that some
    tools can pass a negative offset corresponding to the UTC timezone
    ('-0000'), which is valid and is encoded as such.

    Args:
        author: an author specification (dict with two bytes values: name and
            email, or byte value)
        date_offset: a normalized date/time representation as returned by
            :func:`normalize_timestamp`.

    Returns:
        the byte string containing the authorship data

    """

    ret = [format_author(author)]

    date_offset = normalize_timestamp(date_offset)

    if date_offset is not None:
        date_f = format_date(date_offset["timestamp"])
        offset_f = format_offset(date_offset["offset"], date_offset["negative_utc"])

        ret.extend([b" ", date_f, b" ", offset_f])

    return b"".join(ret)


def revision_identifier(revision):
    """Return the intrinsic identifier for a revision.

    The fields used for the revision identifier computation are:

    - directory
    - parents
    - author
    - author_date
    - committer
    - committer_date
    - extra_headers or metadata -> extra_headers
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
    headers = [(b"tree", identifier_to_str(revision["directory"]).encode())]
    for parent in revision["parents"]:
        if parent:
            headers.append((b"parent", identifier_to_str(parent).encode()))

    headers.append(
        (b"author", format_author_data(revision["author"], revision["date"]))
    )
    headers.append(
        (
            b"committer",
            format_author_data(revision["committer"], revision["committer_date"]),
        )
    )

    # Handle extra headers
    metadata = revision.get("metadata") or {}
    extra_headers = revision.get("extra_headers", ())
    if not extra_headers and "extra_headers" in metadata:
        extra_headers = metadata["extra_headers"]

    headers.extend(extra_headers)

    return identifier_to_str(hash_manifest("commit", headers, revision["message"]))


def target_type_to_git(target_type):
    """Convert a software heritage target type to a git object type"""
    return {
        "content": b"blob",
        "directory": b"tree",
        "revision": b"commit",
        "release": b"tag",
        "snapshot": b"refs",
    }[target_type]


def release_identifier(release):
    """Return the intrinsic identifier for a release."""
    headers = [
        (b"object", identifier_to_str(release["target"]).encode()),
        (b"type", target_type_to_git(release["target_type"])),
        (b"tag", release["name"]),
    ]

    if "author" in release and release["author"]:
        headers.append(
            (b"tagger", format_author_data(release["author"], release["date"]))
        )

    return identifier_to_str(hash_manifest("tag", headers, release["message"]))


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

    for name, target in sorted(snapshot["branches"].items()):
        if not target:
            target_type = b"dangling"
            target_id = b""
        elif target["target_type"] == "alias":
            target_type = b"alias"
            target_id = target["target"]
            if target_id not in snapshot["branches"] or target_id == name:
                unresolved.append((name, target_id))
        else:
            target_type = target["target_type"].encode()
            target_id = identifier_to_bytes(target["target"])

        lines.extend(
            [
                target_type,
                b"\x20",
                name,
                b"\x00",
                ("%d:" % len(target_id)).encode(),
                target_id,
            ]
        )

    if unresolved and not ignore_unresolved:
        raise ValueError(
            "Branch aliases unresolved: %s"
            % ", ".join("%s -> %s" % x for x in unresolved),
            unresolved,
        )

    return identifier_to_str(hash_git_data(b"".join(lines), "snapshot"))


def origin_identifier(origin):
    """Return the intrinsic identifier for an origin.

    An origin's identifier is the sha1 checksum of the entire origin URL

    """
    return hashlib.sha1(origin["url"].encode("utf-8")).hexdigest()


_object_type_map = {
    ORIGIN: {"short_name": "ori", "key_id": "id"},
    SNAPSHOT: {"short_name": "snp", "key_id": "id"},
    RELEASE: {"short_name": "rel", "key_id": "id"},
    REVISION: {"short_name": "rev", "key_id": "id"},
    DIRECTORY: {"short_name": "dir", "key_id": "id"},
    CONTENT: {"short_name": "cnt", "key_id": "sha1_git"},
    RAW_EXTRINSIC_METADATA: {"short_name": "emd", "key_id": "id"},
}

_swhid_type_map = {
    "ori": ORIGIN,
    "snp": SNAPSHOT,
    "rel": RELEASE,
    "rev": REVISION,
    "dir": DIRECTORY,
    "cnt": CONTENT,
    "emd": RAW_EXTRINSIC_METADATA,
}


# type of the "object_type" attribute of the SWHID class; either
# ObjectType or ExtendedObjectType
_TObjectType = TypeVar("_TObjectType", ObjectType, ExtendedObjectType)

# the SWHID class itself (this is used so that X.from_string() can return X
# for all X subclass of _BaseSWHID)
_TSWHID = TypeVar("_TSWHID", bound="_BaseSWHID")


@attr.s(frozen=True, kw_only=True)
class _BaseSWHID(Generic[_TObjectType]):
    """Common base class for CoreSWHID, QualifiedSWHID, and ExtendedSWHID.

    This is an "abstract" class and should not be instantiated directly;
    it only exists to deduplicate code between these three SWHID classes."""

    namespace = attr.ib(type=str, default=SWHID_NAMESPACE)
    """the namespace of the identifier, defaults to ``swh``"""

    scheme_version = attr.ib(type=int, default=SWHID_VERSION)
    """the scheme version of the identifier, defaults to 1"""

    # overridden by subclasses
    object_type: _TObjectType
    """the type of object the identifier points to"""

    object_id = attr.ib(type=bytes, validator=type_validator())
    """object's identifier"""

    @namespace.validator
    def check_namespace(self, attribute, value):
        if value != SWHID_NAMESPACE:
            raise ValidationError(
                "Invalid SWHID: invalid namespace: %(namespace)s",
                params={"namespace": value},
            )

    @scheme_version.validator
    def check_scheme_version(self, attribute, value):
        if value != SWHID_VERSION:
            raise ValidationError(
                "Invalid SWHID: invalid version: %(version)s", params={"version": value}
            )

    @object_id.validator
    def check_object_id(self, attribute, value):
        if len(value) != 20:
            raise ValidationError(
                "Invalid SWHID: invalid checksum: %(object_id)s",
                params={"object_id": hash_to_hex(value)},
            )

    def __str__(self) -> str:
        return SWHID_SEP.join(
            [
                self.namespace,
                str(self.scheme_version),
                self.object_type.value,
                hash_to_hex(self.object_id),
            ]
        )

    @classmethod
    def from_string(cls: Type[_TSWHID], s: str) -> _TSWHID:
        parts = _parse_swhid(s)
        if parts.pop("qualifiers"):
            raise ValidationError(f"{cls.__name__} does not support qualifiers.")
        try:
            return cls(**parts)
        except ValueError as e:
            raise ValidationError(
                "ValueError: %(args)", params={"args": e.args}
            ) from None


@attr.s(frozen=True, kw_only=True)
class CoreSWHID(_BaseSWHID[ObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID).

    Unlike `QualifiedSWHID`, it is restricted to core SWHIDs, ie. SWHIDs
    with no qualifiers.

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = CoreSWHID(
    ...     object_type=ObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'

    And vice-versa with :meth:`CoreSWHID.from_string`:

    >>> swhid == CoreSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0"
    ... )
    True
    """

    object_type = attr.ib(
        type=ObjectType, validator=type_validator(), converter=ObjectType
    )
    """the type of object the identifier points to"""

    def to_extended(self) -> ExtendedSWHID:
        """Converts this CoreSWHID into an ExtendedSWHID.

        As ExtendedSWHID is a superset of CoreSWHID, this is lossless."""
        return ExtendedSWHID(
            namespace=self.namespace,
            scheme_version=self.scheme_version,
            object_type=ExtendedObjectType(self.object_type.value),
            object_id=self.object_id,
        )


def _parse_core_swhid(swhid: Union[str, CoreSWHID, None]) -> Optional[CoreSWHID]:
    if swhid is None or isinstance(swhid, CoreSWHID):
        return swhid
    else:
        return CoreSWHID.from_string(swhid)


def _parse_lines_qualifier(
    lines: Union[str, Tuple[int, Optional[int]], None]
) -> Optional[Tuple[int, Optional[int]]]:
    try:
        if lines is None or isinstance(lines, tuple):
            return lines
        elif "-" in lines:
            (from_, to) = lines.split("-", 2)
            return (int(from_), int(to))
        else:
            return (int(lines), None)
    except ValueError:
        raise ValidationError(
            "Invalid format for the lines qualifier: %(lines)", params={"lines": lines}
        )


def _parse_path_qualifier(path: Union[str, bytes, None]) -> Optional[bytes]:
    if path is None or isinstance(path, bytes):
        return path
    else:
        return urllib.parse.unquote_to_bytes(path)


@attr.s(frozen=True, kw_only=True)
class QualifiedSWHID(_BaseSWHID[ObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID)

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = QualifiedSWHID(
    ...     object_type=ObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ...     lines=(5, 10),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0;lines=5-10'

    And vice-versa with :meth:`QualifiedSWHID.from_string`:

    >>> swhid == QualifiedSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0;lines=5-10"
    ... )
    True
    """

    object_type = attr.ib(
        type=ObjectType, validator=type_validator(), converter=ObjectType
    )
    """the type of object the identifier points to"""

    # qualifiers:

    origin = attr.ib(type=Optional[str], default=None, validator=type_validator())
    """the software origin where an object has been found or observed in the wild,
    as an URI"""

    visit = attr.ib(type=Optional[CoreSWHID], default=None, converter=_parse_core_swhid)
    """the core identifier of a snapshot corresponding to a specific visit
    of a repository containing the designated object"""

    anchor = attr.ib(
        type=Optional[CoreSWHID],
        default=None,
        validator=type_validator(),
        converter=_parse_core_swhid,
    )
    """a designated node in the Merkle DAG relative to which a path to the object
    is specified, as the core identifier of a directory, a revision, a release,
    or a snapshot"""

    path = attr.ib(
        type=Optional[bytes],
        default=None,
        validator=type_validator(),
        converter=_parse_path_qualifier,
    )
    """the absolute file path, from the root directory associated to the anchor node,
    to the object; when the anchor denotes a directory or a revision, and almost always
    when it’s a release, the root directory is uniquely determined;
    when the anchor denotes a snapshot, the root directory is the one pointed to by HEAD
    (possibly indirectly), and undefined if such a reference is missing"""

    lines = attr.ib(
        type=Optional[Tuple[int, Optional[int]]],
        default=None,
        validator=type_validator(),
        converter=_parse_lines_qualifier,
    )
    """lines: line number(s) of interest, usually within a content object"""

    @visit.validator
    def check_visit(self, attribute, value):
        if value and value.object_type != ObjectType.SNAPSHOT:
            raise ValidationError(
                "The 'visit' qualifier must be a 'snp' SWHID, not '%(type)s'",
                params={"type": value.object_type.value},
            )

    @anchor.validator
    def check_anchor(self, attribute, value):
        if value and value.object_type not in (
            ObjectType.DIRECTORY,
            ObjectType.REVISION,
            ObjectType.RELEASE,
            ObjectType.SNAPSHOT,
        ):
            raise ValidationError(
                "The 'visit' qualifier must be a 'dir', 'rev', 'rel', or 'snp' SWHID, "
                "not '%s(type)s'",
                params={"type": value.object_type.value},
            )

    def qualifiers(self) -> Dict[str, str]:
        origin = self.origin
        if origin:
            unescaped_origin = origin
            origin = origin.replace(";", "%3B")
            assert urllib.parse.unquote_to_bytes(
                origin
            ) == urllib.parse.unquote_to_bytes(
                unescaped_origin
            ), "Escaping ';' in the origin qualifier corrupted the origin URL."

        d: Dict[str, Optional[str]] = {
            "origin": origin,
            "visit": str(self.visit) if self.visit else None,
            "anchor": str(self.anchor) if self.anchor else None,
            "path": (
                urllib.parse.quote_from_bytes(self.path)
                if self.path is not None
                else None
            ),
            "lines": (
                "-".join(str(line) for line in self.lines if line is not None)
                if self.lines
                else None
            ),
        }
        return {k: v for (k, v) in d.items() if v is not None}

    def __str__(self) -> str:
        swhid = SWHID_SEP.join(
            [
                self.namespace,
                str(self.scheme_version),
                self.object_type.value,
                hash_to_hex(self.object_id),
            ]
        )
        qualifiers = self.qualifiers()
        if qualifiers:
            for k, v in qualifiers.items():
                swhid += "%s%s=%s" % (SWHID_CTXT_SEP, k, v)
        return swhid

    @classmethod
    def from_string(cls, s: str) -> QualifiedSWHID:
        parts = _parse_swhid(s)
        qualifiers = parts.pop("qualifiers")
        invalid_qualifiers = set(qualifiers) - SWHID_QUALIFIERS
        if invalid_qualifiers:
            raise ValidationError(
                "Invalid qualifier(s): %(qualifiers)",
                params={"qualifiers": ", ".join(invalid_qualifiers)},
            )
        try:
            return QualifiedSWHID(**parts, **qualifiers)
        except ValueError as e:
            raise ValidationError(
                "ValueError: %(args)s", params={"args": e.args}
            ) from None


@attr.s(frozen=True, kw_only=True)
class ExtendedSWHID(_BaseSWHID[ExtendedObjectType]):
    """
    Dataclass holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID).

    It extends  `CoreSWHID`, by allowing non-standard object types; and should
    only be used internally to Software Heritage.

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    To get the raw SWHID string from an instance of this class,
    use the :func:`str` function:

    >>> swhid = ExtendedSWHID(
    ...     object_type=ExtendedObjectType.CONTENT,
    ...     object_id=bytes.fromhex('8ff44f081d43176474b267de5451f2c2e88089d0'),
    ... )
    >>> str(swhid)
    'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'

    And vice-versa with :meth:`CoreSWHID.from_string`:

    >>> swhid == ExtendedSWHID.from_string(
    ...     "swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0"
    ... )
    True
    """

    object_type = attr.ib(
        type=ExtendedObjectType,
        validator=type_validator(),
        converter=ExtendedObjectType,
    )
    """the type of object the identifier points to"""


@attr.s(frozen=True)
class SWHID:
    """
    Deprecated alternative to QualifiedSWHID.

    Args:
        namespace (str): the namespace of the identifier, defaults to ``swh``
        scheme_version (int): the scheme version of the identifier,
            defaults to 1
        object_type (str): the type of object the identifier points to,
            either ``content``, ``directory``, ``release``, ``revision`` or ``snapshot``
        object_id (str): object's identifier
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

    To get the raw SWHID string from an instance of this named tuple,
    use the :func:`str` function::

        swhid = SWHID(
            object_type='content',
            object_id='8ff44f081d43176474b267de5451f2c2e88089d0'
        )
        swhid_str = str(swhid)
        # 'swh:1:cnt:8ff44f081d43176474b267de5451f2c2e88089d0'
    """

    namespace = attr.ib(type=str, default=SWHID_NAMESPACE)
    scheme_version = attr.ib(type=int, default=SWHID_VERSION)
    object_type = attr.ib(type=str, default="")
    object_id = attr.ib(type=str, converter=hash_to_hex, default="")  # type: ignore
    metadata = attr.ib(
        type=ImmutableDict[str, Any], converter=ImmutableDict, default=ImmutableDict()
    )

    def __attrs_post_init__(self):
        warnings.warn(
            "swh.model.identifiers.SWHID is deprecated; "
            "use swh.model.identifiers.QualifiedSWHID instead.",
            DeprecationWarning,
        )

    @namespace.validator
    def check_namespace(self, attribute, value):
        if value != SWHID_NAMESPACE:
            raise ValidationError(
                "Invalid SWHID: invalid namespace: %(namespace)s",
                params={"namespace": value},
            )

    @scheme_version.validator
    def check_scheme_version(self, attribute, value):
        if value != SWHID_VERSION:
            raise ValidationError(
                "Invalid SWHID: invalid version: %(version)s", params={"version": value}
            )

    @object_type.validator
    def check_object_type(self, attribute, value):
        if value not in _object_type_map:
            raise ValidationError(
                "Invalid SWHID: invalid type: %(object_type)s)",
                params={"object_type": value},
            )

    @object_id.validator
    def check_object_id(self, attribute, value):
        try:
            validate_sha1(value)  # can raise if invalid hash
        except ValidationError:
            raise ValidationError(
                "Invalid SWHID: invalid checksum: %(object_id)s",
                params={"object_id": value},
            ) from None

    @metadata.validator
    def check_qualifiers(self, attribute, value):
        for k in value:
            if k not in SWHID_QUALIFIERS:
                raise ValidationError(
                    "Invalid SWHID: unknown qualifier: %(qualifier)s",
                    params={"qualifier": k},
                )

    def to_dict(self) -> Dict[str, Any]:
        return attr.asdict(self)

    def __str__(self) -> str:
        o = _object_type_map.get(self.object_type)
        assert o
        swhid = SWHID_SEP.join(
            [self.namespace, str(self.scheme_version), o["short_name"], self.object_id]
        )
        if self.metadata:
            for k, v in self.metadata.items():
                swhid += "%s%s=%s" % (SWHID_CTXT_SEP, k, v)
        return swhid


def swhid(
    object_type: str,
    object_id: Union[str, Dict[str, Any]],
    scheme_version: int = 1,
    metadata: Union[ImmutableDict[str, Any], Dict[str, Any]] = ImmutableDict(),
) -> str:
    """Compute :ref:`persistent-identifiers`

    Args:
        object_type: object's type, either ``content``, ``directory``,
            ``release``, ``revision`` or ``snapshot``
        object_id: object's identifier
        scheme_version: SWHID scheme version, defaults to 1
        metadata: metadata related to the pointed object

    Raises:
        swh.model.exceptions.ValidationError: In case of invalid object type or id

    Returns:
        the SWHID of the object

    """
    if isinstance(object_id, dict):
        o = _object_type_map[object_type]
        object_id = object_id[o["key_id"]]
    swhid = SWHID(
        scheme_version=scheme_version,
        object_type=object_type,
        object_id=object_id,
        metadata=metadata,  # type: ignore  # mypy can't properly unify types
    )
    return str(swhid)


def _parse_swhid(swhid: str) -> Dict[str, Any]:
    """Parse a Software Heritage identifier (SWHID) from string (see:
    :ref:`persistent-identifiers`.)

    This is for internal use; use :meth:`CoreSWHID.from_string`,
    :meth:`QualifiedSWHID.from_string`, or :meth:`ExtendedSWHID.from_string` instead,
    as they perform validation and build a dataclass.

    Args:
        swhid (str): A persistent identifier

    Raises:
        swh.model.exceptions.ValidationError: if passed string is not a valid SWHID

    """
    m = SWHID_RE.fullmatch(swhid)
    if not m:
        raise ValidationError(
            "Invalid SWHID: invalid syntax: %(swhid)s", params={"swhid": swhid}
        )
    parts: Dict[str, Any] = m.groupdict()

    qualifiers_raw = parts["qualifiers"]
    parts["qualifiers"] = {}
    if qualifiers_raw:
        for qualifier in qualifiers_raw.split(SWHID_CTXT_SEP):
            try:
                k, v = qualifier.split("=")
            except ValueError:
                raise ValidationError(
                    "Invalid SWHID: invalid qualifier: %(qualifier)s",
                    params={"qualifier": qualifier},
                )
            parts["qualifiers"][k] = v

    parts["scheme_version"] = int(parts["scheme_version"])
    parts["object_id"] = hash_to_bytes(parts["object_id"])
    return parts


def parse_swhid(swhid: str) -> SWHID:
    """Parse a Software Heritage identifier (SWHID) from string (see:
    :ref:`persistent-identifiers`.)

    Args:
        swhid (str): A persistent identifier

    Raises:
        swh.model.exceptions.ValidationError: if passed string is not a valid SWHID

    """
    parts = _parse_swhid(swhid)
    return SWHID(
        parts["namespace"],
        parts["scheme_version"],
        _swhid_type_map[parts["object_type"]],
        hash_to_hex(parts["object_id"]),
        parts["qualifiers"],
    )
