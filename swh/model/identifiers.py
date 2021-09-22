# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import binascii
import datetime
from functools import lru_cache
import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .hashutil import MultiHash, git_object_header

# Reexport for backward compatibility
from .swhids import *  # noqa

# The following are deprecated aliases of the variants defined in ObjectType
# while transitioning from SWHID to QualifiedSWHID
ORIGIN = "origin"
SNAPSHOT = "snapshot"
REVISION = "revision"
RELEASE = "release"
DIRECTORY = "directory"
CONTENT = "content"
RAW_EXTRINSIC_METADATA = "raw_extrinsic_metadata"


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


def content_identifier(content: Dict[str, Any]) -> Dict[str, bytes]:
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


def directory_identifier(directory: Dict[str, Any]) -> str:
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
    git_object = directory_git_object(directory)
    return hashlib.new("sha1", git_object).hexdigest()


def directory_git_object(directory: Dict[str, Any]) -> bytes:
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

    return format_git_object_from_parts("tree", components)


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
        microseconds = time_representation.microsecond
        if microseconds:
            time_representation = time_representation.replace(microsecond=0)
        seconds = int(time_representation.timestamp())
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


def format_git_object_from_headers(
    git_type: str,
    headers: Iterable[Tuple[bytes, bytes]],
    message: Optional[bytes] = None,
) -> bytes:
    """Format a git_object comprised of a git header and a manifest,
    which is itself a sequence of `headers`, and an optional `message`.

    The git_object format, compatible with the git format for tag and commit
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
      the formatted git_object as bytes
    """
    entries: List[bytes] = []

    for key, value in headers:
        entries.extend((key, b" ", escape_newlines(value), b"\n"))

    if message is not None:
        entries.extend((b"\n", message))

    concatenated_entries = b"".join(entries)

    header = git_object_header(git_type, len(concatenated_entries))
    return header + concatenated_entries


def format_git_object_from_parts(git_type: str, parts: Iterable[bytes]) -> bytes:
    """Similar to :func:`format_git_object_from_headers`, but for manifests made of
    a flat list of entries, instead of key-value + message, ie. trees and snapshots."""
    concatenated_parts = b"".join(parts)

    header = git_object_header(git_type, len(concatenated_parts))
    return header + concatenated_parts


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


def revision_identifier(revision: Dict[str, Any]) -> str:
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
    git_object = revision_git_object(revision)
    return hashlib.new("sha1", git_object).hexdigest()


def revision_git_object(revision: Dict[str, Any]) -> bytes:
    """Formats the git_object of a revision. See :func:`revision_identifier` for details
    on the format."""
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

    return format_git_object_from_headers("commit", headers, revision["message"])


def target_type_to_git(target_type: str) -> bytes:
    """Convert a software heritage target type to a git object type"""
    return {
        "content": b"blob",
        "directory": b"tree",
        "revision": b"commit",
        "release": b"tag",
        "snapshot": b"refs",
    }[target_type]


def release_identifier(release: Dict[str, Any]) -> str:
    """Return the intrinsic identifier for a release."""
    git_object = release_git_object(release)
    return hashlib.new("sha1", git_object).hexdigest()


def release_git_object(release: Dict[str, Any]) -> bytes:
    headers = [
        (b"object", identifier_to_str(release["target"]).encode()),
        (b"type", target_type_to_git(release["target_type"])),
        (b"tag", release["name"]),
    ]

    if "author" in release and release["author"]:
        headers.append(
            (b"tagger", format_author_data(release["author"], release["date"]))
        )

    return format_git_object_from_headers("tag", headers, release["message"])


def snapshot_identifier(
    snapshot: Dict[str, Any], *, ignore_unresolved: bool = False
) -> str:
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
    git_object = snapshot_git_object(snapshot, ignore_unresolved=ignore_unresolved)
    return hashlib.new("sha1", git_object).hexdigest()


def snapshot_git_object(
    snapshot: Dict[str, Any], *, ignore_unresolved: bool = False
) -> bytes:
    """Formats the git_object of a revision. See :func:`snapshot_identifier` for details
    on the format."""
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
            % ", ".join("%r -> %r" % x for x in unresolved),
            unresolved,
        )

    return format_git_object_from_parts("snapshot", lines)


def origin_identifier(origin):
    """Return the intrinsic identifier for an origin.

    An origin's identifier is the sha1 checksum of the entire origin URL

    """
    return hashlib.sha1(origin["url"].encode("utf-8")).hexdigest()


def raw_extrinsic_metadata_identifier(metadata: Dict[str, Any]) -> str:
    """Return the intrinsic identifier for a RawExtrinsicMetadata object.

    A raw_extrinsic_metadata identifier is a salted sha1 (using the git
    hashing algorithm with the ``raw_extrinsic_metadata`` object type) of
    a manifest following the format::

        target $ExtendedSwhid
        discovery_date $Timestamp
        authority $StrWithoutSpaces $IRI
        fetcher $Str $Version
        format $StrWithoutSpaces
        origin $IRI                         <- optional
        visit $IntInDecimal                 <- optional
        snapshot $CoreSwhid                 <- optional
        release $CoreSwhid                  <- optional
        revision $CoreSwhid                 <- optional
        path $Bytes                         <- optional
        directory $CoreSwhid                <- optional

        $MetadataBytes

    $IRI must be RFC 3987 IRIs (so they may contain newlines, that are escaped as
    described below)

    $StrWithoutSpaces and $Version are ASCII strings, and may not contain spaces.

    $Str is an UTF-8 string.

    $CoreSwhid are core SWHIDs, as defined in :ref:`persistent-identifiers`.
    $ExtendedSwhid is a core SWHID, with extra types allowed ('ori' for
    origins and 'emd' for raw extrinsic metadata)

    $Timestamp is a decimal representation of the rounded-down integer number of
    seconds since the UNIX epoch (1970-01-01 00:00:00 UTC),
    with no leading '0' (unless the timestamp value is zero) and no timezone.
    It may be negative by prefixing it with a '-', which must not be followed
    by a '0'.

    Newlines in $Bytes, $Str, and $Iri are escaped as with other git fields,
    ie. by adding a space after them.

    Returns:
      str: the intrinsic identifier for ``metadata``

    """
    git_object = raw_extrinsic_metadata_git_object(metadata)
    return hashlib.new("sha1", git_object).hexdigest()


def raw_extrinsic_metadata_git_object(metadata: Dict[str, Any]) -> bytes:
    """Formats the git_object of a raw_extrinsic_metadata object.
    See :func:`raw_extrinsic_metadata_identifier` for details
    on the format."""
    # equivalent to using math.floor(dt.timestamp()) to round down,
    # as int(dt.timestamp()) rounds toward zero,
    # which would map two seconds on the 0 timestamp.
    #
    # This should never be an issue in practice as Software Heritage didn't
    # start collecting metadata before 2015.
    timestamp = (
        metadata["discovery_date"]
        .astimezone(datetime.timezone.utc)
        .replace(microsecond=0)
        .timestamp()
    )
    assert timestamp.is_integer()

    headers = [
        (b"target", str(metadata["target"]).encode()),
        (b"discovery_date", str(int(timestamp)).encode("ascii")),
        (
            b"authority",
            f"{metadata['authority']['type']} {metadata['authority']['url']}".encode(),
        ),
        (
            b"fetcher",
            f"{metadata['fetcher']['name']} {metadata['fetcher']['version']}".encode(),
        ),
        (b"format", metadata["format"].encode()),
    ]

    for key in (
        "origin",
        "visit",
        "snapshot",
        "release",
        "revision",
        "path",
        "directory",
    ):
        if metadata.get(key) is not None:
            value: bytes
            if key == "path":
                value = metadata[key]
            else:
                value = str(metadata[key]).encode()

            headers.append((key.encode("ascii"), value))

    return format_git_object_from_headers(
        "raw_extrinsic_metadata", headers, metadata["metadata"]
    )


def extid_identifier(extid: Dict[str, Any]) -> str:
    """Return the intrinsic identifier for an ExtID object.

    An ExtID identifier is a salted sha1 (using the git hashing algorithm with
    the ``extid`` object type) of a manifest following the format:

    ```
    extid_type $StrWithoutSpaces
    [extid_version $Str]
    extid $Bytes
    target $CoreSwhid
    ```

    $StrWithoutSpaces is an ASCII string, and may not contain spaces.

    Newlines in $Bytes are escaped as with other git fields, ie. by adding a
    space after them.

    The extid_version line is only generated if the version is non-zero.

    Returns:
      str: the intrinsic identifier for `extid`

    """

    headers = [
        (b"extid_type", extid["extid_type"].encode("ascii")),
    ]
    extid_version = extid.get("extid_version", 0)
    if extid_version != 0:
        headers.append((b"extid_version", str(extid_version).encode("ascii")))

    headers.extend(
        [(b"extid", extid["extid"]), (b"target", str(extid["target"]).encode("ascii")),]
    )

    git_object = format_git_object_from_headers("extid", headers)
    return hashlib.new("sha1", git_object).hexdigest()
