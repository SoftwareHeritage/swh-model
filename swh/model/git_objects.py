# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
Converts SWH model objects to git(-like) objects

Most of the functions in this module take as argument an object from
:mod:`swh.model.model`, and format it like a git object.

They are the inverse functions of those in :mod:`swh.loader.git.converters`,
but with extensions, as SWH's model is a superset of Git's:

* extensions of existing types (eg. revision/commit and release/tag dates
  can be expressed with precision up to milliseconds, to support formatting
  Mercurial objects)
* new types, for SWH's specific needs (:class:`swh.model.model.RawExtrinsicMetadata`
  and :class:`swh.model.model.ExtID`)
* support for somewhat corrupted git objects that we need to reproduce

This is used for two purposes:

* Format manifests that can be hashed to produce :ref:`intrinsic identifiers
  <persistent-identifiers>`
* Write git objects to reproduce git repositories that were ingested in the archive.
"""


from __future__ import annotations

import datetime
from functools import lru_cache
from typing import Dict, Iterable, List, Optional, Tuple, Union, cast
import warnings

from . import model
from .collections import ImmutableDict
from .hashutil import git_object_header, hash_to_bytehex


def content_git_object(content: model.Content) -> bytes:
    """Formats a content as a git blob.

    A content's identifier is the blob sha1 à la git of the tagged content.
    """
    content = cast(model.Content, content)

    if content.data is None:
        raise model.MissingData("Content data is None, cannot format.")

    return git_object_header("blob", len(content.data)) + content.data


def directory_entry_sort_key(entry: model.DirectoryEntry):
    """The sorting key for tree entries"""
    if isinstance(entry, dict):
        type_ = entry["type"]
        name = entry["name"]
    else:
        type_ = entry.type
        name = entry.name

    if type_ == "dir":
        return name + b"/"
    else:
        return name


@lru_cache()
def _perms_to_bytes(perms):
    """Convert the perms value to its canonical bytes representation"""
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


def format_date(date: model.Timestamp) -> bytes:
    """Convert a date object into an UTC timestamp encoded as ascii bytes.

    Git stores timestamps as an integer number of seconds since the UNIX epoch.

    However, Software Heritage stores timestamps as an integer number of
    microseconds (postgres type "datetime with timezone").

    Therefore, we print timestamps with no microseconds as integers, and
    timestamps with microseconds as floating point values. We elide the
    trailing zeroes from microsecond values, to "future-proof" our
    representation if we ever need more precision in timestamps.

    """
    if isinstance(date, dict):
        # For backward compatibility
        date = model.Timestamp.from_dict(date)

    if not date.microseconds:
        return str(date.seconds).encode()
    else:
        float_value = "%d.%06d" % (date.seconds, date.microseconds)
        return float_value.rstrip("0").encode()


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
    else:
        return model.TimestampWithTimezone.from_dict(time_representation).to_dict()


def directory_git_object(directory: Union[Dict, model.Directory]) -> bytes:
    """Formats a directory as a git tree.

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
    if isinstance(directory, dict):
        # For backward compatibility
        warnings.warn(
            "directory_git_object's argument should be a swh.model.model.Directory "
            "object.",
            DeprecationWarning,
            stacklevel=2,
        )
        directory = model.Directory.from_dict(directory)
    directory = cast(model.Directory, directory)

    components = []

    for entry in sorted(directory.entries, key=directory_entry_sort_key):
        components.extend(
            [
                _perms_to_bytes(entry.perms),
                b"\x20",
                entry.name,
                b"\x00",
                entry.target,
            ]
        )

    return format_git_object_from_parts("tree", components)


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

    return format_git_object_from_parts(git_type, entries)


def format_git_object_from_parts(git_type: str, parts: Iterable[bytes]) -> bytes:
    """Similar to :func:`format_git_object_from_headers`, but for manifests made of
    a flat list of entries, instead of key-value + message, ie. trees and snapshots."""
    concatenated_parts = b"".join(parts)

    header = git_object_header(git_type, len(concatenated_parts))
    return header + concatenated_parts


def format_author_data(
    author: model.Person, date_offset: Optional[model.TimestampWithTimezone]
) -> bytes:
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

    Returns:
        the byte string containing the authorship data
    """

    ret = [author.fullname]

    if date_offset is not None:
        date_f = format_date(date_offset.timestamp)

        ret.extend([b" ", date_f, b" ", date_offset.offset_bytes])

    return b"".join(ret)


def revision_git_object(revision: Union[Dict, model.Revision]) -> bytes:
    """Formats a revision as a git tree.

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

    Author and committer are formatted using the :attr:`Person.fullname` attribute only.
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
    if isinstance(revision, dict):
        # For backward compatibility
        warnings.warn(
            "revision_git_object's argument should be a swh.model.model.Revision "
            "object.",
            DeprecationWarning,
            stacklevel=2,
        )
        revision = model.Revision.from_dict(revision)
    revision = cast(model.Revision, revision)

    headers = [(b"tree", hash_to_bytehex(revision.directory))]
    for parent in revision.parents:
        if parent:
            headers.append((b"parent", hash_to_bytehex(parent)))

    if revision.author is not None:
        headers.append((b"author", format_author_data(revision.author, revision.date)))
    if revision.committer is not None:
        headers.append(
            (
                b"committer",
                format_author_data(revision.committer, revision.committer_date),
            )
        )

    # Handle extra headers
    metadata = revision.metadata or ImmutableDict()
    extra_headers = revision.extra_headers or ()
    if not extra_headers and "extra_headers" in metadata:
        extra_headers = metadata["extra_headers"]

    headers.extend(extra_headers)

    return format_git_object_from_headers("commit", headers, revision.message)


def target_type_to_git(target_type: model.ObjectType) -> bytes:
    """Convert a software heritage target type to a git object type"""
    return {
        model.ObjectType.CONTENT: b"blob",
        model.ObjectType.DIRECTORY: b"tree",
        model.ObjectType.REVISION: b"commit",
        model.ObjectType.RELEASE: b"tag",
        model.ObjectType.SNAPSHOT: b"refs",
    }[target_type]


def release_git_object(release: Union[Dict, model.Release]) -> bytes:
    if isinstance(release, dict):
        # For backward compatibility
        warnings.warn(
            "release_git_object's argument should be a swh.model.model.Directory "
            "object.",
            DeprecationWarning,
            stacklevel=2,
        )
        release = model.Release.from_dict(release)
    release = cast(model.Release, release)

    headers = [
        (b"object", hash_to_bytehex(release.target)),
        (b"type", target_type_to_git(release.target_type)),
        (b"tag", release.name),
    ]

    if release.author is not None:
        headers.append((b"tagger", format_author_data(release.author, release.date)))

    return format_git_object_from_headers("tag", headers, release.message)


def snapshot_git_object(
    snapshot: Union[Dict, model.Snapshot], *, ignore_unresolved: bool = False
) -> bytes:
    """Formats a snapshot as a git-like object.

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
      ignore_unresolved: if False (the default), raises an exception when
        alias branches point to non-existing branches
    """
    if isinstance(snapshot, dict):
        # For backward compatibility
        warnings.warn(
            "snapshot_git_object's argument should be a swh.model.model.Snapshot "
            "object.",
            DeprecationWarning,
            stacklevel=2,
        )
        snapshot = model.Snapshot.from_dict(snapshot)
    snapshot = cast(model.Snapshot, snapshot)

    unresolved = []
    lines = []

    for name, target in sorted(snapshot.branches.items()):
        if not target:
            target_type = b"dangling"
            target_id = b""
        elif target.target_type == model.TargetType.ALIAS:
            target_type = b"alias"
            target_id = target.target
            if target_id not in snapshot.branches or target_id == name:
                unresolved.append((name, target_id))
        else:
            target_type = target.target_type.value.encode()
            target_id = target.target

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


def raw_extrinsic_metadata_git_object(
    metadata: Union[Dict, model.RawExtrinsicMetadata]
) -> bytes:
    """Formats RawExtrinsicMetadata as a git-like object.

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
    """
    if isinstance(metadata, dict):
        # For backward compatibility
        warnings.warn(
            "raw_extrinsic_metadata_git_object's argument should be a "
            "swh.model.model.RawExtrinsicMetadata object.",
            DeprecationWarning,
            stacklevel=2,
        )
        metadata = model.RawExtrinsicMetadata.from_dict(metadata)
    metadata = cast(model.RawExtrinsicMetadata, metadata)

    # equivalent to using math.floor(dt.timestamp()) to round down,
    # as int(dt.timestamp()) rounds toward zero,
    # which would map two seconds on the 0 timestamp.
    #
    # This should never be an issue in practice as Software Heritage didn't
    # start collecting metadata before 2015.
    timestamp = (
        metadata.discovery_date.astimezone(datetime.timezone.utc)
        .replace(microsecond=0)
        .timestamp()
    )
    assert timestamp.is_integer()

    headers = [
        (b"target", str(metadata.target).encode()),
        (b"discovery_date", str(int(timestamp)).encode("ascii")),
        (
            b"authority",
            f"{metadata.authority.type.value} {metadata.authority.url}".encode(),
        ),
        (
            b"fetcher",
            f"{metadata.fetcher.name} {metadata.fetcher.version}".encode(),
        ),
        (b"format", metadata.format.encode()),
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
        if getattr(metadata, key, None) is not None:
            value: bytes
            if key == "path":
                value = getattr(metadata, key)
            else:
                value = str(getattr(metadata, key)).encode()

            headers.append((key.encode("ascii"), value))

    return format_git_object_from_headers(
        "raw_extrinsic_metadata", headers, metadata.metadata
    )


def extid_git_object(extid: model.ExtID) -> bytes:
    """Formats an extid as a gi-like object.

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
    """

    headers = [
        (b"extid_type", extid.extid_type.encode("ascii")),
    ]
    extid_version = extid.extid_version
    if extid_version != 0:
        headers.append((b"extid_version", str(extid_version).encode("ascii")))

    headers.extend(
        [
            (b"extid", extid.extid),
            (b"target", str(extid.target).encode("ascii")),
        ]
    )

    return format_git_object_from_headers("extid", headers)
