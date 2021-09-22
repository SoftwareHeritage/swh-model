# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import datetime
from functools import lru_cache
from typing import Iterable, List, Optional, Tuple

from . import model
from .collections import ImmutableDict
from .hashutil import git_object_header, hash_to_bytehex


def directory_entry_sort_key(entry: model.DirectoryEntry):
    """The sorting key for tree entries"""
    if isinstance(entry, dict):
        # For backward compatibility
        entry = model.DirectoryEntry.from_dict(entry)
    if entry.type == "dir":
        return entry.name + b"/"
    else:
        return entry.name


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


@lru_cache()
def format_offset(offset: int, negative_utc: Optional[bool] = None) -> bytes:
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
    else:
        return model.TimestampWithTimezone.from_dict(time_representation).to_dict()


def directory_git_object(directory: model.Directory) -> bytes:
    if isinstance(directory, dict):
        # For backward compatibility
        directory = model.Directory.from_dict(directory)

    components = []

    for entry in sorted(directory.entries, key=directory_entry_sort_key):
        components.extend(
            [_perms_to_bytes(entry.perms), b"\x20", entry.name, b"\x00", entry.target,]
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

    concatenated_entries = b"".join(entries)

    header = git_object_header(git_type, len(concatenated_entries))
    return header + concatenated_entries


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
        offset_f = format_offset(date_offset.offset, date_offset.negative_utc)

        ret.extend([b" ", date_f, b" ", offset_f])

    return b"".join(ret)


def revision_git_object(revision: model.Revision) -> bytes:
    """Formats the git_object of a revision. See :func:`revision_identifier` for details
    on the format."""
    if isinstance(revision, dict):
        # For backward compatibility
        revision = model.Revision.from_dict(revision)

    headers = [(b"tree", hash_to_bytehex(revision.directory))]
    for parent in revision.parents:
        if parent:
            headers.append((b"parent", hash_to_bytehex(parent)))

    headers.append((b"author", format_author_data(revision.author, revision.date)))
    headers.append(
        (b"committer", format_author_data(revision.committer, revision.committer_date),)
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


def release_git_object(release: model.Release) -> bytes:
    if isinstance(release, dict):
        # For backward compatibility
        release = model.Release.from_dict(release)

    headers = [
        (b"object", hash_to_bytehex(release.target)),
        (b"type", target_type_to_git(release.target_type)),
        (b"tag", release.name),
    ]

    if release.author is not None:
        headers.append((b"tagger", format_author_data(release.author, release.date)))

    return format_git_object_from_headers("tag", headers, release.message)


def snapshot_git_object(snapshot: model.Snapshot) -> bytes:
    """Formats the git_object of a revision. See :func:`snapshot_identifier` for details
    on the format."""
    if isinstance(snapshot, dict):
        # For backward compatibility
        snapshot = model.Snapshot.from_dict(snapshot)

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

    if unresolved:
        raise ValueError(
            "Branch aliases unresolved: %s"
            % ", ".join("%r -> %r" % x for x in unresolved),
            unresolved,
        )

    return format_git_object_from_parts("snapshot", lines)


def raw_extrinsic_metadata_git_object(metadata: model.RawExtrinsicMetadata) -> bytes:
    """Formats the git_object of a raw_extrinsic_metadata object.
    See :func:`raw_extrinsic_metadata_identifier` for details
    on the format."""
    if isinstance(metadata, dict):
        # For backward compatibility
        metadata = model.RawExtrinsicMetadata.from_dict(metadata)

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
        (b"fetcher", f"{metadata.fetcher.name} {metadata.fetcher.version}".encode(),),
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
    headers = [
        (b"extid_type", extid.extid_type.encode("ascii")),
    ]
    extid_version = extid.extid_version
    if extid_version != 0:
        headers.append((b"extid_version", str(extid_version).encode("ascii")))

    headers.extend(
        [(b"extid", extid.extid), (b"target", str(extid.target).encode("ascii")),]
    )

    return format_git_object_from_headers("extid", headers)
