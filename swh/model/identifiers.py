# Copyright (C) 2015-2021  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from __future__ import annotations

import binascii
from functools import lru_cache
from typing import Any, Dict

from . import model

# Reexport for backward compatibility
from .git_objects import *  # noqa
from .hashutil import MultiHash, hash_to_hex

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
    return hash_to_hex(model.Directory.from_dict(directory).id)


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
    return hash_to_hex(model.Revision.from_dict(revision).id)


def release_identifier(release: Dict[str, Any]) -> str:
    """Return the intrinsic identifier for a release."""
    return hash_to_hex(model.Release.from_dict(release).id)


def snapshot_identifier(snapshot: Dict[str, Any]) -> str:
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

    Returns:
      str: the intrinsic identifier for `snapshot`

    """
    return hash_to_hex(model.Snapshot.from_dict(snapshot).id)


def origin_identifier(origin):
    """Return the intrinsic identifier for an origin.

    An origin's identifier is the sha1 checksum of the entire origin URL

    """
    return hash_to_hex(model.Origin.from_dict(origin).id)


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
    return hash_to_hex(model.RawExtrinsicMetadata.from_dict(metadata).id)


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

    return hash_to_hex(model.ExtID.from_dict(extid).id)
