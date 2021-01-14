# Copyright (C) 2015-2020  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import binascii
import datetime
from functools import lru_cache
import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import attr

from .collections import ImmutableDict
from .exceptions import ValidationError
from .fields.hashes import validate_sha1
from .hashutil import MultiHash, hash_git_data, hash_to_hex

ORIGIN = "origin"
SNAPSHOT = "snapshot"
REVISION = "revision"
RELEASE = "release"
DIRECTORY = "directory"
CONTENT = "content"

SWHID_NAMESPACE = "swh"
SWHID_VERSION = 1
SWHID_TYPES = ["ori", "snp", "rel", "rev", "dir", "cnt"]
SWHID_SEP = ":"
SWHID_CTXT_SEP = ";"
SWHID_QUALIFIERS = {"origin", "anchor", "visit", "path", "lines"}

SWHID_RE_RAW = (
    f"(?P<scheme>{SWHID_NAMESPACE})"
    f"{SWHID_SEP}(?P<version>{SWHID_VERSION})"
    f"{SWHID_SEP}(?P<object_type>{'|'.join(SWHID_TYPES)})"
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
}

_swhid_type_map = {
    "ori": ORIGIN,
    "snp": SNAPSHOT,
    "rel": RELEASE,
    "rev": REVISION,
    "dir": DIRECTORY,
    "cnt": CONTENT,
}


@attr.s(frozen=True)
class SWHID:
    """
    Named tuple holding the relevant info associated to a SoftWare Heritage
    persistent IDentifier (SWHID)

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


def parse_swhid(swhid: str) -> SWHID:
    """Parse a Software Heritage identifier (SWHID) from string (see:
    :ref:`persistent-identifiers`.)

    Args:
        swhid (str): A persistent identifier

    Returns:
        a named tuple holding the parsing result

    Raises:
        swh.model.exceptions.ValidationError: if passed string is not a valid SWHID

    """
    m = SWHID_RE.fullmatch(swhid)
    if not m:
        raise ValidationError(
            "Invalid SWHID: invalid syntax: %(swhid)s", params={"swhid": swhid}
        )
    parts = m.groupdict()

    _qualifiers = {}
    qualifiers_raw = parts["qualifiers"]
    if qualifiers_raw:
        for qualifier in qualifiers_raw.split(SWHID_CTXT_SEP):
            try:
                k, v = qualifier.split("=")
            except ValueError:
                raise ValidationError(
                    "Invalid SWHID: invalid qualifier: %(qualifier)s",
                    params={"qualifier": qualifier},
                )
            _qualifiers[k] = v

    return SWHID(
        parts["scheme"],
        int(parts["version"]),
        _swhid_type_map[parts["object_type"]],
        parts["object_id"],
        _qualifiers,  # type: ignore  # mypy can't properly unify types
    )
