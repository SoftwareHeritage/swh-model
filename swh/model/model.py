# Copyright (C) 2018-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""
Implementation of Software Heritage's data model

See :ref:`data-model` for an overview of the data model.

The classes defined in this module are immutable
`attrs objects <https://attrs.org/>`__ and enums.

All classes define a ``from_dict`` class method and a ``to_dict``
method to convert between them and msgpack-serializable objects.
"""

from abc import ABCMeta, abstractmethod
import datetime
from enum import Enum
import hashlib
from typing import Any, Dict, Iterable, Optional, Tuple, TypeVar, Union

import attr
from attrs_strict import AttributeTypeError
import dateutil.parser
import iso8601
from typing_extensions import Final

from . import git_objects
from .collections import ImmutableDict
from .hashutil import DEFAULT_ALGORITHMS, MultiHash, hash_to_hex
from .swhids import CoreSWHID
from .swhids import ExtendedObjectType as SwhidExtendedObjectType
from .swhids import ExtendedSWHID
from .swhids import ObjectType as SwhidObjectType


class MissingData(Exception):
    """Raised by `Content.with_data` when it has no way of fetching the
    data (but not when fetching the data fails)."""

    pass


KeyType = Union[Dict[str, str], Dict[str, bytes], bytes]
"""The type returned by BaseModel.unique_key()."""


SHA1_SIZE = 20

_OFFSET_CHARS = frozenset(b"+-0123456789")

# TODO: Limit this to 20 bytes
Sha1Git = bytes
Sha1 = bytes


KT = TypeVar("KT")
VT = TypeVar("VT")


def hash_repr(h: bytes) -> str:
    if h is None:
        return "None"
    else:
        return f"hash_to_bytes('{hash_to_hex(h)}')"


def freeze_optional_dict(
    d: Union[None, Dict[KT, VT], ImmutableDict[KT, VT]]  # type: ignore
) -> Optional[ImmutableDict[KT, VT]]:
    if isinstance(d, dict):
        return ImmutableDict(d)
    else:
        return d


def dictify(value):
    "Helper function used by BaseModel.to_dict()"
    if isinstance(value, BaseModel):
        return value.to_dict()
    elif isinstance(value, (CoreSWHID, ExtendedSWHID)):
        return str(value)
    elif isinstance(value, Enum):
        return value.value
    elif isinstance(value, (dict, ImmutableDict)):
        return {k: dictify(v) for k, v in value.items()}
    elif isinstance(value, tuple):
        return tuple(dictify(v) for v in value)
    else:
        return value


def _check_type(type_, value):
    if type_ is object or type_ is Any:
        return True

    if type_ is None:
        return value is None

    origin = getattr(type_, "__origin__", None)

    # Non-generic type, check it directly
    if origin is None:
        # This is functionally equivalent to using just this:
        #   return isinstance(value, type)
        # but using type equality before isinstance allows very quick checks
        # when the exact class is used (which is the overwhelming majority of cases)
        # while still allowing subclasses to be used.
        return type(value) == type_ or isinstance(value, type_)

    # Check the type of the value itself
    #
    # For the same reason as above, this condition is functionally equivalent to:
    #   if origin is not Union and not isinstance(value, origin):
    if origin is not Union and type(value) != origin and not isinstance(value, origin):
        return False

    # Then, if it's a container, check its items.
    if origin is tuple:
        args = type_.__args__
        if len(args) == 2 and args[1] is Ellipsis:
            # Infinite tuple
            return all(_check_type(args[0], item) for item in value)
        else:
            # Finite tuple
            if len(args) != len(value):
                return False

            return all(
                _check_type(item_type, item) for (item_type, item) in zip(args, value)
            )
    elif origin is Union:
        args = type_.__args__
        return any(_check_type(variant, value) for variant in args)
    elif origin is ImmutableDict:
        (key_type, value_type) = type_.__args__
        return all(
            _check_type(key_type, key) and _check_type(value_type, value)
            for (key, value) in value.items()
        )
    else:
        # No need to check dict or list. because they are converted to ImmutableDict
        # and tuple respectively.
        raise NotImplementedError(f"Type-checking {type_}")


def type_validator():
    """Like attrs_strict.type_validator(), but stricter.

    It is an attrs validator, which checks attributes have the specified type,
    using type equality instead of ``isinstance()``, for improved performance
    """

    def validator(instance, attribute, value):
        if not _check_type(attribute.type, value):
            raise AttributeTypeError(value, attribute)

    return validator


ModelType = TypeVar("ModelType", bound="BaseModel")


class BaseModel:
    """Base class for SWH model classes.

    Provides serialization/deserialization to/from Python dictionaries,
    that are suitable for JSON/msgpack-like formats."""

    __slots__ = ()

    def to_dict(self):
        """Wrapper of `attr.asdict` that can be overridden by subclasses
        that have special handling of some of the fields."""
        return dictify(attr.asdict(self, recurse=False))

    @classmethod
    def from_dict(cls, d):
        """Takes a dictionary representing a tree of SWH objects, and
        recursively builds the corresponding objects."""
        return cls(**d)

    def anonymize(self: ModelType) -> Optional[ModelType]:
        """Returns an anonymized version of the object, if needed.

        If the object model does not need/support anonymization, returns None.
        """
        return None

    def unique_key(self) -> KeyType:
        """Returns a unique key for this object, that can be used for
        deduplication."""
        raise NotImplementedError(f"unique_key for {self}")

    def check(self) -> None:
        """Performs internal consistency checks, and raises an error if one fails."""
        attr.validate(self)


def _compute_hash_from_manifest(manifest: bytes) -> Sha1Git:
    return hashlib.new("sha1", manifest).digest()


class HashableObject(metaclass=ABCMeta):
    """Mixin to automatically compute object identifier hash when
    the associated model is instantiated."""

    __slots__ = ()

    id: Sha1Git

    def compute_hash(self) -> bytes:
        """Derived model classes must implement this to compute
        the object hash.

        This method is called by the object initialization if the `id`
        attribute is set to an empty value.
        """
        return self._compute_hash_from_attributes()

    @abstractmethod
    def _compute_hash_from_attributes(self) -> Sha1Git:
        raise NotImplementedError(f"_compute_hash_from_attributes for {self}")

    def __attrs_post_init__(self):
        if not self.id:
            obj_id = self.compute_hash()
            object.__setattr__(self, "id", obj_id)

    def unique_key(self) -> KeyType:
        return self.id

    def check(self) -> None:
        super().check()  # type: ignore

        if self.id != self.compute_hash():
            raise ValueError("'id' does not match recomputed hash.")


class HashableObjectWithManifest(HashableObject):
    """Derived class of HashableObject, for objects that may need to store
    verbatim git objects as ``raw_manifest`` to preserve original hashes."""

    raw_manifest: Optional[bytes] = None
    """Stores the original content of git objects when they cannot be faithfully
    represented using only the other attributes.

    This should only be used as a last resort, and only set in the Git loader,
    for objects too corrupt to fit the data model."""

    def to_dict(self):
        d = super().to_dict()
        if d["raw_manifest"] is None:
            del d["raw_manifest"]
        return d

    def compute_hash(self) -> bytes:
        """Derived model classes must implement this to compute
        the object hash.

        This method is called by the object initialization if the `id`
        attribute is set to an empty value.
        """
        if self.raw_manifest is None:
            return super().compute_hash()
        else:
            return _compute_hash_from_manifest(self.raw_manifest)

    def check(self) -> None:
        super().check()

        if (
            self.raw_manifest is not None
            and self.id == self._compute_hash_from_attributes()
        ):
            raise ValueError(
                f"{self} has a non-none raw_manifest attribute, but does not need it."
            )


@attr.s(frozen=True, slots=True)
class Person(BaseModel):
    """Represents the author/committer of a revision or release."""

    object_type: Final = "person"

    fullname = attr.ib(type=bytes, validator=type_validator())
    name = attr.ib(type=Optional[bytes], validator=type_validator())
    email = attr.ib(type=Optional[bytes], validator=type_validator())

    @classmethod
    def from_fullname(cls, fullname: bytes):
        """Returns a Person object, by guessing the name and email from the
        fullname, in the `name <email>` format.

        The fullname is left unchanged."""
        if fullname is None:
            raise TypeError("fullname is None.")

        name: Optional[bytes]
        email: Optional[bytes]

        try:
            open_bracket = fullname.index(b"<")
        except ValueError:
            name = fullname
            email = None
        else:
            raw_name = fullname[:open_bracket]
            raw_email = fullname[open_bracket + 1 :]

            if not raw_name:
                name = None
            else:
                name = raw_name.strip()

            try:
                close_bracket = raw_email.rindex(b">")
            except ValueError:
                email = raw_email
            else:
                email = raw_email[:close_bracket]

        return Person(name=name or None, email=email or None, fullname=fullname,)

    def anonymize(self) -> "Person":
        """Returns an anonymized version of the Person object.

        Anonymization is simply a Person which fullname is the hashed, with unset name
        or email.
        """
        return Person(
            fullname=hashlib.sha256(self.fullname).digest(), name=None, email=None,
        )

    @classmethod
    def from_dict(cls, d):
        """
        If the fullname is missing, construct a fullname
        using the following heuristics: if the name value is None, we return the
        email in angle brackets, else, we return the name, a space, and the email
        in angle brackets.
        """
        if "fullname" not in d:
            parts = []
            if d["name"] is not None:
                parts.append(d["name"])
            if d["email"] is not None:
                parts.append(b"".join([b"<", d["email"], b">"]))

            fullname = b" ".join(parts)
            d = {**d, "fullname": fullname}
        d = {"name": None, "email": None, **d}
        return super().from_dict(d)


@attr.s(frozen=True, slots=True)
class Timestamp(BaseModel):
    """Represents a naive timestamp from a VCS."""

    object_type: Final = "timestamp"

    seconds = attr.ib(type=int, validator=type_validator())
    microseconds = attr.ib(type=int, validator=type_validator())

    @seconds.validator
    def check_seconds(self, attribute, value):
        """Check that seconds fit in a 64-bits signed integer."""
        if not (-(2 ** 63) <= value < 2 ** 63):
            raise ValueError("Seconds must be a signed 64-bits integer.")

    @microseconds.validator
    def check_microseconds(self, attribute, value):
        """Checks that microseconds are positive and < 1000000."""
        if not (0 <= value < 10 ** 6):
            raise ValueError("Microseconds must be in [0, 1000000[.")


@attr.s(frozen=True, slots=True)
class TimestampWithTimezone(BaseModel):
    """Represents a TZ-aware timestamp from a VCS."""

    object_type: Final = "timestamp_with_timezone"

    timestamp = attr.ib(type=Timestamp, validator=type_validator())
    offset = attr.ib(type=int, validator=type_validator())
    negative_utc = attr.ib(type=bool, validator=type_validator())

    offset_bytes = attr.ib(type=bytes, validator=type_validator())
    """Raw git representation of the timezone, as an offset from UTC.
    It should follow this format: ``+HHMM`` or ``-HHMM`` (including ``+0000`` and
    ``-0000``).

    However, when created from git objects, it must be the exact bytes used in the
    original objects, so it may differ from this format when they do.
    """

    @offset.validator
    def check_offset(self, attribute, value):
        """Checks the offset is a 16-bits signed integer (in theory, it
        should always be between -14 and +14 hours)."""
        if not (-(2 ** 15) <= value < 2 ** 15):
            # max 14 hours offset in theory, but you never know what
            # you'll find in the wild...
            raise ValueError("offset too large: %d minutes" % value)

        self._check_offsets_match()

    @negative_utc.validator
    def check_negative_utc(self, attribute, value):
        if self.offset and value:
            raise ValueError("negative_utc can only be True is offset=0")

        self._check_offsets_match()

    @offset_bytes.default
    def _default_offset_bytes(self):
        negative = self.offset < 0 or self.negative_utc
        (hours, minutes) = divmod(abs(self.offset), 60)
        return f"{'-' if negative else '+'}{hours:02}{minutes:02}".encode()

    @offset_bytes.validator
    def check_offset_bytes(self, attribute, value):
        if not set(value) <= _OFFSET_CHARS:
            raise ValueError(f"invalid characters in offset_bytes: {value!r}")

        self._check_offsets_match()

    def _check_offsets_match(self):
        offset_str = self.offset_bytes.decode()
        assert offset_str[0] in "+-"
        sign = int(offset_str[0] + "1")
        hours = int(offset_str[1:-2])
        minutes = int(offset_str[-2:])
        offset = sign * (hours * 60 + minutes)
        if offset != self.offset:
            raise ValueError(
                f"offset_bytes ({self.offset_bytes!r}) does not match offset "
                f"{divmod(self.offset, 60)}"
            )

        if offset == 0 and self.negative_utc != self.offset_bytes.startswith(b"-"):
            raise ValueError(
                f"offset_bytes ({self.offset_bytes!r}) does not match negative_utc "
                f"({self.negative_utc})"
            )

    @classmethod
    def from_dict(cls, time_representation: Union[Dict, datetime.datetime, int]):
        """Builds a TimestampWithTimezone from any of the formats
        accepted by :func:`swh.model.normalize_timestamp`."""
        # TODO: this accept way more types than just dicts; find a better
        # name
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
                    f"TimestampWithTimezone.from_dict received non-integer timestamp "
                    f"member {ts!r}"
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
                    f"TimestampWithTimezone.from_dict received datetime without "
                    f"timezone: {time_representation}"
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
                f"TimestampWithTimezone.from_dict received non-integer timestamp: "
                f"{time_representation!r}"
            )

        return cls(
            timestamp=Timestamp(seconds=seconds, microseconds=microseconds),
            offset=offset,
            negative_utc=negative_utc,
        )

    @classmethod
    def from_datetime(cls, dt: datetime.datetime):
        return cls.from_dict(dt)

    def to_datetime(self) -> datetime.datetime:
        """Convert to a datetime (with a timezone set to the recorded fixed UTC offset)

        Beware that this conversion can be lossy: the negative_utc flag is not
        taken into consideration (since it cannot be represented in a
        datetime). Also note that it may fail due to type overflow.

        """
        timestamp = datetime.datetime.fromtimestamp(
            self.timestamp.seconds,
            datetime.timezone(datetime.timedelta(minutes=self.offset)),
        )
        timestamp = timestamp.replace(microsecond=self.timestamp.microseconds)
        return timestamp

    @classmethod
    def from_iso8601(cls, s):
        """Builds a TimestampWithTimezone from an ISO8601-formatted string.
        """
        dt = iso8601.parse_date(s)
        tstz = cls.from_datetime(dt)
        if dt.tzname() == "-00:00":
            assert tstz.offset_bytes == b"+0000"
            tstz = attr.evolve(tstz, negative_utc=True, offset_bytes=b"-0000")
        return tstz


@attr.s(frozen=True, slots=True)
class Origin(HashableObject, BaseModel):
    """Represents a software source: a VCS and an URL."""

    object_type: Final = "origin"

    url = attr.ib(type=str, validator=type_validator())

    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    def unique_key(self) -> KeyType:
        return {"url": self.url}

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(self.url.encode("utf-8"))

    def swhid(self) -> ExtendedSWHID:
        """Returns a SWHID representing this origin."""
        return ExtendedSWHID(
            object_type=SwhidExtendedObjectType.ORIGIN, object_id=self.id,
        )


@attr.s(frozen=True, slots=True)
class OriginVisit(BaseModel):
    """Represents an origin visit with a given type at a given point in time, by a
    SWH loader."""

    object_type: Final = "origin_visit"

    origin = attr.ib(type=str, validator=type_validator())
    date = attr.ib(type=datetime.datetime, validator=type_validator())
    type = attr.ib(type=str, validator=type_validator())
    """Should not be set before calling 'origin_visit_add()'."""
    visit = attr.ib(type=Optional[int], validator=type_validator(), default=None)

    @date.validator
    def check_date(self, attribute, value):
        """Checks the date has a timezone."""
        if value is not None and value.tzinfo is None:
            raise ValueError("date must be a timezone-aware datetime.")

    def to_dict(self):
        """Serializes the date as a string and omits the visit id if it is
        `None`."""
        ov = super().to_dict()
        if ov["visit"] is None:
            del ov["visit"]
        return ov

    def unique_key(self) -> KeyType:
        return {"origin": self.origin, "date": str(self.date)}


@attr.s(frozen=True, slots=True)
class OriginVisitStatus(BaseModel):
    """Represents a visit update of an origin at a given point in time.

    """

    object_type: Final = "origin_visit_status"

    origin = attr.ib(type=str, validator=type_validator())
    visit = attr.ib(type=int, validator=type_validator())

    date = attr.ib(type=datetime.datetime, validator=type_validator())
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(
            ["created", "ongoing", "full", "partial", "not_found", "failed"]
        ),
    )
    snapshot = attr.ib(
        type=Optional[Sha1Git], validator=type_validator(), repr=hash_repr
    )
    # Type is optional be to able to use it before adding it to the database model
    type = attr.ib(type=Optional[str], validator=type_validator(), default=None)
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=type_validator(),
        converter=freeze_optional_dict,
        default=None,
    )

    @date.validator
    def check_date(self, attribute, value):
        """Checks the date has a timezone."""
        if value is not None and value.tzinfo is None:
            raise ValueError("date must be a timezone-aware datetime.")

    def unique_key(self) -> KeyType:
        return {"origin": self.origin, "visit": str(self.visit), "date": str(self.date)}


class TargetType(Enum):
    """The type of content pointed to by a snapshot branch. Usually a
    revision or an alias."""

    CONTENT = "content"
    DIRECTORY = "directory"
    REVISION = "revision"
    RELEASE = "release"
    SNAPSHOT = "snapshot"
    ALIAS = "alias"

    def __repr__(self):
        return f"TargetType.{self.name}"


class ObjectType(Enum):
    """The type of content pointed to by a release. Usually a revision"""

    CONTENT = "content"
    DIRECTORY = "directory"
    REVISION = "revision"
    RELEASE = "release"
    SNAPSHOT = "snapshot"

    def __repr__(self):
        return f"ObjectType.{self.name}"


@attr.s(frozen=True, slots=True)
class SnapshotBranch(BaseModel):
    """Represents one of the branches of a snapshot."""

    object_type: Final = "snapshot_branch"

    target = attr.ib(type=bytes, validator=type_validator(), repr=hash_repr)
    target_type = attr.ib(type=TargetType, validator=type_validator())

    @target.validator
    def check_target(self, attribute, value):
        """Checks the target type is not an alias, checks the target is a
        valid sha1_git."""
        if self.target_type != TargetType.ALIAS and self.target is not None:
            if len(value) != 20:
                raise ValueError("Wrong length for bytes identifier: %d" % len(value))

    @classmethod
    def from_dict(cls, d):
        return cls(target=d["target"], target_type=TargetType(d["target_type"]))


@attr.s(frozen=True, slots=True)
class Snapshot(HashableObject, BaseModel):
    """Represents the full state of an origin at a given point in time."""

    object_type: Final = "snapshot"

    branches = attr.ib(
        type=ImmutableDict[bytes, Optional[SnapshotBranch]],
        validator=type_validator(),
        converter=freeze_optional_dict,
    )
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.snapshot_git_object(self))

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            branches=ImmutableDict(
                (name, SnapshotBranch.from_dict(branch) if branch else None)
                for (name, branch) in d.pop("branches").items()
            ),
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.SNAPSHOT, object_id=self.id)


@attr.s(frozen=True, slots=True)
class Release(HashableObjectWithManifest, BaseModel):
    object_type: Final = "release"

    name = attr.ib(type=bytes, validator=type_validator())
    message = attr.ib(type=Optional[bytes], validator=type_validator())
    target = attr.ib(type=Optional[Sha1Git], validator=type_validator(), repr=hash_repr)
    target_type = attr.ib(type=ObjectType, validator=type_validator())
    synthetic = attr.ib(type=bool, validator=type_validator())
    author = attr.ib(type=Optional[Person], validator=type_validator(), default=None)
    date = attr.ib(
        type=Optional[TimestampWithTimezone], validator=type_validator(), default=None
    )
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=type_validator(),
        converter=freeze_optional_dict,
        default=None,
    )
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.release_git_object(self))

    @author.validator
    def check_author(self, attribute, value):
        """If the author is `None`, checks the date is `None` too."""
        if self.author is None and self.date is not None:
            raise ValueError("release date must be None if author is None.")

    def to_dict(self):
        rel = super().to_dict()
        if rel["metadata"] is None:
            del rel["metadata"]
        return rel

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        if d.get("author"):
            d["author"] = Person.from_dict(d["author"])
        if d.get("date"):
            d["date"] = TimestampWithTimezone.from_dict(d["date"])
        return cls(target_type=ObjectType(d.pop("target_type")), **d)

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.RELEASE, object_id=self.id)

    def anonymize(self) -> "Release":
        """Returns an anonymized version of the Release object.

        Anonymization consists in replacing the author with an anonymized Person object.
        """
        author = self.author and self.author.anonymize()
        return attr.evolve(self, author=author)


class RevisionType(Enum):
    GIT = "git"
    TAR = "tar"
    DSC = "dsc"
    SUBVERSION = "svn"
    MERCURIAL = "hg"
    CVS = "cvs"
    BAZAAR = "bzr"

    def __repr__(self):
        return f"RevisionType.{self.name}"


def tuplify_extra_headers(value: Iterable):
    return tuple((k, v) for k, v in value)


@attr.s(frozen=True, slots=True)
class Revision(HashableObjectWithManifest, BaseModel):
    object_type: Final = "revision"

    message = attr.ib(type=Optional[bytes], validator=type_validator())
    author = attr.ib(type=Person, validator=type_validator())
    committer = attr.ib(type=Person, validator=type_validator())
    date = attr.ib(type=Optional[TimestampWithTimezone], validator=type_validator())
    committer_date = attr.ib(
        type=Optional[TimestampWithTimezone], validator=type_validator()
    )
    type = attr.ib(type=RevisionType, validator=type_validator())
    directory = attr.ib(type=Sha1Git, validator=type_validator(), repr=hash_repr)
    synthetic = attr.ib(type=bool, validator=type_validator())
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=type_validator(),
        converter=freeze_optional_dict,
        default=None,
    )
    parents = attr.ib(type=Tuple[Sha1Git, ...], validator=type_validator(), default=())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)
    extra_headers = attr.ib(
        type=Tuple[Tuple[bytes, bytes], ...],
        validator=type_validator(),
        converter=tuplify_extra_headers,
        default=(),
    )
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def __attrs_post_init__(self):
        super().__attrs_post_init__()
        # ensure metadata is a deep copy of whatever was given, and if needed
        # extract extra_headers from there
        if self.metadata:
            metadata = self.metadata
            if not self.extra_headers and "extra_headers" in metadata:
                (extra_headers, metadata) = metadata.copy_pop("extra_headers")
                object.__setattr__(
                    self, "extra_headers", tuplify_extra_headers(extra_headers),
                )
                attr.validate(self)
            object.__setattr__(self, "metadata", metadata)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.revision_git_object(self))

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        date = d.pop("date")
        if date:
            date = TimestampWithTimezone.from_dict(date)

        committer_date = d.pop("committer_date")
        if committer_date:
            committer_date = TimestampWithTimezone.from_dict(committer_date)

        return cls(
            author=Person.from_dict(d.pop("author")),
            committer=Person.from_dict(d.pop("committer")),
            date=date,
            committer_date=committer_date,
            type=RevisionType(d.pop("type")),
            parents=tuple(d.pop("parents")),  # for BW compat
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.REVISION, object_id=self.id)

    def anonymize(self) -> "Revision":
        """Returns an anonymized version of the Revision object.

        Anonymization consists in replacing the author and committer with an anonymized
        Person object.
        """
        return attr.evolve(
            self, author=self.author.anonymize(), committer=self.committer.anonymize()
        )


@attr.s(frozen=True, slots=True)
class DirectoryEntry(BaseModel):
    object_type: Final = "directory_entry"

    name = attr.ib(type=bytes, validator=type_validator())
    type = attr.ib(type=str, validator=attr.validators.in_(["file", "dir", "rev"]))
    target = attr.ib(type=Sha1Git, validator=type_validator(), repr=hash_repr)
    perms = attr.ib(type=int, validator=type_validator(), converter=int, repr=oct)
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""

    @name.validator
    def check_name(self, attribute, value):
        if b"/" in value:
            raise ValueError(f"{value!r} is not a valid directory entry name.")


@attr.s(frozen=True, slots=True)
class Directory(HashableObjectWithManifest, BaseModel):
    object_type: Final = "directory"

    entries = attr.ib(type=Tuple[DirectoryEntry, ...], validator=type_validator())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)
    raw_manifest = attr.ib(type=Optional[bytes], default=None)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.directory_git_object(self))

    @entries.validator
    def check_entries(self, attribute, value):
        seen = set()
        for entry in value:
            if entry.name in seen:
                raise ValueError(
                    "{self.swhid()} has duplicated entry name: {entry.name!r}"
                )
            seen.add(entry.name)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            entries=tuple(
                DirectoryEntry.from_dict(entry) for entry in d.pop("entries")
            ),
            **d,
        )

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.DIRECTORY, object_id=self.id)


@attr.s(frozen=True, slots=True)
class BaseContent(BaseModel):
    status = attr.ib(
        type=str, validator=attr.validators.in_(["visible", "hidden", "absent"])
    )

    @staticmethod
    def _hash_data(data: bytes):
        """Hash some data, returning most of the fields of a content object"""
        d = MultiHash.from_data(data).digest()
        d["data"] = data
        d["length"] = len(data)

        return d

    @classmethod
    def from_dict(cls, d, use_subclass=True):
        if use_subclass:
            # Chooses a subclass to instantiate instead.
            if d["status"] == "absent":
                return SkippedContent.from_dict(d)
            else:
                return Content.from_dict(d)
        else:
            return super().from_dict(d)

    def get_hash(self, hash_name):
        if hash_name not in DEFAULT_ALGORITHMS:
            raise ValueError("{} is not a valid hash name.".format(hash_name))
        return getattr(self, hash_name)

    def hashes(self) -> Dict[str, bytes]:
        """Returns a dictionary {hash_name: hash_value}"""
        return {algo: getattr(self, algo) for algo in DEFAULT_ALGORITHMS}


@attr.s(frozen=True, slots=True)
class Content(BaseContent):
    object_type: Final = "content"

    sha1 = attr.ib(type=bytes, validator=type_validator(), repr=hash_repr)
    sha1_git = attr.ib(type=Sha1Git, validator=type_validator(), repr=hash_repr)
    sha256 = attr.ib(type=bytes, validator=type_validator(), repr=hash_repr)
    blake2s256 = attr.ib(type=bytes, validator=type_validator(), repr=hash_repr)

    length = attr.ib(type=int, validator=type_validator())

    status = attr.ib(
        type=str,
        validator=attr.validators.in_(["visible", "hidden"]),
        default="visible",
    )

    data = attr.ib(type=Optional[bytes], validator=type_validator(), default=None)

    ctime = attr.ib(
        type=Optional[datetime.datetime],
        validator=type_validator(),
        default=None,
        eq=False,
    )

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive."""
        if value < 0:
            raise ValueError("Length must be positive.")

    @ctime.validator
    def check_ctime(self, attribute, value):
        """Checks the ctime has a timezone."""
        if value is not None and value.tzinfo is None:
            raise ValueError("ctime must be a timezone-aware datetime.")

    def to_dict(self):
        content = super().to_dict()
        if content["data"] is None:
            del content["data"]
        if content["ctime"] is None:
            del content["ctime"]
        return content

    @classmethod
    def from_data(cls, data, status="visible", ctime=None) -> "Content":
        """Generate a Content from a given `data` byte string.

        This populates the Content with the hashes and length for the data
        passed as argument, as well as the data itself.
        """
        d = cls._hash_data(data)
        d["status"] = status
        d["ctime"] = ctime
        return cls(**d)

    @classmethod
    def from_dict(cls, d):
        if isinstance(d.get("ctime"), str):
            d = d.copy()
            d["ctime"] = dateutil.parser.parse(d["ctime"])
        return super().from_dict(d, use_subclass=False)

    def with_data(self) -> "Content":
        """Loads the `data` attribute; meaning that it is guaranteed not to
        be None after this call.

        This call is almost a no-op, but subclasses may overload this method
        to lazy-load data (eg. from disk or objstorage)."""
        if self.data is None:
            raise MissingData("Content data is None.")
        return self

    def unique_key(self) -> KeyType:
        return self.sha1  # TODO: use a dict of hashes

    def swhid(self) -> CoreSWHID:
        """Returns a SWHID representing this object."""
        return CoreSWHID(object_type=SwhidObjectType.CONTENT, object_id=self.sha1_git)


@attr.s(frozen=True, slots=True)
class SkippedContent(BaseContent):
    object_type: Final = "skipped_content"

    sha1 = attr.ib(type=Optional[bytes], validator=type_validator(), repr=hash_repr)
    sha1_git = attr.ib(
        type=Optional[Sha1Git], validator=type_validator(), repr=hash_repr
    )
    sha256 = attr.ib(type=Optional[bytes], validator=type_validator(), repr=hash_repr)
    blake2s256 = attr.ib(
        type=Optional[bytes], validator=type_validator(), repr=hash_repr
    )

    length = attr.ib(type=Optional[int], validator=type_validator())

    status = attr.ib(type=str, validator=attr.validators.in_(["absent"]))
    reason = attr.ib(type=Optional[str], validator=type_validator(), default=None)

    origin = attr.ib(type=Optional[str], validator=type_validator(), default=None)

    ctime = attr.ib(
        type=Optional[datetime.datetime],
        validator=type_validator(),
        default=None,
        eq=False,
    )

    @reason.validator
    def check_reason(self, attribute, value):
        """Checks the reason is full if status != absent."""
        assert self.reason == value
        if value is None:
            raise ValueError("Must provide a reason if content is absent.")

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive or -1."""
        if value < -1:
            raise ValueError("Length must be positive or -1.")

    @ctime.validator
    def check_ctime(self, attribute, value):
        """Checks the ctime has a timezone."""
        if value is not None and value.tzinfo is None:
            raise ValueError("ctime must be a timezone-aware datetime.")

    def to_dict(self):
        content = super().to_dict()
        if content["origin"] is None:
            del content["origin"]
        if content["ctime"] is None:
            del content["ctime"]
        return content

    @classmethod
    def from_data(
        cls, data: bytes, reason: str, ctime: Optional[datetime.datetime] = None
    ) -> "SkippedContent":
        """Generate a SkippedContent from a given `data` byte string.

        This populates the SkippedContent with the hashes and length for the
        data passed as argument.

        You can use `attr.evolve` on such a generated content to nullify some
        of its attributes, e.g. for tests.
        """
        d = cls._hash_data(data)
        del d["data"]
        d["status"] = "absent"
        d["reason"] = reason
        d["ctime"] = ctime
        return cls(**d)

    @classmethod
    def from_dict(cls, d):
        d2 = d.copy()
        if d2.pop("data", None) is not None:
            raise ValueError('SkippedContent has no "data" attribute %r' % d)
        return super().from_dict(d2, use_subclass=False)

    def unique_key(self) -> KeyType:
        return self.hashes()


class MetadataAuthorityType(Enum):
    DEPOSIT_CLIENT = "deposit_client"
    FORGE = "forge"
    REGISTRY = "registry"

    def __repr__(self):
        return f"MetadataAuthorityType.{self.name}"


@attr.s(frozen=True, slots=True)
class MetadataAuthority(BaseModel):
    """Represents an entity that provides metadata about an origin or
    software artifact."""

    object_type: Final = "metadata_authority"

    type = attr.ib(type=MetadataAuthorityType, validator=type_validator())
    url = attr.ib(type=str, validator=type_validator())
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, Any]],
        default=None,
        validator=type_validator(),
        converter=freeze_optional_dict,
    )

    def to_dict(self):
        d = super().to_dict()
        if d["metadata"] is None:
            del d["metadata"]
        return d

    @classmethod
    def from_dict(cls, d):
        d = {
            **d,
            "type": MetadataAuthorityType(d["type"]),
        }
        return super().from_dict(d)

    def unique_key(self) -> KeyType:
        return {"type": self.type.value, "url": self.url}


@attr.s(frozen=True, slots=True)
class MetadataFetcher(BaseModel):
    """Represents a software component used to fetch metadata from a metadata
    authority, and ingest them into the Software Heritage archive."""

    object_type: Final = "metadata_fetcher"

    name = attr.ib(type=str, validator=type_validator())
    version = attr.ib(type=str, validator=type_validator())
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, Any]],
        default=None,
        validator=type_validator(),
        converter=freeze_optional_dict,
    )

    def to_dict(self):
        d = super().to_dict()
        if d["metadata"] is None:
            del d["metadata"]
        return d

    def unique_key(self) -> KeyType:
        return {"name": self.name, "version": self.version}


def normalize_discovery_date(value: Any) -> datetime.datetime:
    if not isinstance(value, datetime.datetime):
        raise TypeError("discovery_date must be a timezone-aware datetime.")

    if value.tzinfo is None:
        raise ValueError("discovery_date must be a timezone-aware datetime.")

    # Normalize timezone to utc, and truncate microseconds to 0
    return value.astimezone(datetime.timezone.utc).replace(microsecond=0)


@attr.s(frozen=True, slots=True)
class RawExtrinsicMetadata(HashableObject, BaseModel):
    object_type: Final = "raw_extrinsic_metadata"

    # target object
    target = attr.ib(type=ExtendedSWHID, validator=type_validator())

    # source
    discovery_date = attr.ib(type=datetime.datetime, converter=normalize_discovery_date)
    authority = attr.ib(type=MetadataAuthority, validator=type_validator())
    fetcher = attr.ib(type=MetadataFetcher, validator=type_validator())

    # the metadata itself
    format = attr.ib(type=str, validator=type_validator())
    metadata = attr.ib(type=bytes, validator=type_validator())

    # context
    origin = attr.ib(type=Optional[str], default=None, validator=type_validator())
    visit = attr.ib(type=Optional[int], default=None, validator=type_validator())
    snapshot = attr.ib(
        type=Optional[CoreSWHID], default=None, validator=type_validator()
    )
    release = attr.ib(
        type=Optional[CoreSWHID], default=None, validator=type_validator()
    )
    revision = attr.ib(
        type=Optional[CoreSWHID], default=None, validator=type_validator()
    )
    path = attr.ib(type=Optional[bytes], default=None, validator=type_validator())
    directory = attr.ib(
        type=Optional[CoreSWHID], default=None, validator=type_validator()
    )

    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(
            git_objects.raw_extrinsic_metadata_git_object(self)
        )

    @origin.validator
    def check_origin(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.SNAPSHOT,
            SwhidExtendedObjectType.RELEASE,
            SwhidExtendedObjectType.REVISION,
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'origin' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if value.startswith("swh:"):
            # Technically this is valid; but:
            # 1. SWHIDs are URIs, not URLs
            # 2. if a SWHID gets here, it's very likely to be a mistake
            #    (and we can remove this check if it turns out there is a
            #    legitimate use for it).
            raise ValueError(f"SWHID used as context origin URL: {value}")

    @visit.validator
    def check_visit(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.SNAPSHOT,
            SwhidExtendedObjectType.RELEASE,
            SwhidExtendedObjectType.REVISION,
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'visit' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        if self.origin is None:
            raise ValueError("'origin' context must be set if 'visit' is.")

        if value <= 0:
            raise ValueError("Nonpositive visit id")

    @snapshot.validator
    def check_snapshot(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.RELEASE,
            SwhidExtendedObjectType.REVISION,
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'snapshot' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        self._check_swhid(SwhidObjectType.SNAPSHOT, value)

    @release.validator
    def check_release(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.REVISION,
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'release' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        self._check_swhid(SwhidObjectType.RELEASE, value)

    @revision.validator
    def check_revision(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'revision' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        self._check_swhid(SwhidObjectType.REVISION, value)

    @path.validator
    def check_path(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (
            SwhidExtendedObjectType.DIRECTORY,
            SwhidExtendedObjectType.CONTENT,
        ):
            raise ValueError(
                f"Unexpected 'path' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

    @directory.validator
    def check_directory(self, attribute, value):
        if value is None:
            return

        if self.target.object_type not in (SwhidExtendedObjectType.CONTENT,):
            raise ValueError(
                f"Unexpected 'directory' context for "
                f"{self.target.object_type.name.lower()} object: {value}"
            )

        self._check_swhid(SwhidObjectType.DIRECTORY, value)

    def _check_swhid(self, expected_object_type, swhid):
        if isinstance(swhid, str):
            raise ValueError(f"Expected SWHID, got a string: {swhid}")

        if swhid.object_type != expected_object_type:
            raise ValueError(
                f"Expected SWHID type '{expected_object_type.name.lower()}', "
                f"got '{swhid.object_type.name.lower()}' in {swhid}"
            )

    def to_dict(self):
        d = super().to_dict()

        context_keys = (
            "origin",
            "visit",
            "snapshot",
            "release",
            "revision",
            "directory",
            "path",
        )
        for context_key in context_keys:
            if d[context_key] is None:
                del d[context_key]
        return d

    @classmethod
    def from_dict(cls, d):
        d = {
            **d,
            "target": ExtendedSWHID.from_string(d["target"]),
            "authority": MetadataAuthority.from_dict(d["authority"]),
            "fetcher": MetadataFetcher.from_dict(d["fetcher"]),
        }

        swhid_keys = ("snapshot", "release", "revision", "directory")
        for swhid_key in swhid_keys:
            if d.get(swhid_key):
                d[swhid_key] = CoreSWHID.from_string(d[swhid_key])

        return super().from_dict(d)

    def swhid(self) -> ExtendedSWHID:
        """Returns a SWHID representing this RawExtrinsicMetadata object."""
        return ExtendedSWHID(
            object_type=SwhidExtendedObjectType.RAW_EXTRINSIC_METADATA,
            object_id=self.id,
        )


@attr.s(frozen=True, slots=True)
class ExtID(HashableObject, BaseModel):
    object_type: Final = "extid"

    extid_type = attr.ib(type=str, validator=type_validator())
    extid = attr.ib(type=bytes, validator=type_validator())
    target = attr.ib(type=CoreSWHID, validator=type_validator())
    extid_version = attr.ib(type=int, validator=type_validator(), default=0)

    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"", repr=hash_repr)

    @classmethod
    def from_dict(cls, d):
        return cls(
            extid=d["extid"],
            extid_type=d["extid_type"],
            target=CoreSWHID.from_string(d["target"]),
            extid_version=d.get("extid_version", 0),
        )

    def _compute_hash_from_attributes(self) -> bytes:
        return _compute_hash_from_manifest(git_objects.extid_git_object(self))
