# Copyright (C) 2018-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from abc import ABCMeta, abstractmethod
import datetime
from enum import Enum
from hashlib import sha256
from typing import Any, Dict, Iterable, Optional, Tuple, TypeVar, Union

import attr
from attrs_strict import type_validator
import dateutil.parser
import iso8601
from typing_extensions import Final

from .collections import ImmutableDict
from .hashutil import DEFAULT_ALGORITHMS, MultiHash, hash_to_bytes
from .identifiers import (
    directory_identifier,
    extid_identifier,
    normalize_timestamp,
    origin_identifier,
    raw_extrinsic_metadata_identifier,
    release_identifier,
    revision_identifier,
    snapshot_identifier,
)
from .identifiers import CoreSWHID
from .identifiers import ExtendedObjectType as SwhidExtendedObjectType
from .identifiers import ExtendedSWHID
from .identifiers import ObjectType as SwhidObjectType


class MissingData(Exception):
    """Raised by `Content.with_data` when it has no way of fetching the
    data (but not when fetching the data fails)."""

    pass


KeyType = Union[Dict[str, str], Dict[str, bytes], bytes]
"""The type returned by BaseModel.unique_key()."""


SHA1_SIZE = 20

# TODO: Limit this to 20 bytes
Sha1Git = bytes
Sha1 = bytes


KT = TypeVar("KT")
VT = TypeVar("VT")


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


class HashableObject(metaclass=ABCMeta):
    """Mixin to automatically compute object identifier hash when
    the associated model is instantiated."""

    __slots__ = ()

    id: Sha1Git

    @abstractmethod
    def compute_hash(self) -> bytes:
        """Derived model classes must implement this to compute
        the object hash.

        This method is called by the object initialization if the `id`
        attribute is set to an empty value.
        """
        pass

    def __attrs_post_init__(self):
        if not self.id:
            obj_id = self.compute_hash()
            object.__setattr__(self, "id", obj_id)

    def unique_key(self) -> KeyType:
        return self.id


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
        return Person(fullname=sha256(self.fullname).digest(), name=None, email=None,)


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

    @offset.validator
    def check_offset(self, attribute, value):
        """Checks the offset is a 16-bits signed integer (in theory, it
        should always be between -14 and +14 hours)."""
        if not (-(2 ** 15) <= value < 2 ** 15):
            # max 14 hours offset in theory, but you never know what
            # you'll find in the wild...
            raise ValueError("offset too large: %d minutes" % value)

    @negative_utc.validator
    def check_negative_utc(self, attribute, value):
        if self.offset and value:
            raise ValueError("negative_utc can only be True is offset=0")

    @classmethod
    def from_dict(cls, obj: Union[Dict, datetime.datetime, int]):
        """Builds a TimestampWithTimezone from any of the formats
        accepted by :func:`swh.model.normalize_timestamp`."""
        # TODO: this accept way more types than just dicts; find a better
        # name
        d = normalize_timestamp(obj)
        return cls(
            timestamp=Timestamp.from_dict(d["timestamp"]),
            offset=d["offset"],
            negative_utc=d["negative_utc"],
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
            tstz = attr.evolve(tstz, negative_utc=True)
        return tstz


@attr.s(frozen=True, slots=True)
class Origin(BaseModel):
    """Represents a software source: a VCS and an URL."""

    object_type: Final = "origin"

    url = attr.ib(type=str, validator=type_validator())

    def unique_key(self) -> KeyType:
        return {"url": self.url}

    def swhid(self) -> ExtendedSWHID:
        """Returns a SWHID representing this origin."""
        return ExtendedSWHID(
            object_type=SwhidExtendedObjectType.ORIGIN,
            object_id=hash_to_bytes(origin_identifier(self.unique_key())),
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
    snapshot = attr.ib(type=Optional[Sha1Git], validator=type_validator())
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


class ObjectType(Enum):
    """The type of content pointed to by a release. Usually a revision"""

    CONTENT = "content"
    DIRECTORY = "directory"
    REVISION = "revision"
    RELEASE = "release"
    SNAPSHOT = "snapshot"


@attr.s(frozen=True, slots=True)
class SnapshotBranch(BaseModel):
    """Represents one of the branches of a snapshot."""

    object_type: Final = "snapshot_branch"

    target = attr.ib(type=bytes, validator=type_validator())
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
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    def compute_hash(self) -> bytes:
        return hash_to_bytes(snapshot_identifier(self.to_dict()))

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
class Release(HashableObject, BaseModel):
    object_type: Final = "release"

    name = attr.ib(type=bytes, validator=type_validator())
    message = attr.ib(type=Optional[bytes], validator=type_validator())
    target = attr.ib(type=Optional[Sha1Git], validator=type_validator())
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
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    def compute_hash(self) -> bytes:
        return hash_to_bytes(release_identifier(self.to_dict()))

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


def tuplify_extra_headers(value: Iterable):
    return tuple((k, v) for k, v in value)


@attr.s(frozen=True, slots=True)
class Revision(HashableObject, BaseModel):
    object_type: Final = "revision"

    message = attr.ib(type=Optional[bytes], validator=type_validator())
    author = attr.ib(type=Person, validator=type_validator())
    committer = attr.ib(type=Person, validator=type_validator())
    date = attr.ib(type=Optional[TimestampWithTimezone], validator=type_validator())
    committer_date = attr.ib(
        type=Optional[TimestampWithTimezone], validator=type_validator()
    )
    type = attr.ib(type=RevisionType, validator=type_validator())
    directory = attr.ib(type=Sha1Git, validator=type_validator())
    synthetic = attr.ib(type=bool, validator=type_validator())
    metadata = attr.ib(
        type=Optional[ImmutableDict[str, object]],
        validator=type_validator(),
        converter=freeze_optional_dict,
        default=None,
    )
    parents = attr.ib(type=Tuple[Sha1Git, ...], validator=type_validator(), default=())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")
    extra_headers = attr.ib(
        type=Tuple[Tuple[bytes, bytes], ...],
        validator=type_validator(),
        converter=tuplify_extra_headers,
        default=(),
    )

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

    def compute_hash(self) -> bytes:
        return hash_to_bytes(revision_identifier(self.to_dict()))

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
    target = attr.ib(type=Sha1Git, validator=type_validator())
    perms = attr.ib(type=int, validator=type_validator())
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""


@attr.s(frozen=True, slots=True)
class Directory(HashableObject, BaseModel):
    object_type: Final = "directory"

    entries = attr.ib(type=Tuple[DirectoryEntry, ...], validator=type_validator())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    def compute_hash(self) -> bytes:
        return hash_to_bytes(directory_identifier(self.to_dict()))

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

    sha1 = attr.ib(type=bytes, validator=type_validator())
    sha1_git = attr.ib(type=Sha1Git, validator=type_validator())
    sha256 = attr.ib(type=bytes, validator=type_validator())
    blake2s256 = attr.ib(type=bytes, validator=type_validator())

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

    sha1 = attr.ib(type=Optional[bytes], validator=type_validator())
    sha1_git = attr.ib(type=Optional[Sha1Git], validator=type_validator())
    sha256 = attr.ib(type=Optional[bytes], validator=type_validator())
    blake2s256 = attr.ib(type=Optional[bytes], validator=type_validator())

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

    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    def compute_hash(self) -> bytes:
        return hash_to_bytes(raw_extrinsic_metadata_identifier(self.to_dict()))

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

    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    @classmethod
    def from_dict(cls, d):
        return cls(
            extid=d["extid"],
            extid_type=d["extid_type"],
            target=CoreSWHID.from_string(d["target"]),
            extid_version=d.get("extid_version", 0),
        )

    def compute_hash(self) -> bytes:
        return hash_to_bytes(extid_identifier(self.to_dict()))
