# Copyright (C) 2018-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime

from abc import ABCMeta, abstractmethod
from enum import Enum
from hashlib import sha256
from typing import Dict, Optional, Tuple, TypeVar, Union
from typing_extensions import Final

import attr
from attrs_strict import type_validator
import dateutil.parser
import iso8601

from .identifiers import (
    normalize_timestamp,
    directory_identifier,
    revision_identifier,
    release_identifier,
    snapshot_identifier,
)
from .hashutil import DEFAULT_ALGORITHMS, hash_to_bytes, MultiHash


class MissingData(Exception):
    """Raised by `Content.with_data` when it has no way of fetching the
    data (but not when fetching the data fails)."""

    pass


SHA1_SIZE = 20

# TODO: Limit this to 20 bytes
Sha1Git = bytes


def dictify(value):
    "Helper function used by BaseModel.to_dict()"
    if isinstance(value, BaseModel):
        return value.to_dict()
    elif isinstance(value, Enum):
        return value.value
    elif isinstance(value, dict):
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


class HashableObject(metaclass=ABCMeta):
    """Mixin to automatically compute object identifier hash when
    the associated model is instantiated."""

    @staticmethod
    @abstractmethod
    def compute_hash(object_dict):
        """Derived model classes must implement this to compute
        the object hash from its dict representation."""
        pass

    def __attrs_post_init__(self):
        if not self.id:
            obj_id = hash_to_bytes(self.compute_hash(self.to_dict()))
            object.__setattr__(self, "id", obj_id)


@attr.s(frozen=True)
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


@attr.s(frozen=True)
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


@attr.s(frozen=True)
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

    @classmethod
    def from_iso8601(cls, s):
        """Builds a TimestampWithTimezone from an ISO8601-formatted string.
        """
        dt = iso8601.parse_date(s)
        tstz = cls.from_datetime(dt)
        if dt.tzname() == "-00:00":
            tstz = attr.evolve(tstz, negative_utc=True)
        return tstz


@attr.s(frozen=True)
class Origin(BaseModel):
    """Represents a software source: a VCS and an URL."""

    object_type: Final = "origin"

    url = attr.ib(type=str, validator=type_validator())


@attr.s(frozen=True)
class OriginVisit(BaseModel):
    """Represents an origin visit with a given type at a given point in time, by a
    SWH loader."""

    object_type: Final = "origin_visit"

    origin = attr.ib(type=str, validator=type_validator())
    date = attr.ib(type=datetime.datetime, validator=type_validator())
    type = attr.ib(type=str, validator=type_validator())
    """Should not be set before calling 'origin_visit_add()'."""
    visit = attr.ib(type=Optional[int], validator=type_validator(), default=None)

    def to_dict(self):
        """Serializes the date as a string and omits the visit id if it is
        `None`."""
        ov = super().to_dict()
        if ov["visit"] is None:
            del ov["visit"]
        return ov


@attr.s(frozen=True)
class OriginVisitStatus(BaseModel):
    """Represents a visit update of an origin at a given point in time.

    """

    object_type: Final = "origin_visit_status"

    origin = attr.ib(type=str, validator=type_validator())
    visit = attr.ib(type=int, validator=type_validator())

    date = attr.ib(type=datetime.datetime, validator=type_validator())
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(["created", "ongoing", "full", "partial"]),
    )
    snapshot = attr.ib(type=Optional[Sha1Git], validator=type_validator())
    metadata = attr.ib(
        type=Optional[Dict[str, object]], validator=type_validator(), default=None
    )


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


@attr.s(frozen=True)
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


@attr.s(frozen=True)
class Snapshot(BaseModel, HashableObject):
    """Represents the full state of an origin at a given point in time."""

    object_type: Final = "snapshot"

    branches = attr.ib(
        type=Dict[bytes, Optional[SnapshotBranch]], validator=type_validator()
    )
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    @staticmethod
    def compute_hash(object_dict):
        return snapshot_identifier(object_dict)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            branches={
                name: SnapshotBranch.from_dict(branch) if branch else None
                for (name, branch) in d.pop("branches").items()
            },
            **d,
        )


@attr.s(frozen=True)
class Release(BaseModel, HashableObject):
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
        type=Optional[Dict[str, object]], validator=type_validator(), default=None
    )
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    @staticmethod
    def compute_hash(object_dict):
        return release_identifier(object_dict)

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


@attr.s(frozen=True)
class Revision(BaseModel, HashableObject):
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
        type=Optional[Dict[str, object]], validator=type_validator(), default=None
    )
    parents = attr.ib(type=Tuple[Sha1Git, ...], validator=type_validator(), default=())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    @staticmethod
    def compute_hash(object_dict):
        return revision_identifier(object_dict)

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

    def anonymize(self) -> "Revision":
        """Returns an anonymized version of the Revision object.

        Anonymization consists in replacing the author and committer with an anonymized
        Person object.
        """
        return attr.evolve(
            self, author=self.author.anonymize(), committer=self.committer.anonymize()
        )


@attr.s(frozen=True)
class DirectoryEntry(BaseModel):
    object_type: Final = "directory_entry"

    name = attr.ib(type=bytes, validator=type_validator())
    type = attr.ib(type=str, validator=attr.validators.in_(["file", "dir", "rev"]))
    target = attr.ib(type=Sha1Git, validator=type_validator())
    perms = attr.ib(type=int, validator=type_validator())
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""


@attr.s(frozen=True)
class Directory(BaseModel, HashableObject):
    object_type: Final = "directory"

    entries = attr.ib(type=Tuple[DirectoryEntry, ...], validator=type_validator())
    id = attr.ib(type=Sha1Git, validator=type_validator(), default=b"")

    @staticmethod
    def compute_hash(object_dict):
        return directory_identifier(object_dict)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            entries=tuple(
                DirectoryEntry.from_dict(entry) for entry in d.pop("entries")
            ),
            **d,
        )


@attr.s(frozen=True)
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


@attr.s(frozen=True)
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

    def to_dict(self):
        content = super().to_dict()
        if content["data"] is None:
            del content["data"]
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


@attr.s(frozen=True)
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

    def to_dict(self):
        content = super().to_dict()
        if content["origin"] is None:
            del content["origin"]
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
