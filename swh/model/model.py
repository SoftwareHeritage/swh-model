# Copyright (C) 2018-2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime

from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import List, Optional, Dict, Union

import attr
import dateutil.parser
import iso8601

from .identifiers import (
    normalize_timestamp, directory_identifier, revision_identifier,
    release_identifier, snapshot_identifier
)
from .hashutil import DEFAULT_ALGORITHMS, hash_to_bytes


class MissingData(Exception):
    """Raised by `Content.with_data` when it has no way of fetching the
    data (but not when fetching the data fails)."""
    pass


SHA1_SIZE = 20

# TODO: Limit this to 20 bytes
Sha1Git = bytes


class BaseModel:
    """Base class for SWH model classes.

    Provides serialization/deserialization to/from Python dictionaries,
    that are suitable for JSON/msgpack-like formats."""

    def to_dict(self):
        """Wrapper of `attr.asdict` that can be overridden by subclasses
        that have special handling of some of the fields."""

        def dictify(value):
            if isinstance(value, BaseModel):
                return value.to_dict()
            elif isinstance(value, Enum):
                return value.value
            elif isinstance(value, dict):
                return {k: dictify(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [dictify(v) for v in value]
            else:
                return value

        ret = attr.asdict(self, recurse=False)
        return dictify(ret)

    @classmethod
    def from_dict(cls, d):
        """Takes a dictionary representing a tree of SWH objects, and
        recursively builds the corresponding objects."""
        return cls(**d)


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
            object.__setattr__(self, 'id', obj_id)


@attr.s(frozen=True)
class Person(BaseModel):
    """Represents the author/committer of a revision or release."""
    fullname = attr.ib(type=bytes)
    name = attr.ib(type=Optional[bytes])
    email = attr.ib(type=Optional[bytes])


@attr.s(frozen=True)
class Timestamp(BaseModel):
    """Represents a naive timestamp from a VCS."""
    seconds = attr.ib(type=int)
    microseconds = attr.ib(type=int)

    @seconds.validator
    def check_seconds(self, attribute, value):
        """Check that seconds fit in a 64-bits signed integer."""
        if not (-2**63 <= value < 2**63):
            raise ValueError('Seconds must be a signed 64-bits integer.')

    @microseconds.validator
    def check_microseconds(self, attribute, value):
        """Checks that microseconds are positive and < 1000000."""
        if not (0 <= value < 10**6):
            raise ValueError('Microseconds must be in [0, 1000000[.')


@attr.s(frozen=True)
class TimestampWithTimezone(BaseModel):
    """Represents a TZ-aware timestamp from a VCS."""
    timestamp = attr.ib(type=Timestamp)
    offset = attr.ib(type=int)
    negative_utc = attr.ib(type=bool)

    @offset.validator
    def check_offset(self, attribute, value):
        """Checks the offset is a 16-bits signed integer (in theory, it
        should always be between -14 and +14 hours)."""
        if not (-2**15 <= value < 2**15):
            # max 14 hours offset in theory, but you never know what
            # you'll find in the wild...
            raise ValueError('offset too large: %d minutes' % value)

    @classmethod
    def from_dict(cls, obj: Union[Dict, datetime.datetime, int]):
        """Builds a TimestampWithTimezone from any of the formats
        accepted by :func:`swh.model.normalize_timestamp`."""
        # TODO: this accept way more types than just dicts; find a better
        # name
        d = normalize_timestamp(obj)
        return cls(
            timestamp=Timestamp.from_dict(d['timestamp']),
            offset=d['offset'],
            negative_utc=d['negative_utc'])

    @classmethod
    def from_datetime(cls, dt: datetime.datetime):
        return cls.from_dict(dt)

    @classmethod
    def from_iso8601(cls, s):
        """Builds a TimestampWithTimezone from an ISO8601-formatted string.
        """
        dt = iso8601.parse_date(s)
        tstz = cls.from_datetime(dt)
        if dt.tzname() == '-00:00':
            tstz = attr.evolve(tstz, negative_utc=True)
        return tstz


@attr.s(frozen=True)
class Origin(BaseModel):
    """Represents a software source: a VCS and an URL."""
    url = attr.ib(type=str)
    type = attr.ib(type=Optional[str], default=None)

    def to_dict(self):
        r = super().to_dict()
        r.pop('type', None)
        return r


@attr.s(frozen=True)
class OriginVisit(BaseModel):
    """Represents a visit of an origin at a given point in time, by a
    SWH loader."""
    origin = attr.ib(type=str)
    date = attr.ib(type=datetime.datetime)
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(['ongoing', 'full', 'partial']))
    type = attr.ib(type=str)
    snapshot = attr.ib(type=Optional[Sha1Git])
    metadata = attr.ib(type=Optional[Dict[str, object]],
                       default=None)

    visit = attr.ib(type=Optional[int],
                    default=None)
    """Should not be set before calling 'origin_visit_add()'."""

    def to_dict(self):
        """Serializes the date as a string and omits the visit id if it is
        `None`."""
        ov = super().to_dict()
        if ov['visit'] is None:
            del ov['visit']
        return ov

    @classmethod
    def from_dict(cls, d):
        """Parses the date from a string, and accepts missing visit ids."""
        d = d.copy()
        date = d.pop('date')
        return cls(
            date=(date
                  if isinstance(date, datetime.datetime)
                  else dateutil.parser.parse(date)),
            **d)


class TargetType(Enum):
    """The type of content pointed to by a snapshot branch. Usually a
    revision or an alias."""
    CONTENT = 'content'
    DIRECTORY = 'directory'
    REVISION = 'revision'
    RELEASE = 'release'
    SNAPSHOT = 'snapshot'
    ALIAS = 'alias'


class ObjectType(Enum):
    """The type of content pointed to by a release. Usually a revision"""
    CONTENT = 'content'
    DIRECTORY = 'directory'
    REVISION = 'revision'
    RELEASE = 'release'
    SNAPSHOT = 'snapshot'


@attr.s(frozen=True)
class SnapshotBranch(BaseModel):
    """Represents one of the branches of a snapshot."""
    target = attr.ib(type=bytes)
    target_type = attr.ib(type=TargetType)

    @target.validator
    def check_target(self, attribute, value):
        """Checks the target type is not an alias, checks the target is a
        valid sha1_git."""
        if self.target_type != TargetType.ALIAS and self.target is not None:
            if len(value) != 20:
                raise ValueError('Wrong length for bytes identifier: %d' %
                                 len(value))

    @classmethod
    def from_dict(cls, d):
        return cls(
            target=d['target'],
            target_type=TargetType(d['target_type']))


@attr.s(frozen=True)
class Snapshot(BaseModel, HashableObject):
    """Represents the full state of an origin at a given point in time."""
    branches = attr.ib(type=Dict[bytes, Optional[SnapshotBranch]])
    id = attr.ib(type=Sha1Git, default=b'')

    @staticmethod
    def compute_hash(object_dict):
        return snapshot_identifier(object_dict)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            branches={
                name: SnapshotBranch.from_dict(branch) if branch else None
                for (name, branch) in d.pop('branches').items()
            },
            **d)


@attr.s(frozen=True)
class Release(BaseModel, HashableObject):
    name = attr.ib(type=bytes)
    message = attr.ib(type=bytes)
    target = attr.ib(type=Optional[Sha1Git])
    target_type = attr.ib(type=ObjectType)
    synthetic = attr.ib(type=bool)
    author = attr.ib(type=Optional[Person],
                     default=None)
    date = attr.ib(type=Optional[TimestampWithTimezone],
                   default=None)
    metadata = attr.ib(type=Optional[Dict[str, object]],
                       default=None)
    id = attr.ib(type=Sha1Git, default=b'')

    @staticmethod
    def compute_hash(object_dict):
        return release_identifier(object_dict)

    @author.validator
    def check_author(self, attribute, value):
        """If the author is `None`, checks the date is `None` too."""
        if self.author is None and self.date is not None:
            raise ValueError('release date must be None if author is None.')

    def to_dict(self):
        rel = super().to_dict()
        if rel['metadata'] is None:
            del rel['metadata']
        return rel

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        if d.get('author'):
            d['author'] = Person.from_dict(d['author'])
        if d.get('date'):
            d['date'] = TimestampWithTimezone.from_dict(d['date'])
        return cls(
            target_type=ObjectType(d.pop('target_type')),
            **d)


class RevisionType(Enum):
    GIT = 'git'
    TAR = 'tar'
    DSC = 'dsc'
    SUBVERSION = 'svn'
    MERCURIAL = 'hg'


@attr.s(frozen=True)
class Revision(BaseModel, HashableObject):
    message = attr.ib(type=bytes)
    author = attr.ib(type=Person)
    committer = attr.ib(type=Person)
    date = attr.ib(type=Optional[TimestampWithTimezone])
    committer_date = attr.ib(type=Optional[TimestampWithTimezone])
    type = attr.ib(type=RevisionType)
    directory = attr.ib(type=Sha1Git)
    synthetic = attr.ib(type=bool)
    metadata = attr.ib(type=Optional[Dict[str, object]],
                       default=None)
    parents = attr.ib(type=List[Sha1Git],
                      default=attr.Factory(list))
    id = attr.ib(type=Sha1Git, default=b'')

    @staticmethod
    def compute_hash(object_dict):
        return revision_identifier(object_dict)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        date = d.pop('date')
        if date:
            date = TimestampWithTimezone.from_dict(date)

        committer_date = d.pop('committer_date')
        if committer_date:
            committer_date = TimestampWithTimezone.from_dict(
                committer_date)

        return cls(
            author=Person.from_dict(d.pop('author')),
            committer=Person.from_dict(d.pop('committer')),
            date=date,
            committer_date=committer_date,
            type=RevisionType(d.pop('type')),
            **d)


@attr.s(frozen=True)
class DirectoryEntry(BaseModel):
    name = attr.ib(type=bytes)
    type = attr.ib(type=str,
                   validator=attr.validators.in_(['file', 'dir', 'rev']))
    target = attr.ib(type=Sha1Git)
    perms = attr.ib(type=int)
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""


@attr.s(frozen=True)
class Directory(BaseModel, HashableObject):
    entries = attr.ib(type=List[DirectoryEntry])
    id = attr.ib(type=Sha1Git, default=b'')

    @staticmethod
    def compute_hash(object_dict):
        return directory_identifier(object_dict)

    @classmethod
    def from_dict(cls, d):
        d = d.copy()
        return cls(
            entries=[DirectoryEntry.from_dict(entry)
                     for entry in d.pop('entries')],
            **d)


@attr.s(frozen=True)
class BaseContent(BaseModel):
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(['visible', 'hidden', 'absent']))

    def to_dict(self):
        content = super().to_dict()
        if content['ctime'] is None:
            del content['ctime']
        return content

    @classmethod
    def from_dict(cls, d, use_subclass=True):
        if use_subclass:
            # Chooses a subclass to instantiate instead.
            if d['status'] == 'absent':
                return SkippedContent.from_dict(d)
            else:
                return Content.from_dict(d)
        else:
            return super().from_dict(d)

    def get_hash(self, hash_name):
        if hash_name not in DEFAULT_ALGORITHMS:
            raise ValueError('{} is not a valid hash name.'.format(hash_name))
        return getattr(self, hash_name)

    def hashes(self) -> Dict[str, bytes]:
        """Returns a dictionary {hash_name: hash_value}"""
        return {algo: getattr(self, algo) for algo in DEFAULT_ALGORITHMS}


@attr.s(frozen=True)
class Content(BaseContent):
    sha1 = attr.ib(type=bytes)
    sha1_git = attr.ib(type=Sha1Git)
    sha256 = attr.ib(type=bytes)
    blake2s256 = attr.ib(type=bytes)

    length = attr.ib(type=int)

    status = attr.ib(
        type=str,
        default='visible',
        validator=attr.validators.in_(['visible', 'hidden']))

    data = attr.ib(type=Optional[bytes], default=None)

    ctime = attr.ib(type=Optional[datetime.datetime],
                    default=None)

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive."""
        if value < 0:
            raise ValueError('Length must be positive.')

    def to_dict(self):
        content = super().to_dict()
        if content['data'] is None:
            del content['data']
        return content

    @classmethod
    def from_dict(cls, d):
        return super().from_dict(d, use_subclass=False)

    def with_data(self) -> 'Content':
        """Loads the `data` attribute; meaning that it is guaranteed not to
        be None after this call.

        This call is almost a no-op, but subclasses may overload this method
        to lazy-load data (eg. from disk or objstorage)."""
        if self.data is None:
            raise MissingData('Content data is None.')
        return self


@attr.s(frozen=True)
class SkippedContent(BaseContent):
    sha1 = attr.ib(type=Optional[bytes])
    sha1_git = attr.ib(type=Optional[Sha1Git])
    sha256 = attr.ib(type=Optional[bytes])
    blake2s256 = attr.ib(type=Optional[bytes])

    length = attr.ib(type=Optional[int])

    status = attr.ib(
        type=str,
        validator=attr.validators.in_(['absent']))
    reason = attr.ib(type=Optional[str],
                     default=None)

    origin = attr.ib(type=Optional[Origin],
                     default=None)

    ctime = attr.ib(type=Optional[datetime.datetime],
                    default=None)

    @reason.validator
    def check_reason(self, attribute, value):
        """Checks the reason is full if status != absent."""
        assert self.reason == value
        if value is None:
            raise ValueError('Must provide a reason if content is absent.')

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive or -1."""
        if value < -1:
            raise ValueError('Length must be positive or -1.')

    def to_dict(self):
        content = super().to_dict()
        if content['origin'] is None:
            del content['origin']
        return content

    @classmethod
    def from_dict(cls, d):
        d2 = d
        d = d.copy()
        if d.pop('data', None) is not None:
            raise ValueError('SkippedContent has no "data" attribute %r' % d2)
        return super().from_dict(d, use_subclass=False)
