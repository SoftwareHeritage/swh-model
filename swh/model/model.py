# Copyright (C) 2018-2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
from enum import Enum
from typing import List, Optional, Dict

import attr
import dateutil.parser

from .identifiers import normalize_timestamp

# TODO: Limit this to 20 bytes
Sha1Git = bytes


def contains_optional_validator(validator):
    """Inspects an attribute's validator to find its type.
    Inspired by `hypothesis/searchstrategy/attrs.py`."""
    if isinstance(validator, attr.validators._OptionalValidator):
        return True
    elif isinstance(validator, attr.validators._AndValidator):
        for validator in validator._validators:
            res = contains_optional_validator(validator)
            if res:
                return True
    else:
        return False


class BaseModel:
    """Base class for SWH model classes.

    Provides serialization/deserialization to/from Python dictionaries,
    that are suitable for JSON/msgpack-like formats."""

    def to_dict(self):
        """Wrapper of `attr.asdict` that can be overriden by subclasses
        that have special handling of some of the fields."""
        return attr.asdict(self)

    @classmethod
    def from_dict(cls, d):
        """Takes a dictionary representing a tree of SWH objects, and
        recursively builds the corresponding objects."""
        if not isinstance(d, dict):
            raise TypeError(
                '%s.from_dict expects a dict, not %r' % (cls.__name__, d))
        kwargs = {}
        for (name, attribute) in attr.fields_dict(cls).items():
            type_ = attribute.type

            # Heuristic to detect `Optional[X]` and unwrap it to `X`.
            if contains_optional_validator(attribute.validator):
                if name not in d:
                    continue
                if d[name] is None:
                    continue
                else:
                    type_ = type_.__args__[0]

            # Construct an object of the expected type
            if issubclass(type_, BaseModel):
                kwargs[name] = type_.from_dict(d[name])
            elif issubclass(type_, Enum):
                kwargs[name] = type_(d[name])
            else:
                kwargs[name] = d[name]

        return cls(**kwargs)


@attr.s
class Person(BaseModel):
    """Represents the author/committer of a revision or release."""
    name = attr.ib(type=bytes)
    email = attr.ib(type=bytes)
    fullname = attr.ib(type=bytes)


@attr.s
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


@attr.s
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
    def from_dict(cls, d):
        """Builds a TimestampWithTimezone from any of the formats
        accepted by :py:`swh.model.normalize_timestamp`."""
        return super().from_dict(normalize_timestamp(d))


@attr.s
class Origin(BaseModel):
    """Represents a software source: a VCS and an URL."""
    type = attr.ib(type=str)
    url = attr.ib(type=str)


@attr.s
class OriginVisit(BaseModel):
    """Represents a visit of an origin at a given point in time, by a
    SWH loader."""
    origin = attr.ib(type=Origin)
    date = attr.ib(type=datetime.datetime)
    visit = attr.ib(type=Optional[int],
                    validator=attr.validators.optional([]))
    """Should not be set before calling 'origin_visit_add()'."""

    def to_dict(self):
        """Serializes the date as a string and omits the visit id if it is
        `None`."""
        ov = super().to_dict()
        ov['date'] = str(self.date)
        if ov['visit'] is None:
            del ov['visit']
        return ov

    @classmethod
    def from_dict(cls, d):
        """Parses the date from a string, and accepts missing visit ids."""
        return cls(
            origin=Origin.from_dict(d['origin']),
            date=dateutil.parser.parse(d['date']),
            visit=d.get('visit'))


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


@attr.s
class SnapshotBranch(BaseModel):
    """Represents one of the branches of a snapshot."""
    target = attr.ib(type=bytes)
    target_type = attr.ib(type=TargetType)

    @target.validator
    def check_target(self, attribute, value):
        """Checks the target type is not an alias, checks the target is a
        valid sha1_git."""
        if self.target_type != TargetType.ALIAS:
            if len(value) != 20:
                raise ValueError('Wrong length for bytes identifier: %d' %
                                 len(value))

    def to_dict(self):
        branch = attr.asdict(self)
        branch['target_type'] = branch['target_type'].value
        return branch


@attr.s
class Snapshot(BaseModel):
    """Represents the full state of an origin at a given point in time."""
    id = attr.ib(type=Sha1Git)
    branches = attr.ib(type=Dict[bytes, Optional[SnapshotBranch]])

    def to_dict(self):
        return {
            'id': self.id,
            'branches': {
                name: branch.to_dict()
                for (name, branch) in self.branches.items()
            }
        }

    @classmethod
    def from_dict(cls, d):
        d = {
            **d,
            'branches': {
                name: SnapshotBranch.from_dict(branch)
                for (name, branch) in d['branches'].items()
            }
        }
        return cls(**d)


@attr.s
class Release(BaseModel):
    id = attr.ib(type=Sha1Git)
    name = attr.ib(type=bytes)
    message = attr.ib(type=bytes)
    target = attr.ib(type=Optional[Sha1Git],
                     validator=attr.validators.optional([]))
    target_type = attr.ib(type=ObjectType)
    synthetic = attr.ib(type=bool)
    author = attr.ib(type=Optional[Person],
                     default=None,
                     validator=attr.validators.optional([]))
    date = attr.ib(type=Optional[TimestampWithTimezone],
                   default=None,
                   validator=attr.validators.optional([]))

    @author.validator
    def check_author(self, attribute, value):
        """If the author is `None`, checks the date is `None` too."""
        if self.author is None and self.date is not None:
            raise ValueError('release date must be None if author is None.')

    def to_dict(self):
        rel = attr.asdict(self)
        rel['date'] = self.date.to_dict() if self.date is not None else None
        rel['target_type'] = rel['target_type'].value
        return rel


class RevisionType(Enum):
    GIT = 'git'
    TAR = 'tar'
    DSC = 'dsc'
    SUBVERSION = 'svn'
    MERCURIAL = 'hg'


@attr.s
class Revision(BaseModel):
    id = attr.ib(type=Sha1Git)
    message = attr.ib(type=bytes)
    author = attr.ib(type=Person)
    committer = attr.ib(type=Person)
    date = attr.ib(type=TimestampWithTimezone)
    committer_date = attr.ib(type=TimestampWithTimezone)
    type = attr.ib(type=RevisionType)
    directory = attr.ib(type=Sha1Git)
    synthetic = attr.ib(type=bool)
    metadata = attr.ib(type=Optional[Dict[str, object]],
                       default=None,
                       validator=attr.validators.optional([]))
    parents = attr.ib(type=List[Sha1Git],
                      default=attr.Factory(list))

    def to_dict(self):
        rev = attr.asdict(self)
        rev['date'] = self.date.to_dict()
        rev['committer_date'] = self.committer_date.to_dict()
        rev['type'] = rev['type'].value
        return rev


@attr.s
class DirectoryEntry(BaseModel):
    name = attr.ib(type=bytes)
    type = attr.ib(type=str,
                   validator=attr.validators.in_(['file', 'dir', 'rev']))
    target = attr.ib(type=Sha1Git)
    perms = attr.ib(type=int)
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""


@attr.s
class Directory(BaseModel):
    id = attr.ib(type=Sha1Git)
    entries = attr.ib(type=List[DirectoryEntry])

    def to_dict(self):
        dir_ = attr.asdict(self)
        dir_['entries'] = [entry.to_dict() for entry in self.entries]
        return dir_

    @classmethod
    def from_dict(cls, d):
        d = {
            **d,
            'entries': list(map(DirectoryEntry.from_dict, d['entries']))
        }
        return super().from_dict(d)


@attr.s
class Content(BaseModel):
    sha1 = attr.ib(type=bytes)
    sha1_git = attr.ib(type=Sha1Git)
    sha256 = attr.ib(type=bytes)
    blake2s256 = attr.ib(type=bytes)

    length = attr.ib(type=int)
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(['visible', 'absent', 'hidden']))
    reason = attr.ib(type=Optional[str],
                     default=None,
                     validator=attr.validators.optional([]))
    data = attr.ib(type=Optional[bytes],
                   default=None,
                   validator=attr.validators.optional([]))

    @length.validator
    def check_length(self, attribute, value):
        """Checks the length is positive."""
        if value < 0:
            raise ValueError('Length must be positive.')

    @reason.validator
    def check_reason(self, attribute, value):
        """Checks the reason is full iff status != absent."""
        assert self.reason == value
        if self.status == 'absent' and value is None:
            raise ValueError('Must provide a reason if content is absent.')
        elif self.status != 'absent' and value is not None:
            raise ValueError(
                'Must not provide a reason if content is not absent.')

    def to_dict(self):
        content = attr.asdict(self)
        if content['data'] is None:
            del content['data']
        if content['reason'] is None:
            del content['reason']
        return content
