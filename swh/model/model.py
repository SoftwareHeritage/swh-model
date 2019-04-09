# Copyright (C) 2018-2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
from enum import Enum
from typing import List, Optional, Dict

import attr


# TODO: Limit this to 20 bytes
Sha1Git = bytes


@attr.s
class Person:
    name = attr.ib(type=bytes)
    email = attr.ib(type=bytes)
    fullname = attr.ib(type=bytes)


@attr.s
class Timestamp:
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
class TimestampWithTimezone:
    timestamp = attr.ib(type=Timestamp)
    offset = attr.ib(type=int)
    negative_utc = attr.ib(type=bool)

    def to_dict(self):
        return attr.asdict(self)

    @offset.validator
    def check_offset(self, attribute, value):
        if not (-2**15 <= value < 2**15):
            # max 14 hours offset in theory, but you never know what
            # you'll find in the wild...
            raise ValueError('offset too large: %d minutes' % value)


@attr.s
class Origin:
    type = attr.ib(type=str)
    url = attr.ib(type=str)

    def to_dict(self):
        return attr.asdict(self)


@attr.s
class OriginVisit:
    origin = attr.ib(type=Origin)
    date = attr.ib(type=datetime.datetime)
    visit = attr.ib(type=Optional[int])
    """Should not be set before calling 'origin_visit_add()'."""

    def to_dict(self):
        ov = attr.asdict(self)
        ov['origin'] = self.origin.to_dict()
        ov['date'] = str(self.date)
        if not ov['visit']:
            del ov['visit']
        return ov


class TargetType(Enum):
    CONTENT = 'content'
    DIRECTORY = 'directory'
    REVISION = 'revision'
    RELEASE = 'release'
    SNAPSHOT = 'snapshot'
    ALIAS = 'alias'


class ObjectType(Enum):
    CONTENT = 'content'
    DIRECTORY = 'directory'
    REVISION = 'revision'
    RELEASE = 'release'
    SNAPSHOT = 'snapshot'


@attr.s
class SnapshotBranch:
    target = attr.ib(type=bytes)
    target_type = attr.ib(type=TargetType)

    @target.validator
    def check_target(self, attribute, value):
        if self.target_type != TargetType.ALIAS:
            if len(value) != 20:
                raise ValueError('Wrong length for bytes identifier: %d' %
                                 len(value))

    def to_dict(self):
        branch = attr.asdict(self)
        branch['target_type'] = branch['target_type'].value
        return branch


@attr.s
class Snapshot:
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


@attr.s
class Release:
    id = attr.ib(type=Sha1Git)
    name = attr.ib(type=bytes)
    message = attr.ib(type=bytes)
    date = attr.ib(type=Optional[TimestampWithTimezone])
    author = attr.ib(type=Optional[Person])
    target = attr.ib(type=Optional[Sha1Git])
    target_type = attr.ib(type=ObjectType)
    synthetic = attr.ib(type=bool)

    def to_dict(self):
        rel = attr.asdict(self)
        rel['date'] = self.date.to_dict() if self.date is not None else None
        rel['target_type'] = rel['target_type'].value
        return rel

    @author.validator
    def check_author(self, attribute, value):
        if self.author is None and self.date is not None:
            raise ValueError('release date must be None if date is None.')


class RevisionType(Enum):
    GIT = 'git'
    TAR = 'tar'
    DSC = 'dsc'
    SUBVERSION = 'svn'
    MERCURIAL = 'hg'


@attr.s
class Revision:
    id = attr.ib(type=Sha1Git)
    message = attr.ib(type=bytes)
    author = attr.ib(type=Person)
    committer = attr.ib(type=Person)
    date = attr.ib(type=TimestampWithTimezone)
    committer_date = attr.ib(type=TimestampWithTimezone)
    parents = attr.ib(type=List[Sha1Git])
    type = attr.ib(type=RevisionType)
    directory = attr.ib(type=Sha1Git)
    metadata = attr.ib(type=Optional[Dict[str, object]])
    synthetic = attr.ib(type=bool)

    def to_dict(self):
        rev = attr.asdict(self)
        rev['date'] = self.date.to_dict()
        rev['committer_date'] = self.committer_date.to_dict()
        rev['type'] = rev['type'].value
        return rev


@attr.s
class DirectoryEntry:
    name = attr.ib(type=bytes)
    type = attr.ib(type=str,
                   validator=attr.validators.in_(['file', 'dir', 'rev']))
    target = attr.ib(type=Sha1Git)
    perms = attr.ib(type=int)
    """Usually one of the values of `swh.model.from_disk.DentryPerms`."""

    def to_dict(self):
        return attr.asdict(self)


@attr.s
class Directory:
    id = attr.ib(type=Sha1Git)
    entries = attr.ib(type=List[DirectoryEntry])

    def to_dict(self):
        dir_ = attr.asdict(self)
        dir_['entries'] = [entry.to_dict() for entry in self.entries]
        return dir_


@attr.s
class Content:
    sha1 = attr.ib(type=bytes)
    sha1_git = attr.ib(type=Sha1Git)
    sha256 = attr.ib(type=bytes)
    blake2s256 = attr.ib(type=bytes)

    data = attr.ib(type=bytes)
    length = attr.ib(type=int)
    status = attr.ib(
        type=str,
        validator=attr.validators.in_(['visible', 'absent', 'hidden']))
    reason = attr.ib(type=Optional[str])

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
