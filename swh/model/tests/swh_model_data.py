# Copyright (C) 2019-2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
from typing import Dict, Sequence

import attr

from swh.model.hashutil import MultiHash, hash_to_bytes
from swh.model.identifiers import ExtendedSWHID
from swh.model.model import (
    BaseModel,
    Content,
    Directory,
    DirectoryEntry,
    MetadataAuthority,
    MetadataAuthorityType,
    MetadataFetcher,
    ObjectType,
    Origin,
    OriginVisit,
    OriginVisitStatus,
    Person,
    RawExtrinsicMetadata,
    Release,
    Revision,
    RevisionType,
    SkippedContent,
    Snapshot,
    SnapshotBranch,
    TargetType,
    Timestamp,
    TimestampWithTimezone,
)

UTC = datetime.timezone.utc

CONTENTS = [
    Content(
        length=4,
        data=f"foo{i}".encode(),
        status="visible",
        **MultiHash.from_data(f"foo{i}".encode()).digest(),
    )
    for i in range(10)
] + [
    Content(
        length=14,
        data=f"forbidden foo{i}".encode(),
        status="hidden",
        **MultiHash.from_data(f"forbidden foo{i}".encode()).digest(),
    )
    for i in range(10)
]

SKIPPED_CONTENTS = [
    SkippedContent(
        length=4,
        status="absent",
        reason=f"because chr({i}) != '*'",
        **MultiHash.from_data(f"bar{i}".encode()).digest(),
    )
    for i in range(2)
]

duplicate_content1 = Content(
    length=4,
    sha1=hash_to_bytes("44973274ccef6ab4dfaaf86599792fa9c3fe4689"),
    sha1_git=b"another-foo",
    blake2s256=b"another-bar",
    sha256=b"another-baz",
    status="visible",
)

# Craft a sha1 collision
sha1_array = bytearray(duplicate_content1.sha1_git)
sha1_array[0] += 1
duplicate_content2 = attr.evolve(duplicate_content1, sha1_git=bytes(sha1_array))


DUPLICATE_CONTENTS = [duplicate_content1, duplicate_content2]


COMMITTERS = [
    Person(fullname=b"foo", name=b"foo", email=b""),
    Person(fullname=b"bar", name=b"bar", email=b""),
]

DATES = [
    TimestampWithTimezone(
        timestamp=Timestamp(seconds=1234567891, microseconds=0,),
        offset=120,
        negative_utc=False,
    ),
    TimestampWithTimezone(
        timestamp=Timestamp(seconds=1234567892, microseconds=0,),
        offset=120,
        negative_utc=False,
    ),
]

REVISIONS = [
    Revision(
        id=hash_to_bytes("4ca486e65eb68e4986aeef8227d2db1d56ce51b3"),
        message=b"hello",
        date=DATES[0],
        committer=COMMITTERS[0],
        author=COMMITTERS[0],
        committer_date=DATES[0],
        type=RevisionType.GIT,
        directory=b"\x01" * 20,
        synthetic=False,
        metadata=None,
        parents=(),
    ),
    Revision(
        id=hash_to_bytes("677063f5c405d6fc1781fc56379c9a9adf43d3a0"),
        message=b"hello again",
        date=DATES[1],
        committer=COMMITTERS[1],
        author=COMMITTERS[1],
        committer_date=DATES[1],
        type=RevisionType.MERCURIAL,
        directory=b"\x02" * 20,
        synthetic=False,
        metadata=None,
        parents=(),
        extra_headers=((b"foo", b"bar"),),
    ),
]

RELEASES = [
    Release(
        id=hash_to_bytes("8059dc4e17fcd0e51ca3bcd6b80f4577d281fd08"),
        name=b"v0.0.1",
        date=TimestampWithTimezone(
            timestamp=Timestamp(seconds=1234567890, microseconds=0,),
            offset=120,
            negative_utc=False,
        ),
        author=COMMITTERS[0],
        target_type=ObjectType.REVISION,
        target=b"\x04" * 20,
        message=b"foo",
        synthetic=False,
    ),
]

ORIGINS = [
    Origin(url="https://somewhere.org/den/fox",),
    Origin(url="https://overtherainbow.org/fox/den",),
]

ORIGIN_VISITS = [
    OriginVisit(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2013, 5, 7, 4, 20, 39, 369271, tzinfo=UTC),
        visit=1,
        type="git",
    ),
    OriginVisit(
        origin=ORIGINS[1].url,
        date=datetime.datetime(2014, 11, 27, 17, 20, 39, tzinfo=UTC),
        visit=1,
        type="hg",
    ),
    OriginVisit(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2018, 11, 27, 17, 20, 39, tzinfo=UTC),
        visit=2,
        type="git",
    ),
    OriginVisit(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2018, 11, 27, 17, 20, 39, tzinfo=UTC),
        visit=3,
        type="git",
    ),
    OriginVisit(
        origin=ORIGINS[1].url,
        date=datetime.datetime(2015, 11, 27, 17, 20, 39, tzinfo=UTC),
        visit=2,
        type="hg",
    ),
]

# The origin-visit-status dates needs to be shifted slightly in the future from their
# visit dates counterpart. Otherwise, we are hitting storage-wise the "on conflict"
# ignore policy (because origin-visit-add creates an origin-visit-status with the same
# parameters from the origin-visit {origin, visit, date}...
ORIGIN_VISIT_STATUSES = [
    OriginVisitStatus(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2013, 5, 7, 4, 20, 39, 432222, tzinfo=UTC),
        visit=1,
        type="git",
        status="ongoing",
        snapshot=None,
        metadata=None,
    ),
    OriginVisitStatus(
        origin=ORIGINS[1].url,
        date=datetime.datetime(2014, 11, 27, 17, 21, 12, tzinfo=UTC),
        visit=1,
        type="hg",
        status="ongoing",
        snapshot=None,
        metadata=None,
    ),
    OriginVisitStatus(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2018, 11, 27, 17, 20, 59, tzinfo=UTC),
        visit=2,
        type="git",
        status="ongoing",
        snapshot=None,
        metadata=None,
    ),
    OriginVisitStatus(
        origin=ORIGINS[0].url,
        date=datetime.datetime(2018, 11, 27, 17, 20, 49, tzinfo=UTC),
        visit=3,
        type="git",
        status="full",
        snapshot=hash_to_bytes("17d0066a4a80aba4a0e913532ee8ff2014f006a9"),
        metadata=None,
    ),
    OriginVisitStatus(
        origin=ORIGINS[1].url,
        date=datetime.datetime(2015, 11, 27, 17, 22, 18, tzinfo=UTC),
        visit=2,
        type="hg",
        status="partial",
        snapshot=hash_to_bytes("8ce268b87faf03850693673c3eb5c9bb66e1ca38"),
        metadata=None,
    ),
]


DIRECTORIES = [
    Directory(id=hash_to_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904"), entries=()),
    Directory(
        id=hash_to_bytes("21416d920e0ebf0df4a7888bed432873ed5cb3a7"),
        entries=(
            DirectoryEntry(
                name=b"file1.ext",
                perms=0o644,
                type="file",
                target=CONTENTS[0].sha1_git,
            ),
            DirectoryEntry(
                name=b"dir1",
                perms=0o755,
                type="dir",
                target=hash_to_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
            ),
            DirectoryEntry(
                name=b"subprepo1", perms=0o160000, type="rev", target=REVISIONS[1].id,
            ),
        ),
    ),
]


SNAPSHOTS = [
    Snapshot(
        id=hash_to_bytes("17d0066a4a80aba4a0e913532ee8ff2014f006a9"),
        branches={
            b"master": SnapshotBranch(
                target_type=TargetType.REVISION, target=REVISIONS[0].id
            )
        },
    ),
    Snapshot(
        id=hash_to_bytes("8ce268b87faf03850693673c3eb5c9bb66e1ca38"),
        branches={
            b"target/revision": SnapshotBranch(
                target_type=TargetType.REVISION, target=REVISIONS[0].id,
            ),
            b"target/alias": SnapshotBranch(
                target_type=TargetType.ALIAS, target=b"target/revision"
            ),
            b"target/directory": SnapshotBranch(
                target_type=TargetType.DIRECTORY, target=DIRECTORIES[0].id,
            ),
            b"target/release": SnapshotBranch(
                target_type=TargetType.RELEASE, target=RELEASES[0].id
            ),
            b"target/snapshot": SnapshotBranch(
                target_type=TargetType.SNAPSHOT,
                target=hash_to_bytes("17d0066a4a80aba4a0e913532ee8ff2014f006a9"),
            ),
        },
    ),
]


METADATA_AUTHORITIES = [
    MetadataAuthority(
        type=MetadataAuthorityType.FORGE, url="http://example.org/", metadata={},
    ),
]

METADATA_FETCHERS = [
    MetadataFetcher(name="test-fetcher", version="1.0.0", metadata={},)
]

RAW_EXTRINSIC_METADATA = [
    RawExtrinsicMetadata(
        target=Origin("http://example.org/foo.git").swhid(),
        discovery_date=datetime.datetime(2020, 7, 30, 17, 8, 20, tzinfo=UTC),
        authority=attr.evolve(METADATA_AUTHORITIES[0], metadata=None),
        fetcher=attr.evolve(METADATA_FETCHERS[0], metadata=None),
        format="json",
        metadata=b'{"foo": "bar"}',
    ),
    RawExtrinsicMetadata(
        target=ExtendedSWHID.from_string(str(CONTENTS[0].swhid())),
        discovery_date=datetime.datetime(2020, 7, 30, 17, 8, 20, tzinfo=UTC),
        authority=attr.evolve(METADATA_AUTHORITIES[0], metadata=None),
        fetcher=attr.evolve(METADATA_FETCHERS[0], metadata=None),
        format="json",
        metadata=b'{"foo": "bar"}',
    ),
]


TEST_OBJECTS: Dict[str, Sequence[BaseModel]] = {
    "content": CONTENTS,
    "directory": DIRECTORIES,
    "metadata_authority": METADATA_AUTHORITIES,
    "metadata_fetcher": METADATA_FETCHERS,
    "origin": ORIGINS,
    "origin_visit": ORIGIN_VISITS,
    "origin_visit_status": ORIGIN_VISIT_STATUSES,
    "raw_extrinsic_metadata": RAW_EXTRINSIC_METADATA,
    "release": RELEASES,
    "revision": REVISIONS,
    "snapshot": SNAPSHOTS,
    "skipped_content": SKIPPED_CONTENTS,
}
