# Copyright (C) 2019-2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
from typing import Dict, Sequence

import attr

from swh.model.hashutil import MultiHash, hash_to_bytes
from swh.model.model import (
    BaseModel,
    Content,
    Directory,
    DirectoryEntry,
    ExtID,
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
from swh.model.swhids import ExtendedSWHID

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
        timestamp=Timestamp(
            seconds=1234567891,
            microseconds=0,
        ),
        offset_bytes=b"+0200",
    ),
    TimestampWithTimezone(
        timestamp=Timestamp(
            seconds=1234567892,
            microseconds=0,
        ),
        offset_bytes=b"+0200",
    ),
]

REVISIONS = [
    Revision(
        id=hash_to_bytes("66c7c1cd9673275037140f2abff7b7b11fc9439c"),
        message=b"hello",
        date=DATES[0],
        committer=COMMITTERS[0],
        author=COMMITTERS[0],
        committer_date=DATES[0],
        type=RevisionType.GIT,
        directory=b"\x01" * 20,
        synthetic=False,
        metadata=None,
        parents=(
            hash_to_bytes("9b918dd063cec85c2bc63cc7f167e29f5894dcbc"),
            hash_to_bytes("757f38bdcd8473aaa12df55357f5e2f1a318e672"),
        ),
    ),
    Revision(
        id=hash_to_bytes("c7f96242d73c267adc77c2908e64e0c1cb6a4431"),
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
    Revision(
        id=hash_to_bytes("51580d63b8dcc0ec73e74994e66896858542840a"),
        message=b"hello",
        date=DATES[0],
        committer=COMMITTERS[0],
        author=COMMITTERS[0],
        committer_date=DATES[0],
        type=RevisionType.GIT,
        directory=b"\x01" * 20,
        synthetic=False,
        metadata=None,
        parents=(hash_to_bytes("9b918dd063cec85c2bc63cc7f167e29f5894dcbc"),),
        raw_manifest=(
            b"commit 207\x00"
            b"tree 0101010101010101010101010101010101010101\n"
            b"parent 9B918DD063CEC85C2BC63CC7F167E29F5894DCBC"  # upper-cased
            b"nauthor foo 1234567891 +0200\n"
            b"committer foo 1234567891 +0200"
            b"\n\nhello"
        ),
    ),
]

EXTIDS = [
    ExtID(
        extid_type="git256",
        extid=b"\x03" * 32,
        target=REVISIONS[0].swhid(),
    ),
    ExtID(
        extid_type="hg",
        extid=b"\x04" * 20,
        target=REVISIONS[1].swhid(),
    ),
    ExtID(
        extid_type="hg-nodeid",
        extid=b"\x05" * 20,
        target=REVISIONS[1].swhid(),
        extid_version=1,
    ),
]

RELEASES = [
    Release(
        id=hash_to_bytes("8059dc4e17fcd0e51ca3bcd6b80f4577d281fd08"),
        name=b"v0.0.1",
        date=TimestampWithTimezone(
            timestamp=Timestamp(
                seconds=1234567890,
                microseconds=0,
            ),
            offset_bytes=b"+0200",
        ),
        author=COMMITTERS[0],
        target_type=ObjectType.REVISION,
        target=b"\x04" * 20,
        message=b"foo",
        synthetic=False,
    ),
    Release(
        id=hash_to_bytes("ee4d20e80af850cc0f417d25dc5073792c5010d2"),
        name=b"this-is-a/tag/1.0",
        date=None,
        author=None,
        target_type=ObjectType.DIRECTORY,
        target=b"\x05" * 20,
        message=b"bar",
        synthetic=False,
    ),
    Release(
        id=hash_to_bytes("1cdd1e87234b6f066d0855a3b5b567638a55d583"),
        name=b"v0.0.1",
        date=TimestampWithTimezone(
            timestamp=Timestamp(
                seconds=1234567890,
                microseconds=0,
            ),
            offset_bytes=b"+0200",
        ),
        author=COMMITTERS[0],
        target_type=ObjectType.REVISION,
        target=b"\x04" * 20,
        message=b"foo",
        synthetic=False,
        raw_manifest=(
            b"tag 102\x00"
            b"object 0404040404040404040404040404040404040404\n"
            b"type commit\n"
            b"tag v0.0.1\n"
            b"tagger foo 1234567890 +200"  # missing leading 0 for timezone
            b"\n\nfoo"
        ),
    ),
]

ORIGINS = [
    Origin(
        url="https://somewhere.org/den/fox",
    ),
    Origin(
        url="https://overtherainbow.org/fox/den",
    ),
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
        snapshot=hash_to_bytes("9e78d7105c5e0f886487511e2a92377b4ee4c32a"),
        metadata=None,
    ),
    OriginVisitStatus(
        origin=ORIGINS[1].url,
        date=datetime.datetime(2015, 11, 27, 17, 22, 18, tzinfo=UTC),
        visit=2,
        type="hg",
        status="partial",
        snapshot=hash_to_bytes("0e7f84ede9a254f2cd55649ad5240783f557e65f"),
        metadata=None,
    ),
]


DIRECTORIES = [
    Directory(id=hash_to_bytes("4b825dc642cb6eb9a060e54bf8d69288fbee4904"), entries=()),
    Directory(
        id=hash_to_bytes("87b339104f7dc2a8163dec988445e3987995545f"),
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
                name=b"subprepo1",
                perms=0o160000,
                type="rev",
                target=REVISIONS[1].id,
            ),
        ),
    ),
    Directory(
        id=hash_to_bytes("d135a91ac82a754e7f4bdeff8d56ef06d921eb7d"),
        entries=(
            DirectoryEntry(
                name=b"file1.ext",
                perms=0o644,
                type="file",
                target=b"\x11" * 20,
            ),
        ),
        raw_manifest=(
            b"tree 34\x00"
            + b"00644 file1.ext\x00"  # added two leading zeros
            + b"\x11" * 20
        ),
    ),
]


SNAPSHOTS = [
    Snapshot(
        id=hash_to_bytes("9e78d7105c5e0f886487511e2a92377b4ee4c32a"),
        branches={
            b"master": SnapshotBranch(
                target_type=TargetType.REVISION, target=REVISIONS[0].id
            )
        },
    ),
    Snapshot(
        id=hash_to_bytes("0e7f84ede9a254f2cd55649ad5240783f557e65f"),
        branches={
            b"target/revision": SnapshotBranch(
                target_type=TargetType.REVISION,
                target=REVISIONS[0].id,
            ),
            b"target/alias": SnapshotBranch(
                target_type=TargetType.ALIAS, target=b"target/revision"
            ),
            b"target/directory": SnapshotBranch(
                target_type=TargetType.DIRECTORY,
                target=DIRECTORIES[0].id,
            ),
            b"target/release": SnapshotBranch(
                target_type=TargetType.RELEASE, target=RELEASES[0].id
            ),
            b"target/snapshot": SnapshotBranch(
                target_type=TargetType.SNAPSHOT,
                target=hash_to_bytes("9e78d7105c5e0f886487511e2a92377b4ee4c32a"),
            ),
        },
    ),
]


METADATA_AUTHORITIES = [
    MetadataAuthority(
        type=MetadataAuthorityType.FORGE,
        url="http://example.org/",
        metadata={},
    ),
]

METADATA_FETCHERS = [
    MetadataFetcher(
        name="test-fetcher",
        version="1.0.0",
        metadata={},
    )
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
    "extid": EXTIDS,
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

SAMPLE_FOLDER_SWHIDS = [
    "swh:1:dir:e8b0f1466af8608c8a3fb9879db172b887e80759",
    "swh:1:cnt:7d5c08111e21c8a9f71540939998551683375fad",
    "swh:1:cnt:68769579c3eaadbe555379b9c3538e6628bae1eb",
    "swh:1:cnt:e86b45e538d9b6888c969c89fbd22a85aa0e0366",
    "swh:1:dir:3c1f578394f4623f74a0ba7fe761729f59fc6ec4",
    "swh:1:dir:c3020f6bf135a38c6df3afeb5fb38232c5e07087",
    "swh:1:cnt:133693b125bad2b4ac318535b84901ebb1f6b638",
    "swh:1:dir:4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "swh:1:cnt:19102815663d23f8b75a47e7a01965dcdc96468c",
    "swh:1:dir:2b41c40f0d1fbffcba12497db71fba83fcca96e5",
    "swh:1:cnt:8185dfb2c0c2c597d16f75a8a0c37668567c3d7e",
    "swh:1:cnt:7c4c57ba9ff496ad179b8f65b1d286edbda34c9a",
    "swh:1:cnt:acac326ddd63b0bc70840659d4ac43619484e69f",
]
