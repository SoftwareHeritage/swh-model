# Copyright (C) 2019-2021 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import string
from typing import Sequence

from hypothesis import assume
from hypothesis.extra.dateutil import timezones
from hypothesis.strategies import (
    binary,
    booleans,
    builds,
    characters,
    composite,
    datetimes,
    dictionaries,
    from_regex,
    integers,
    just,
    lists,
    none,
    one_of,
    sampled_from,
    sets,
    text,
    tuples,
)

from .from_disk import DentryPerms
from .model import (
    BaseContent,
    Content,
    Directory,
    DirectoryEntry,
    MetadataAuthority,
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
from .swhids import ExtendedObjectType, ExtendedSWHID

pgsql_alphabet = characters(
    blacklist_categories=("Cs",), blacklist_characters=["\u0000"]
)  # postgresql does not like these


def optional(strategy):
    return one_of(none(), strategy)


def pgsql_text():
    return text(alphabet=pgsql_alphabet)


def sha1_git():
    return binary(min_size=20, max_size=20)


def sha1():
    return binary(min_size=20, max_size=20)


def binaries_without_bytes(blacklist: Sequence[int]):
    """Like hypothesis.strategies.binary, but takes a sequence of bytes that
    should not be included."""
    return lists(sampled_from([i for i in range(256) if i not in blacklist])).map(bytes)


@composite
def extended_swhids(draw):
    object_type = draw(sampled_from(ExtendedObjectType))
    object_id = draw(sha1_git())
    return ExtendedSWHID(object_type=object_type, object_id=object_id)


def aware_datetimes():
    # datetimes in Software Heritage are not used for software artifacts
    # (which may be much older than 2000), but only for objects like scheduler
    # task runs, and origin visits, which were created by Software Heritage,
    # so at least in 2015.
    # We're forbidding old datetimes, because until 1956, many timezones had seconds
    # in their "UTC offsets" (see
    # <https://en.wikipedia.org/wiki/Time_zone#Worldwide_time_zones>), which is not
    # encodable in ISO8601; and we need our datetimes to be ISO8601-encodable in the
    # RPC protocol
    min_value = datetime.datetime(2000, 1, 1, 0, 0, 0)
    return datetimes(min_value=min_value, timezones=timezones())


@composite
def iris(draw):
    protocol = draw(sampled_from(["git", "http", "https", "deb"]))
    domain = draw(from_regex(r"\A([a-z]([a-z0-9é🏛️-]*)\.){1,3}([a-z0-9é])+\Z"))

    return "%s://%s" % (protocol, domain)


@composite
def persons_d(draw):
    fullname = draw(binary())
    email = draw(optional(binary()))
    name = draw(optional(binary()))
    assume(not (len(fullname) == 32 and email is None and name is None))
    return dict(fullname=fullname, name=name, email=email)


def persons(**kwargs):
    return persons_d(**kwargs).map(Person.from_dict)


def timestamps_d(**kwargs):
    max_seconds = datetime.datetime.max.replace(
        tzinfo=datetime.timezone.utc
    ).timestamp()
    min_seconds = datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc
    ).timestamp()

    # in Python 3.9, datetime.datetime.max is 9999-12-31T23:59:59.999999, which
    # means its .timestamp() is 253402300799.999999 in UTC. Unfortunately, because of
    # flotting-point loss of precision, this is rounded up to 253402300800.0, which
    # is the timestamp of 10000-01-01T00:00:00 in UTC, which cannot be passed to
    # datetime.datetime.fromtimestamp because it overflows.
    # To work around this issue, we move from max_seconds and min_seconds one second
    # closer to Epoch, which is more than enough (actually, subtracting 20ms from
    # max_seconds is enough).
    max_seconds -= 1
    min_seconds += 1

    defaults = dict(
        seconds=integers(min_seconds, max_seconds),
        microseconds=integers(0, 1000000 - 1),
    )
    return builds(dict, **{**defaults, **kwargs})


def timestamps():
    return timestamps_d().map(Timestamp.from_dict)


@composite
def timestamps_with_timezone_d(
    draw,
    *,
    timestamp=timestamps_d(),
    offset=integers(min_value=-14 * 60, max_value=14 * 60),
    negative_utc=booleans(),
):
    timestamp = draw(timestamp)
    offset = draw(offset)
    negative_utc = draw(negative_utc)
    assume(not (negative_utc and offset))
    return dict(timestamp=timestamp, offset=offset, negative_utc=negative_utc)


timestamps_with_timezone = timestamps_with_timezone_d().map(
    TimestampWithTimezone.from_dict
)


def origins_d(*, url=iris()):
    return builds(dict, url=url)


def origins(**kwargs):
    return origins_d(**kwargs).map(Origin.from_dict)


def origin_visits_d(**kwargs):
    defaults = dict(
        visit=integers(1, 1000),
        origin=iris(),
        date=aware_datetimes(),
        type=pgsql_text(),
    )
    return builds(dict, **{**defaults, **kwargs})


def origin_visits(**kwargs):
    return origin_visits_d(**kwargs).map(OriginVisit.from_dict)


def metadata_dicts():
    return dictionaries(pgsql_text(), pgsql_text())


def origin_visit_statuses_d(**kwargs):
    defaults = dict(
        visit=integers(1, 1000),
        origin=iris(),
        type=optional(sampled_from(["git", "svn", "pypi", "debian"])),
        status=sampled_from(
            ["created", "ongoing", "full", "partial", "not_found", "failed"]
        ),
        date=aware_datetimes(),
        snapshot=optional(sha1_git()),
        metadata=optional(metadata_dicts()),
    )
    return builds(dict, **{**defaults, **kwargs})


def origin_visit_statuses(**kwargs):
    return origin_visit_statuses_d(**kwargs).map(OriginVisitStatus.from_dict)


@composite
def releases_d(draw, **kwargs):
    defaults = dict(
        target_type=sampled_from([x.value for x in ObjectType]),
        name=binary(),
        message=optional(binary()),
        synthetic=booleans(),
        target=sha1_git(),
        metadata=optional(revision_metadata()),
        raw_manifest=optional(binary()),
    )

    d = draw(
        one_of(
            # None author/date:
            builds(dict, author=none(), date=none(), **{**defaults, **kwargs}),
            # non-None author/date:
            builds(
                dict,
                date=timestamps_with_timezone_d(),
                author=persons_d(),
                **{**defaults, **kwargs},
            ),
            # it is also possible for date to be None but not author, but let's not
            # overwhelm hypothesis with this edge case
        )
    )

    if d["raw_manifest"] is None:
        del d["raw_manifest"]
    return d


def releases(**kwargs):
    return releases_d(**kwargs).map(Release.from_dict)


revision_metadata = metadata_dicts


def extra_headers():
    return lists(
        tuples(binary(min_size=0, max_size=50), binary(min_size=0, max_size=500))
    ).map(tuple)


@composite
def revisions_d(draw, **kwargs):
    defaults = dict(
        message=optional(binary()),
        synthetic=booleans(),
        parents=tuples(sha1_git()),
        directory=sha1_git(),
        type=sampled_from([x.value for x in RevisionType]),
        metadata=optional(revision_metadata()),
        extra_headers=extra_headers(),
        raw_manifest=optional(binary()),
    )
    d = draw(
        one_of(
            # None author/committer/date/committer_date
            builds(
                dict,
                author=none(),
                committer=none(),
                date=none(),
                committer_date=none(),
                **{**defaults, **kwargs},
            ),
            # non-None author/committer/date/committer_date
            builds(
                dict,
                author=persons_d(),
                committer=persons_d(),
                date=timestamps_with_timezone_d(),
                committer_date=timestamps_with_timezone_d(),
                **{**defaults, **kwargs},
            ),
            # There are many other combinations, but let's not overwhelm hypothesis
            # with these edge cases
        )
    )
    # TODO: metadata['extra_headers'] can have binary keys and values

    if d["raw_manifest"] is None:
        del d["raw_manifest"]
    return d


def revisions(**kwargs):
    return revisions_d(**kwargs).map(Revision.from_dict)


def directory_entries_d(**kwargs):
    defaults = dict(
        name=binaries_without_bytes(b"/"),
        target=sha1_git(),
    )
    return one_of(
        builds(
            dict,
            type=just("file"),
            perms=one_of(
                integers(min_value=0o100000, max_value=0o100777),  # regular file
                integers(min_value=0o120000, max_value=0o120777),  # symlink
            ),
            **{**defaults, **kwargs},
        ),
        builds(
            dict,
            type=just("dir"),
            perms=integers(
                min_value=DentryPerms.directory,
                max_value=DentryPerms.directory + 0o777,
            ),
            **{**defaults, **kwargs},
        ),
        builds(
            dict,
            type=just("rev"),
            perms=integers(
                min_value=DentryPerms.revision,
                max_value=DentryPerms.revision + 0o777,
            ),
            **{**defaults, **kwargs},
        ),
    )


def directory_entries(**kwargs):
    return directory_entries_d(**kwargs).map(DirectoryEntry)


@composite
def directories_d(draw, raw_manifest=optional(binary())):
    d = draw(builds(dict, entries=tuples(directory_entries_d())))

    d["raw_manifest"] = draw(raw_manifest)
    if d["raw_manifest"] is None:
        del d["raw_manifest"]
    return d


def directories(**kwargs):
    return directories_d(**kwargs).map(Directory.from_dict)


def contents_d():
    return one_of(present_contents_d(), skipped_contents_d())


def contents():
    return one_of(present_contents(), skipped_contents())


def present_contents_d(**kwargs):
    defaults = dict(
        data=binary(max_size=4096),
        ctime=optional(aware_datetimes()),
        status=one_of(just("visible"), just("hidden")),
    )
    return builds(dict, **{**defaults, **kwargs})


def present_contents(**kwargs):
    return present_contents_d().map(lambda d: Content.from_data(**d))


@composite
def skipped_contents_d(
    draw, reason=pgsql_text(), status=just("absent"), ctime=optional(aware_datetimes())
):
    result = BaseContent._hash_data(draw(binary(max_size=4096)))
    result.pop("data")
    nullify_attrs = draw(
        sets(sampled_from(["sha1", "sha1_git", "sha256", "blake2s256"]))
    )
    for k in nullify_attrs:
        result[k] = None
    result["reason"] = draw(reason)
    result["status"] = draw(status)
    result["ctime"] = draw(ctime)
    return result


def skipped_contents(**kwargs):
    return skipped_contents_d().map(SkippedContent.from_dict)


def branch_names():
    return binary(min_size=1)


def branch_targets_object_d():
    return builds(
        dict,
        target=sha1_git(),
        target_type=sampled_from(
            [x.value for x in TargetType if x.value not in ("alias",)]
        ),
    )


def branch_targets_alias_d():
    return builds(
        dict, target=sha1_git(), target_type=just("alias")
    )  # TargetType.ALIAS.value))


def branch_targets_d(*, only_objects=False):
    if only_objects:
        return branch_targets_object_d()
    else:
        return one_of(branch_targets_alias_d(), branch_targets_object_d())


def branch_targets(*, only_objects=False):
    return builds(SnapshotBranch.from_dict, branch_targets_d(only_objects=only_objects))


@composite
def snapshots_d(draw, *, min_size=0, max_size=100, only_objects=False):
    branches = draw(
        dictionaries(
            keys=branch_names(),
            values=optional(branch_targets_d(only_objects=only_objects)),
            min_size=min_size,
            max_size=max_size,
        )
    )

    if not only_objects:
        # Make sure aliases point to actual branches
        unresolved_aliases = {
            branch: target["target"]
            for branch, target in branches.items()
            if (
                target
                and target["target_type"] == "alias"
                and target["target"] not in branches
            )
        }
        for alias_name, alias_target in unresolved_aliases.items():
            # Override alias branch with one pointing to a real object
            # if max_size constraint is reached
            alias = alias_target if len(branches) < max_size else alias_name
            branches[alias] = draw(branch_targets_d(only_objects=True))

    # Ensure no cycles between aliases
    while True:
        try:
            snapshot = Snapshot.from_dict(
                {
                    "branches": {
                        name: branch or None for (name, branch) in branches.items()
                    }
                }
            )
        except ValueError as e:
            for (source, target) in e.args[1]:
                branches[source] = draw(branch_targets_d(only_objects=True))
        else:
            break

    return snapshot.to_dict()


def snapshots(*, min_size=0, max_size=100, only_objects=False):
    return snapshots_d(
        min_size=min_size, max_size=max_size, only_objects=only_objects
    ).map(Snapshot.from_dict)


def metadata_authorities(url=iris()):
    return builds(MetadataAuthority, url=url, metadata=just(None))


def metadata_fetchers(**kwargs):
    defaults = dict(
        name=text(min_size=1, alphabet=string.printable),
        version=text(
            min_size=1,
            alphabet=string.ascii_letters + string.digits + string.punctuation,
        ),
    )
    return builds(
        MetadataFetcher,
        metadata=just(None),
        **{**defaults, **kwargs},
    )


def raw_extrinsic_metadata(**kwargs):
    defaults = dict(
        target=extended_swhids(),
        discovery_date=aware_datetimes(),
        authority=metadata_authorities(),
        fetcher=metadata_fetchers(),
        format=text(min_size=1, alphabet=string.printable),
    )
    return builds(RawExtrinsicMetadata, **{**defaults, **kwargs})


def raw_extrinsic_metadata_d(**kwargs):
    return raw_extrinsic_metadata(**kwargs).map(RawExtrinsicMetadata.to_dict)


def objects(blacklist_types=("origin_visit_status",), split_content=False):
    """generates a random couple (type, obj)

    which obj is an instance of the Model class corresponding to obj_type.

    `blacklist_types` is a list of obj_type to exclude from the strategy.

    If `split_content` is True, generates Content and SkippedContent under different
    obj_type, resp. "content" and "skipped_content".
    """
    strategies = [
        ("origin", origins),
        ("origin_visit", origin_visits),
        ("origin_visit_status", origin_visit_statuses),
        ("snapshot", snapshots),
        ("release", releases),
        ("revision", revisions),
        ("directory", directories),
        ("raw_extrinsic_metadata", raw_extrinsic_metadata),
    ]
    if split_content:
        strategies.append(("content", present_contents))
        strategies.append(("skipped_content", skipped_contents))
    else:
        strategies.append(("content", contents))
    args = [
        obj_gen().map(lambda x, obj_type=obj_type: (obj_type, x))
        for (obj_type, obj_gen) in strategies
        if obj_type not in blacklist_types
    ]
    return one_of(*args)


def object_dicts(blacklist_types=("origin_visit_status",), split_content=False):
    """generates a random couple (type, dict)

    which dict is suitable for <ModelForType>.from_dict() factory methods.

    `blacklist_types` is a list of obj_type to exclude from the strategy.

    If `split_content` is True, generates Content and SkippedContent under different
    obj_type, resp. "content" and "skipped_content".

    """
    strategies = [
        ("origin", origins_d),
        ("origin_visit", origin_visits_d),
        ("origin_visit_status", origin_visit_statuses_d),
        ("snapshot", snapshots_d),
        ("release", releases_d),
        ("revision", revisions_d),
        ("directory", directories_d),
        ("raw_extrinsic_metadata", raw_extrinsic_metadata_d),
    ]
    if split_content:
        strategies.append(("content", present_contents_d))
        strategies.append(("skipped_content", skipped_contents_d))
    else:
        strategies.append(("content", contents_d))
    args = [
        obj_gen().map(lambda x, obj_type=obj_type: (obj_type, x))
        for (obj_type, obj_gen) in strategies
        if obj_type not in blacklist_types
    ]
    return one_of(*args)
