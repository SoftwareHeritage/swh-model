# Copyright (C) 2019-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime

from hypothesis import assume
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
)

from .from_disk import DentryPerms
from .model import (
    Person,
    Timestamp,
    TimestampWithTimezone,
    Origin,
    OriginVisit,
    OriginVisitStatus,
    Snapshot,
    SnapshotBranch,
    ObjectType,
    TargetType,
    Release,
    Revision,
    RevisionType,
    BaseContent,
    Directory,
    DirectoryEntry,
    Content,
    SkippedContent,
)
from .identifiers import snapshot_identifier, identifier_to_bytes


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


@composite
def urls(draw):
    protocol = draw(sampled_from(["git", "http", "https", "deb"]))
    domain = draw(from_regex(r"\A([a-z]([a-z0-9-]*)\.){1,3}[a-z0-9]+\Z"))

    return "%s://%s" % (protocol, domain)


def persons_d():
    return builds(
        dict, fullname=binary(), email=optional(binary()), name=optional(binary()),
    )


def persons():
    return persons_d().map(Person.from_dict)


def timestamps_d():
    max_seconds = datetime.datetime.max.replace(
        tzinfo=datetime.timezone.utc
    ).timestamp()
    min_seconds = datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc
    ).timestamp()
    return builds(
        dict,
        seconds=integers(min_seconds, max_seconds),
        microseconds=integers(0, 1000000),
    )


def timestamps():
    return timestamps_d().map(Timestamp.from_dict)


@composite
def timestamps_with_timezone_d(
    draw,
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


def origins_d():
    return builds(dict, url=urls())


def origins():
    return origins_d().map(Origin.from_dict)


def origin_visits_d():
    return builds(
        dict,
        visit=integers(0, 1000),
        origin=urls(),
        date=datetimes(),
        status=sampled_from(["ongoing", "full", "partial"]),
        type=pgsql_text(),
        snapshot=optional(sha1_git()),
    )


def origin_visits():
    return origin_visits_d().map(OriginVisit.from_dict)


def metadata_dicts():
    return dictionaries(pgsql_text(), pgsql_text())


def origin_visit_statuses_d():
    return builds(
        dict,
        visit=integers(0, 1000),
        origin=urls(),
        status=sampled_from(["ongoing", "full", "partial"]),
        date=datetimes(),
        snapshot=optional(sha1_git()),
        metadata=one_of(none(), metadata_dicts()),
    )


def origin_visit_statuses():
    return origin_visit_statuses_d().map(OriginVisitStatus.from_dict)


@composite
def releases_d(draw):
    target_type = sampled_from([x.value for x in ObjectType])
    name = binary()
    message = binary()
    synthetic = booleans()
    target = sha1_git()
    metadata = one_of(none(), revision_metadata())

    return draw(
        one_of(
            builds(
                dict,
                name=name,
                message=message,
                synthetic=synthetic,
                author=none(),
                date=none(),
                target=target,
                target_type=target_type,
                metadata=metadata,
            ),
            builds(
                dict,
                name=name,
                message=message,
                synthetic=synthetic,
                date=timestamps_with_timezone_d(),
                author=persons_d(),
                target=target,
                target_type=target_type,
                metadata=metadata,
            ),
        )
    )


def releases():
    return releases_d().map(Release.from_dict)


revision_metadata = metadata_dicts


def revisions_d():
    return builds(
        dict,
        message=binary(),
        synthetic=booleans(),
        author=persons_d(),
        committer=persons_d(),
        date=timestamps_with_timezone_d(),
        committer_date=timestamps_with_timezone_d(),
        parents=lists(sha1_git()),
        directory=sha1_git(),
        type=sampled_from([x.value for x in RevisionType]),
        metadata=one_of(none(), revision_metadata()),
    )
    # TODO: metadata['extra_headers'] can have binary keys and values


def revisions():
    return revisions_d().map(Revision.from_dict)


def directory_entries_d():
    return builds(
        dict,
        name=binary(),
        target=sha1_git(),
        type=sampled_from(["file", "dir", "rev"]),
        perms=sampled_from([perm.value for perm in DentryPerms]),
    )


def directory_entries():
    return directory_entries_d().map(DirectoryEntry)


def directories_d():
    return builds(dict, entries=lists(directory_entries_d()))


def directories():
    return directories_d().map(Directory.from_dict)


def contents_d():
    return one_of(present_contents_d(), skipped_contents_d())


def contents():
    return one_of(present_contents(), skipped_contents())


def present_contents_d():
    return builds(
        dict,
        data=binary(max_size=4096),
        ctime=optional(datetimes()),
        status=one_of(just("visible"), just("hidden")),
    )


def present_contents():
    return present_contents_d().map(lambda d: Content.from_data(**d))


@composite
def skipped_contents_d(draw):
    result = BaseContent._hash_data(draw(binary(max_size=4096)))
    result.pop("data")
    nullify_attrs = draw(
        sets(sampled_from(["sha1", "sha1_git", "sha256", "blake2s256"]))
    )
    for k in nullify_attrs:
        result[k] = None
    result["reason"] = draw(pgsql_text())
    result["status"] = "absent"
    result["ctime"] = draw(optional(datetimes()))
    return result


def skipped_contents():
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
            values=one_of(none(), branch_targets_d(only_objects=only_objects)),
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
            id_ = snapshot_identifier(
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

    return dict(id=identifier_to_bytes(id_), branches=branches)


def snapshots(*, min_size=0, max_size=100, only_objects=False):
    return snapshots_d(
        min_size=min_size, max_size=max_size, only_objects=only_objects
    ).map(Snapshot.from_dict)


def objects():
    return one_of(
        origins().map(lambda x: ("origin", x)),
        origin_visits().map(lambda x: ("origin_visit", x)),
        origin_visit_statuses().map(lambda x: ("origin_visit_update", x)),
        snapshots().map(lambda x: ("snapshot", x)),
        releases().map(lambda x: ("release", x)),
        revisions().map(lambda x: ("revision", x)),
        directories().map(lambda x: ("directory", x)),
        contents().map(lambda x: ("content", x)),
    )


def object_dicts():
    """generates a random couple (type, dict)

    which dict is suitable for <ModelForType>.from_dict() factory methods.
    """
    return one_of(
        origins_d().map(lambda x: ("origin", x)),
        origin_visits_d().map(lambda x: ("origin_visit", x)),
        snapshots_d().map(lambda x: ("snapshot", x)),
        releases_d().map(lambda x: ("release", x)),
        revisions_d().map(lambda x: ("revision", x)),
        directories_d().map(lambda x: ("directory", x)),
        contents_d().map(lambda x: ("content", x)),
    )
