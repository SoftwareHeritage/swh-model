# Copyright (C) 2019-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import attr
import datetime

from hypothesis import assume
from hypothesis.strategies import (
    binary, booleans, builds, characters, composite, dictionaries,
    from_regex, integers, just, lists, none, one_of,
    sampled_from, sets, text, tuples,
)

from .from_disk import DentryPerms
from .model import (
    Person, Timestamp, TimestampWithTimezone, Origin, OriginVisit,
    OriginVisitUpdate, Snapshot, SnapshotBranch, TargetType, Release,
    Revision, Directory, DirectoryEntry, Content, SkippedContent
)
from .identifiers import snapshot_identifier, identifier_to_bytes


pgsql_alphabet = characters(
    blacklist_categories=('Cs', ),
    blacklist_characters=['\u0000'])  # postgresql does not like these


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
    protocol = draw(sampled_from(['git', 'http', 'https', 'deb']))
    domain = draw(from_regex(r'\A([a-z]([a-z0-9-]*)\.){1,3}[a-z0-9]+\Z'))

    return '%s://%s' % (protocol, domain)


def persons():
    return builds(Person, email=optional(binary()), name=optional(binary()))


def timestamps():
    max_seconds = datetime.datetime.max.replace(
        tzinfo=datetime.timezone.utc).timestamp()
    min_seconds = datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc).timestamp()
    return builds(
        Timestamp,
        seconds=integers(min_seconds, max_seconds),
        microseconds=integers(0, 1000000))


@composite
def timestamps_with_timezone(
        draw,
        timestamp=timestamps(),
        offset=integers(min_value=-14*60, max_value=14*60),
        negative_utc=booleans()):
    timestamp = draw(timestamp)
    offset = draw(offset)
    negative_utc = draw(negative_utc)
    assume(not (negative_utc and offset))
    return TimestampWithTimezone(
        timestamp=timestamp,
        offset=offset,
        negative_utc=negative_utc)


def origins():
    return builds(
        Origin,
        url=urls())


def origin_visits():
    return builds(
        OriginVisit,
        visit=integers(0, 1000),
        origin=urls(),
        status=sampled_from(['ongoing', 'full', 'partial']),
        type=pgsql_text(),
        snapshot=optional(sha1_git()),
    )


def metadata_dicts():
    return dictionaries(pgsql_text(), pgsql_text())


def origin_visit_updates():
    return builds(
        OriginVisitUpdate,
        visit=integers(0, 1000),
        origin=urls(),
        status=sampled_from(['ongoing', 'full', 'partial']),
        snapshot=optional(sha1_git()),
        metadata=one_of(none(), metadata_dicts()))


@composite
def releases(draw):
    (date, author) = draw(one_of(
        tuples(none(), none()),
        tuples(timestamps_with_timezone(), persons())))
    rel = draw(builds(
        Release,
        author=none(),
        date=none(),
        target=sha1_git()))
    return attr.evolve(
        rel,
        date=date,
        author=author)


revision_metadata = metadata_dicts


def revisions():
    return builds(
        Revision,
        author=persons(),
        committer=persons(),
        date=timestamps_with_timezone(),
        committer_date=timestamps_with_timezone(),
        parents=lists(sha1_git()),
        directory=sha1_git(),
        metadata=one_of(none(), revision_metadata()))
    # TODO: metadata['extra_headers'] can have binary keys and values


def directory_entries():
    return builds(
        DirectoryEntry,
        target=sha1_git(),
        perms=sampled_from([perm.value for perm in DentryPerms]))


def directories():
    return builds(
        Directory,
        entries=lists(directory_entries()))


def contents():
    return one_of(present_contents(), skipped_contents())


def present_contents():
    return builds(
        Content.from_data,
        binary(max_size=4096),
        status=one_of(just('visible'), just('hidden')),
    )


@composite
def skipped_contents(draw):
    nullify_attrs = draw(
        sets(sampled_from(['sha1', 'sha1_git', 'sha256', 'blake2s256']))
    )

    new_attrs = {
        k: None
        for k in nullify_attrs
    }

    ret = draw(builds(
        SkippedContent.from_data,
        binary(max_size=4096),
        reason=pgsql_text(),
    ))

    return attr.evolve(ret, **new_attrs)


def branch_names():
    return binary(min_size=1)


def branch_targets_object():
    return builds(
        SnapshotBranch,
        target=sha1_git(),
        target_type=sampled_from([
            TargetType.CONTENT, TargetType.DIRECTORY, TargetType.REVISION,
            TargetType.RELEASE, TargetType.SNAPSHOT]))


def branch_targets_alias():
    return builds(
        SnapshotBranch,
        target_type=just(TargetType.ALIAS))


def branch_targets(*, only_objects=False):
    if only_objects:
        return branch_targets_object()
    else:
        return one_of(branch_targets_alias(), branch_targets_object())


@composite
def snapshots(draw, *, min_size=0, max_size=100, only_objects=False):
    branches = draw(dictionaries(
        keys=branch_names(),
        values=one_of(
            none(),
            branch_targets(only_objects=only_objects)
        ),
        min_size=min_size,
        max_size=max_size,
    ))

    if not only_objects:
        # Make sure aliases point to actual branches
        unresolved_aliases = {
            target.target
            for target in branches.values()
            if (target
                and target.target_type == 'alias'
                and target.target not in branches)
         }

        for alias in unresolved_aliases:
            branches[alias] = draw(branch_targets(only_objects=True))

    # Ensure no cycles between aliases
    while True:
        try:
            id_ = snapshot_identifier({
                'branches': {
                    name: branch.to_dict() if branch else None
                    for (name, branch) in branches.items()}})
        except ValueError as e:
            for (source, target) in e.args[1]:
                branches[source] = draw(branch_targets(only_objects=True))
        else:
            break
    return Snapshot(
        id=identifier_to_bytes(id_),
        branches=branches)


def objects():
    return one_of(
        origins().map(lambda x: ('origin', x)),
        origin_visits().map(lambda x: ('origin_visit', x)),
        origin_visit_updates().map(lambda x: ('origin_visit_update', x)),
        snapshots().map(lambda x: ('snapshot', x)),
        releases().map(lambda x: ('release', x)),
        revisions().map(lambda x: ('revision', x)),
        directories().map(lambda x: ('directory', x)),
        contents().map(lambda x: ('content', x)),
    )


def object_dicts():
    return objects().map(lambda x: (x[0], x[1].to_dict()))
