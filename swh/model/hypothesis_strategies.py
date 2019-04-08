# Copyright (C) 2019 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from hypothesis.strategies import (
    lists, one_of, composite, builds, integers, sampled_from, binary,
    dictionaries, none, from_regex, just
)


from .from_disk import DentryPerms
from .model import (
    Person, Timestamp, TimestampWithTimezone, Origin, OriginVisit,
    Snapshot, SnapshotBranch, TargetType, Release, Revision,
    Directory, DirectoryEntry, Content
)
from .identifiers import snapshot_identifier, identifier_to_bytes


def sha1_git():
    return binary(min_size=20, max_size=20)


@composite
def urls(draw):
    protocol = draw(sampled_from(['git', 'http', 'https', 'deb']))
    domain = draw(from_regex(r'\A([a-z]([a-z0-9-]*)\.){1,3}[a-z0-9]+\Z'))

    return '%s://%s' % (protocol, domain)


def persons():
    return builds(Person)


def timestamps():
    return builds(
        Timestamp,
        seconds=integers(-2**63, 2**63-1),
        microseconds=integers(0, 1000000))


def timestamps_with_timezone():
    return builds(
        TimestampWithTimezone,
        timestamp=timestamps(),
        offset=integers(-2**16, 2**16-1))


def origins():
    return builds(
        Origin,
        type=sampled_from(['git', 'hg', 'svn', 'pypi', 'deb']),
        url=urls())


def origin_visits():
    return builds(
        OriginVisit,
        visit=integers(0, 1000),
        origin=origins())


def releases():
    return builds(
        Release,
        id=sha1_git(),
        date=timestamps_with_timezone(),
        author=one_of(none(), persons()),
        target=one_of(none(), sha1_git()))


def revisions():
    return builds(
        Revision,
        id=sha1_git(),
        date=timestamps_with_timezone(),
        committer_date=timestamps_with_timezone(),
        parents=lists(binary()),
        directory=binary(),
        metadata=one_of(none(), dictionaries(binary(), binary())))


def directory_entries():
    return builds(
        DirectoryEntry,
        target=sha1_git(),
        perms=sampled_from([perm.value for perm in DentryPerms]))


def directories():
    return builds(
        Directory,
        id=sha1_git(),
        entries=lists(directory_entries()))


def contents():
    def filter_data(content):
        if content.status != 'visible':
            content.data = None
        return content

    return builds(
        Content,
        length=integers(0),
        data=binary(),
        sha1_git=sha1_git(),
    ).map(filter_data)


def branch_names():
    return binary()


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
        values=branch_targets(only_objects=only_objects),
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

    while True:
        try:
            id_ = snapshot_identifier({
                'branches': {
                    name: branch.to_dict()
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
        snapshots().map(lambda x: ('snapshot', x)),
        releases().map(lambda x: ('release', x)),
        revisions().map(lambda x: ('revision', x)),
        directories().map(lambda x: ('directory', x)),
        contents().map(lambda x: ('content', x)),
    )


def object_dicts():
    return objects().map(lambda x: (x[0], x[1].to_dict()))
