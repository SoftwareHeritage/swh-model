# Copyright (C) 2022 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Primitives for finding unknown content efficiently."""

from __future__ import annotations

from collections import namedtuple
import itertools
import logging
import random
from typing import Any, Iterable, List, Mapping, NamedTuple, Set, Union

from typing_extensions import Protocol, runtime_checkable

from .from_disk import model
from .model import Sha1Git

logger = logging.getLogger(__name__)

# Maximum amount when sampling from the undecided set of directory entries
SAMPLE_SIZE = 1000

# Sets of sha1 of contents, skipped contents and directories respectively
Sample: NamedTuple = namedtuple(
    "Sample", ["contents", "skipped_contents", "directories"]
)


@runtime_checkable
class ArchiveDiscoveryInterface(Protocol):
    """Interface used in discovery code to abstract over ways of connecting to
    the SWH archive (direct storage, web API, etc.) for all methods needed by
    discovery algorithms."""

    contents: List[model.Content]
    skipped_contents: List[model.SkippedContent]
    directories: List[model.Directory]

    def __init__(
        self,
        contents: List[model.Content],
        skipped_contents: List[model.SkippedContent],
        directories: List[model.Directory],
    ) -> None:
        self.contents = contents
        self.skipped_contents = skipped_contents
        self.directories = directories

    async def content_missing(self, contents: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List content missing from the archive by sha1"""

    async def skipped_content_missing(
        self, skipped_contents: List[Sha1Git]
    ) -> Iterable[Sha1Git]:
        """List skipped content missing from the archive by sha1"""

    async def directory_missing(self, directories: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List directories missing from the archive by sha1"""


class BaseDiscoveryGraph:
    """Creates the base structures and methods needed for discovery algorithms.
    Subclasses should override ``get_sample`` to affect how the discovery is made."""

    def __init__(self, contents, skipped_contents, directories):
        self._all_contents: Mapping[
            Sha1Git, Union[model.Content, model.SkippedContent]
        ] = {}
        self._undecided_directories: Set[Sha1Git] = set()
        self._children: Mapping[Sha1Git, model.DirectoryEntry] = {}
        self._parents: Mapping[model.DirectoryEntry, Sha1Git] = {}
        self.undecided: Set[Sha1Git] = set()

        for content in itertools.chain(contents, skipped_contents):
            self.undecided.add(content.sha1_git)
            self._all_contents[content.sha1_git] = content

        for directory in directories:
            self.undecided.add(directory.id)
            self._undecided_directories.add(directory.id)
            self._children[directory.id] = {c.target for c in directory.entries}
            for child in directory.entries:
                self._parents.setdefault(child.target, set()).add(directory.id)

        self.undecided |= self._undecided_directories
        self.known: Set[Sha1Git] = set()
        self.unknown: Set[Sha1Git] = set()

    def mark_known(self, entries: Iterable[Sha1Git]):
        """Mark ``entries`` and those they imply as known in the SWH archive"""
        self._mark_entries(entries, self._children, self.known)

    def mark_unknown(self, entries: Iterable[Sha1Git]):
        """Mark ``entries`` and those they imply as unknown in the SWH archive"""
        self._mark_entries(entries, self._parents, self.unknown)

    def _mark_entries(
        self,
        entries: Iterable[Sha1Git],
        transitive_mapping: Mapping[Any, Any],
        target_set: Set[Any],
    ):
        """Use Merkle graph properties to mark a directory entry as known or unknown.

        If an entry is known, then all of its descendants are known. If it's
        unknown, then all of its ancestors are unknown.

        - ``entries``: directory entries to mark along with their ancestors/descendants
          where applicable.
        - ``transitive_mapping``: mapping from an entry to the next entries to mark
          in the hierarchy, if any.
        - ``target_set``: set where marked entries will be added.

        """
        to_process = set(entries)
        while to_process:
            current = to_process.pop()
            target_set.add(current)
            self.undecided.discard(current)
            self._undecided_directories.discard(current)
            next_entries = transitive_mapping.get(current, set()) & self.undecided
            to_process.update(next_entries)

    async def get_sample(
        self,
    ) -> Sample:
        """Return a three-tuple of samples from the undecided sets of contents,
        skipped contents and directories respectively.
        These samples will be queried against the storage which will tell us
        which are known."""
        raise NotImplementedError()

    async def do_query(
        self, archive: ArchiveDiscoveryInterface, sample: Sample
    ) -> None:
        """Given a three-tuple of samples, ask the archive which are known or
        unknown and mark them as such."""

        methods = (
            archive.content_missing,
            archive.skipped_content_missing,
            archive.directory_missing,
        )

        for sample_per_type, method in zip(sample, methods):
            if not sample_per_type:
                continue
            known = set(sample_per_type)
            unknown = set(await method(list(sample_per_type)))
            known -= unknown

            self.mark_known(known)
            self.mark_unknown(unknown)


class RandomDirSamplingDiscoveryGraph(BaseDiscoveryGraph):
    """Use a random sampling using only directories.

    This allows us to find a statistically good spread of entries in the graph
    with a smaller population than using all types of entries. When there are
    no more directories, only contents or skipped contents are undecided if any
    are left: we send them directly to the storage since they should be few and
    their structure flat."""

    async def get_sample(self) -> Sample:
        if self._undecided_directories:
            if len(self._undecided_directories) <= SAMPLE_SIZE:
                return Sample(
                    contents=set(),
                    skipped_contents=set(),
                    directories=set(self._undecided_directories),
                )
            sample = random.sample(tuple(self._undecided_directories), SAMPLE_SIZE)
            directories = {o for o in sample}
            return Sample(
                contents=set(), skipped_contents=set(), directories=directories
            )

        contents = set()
        skipped_contents = set()

        for sha1 in self.undecided:
            obj = self._all_contents[sha1]
            obj_type = obj.object_type
            if obj_type == model.Content.object_type:
                contents.add(sha1)
            elif obj_type == model.SkippedContent.object_type:
                skipped_contents.add(sha1)
            else:
                raise TypeError(f"Unexpected object type {obj_type}")

        return Sample(
            contents=contents, skipped_contents=skipped_contents, directories=set()
        )


async def filter_known_objects(archive: ArchiveDiscoveryInterface):
    """Filter ``archive``'s ``contents``, ``skipped_contents`` and ``directories``
    to only return those that are unknown to the SWH archive using a discovery
    algorithm."""
    contents = archive.contents
    skipped_contents = archive.skipped_contents
    directories = archive.directories

    contents_count = len(contents)
    skipped_contents_count = len(skipped_contents)
    directories_count = len(directories)

    graph = RandomDirSamplingDiscoveryGraph(contents, skipped_contents, directories)

    while graph.undecided:
        sample = await graph.get_sample()
        await graph.do_query(archive, sample)

    contents = [c for c in contents if c.sha1_git in graph.unknown]
    skipped_contents = [c for c in skipped_contents if c.sha1_git in graph.unknown]
    directories = [c for c in directories if c.id in graph.unknown]

    logger.debug(
        "Filtered out %d contents, %d skipped contents and %d directories",
        contents_count - len(contents),
        skipped_contents_count - len(skipped_contents),
        directories_count - len(directories),
    )

    return (contents, skipped_contents, directories)
