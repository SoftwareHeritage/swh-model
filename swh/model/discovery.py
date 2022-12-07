# Copyright (C) 2022 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

"""Primitives for finding the unknown parts of disk contents efficiently."""

import abc
from collections import namedtuple
import itertools
import logging
from typing import Any, Iterable, List, Mapping, NamedTuple, Set, Union

from swh.model.from_disk import model
from swh.model.model import Sha1Git
from swh.storage.interface import StorageInterface

logger = logging.getLogger(__name__)

# Maximum amount when sampling from the undecided set of directory entries
SAMPLE_SIZE = 1000

# Sets of sha1 of contents, skipped contents and directories respectively
Sample: NamedTuple = namedtuple(
    "Sample", ["contents", "skipped_contents", "directories"]
)


class ArchiveDiscoveryInterface(abc.ABC):
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

    @abc.abstractmethod
    async def content_missing(self, contents: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List content missing from the archive by sha1"""

    @abc.abstractmethod
    async def skipped_content_missing(
        self, skipped_contents: List[Sha1Git]
    ) -> Iterable[Sha1Git]:
        """List skipped content missing from the archive by sha1"""

    @abc.abstractmethod
    async def directory_missing(self, directories: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List directories missing from the archive by sha1"""


class DiscoveryStorageConnection(ArchiveDiscoveryInterface):
    """Use the storage APIs to query the archive"""

    def __init__(
        self,
        contents: List[model.Content],
        skipped_contents: List[model.SkippedContent],
        directories: List[model.Directory],
        swh_storage: StorageInterface,
    ) -> None:
        super().__init__(contents, skipped_contents, directories)
        self.storage = swh_storage

    async def content_missing(self, contents: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List content missing from the archive by sha1"""
        return self.storage.content_missing_per_sha1_git(contents)

    async def skipped_content_missing(
        self, skipped_contents: List[Sha1Git]
    ) -> Iterable[Sha1Git]:
        """List skipped content missing from the archive by sha1"""
        contents = [
            {"sha1_git": s, "sha1": None, "sha256": None, "blake2s256": None}
            for s in skipped_contents
        ]
        return (d["sha1_git"] for d in self.storage.skipped_content_missing(contents))

    async def directory_missing(self, directories: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List directories missing from the archive by sha1"""
        return self.storage.directory_missing(directories)


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
