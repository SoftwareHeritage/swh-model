# Copyright (C) 2023 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from dataclasses import dataclass
from typing import Iterable, List

from swh.model import discovery, model
from swh.model.hashutil import hash_to_bytes
from swh.model.model import Sha1Git
from swh.model.tests.test_identifiers import directory_example

pytest_plugins = ["aiohttp.pytest_plugin"]

UNKNOWN_HASH = hash_to_bytes("17140cb6109f1e3296dc52e2b2cd29bcb40e86be")
KNOWN_CONTENT_HASH = hash_to_bytes("e8e4106de42e2d5d5efab6a9422b9a8677c993c8")
KNOWN_DIRECTORY_HASH = hash_to_bytes("d7ed3d2c31d608823be58b1cbe57605310615231")
KNOWN_DIRECTORY_HASH_2 = hash_to_bytes("c76724e9a0be4b60f4bf0cb48b261df8eda94b1d")


@dataclass
class FakeArchive:
    contents: List[model.Content]
    skipped_contents: List[model.SkippedContent]
    directories: List[model.Directory]

    def content_missing(self, contents: List[Sha1Git]) -> Iterable[Sha1Git]:
        return []

    def skipped_content_missing(
        self, skipped_contents: List[Sha1Git]
    ) -> Iterable[Sha1Git]:
        """List skipped content missing from the archive by sha1"""
        return []

    def directory_missing(self, directories: List[Sha1Git]) -> Iterable[Sha1Git]:
        """List directories missing from the archive by sha1"""
        return []


def test_filter_known_objects(monkeypatch):
    # Test with smaller sample sizes to actually trigger the random sampling
    monkeypatch.setattr(discovery, "SAMPLE_SIZE", 1)

    base_directory = model.Directory.from_dict(directory_example)

    # Hardcoding another hash is enough since it's all that's being checked
    directory_data = directory_example.copy()
    directory_data["id"] = KNOWN_DIRECTORY_HASH_2
    other_directory = model.Directory.from_dict(directory_data)
    archive = FakeArchive(
        contents=[model.Content.from_data(b"blabla")],
        skipped_contents=[model.SkippedContent.from_data(b"blabla2", reason="reason")],
        directories=[
            base_directory,
            other_directory,
        ],
    )
    assert archive.contents[0].sha1_git == KNOWN_CONTENT_HASH
    assert archive.directories[0].id == KNOWN_DIRECTORY_HASH
    assert archive.directories[1].id == KNOWN_DIRECTORY_HASH_2
    (contents, skipped_contents, directories) = discovery.filter_known_objects(archive)
    assert len(contents) == 0
    assert len(skipped_contents) == 0
    assert len(directories) == 0
