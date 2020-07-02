# Copyright (C) 2017-2020 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import datetime
import enum
import os
import stat

import attr
from attrs_strict import type_validator
from typing import Any, Iterable, List, Optional, Tuple
from typing_extensions import Final

from .hashutil import MultiHash
from .merkle import MerkleLeaf, MerkleNode
from .identifiers import (
    directory_entry_sort_key,
    directory_identifier,
    identifier_to_bytes as id_to_bytes,
    identifier_to_str as id_to_str,
)
from . import model


@attr.s
class DiskBackedContent(model.BaseContent):
    """Content-like class, which allows lazy-loading data from the disk."""

    object_type: Final = "content_file"

    sha1 = attr.ib(type=bytes, validator=type_validator())
    sha1_git = attr.ib(type=model.Sha1Git, validator=type_validator())
    sha256 = attr.ib(type=bytes, validator=type_validator())
    blake2s256 = attr.ib(type=bytes, validator=type_validator())

    length = attr.ib(type=int, validator=type_validator())

    status = attr.ib(
        type=str,
        validator=attr.validators.in_(["visible", "hidden"]),
        default="visible",
    )

    ctime = attr.ib(
        type=Optional[datetime.datetime],
        validator=type_validator(),
        default=None,
        eq=False,
    )

    path = attr.ib(type=Optional[bytes], default=None)

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    def __attrs_post_init__(self):
        if self.path is None:
            raise TypeError("path must not be None.")

    def with_data(self) -> model.Content:
        args = self.to_dict()
        del args["path"]
        assert self.path is not None
        with open(self.path, "rb") as fd:
            return model.Content.from_dict({**args, "data": fd.read()})


class DentryPerms(enum.IntEnum):
    """Admissible permissions for directory entries."""

    content = 0o100644
    """Content"""
    executable_content = 0o100755
    """Executable content (e.g. executable script)"""
    symlink = 0o120000
    """Symbolic link"""
    directory = 0o040000
    """Directory"""
    revision = 0o160000
    """Revision (e.g. submodule)"""


def mode_to_perms(mode):
    """Convert a file mode to a permission compatible with Software Heritage
    directory entries

    Args:
      mode (int): a file mode as returned by :func:`os.stat` in
                  :attr:`os.stat_result.st_mode`

    Returns:
      DentryPerms: one of the following values:
        :const:`DentryPerms.content`: plain file
        :const:`DentryPerms.executable_content`: executable file
        :const:`DentryPerms.symlink`: symbolic link
        :const:`DentryPerms.directory`: directory

    """
    if stat.S_ISLNK(mode):
        return DentryPerms.symlink
    if stat.S_ISDIR(mode):
        return DentryPerms.directory
    else:
        # file is executable in any way
        if mode & (0o111):
            return DentryPerms.executable_content
        else:
            return DentryPerms.content


class Content(MerkleLeaf):
    """Representation of a Software Heritage content as a node in a Merkle tree.

    The current Merkle hash for the Content nodes is the `sha1_git`, which
    makes it consistent with what :class:`Directory` uses for its own hash
    computation.

    """

    __slots__ = []  # type: List[str]
    object_type: Final = "content"

    @classmethod
    def from_bytes(cls, *, mode, data):
        """Convert data (raw :class:`bytes`) to a Software Heritage content entry

        Args:
          mode (int): a file mode (passed to :func:`mode_to_perms`)
          data (bytes): raw contents of the file
        """
        ret = MultiHash.from_data(data).digest()
        ret["length"] = len(data)
        ret["perms"] = mode_to_perms(mode)
        ret["data"] = data
        ret["status"] = "visible"

        return cls(ret)

    @classmethod
    def from_symlink(cls, *, path, mode):
        """Convert a symbolic link to a Software Heritage content entry"""
        return cls.from_bytes(mode=mode, data=os.readlink(path))

    @classmethod
    def from_file(cls, *, path, max_content_length=None):
        """Compute the Software Heritage content entry corresponding to an
        on-disk file.

        The returned dictionary contains keys useful for both:
        - loading the content in the archive (hashes, `length`)
        - using the content as a directory entry in a directory

        Args:
          save_path (bool): add the file path to the entry
          max_content_length (Optional[int]): if given, all contents larger
            than this will be skipped.

        """
        file_stat = os.lstat(path)
        mode = file_stat.st_mode
        length = file_stat.st_size
        too_large = max_content_length is not None and length > max_content_length

        if stat.S_ISLNK(mode):
            # Symbolic link: return a file whose contents are the link target

            if too_large:
                # Unlike large contents, we can't stream symlinks to
                # MultiHash, and we don't want to fit them in memory if
                # they exceed max_content_length either.
                # Thankfully, this should not happen for reasonable values of
                # max_content_length because of OS/filesystem limitations,
                # so let's just raise an error.
                raise Exception(f"Symlink too large ({length} bytes)")

            return cls.from_symlink(path=path, mode=mode)
        elif not stat.S_ISREG(mode):
            # not a regular file: return the empty file instead
            return cls.from_bytes(mode=mode, data=b"")

        if too_large:
            skip_reason = "Content too large"
        else:
            skip_reason = None

        hashes = MultiHash.from_path(path).digest()
        if skip_reason:
            ret = {
                **hashes,
                "status": "absent",
                "reason": skip_reason,
            }
        else:
            ret = {
                **hashes,
                "status": "visible",
            }

        ret["path"] = path
        ret["perms"] = mode_to_perms(mode)
        ret["length"] = length

        obj = cls(ret)
        return obj

    def __repr__(self):
        return "Content(id=%s)" % id_to_str(self.hash)

    def compute_hash(self):
        return self.data["sha1_git"]

    def to_model(self) -> model.BaseContent:
        """Builds a `model.BaseContent` object based on this leaf."""
        data = self.get_data().copy()
        data.pop("perms", None)
        if data["status"] == "absent":
            data.pop("path", None)
            return model.SkippedContent.from_dict(data)
        elif "data" in data:
            return model.Content.from_dict(data)
        else:
            return DiskBackedContent.from_dict(data)


def accept_all_directories(dirpath: str, dirname: str, entries: Iterable[Any]) -> bool:
    """Default filter for :func:`Directory.from_disk` accepting all
    directories

    Args:
      dirname (bytes): directory name
      entries (list): directory entries
    """
    return True


def ignore_empty_directories(
    dirpath: str, dirname: str, entries: Iterable[Any]
) -> bool:
    """Filter for :func:`directory_to_objects` ignoring empty directories

    Args:
      dirname (bytes): directory name
      entries (list): directory entries
    Returns:
      True if the directory is not empty, false if the directory is empty
    """
    return bool(entries)


def ignore_named_directories(names, *, case_sensitive=True):
    """Filter for :func:`directory_to_objects` to ignore directories named one
    of names.

    Args:
      names (list of bytes): names to ignore
      case_sensitive (bool): whether to do the filtering in a case sensitive
        way
    Returns:
      a directory filter for :func:`directory_to_objects`
    """
    if not case_sensitive:
        names = [name.lower() for name in names]

    def named_filter(
        dirpath: str,
        dirname: str,
        entries: Iterable[Any],
        names: Iterable[Any] = names,
        case_sensitive: bool = case_sensitive,
    ):
        if case_sensitive:
            return dirname not in names
        else:
            return dirname.lower() not in names

    return named_filter


def iter_directory(
    directory,
) -> Tuple[List[model.Content], List[model.SkippedContent], List[model.Directory]]:
    """Return the directory listing from a disk-memory directory instance.

    Raises:
        TypeError in case an unexpected object type is listed.

    Returns:
        Tuple of respectively iterable of content, skipped content and directories.

    """
    contents: List[model.Content] = []
    skipped_contents: List[model.SkippedContent] = []
    directories: List[model.Directory] = []

    for obj in directory.iter_tree():
        obj = obj.to_model()
        obj_type = obj.object_type
        if obj_type in (model.Content.object_type, DiskBackedContent.object_type):
            # FIXME: read the data from disk later (when the
            # storage buffer is flushed).
            obj = obj.with_data()
            contents.append(obj)
        elif obj_type == model.SkippedContent.object_type:
            skipped_contents.append(obj)
        elif obj_type == model.Directory.object_type:
            directories.append(obj)
        else:
            raise TypeError(f"Unexpected object type from disk: {obj}")

    return contents, skipped_contents, directories


class Directory(MerkleNode):
    """Representation of a Software Heritage directory as a node in a Merkle Tree.

    This class can be used to generate, from an on-disk directory, all the
    objects that need to be sent to the Software Heritage archive.

    The :func:`from_disk` constructor allows you to generate the data structure
    from a directory on disk. The resulting :class:`Directory` can then be
    manipulated as a dictionary, using the path as key.

    The :func:`collect` method is used to retrieve all the objects that need to
    be added to the Software Heritage archive since the last collection, by
    class (contents and directories).

    When using the dict-like methods to update the contents of the directory,
    the affected levels of hierarchy are reset and can be collected again using
    the same method. This enables the efficient collection of updated nodes,
    for instance when the client is applying diffs.
    """

    __slots__ = ["__entries"]
    object_type: Final = "directory"

    @classmethod
    def from_disk(
        cls, *, path, dir_filter=accept_all_directories, max_content_length=None
    ):
        """Compute the Software Heritage objects for a given directory tree

        Args:
          path (bytes): the directory to traverse
          data (bool): whether to add the data to the content objects
          save_path (bool): whether to add the path to the content objects
          dir_filter (function): a filter to ignore some directories by
            name or contents. Takes two arguments: dirname and entries, and
            returns True if the directory should be added, False if the
            directory should be ignored.
          max_content_length (Optional[int]): if given, all contents larger
            than this will be skipped.
        """
        top_path = path
        dirs = {}

        for root, dentries, fentries in os.walk(top_path, topdown=False):
            entries = {}
            # Join fentries and dentries in the same processing, as symbolic
            # links to directories appear in dentries...
            for name in fentries + dentries:
                path = os.path.join(root, name)
                if not os.path.isdir(path) or os.path.islink(path):
                    content = Content.from_file(
                        path=path, max_content_length=max_content_length
                    )
                    entries[name] = content
                else:
                    if dir_filter(path, name, dirs[path].entries):
                        entries[name] = dirs[path]

            dirs[root] = cls({"name": os.path.basename(root)})
            dirs[root].update(entries)

        return dirs[top_path]

    def __init__(self, data=None):
        super().__init__(data=data)
        self.__entries = None

    def invalidate_hash(self):
        self.__entries = None
        super().invalidate_hash()

    @staticmethod
    def child_to_directory_entry(name, child):
        if child.object_type == "directory":
            return {
                "type": "dir",
                "perms": DentryPerms.directory,
                "target": child.hash,
                "name": name,
            }
        elif child.object_type == "content":
            return {
                "type": "file",
                "perms": child.data["perms"],
                "target": child.hash,
                "name": name,
            }
        else:
            raise ValueError(f"unknown child {child}")

    def get_data(self, **kwargs):
        return {
            "id": self.hash,
            "entries": self.entries,
        }

    @property
    def entries(self):
        """Child nodes, sorted by name in the same way `directory_identifier`
        does."""
        if self.__entries is None:
            self.__entries = sorted(
                (
                    self.child_to_directory_entry(name, child)
                    for name, child in self.items()
                ),
                key=directory_entry_sort_key,
            )

        return self.__entries

    def compute_hash(self):
        return id_to_bytes(directory_identifier({"entries": self.entries}))

    def to_model(self) -> model.Directory:
        """Builds a `model.Directory` object based on this node;
        ignoring its children."""
        return model.Directory.from_dict(self.get_data())

    def __getitem__(self, key):
        if not isinstance(key, bytes):
            raise ValueError("Can only get a bytes from Directory")

        # Convenience shortcut
        if key == b"":
            return self

        if b"/" not in key:
            return super().__getitem__(key)
        else:
            key1, key2 = key.split(b"/", 1)
            return self.__getitem__(key1)[key2]

    def __setitem__(self, key, value):
        if not isinstance(key, bytes):
            raise ValueError("Can only set a bytes Directory entry")
        if not isinstance(value, (Content, Directory)):
            raise ValueError(
                "Can only set a Directory entry to a Content or " "Directory"
            )

        if key == b"":
            raise ValueError("Directory entry must have a name")
        if b"\x00" in key:
            raise ValueError("Directory entry name must not contain nul bytes")

        if b"/" not in key:
            return super().__setitem__(key, value)
        else:
            key1, key2 = key.rsplit(b"/", 1)
            self[key1].__setitem__(key2, value)

    def __delitem__(self, key):
        if not isinstance(key, bytes):
            raise ValueError("Can only delete a bytes Directory entry")

        if b"/" not in key:
            super().__delitem__(key)
        else:
            key1, key2 = key.rsplit(b"/", 1)
            del self[key1][key2]

    def __repr__(self):
        return "Directory(id=%s, entries=[%s])" % (
            id_to_str(self.hash),
            ", ".join(str(entry) for entry in self),
        )
