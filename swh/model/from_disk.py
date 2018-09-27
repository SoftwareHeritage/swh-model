# Copyright (C) 2017-2018 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import enum
import os
import stat

from .hashutil import MultiHash, HASH_BLOCK_SIZE
from .merkle import MerkleLeaf, MerkleNode
from .identifiers import (
    directory_identifier,
    identifier_to_bytes as id_to_bytes,
    identifier_to_str as id_to_str,
)


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
    __slots__ = []
    type = 'content'

    @classmethod
    def from_bytes(cls, *, mode, data):
        """Convert data (raw :class:`bytes`) to a Software Heritage content entry

        Args:
          mode (int): a file mode (passed to :func:`mode_to_perms`)
          data (bytes): raw contents of the file
        """
        ret = MultiHash.from_data(data).digest()
        ret['length'] = len(data)
        ret['perms'] = mode_to_perms(mode)
        ret['data'] = data

        return cls(ret)

    @classmethod
    def from_symlink(cls, *, path, mode):
        """Convert a symbolic link to a Software Heritage content entry"""
        return cls.from_bytes(mode=mode, data=os.readlink(path))

    @classmethod
    def from_file(cls, *, path, data=False, save_path=False):
        """Compute the Software Heritage content entry corresponding to an
        on-disk file.

        The returned dictionary contains keys useful for both:
        - loading the content in the archive (hashes, `length`)
        - using the content as a directory entry in a directory

        Args:
          path (bytes): path to the file for which we're computing the
            content entry
          data (bool): add the file data to the entry
          save_path (bool): add the file path to the entry

        """
        file_stat = os.lstat(path)
        mode = file_stat.st_mode

        if stat.S_ISLNK(mode):
            # Symbolic link: return a file whose contents are the link target
            return cls.from_symlink(path=path, mode=mode)
        elif not stat.S_ISREG(mode):
            # not a regular file: return the empty file instead
            return cls.from_bytes(mode=mode, data=b'')

        length = file_stat.st_size

        if not data:
            ret = MultiHash.from_path(path).digest()
        else:
            h = MultiHash(length=length)
            chunks = []
            with open(path, 'rb') as fobj:
                while True:
                    chunk = fobj.read(HASH_BLOCK_SIZE)
                    if not chunk:
                        break
                    h.update(chunk)
                    chunks.append(chunk)

            ret = h.digest()
            ret['data'] = b''.join(chunks)

        if save_path:
            ret['path'] = path
        ret['perms'] = mode_to_perms(mode)
        ret['length'] = length

        obj = cls(ret)
        return obj

    def __repr__(self):
        return 'Content(id=%s)' % id_to_str(self.hash)

    def compute_hash(self):
        return self.data['sha1_git']


def accept_all_directories(dirname, entries):
    """Default filter for :func:`Directory.from_disk` accepting all
    directories

    Args:
      dirname (bytes): directory name
      entries (list): directory entries
    """
    return True


def ignore_empty_directories(dirname, entries):
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

    def named_filter(dirname, entries,
                     names=names, case_sensitive=case_sensitive):
        if case_sensitive:
            return dirname not in names
        else:
            return dirname.lower() not in names

    return named_filter


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
    __slots__ = ['__entries']
    type = 'directory'

    @classmethod
    def from_disk(cls, *, path, data=False, save_path=False,
                  dir_filter=accept_all_directories):
        """Compute the Software Heritage objects for a given directory tree

        Args:
          path (bytes): the directory to traverse
          data (bool): whether to add the data to the content objects
          save_path (bool): whether to add the path to the content objects
          dir_filter (function): a filter to ignore some directories by
            name or contents. Takes two arguments: dirname and entries, and
            returns True if the directory should be added, False if the
            directory should be ignored.
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
                    content = Content.from_file(path=path, data=data,
                                                save_path=save_path)
                    entries[name] = content
                else:
                    if dir_filter(name, dirs[path].entries):
                        entries[name] = dirs[path]

            dirs[root] = cls({'name': os.path.basename(root)})
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
        if isinstance(child, Directory):
            return {
                'type': 'dir',
                'perms': DentryPerms.directory,
                'target': child.hash,
                'name': name,
            }
        elif isinstance(child, Content):
            return {
                'type': 'file',
                'perms': child.data['perms'],
                'target': child.hash,
                'name': name,
            }
        else:
            raise ValueError('unknown child')

    def get_data(self, **kwargs):
        return {
            'id': self.hash,
            'entries': self.entries,
        }

    @property
    def entries(self):
        if self.__entries is None:
            self.__entries = [
                self.child_to_directory_entry(name, child)
                for name, child in self.items()
            ]

        return self.__entries

    def compute_hash(self):
        return id_to_bytes(directory_identifier({'entries': self.entries}))

    def __getitem__(self, key):
        if not isinstance(key, bytes):
            raise ValueError('Can only get a bytes from Directory')

        # Convenience shortcut
        if key == b'':
            return self

        if b'/' not in key:
            return super().__getitem__(key)
        else:
            key1, key2 = key.split(b'/', 1)
            return self.__getitem__(key1)[key2]

    def __setitem__(self, key, value):
        if not isinstance(key, bytes):
            raise ValueError('Can only set a bytes Directory entry')
        if not isinstance(value, (Content, Directory)):
            raise ValueError('Can only set a Directory entry to a Content or '
                             'Directory')

        if key == b'':
            raise ValueError('Directory entry must have a name')
        if b'\x00' in key:
            raise ValueError('Directory entry name must not contain nul bytes')

        if b'/' not in key:
            return super().__setitem__(key, value)
        else:
            key1, key2 = key.rsplit(b'/', 1)
            self[key1].__setitem__(key2, value)

    def __delitem__(self, key):
        if not isinstance(key, bytes):
            raise ValueError('Can only delete a bytes Directory entry')

        if b'/' not in key:
            super().__delitem__(key)
        else:
            key1, key2 = key.rsplit(b'/', 1)
            del self[key1][key2]

    def __repr__(self):
        return 'Directory(id=%s, entries=[%s])' % (
            id_to_str(self.hash),
            ', '.join(str(entry) for entry in self),
        )
