# Copyright (C) 2015  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


import os

from enum import Enum

from swh.model import hashutil, identifiers


ROOT_TREE_KEY = b''


class GitType(Enum):
    BLOB = b'blob'
    TREE = b'tree'
    EXEC = b'exec'
    LINK = b'link'
    COMM = b'commit'
    RELE = b'release'
    REFS = b'ref'


class GitPerm(Enum):
    BLOB = b'100644'
    TREE = b'40000'
    EXEC = b'100755'
    LINK = b'120000'


def compute_directory_git_sha1(dirpath, hashes):
    """Compute a directory git sha1 for a dirpath.

    Args:
        dirpath: the directory's absolute path
        hashes: list of tree entries with keys:
            - sha1_git: the tree entry's sha1
            - name: file or subdir's name
            - perms: the tree entry's sha1 permissions

        Returns:
            the binary sha1 of the dictionary's identifier

        Assumes:
            Every path exists in hashes.

    """
    directory = {
        'entries':
        [
            {
                'name': entry['name'],
                'perms': int(entry['perms'].value, 8),
                'target': entry['sha1_git'],
                'type': 'dir' if entry['perms'] == GitPerm.TREE else 'file',
            }
            for entry in hashes[dirpath]
        ]
    }
    return hashutil.hash_to_bytes(identifiers.directory_identifier(directory))


def compute_revision_sha1_git(revision):
    """Compute a revision sha1 git from its dict representation.

    Args:
        revision: Additional dictionary information needed to compute a
        synthetic
        revision. Following keys are expected:
            - author
            - date
            - committer
            - committer_date
            - message
            - type
            - directory: binary form of the tree hash

    Returns:
        revision sha1 in bytes

    # FIXME: beware, bytes output from storage api

    """
    return hashutil.hash_to_bytes(identifiers.revision_identifier(revision))


def compute_release_sha1_git(release):
    """Compute a release sha1 git from its dict representation.

    Args:
        release: Additional dictionary information needed to compute a
        synthetic release. Following keys are expected:
            - name
            - message
            - date
            - author
            - revision: binary form of the sha1_git revision targeted by this

    Returns:
        release sha1 in bytes

    """
    return hashutil.hash_to_bytes(identifiers.release_identifier(release))


def compute_link_metadata(linkpath):
    """Given a linkpath, compute the git metadata.

    Args:
        linkpath: absolute pathname of the link

    Returns:
        Dictionary of values:
            - data: link's content
            - length: link's content length
            - name: basename of the link
            - perms: git permission for link
            - type: git type for link
            - path: absolute path to the link on filesystem

    """
    data = os.readlink(linkpath)
    link_metadata = hashutil.hash_data(data)
    link_metadata.update({
        'data': data,
        'length': len(data),
        'name': os.path.basename(linkpath),
        'perms': GitPerm.LINK,
        'type': GitType.BLOB,
        'path': linkpath
    })

    return link_metadata


def compute_blob_metadata(filepath):
    """Given a filepath, compute the git metadata.

    Args:
        filepath: absolute pathname of the file.

    Returns:
        Dictionary of values:
            - name: basename of the file
            - perms: git permission for file
            - type: git type for file
            - path: absolute filepath on filesystem

    """
    blob_metadata = hashutil.hash_path(filepath)
    perms = GitPerm.EXEC if os.access(filepath, os.X_OK) else GitPerm.BLOB
    blob_metadata.update({
        'name': os.path.basename(filepath),
        'perms': perms,
        'type': GitType.BLOB,
        'path': filepath
    })

    return blob_metadata


def compute_tree_metadata(dirname, ls_hashes):
    """Given a dirname, compute the git metadata.

    Args:
        dirname: absolute pathname of the directory.

    Returns:
        Dictionary of values:
            - sha1_git: tree's sha1 git
            - name: basename of the directory
            - perms: git permission for directory
            - type: git type for directory
            - path: absolute path to directory on filesystem

    """
    return {
        'sha1_git': compute_directory_git_sha1(dirname, ls_hashes),
        'name': os.path.basename(dirname),
        'perms': GitPerm.TREE,
        'type': GitType.TREE,
        'path': dirname
    }


def walk_and_compute_sha1_from_directory(rootdir,
                                         dir_ok_fn=lambda dirpath: True):
    """Compute git sha1 from directory rootdir.

    Args:
        - rootdir: Root directory from which beginning the git hash computation

        - dir_ok_fn: Filter function to filter directory according to rules
        defined in the function. By default, all folders are ok.
        Example override: dir_ok_fn = lambda dirpath: b'svn' not in dirpath

    Returns:
        Dictionary of entries with keys <path-name> and as values a list of
        directory entries.
        Those are list of dictionary with keys:
          - 'perms'
          - 'type'
          - 'name'
          - 'sha1_git'
          - and specifically content: 'sha1', 'sha256', ...

    Note:
        One special key is ROOT_TREE_KEY to indicate the upper root of the
        directory (this is the revision's directory).

    Raises:
        Nothing
        If something is raised, this is a programmatic error.

    """
    ls_hashes = {}
    all_links = set()

    def filtfn(dirpath, dirnames):
        return list(filter(lambda dirname: dir_ok_fn(os.path.join(dirpath,
                                                                  dirname)),
                           dirnames))

    gen_dir = ((dp, filtfn(dp, dns), fns) for (dp, dns, fns)
               in os.walk(rootdir, topdown=False)
               if dir_ok_fn(dp))

    for dirpath, dirnames, filenames in gen_dir:
        hashes = []

        links = (os.path.join(dirpath, file)
                 for file in (filenames+dirnames)
                 if os.path.islink(os.path.join(dirpath, file)))

        for linkpath in links:
            all_links.add(linkpath)
            m_hashes = compute_link_metadata(linkpath)
            hashes.append(m_hashes)

        only_files = (os.path.join(dirpath, file)
                      for file in filenames
                      if os.path.join(dirpath, file) not in all_links)
        for filepath in only_files:
            m_hashes = compute_blob_metadata(filepath)
            hashes.append(m_hashes)

        ls_hashes[dirpath] = hashes

        dir_hashes = []
        subdirs = (os.path.join(dirpath, dir)
                   for dir in dirnames
                   if os.path.join(dirpath, dir)
                   not in all_links)
        for fulldirname in subdirs:
            tree_hash = compute_tree_metadata(fulldirname, ls_hashes)
            dir_hashes.append(tree_hash)

        ls_hashes[dirpath].extend(dir_hashes)

    # compute the current directory hashes
    root_hash = {
        'sha1_git': compute_directory_git_sha1(rootdir, ls_hashes),
        'path': rootdir,
        'name': os.path.basename(rootdir),
        'perms': GitPerm.TREE,
        'type': GitType.TREE
    }
    ls_hashes[ROOT_TREE_KEY] = [root_hash]

    return ls_hashes
