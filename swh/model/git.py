# Copyright (C) 2015-2017  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information


import os
import stat

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


def _compute_directory_git_sha1(hashes):
    """Compute a directory git sha1 from hashes.

    Args:
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
            for entry in hashes
        ]
    }
    return hashutil.hash_to_bytes(identifiers.directory_identifier(directory))


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
    return _compute_directory_git_sha1(hashes[dirpath])


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
                  This could be special files (fifo, character or
                  block device), they will be considered empty files.

    Returns:
        Dictionary of values:
            - name: basename of the file
            - length: data length
            - perms: git permission for file
            - type: git type for file
            - path: absolute filepath on filesystem

    """
    mode = os.lstat(filepath).st_mode
    if not stat.S_ISREG(mode):  # special (block or character device, fifo)
        perms = GitPerm.BLOB
        blob_metadata = hashutil.hash_data(b'')
        blob_metadata['length'] = 0
    else:
        perms = GitPerm.EXEC if os.access(filepath, os.X_OK) else GitPerm.BLOB
        blob_metadata = hashutil.hash_path(filepath)

    blob_metadata.update({
        'name': os.path.basename(filepath),
        'perms': perms,
        'type': GitType.BLOB,
        'path': filepath
    })

    return blob_metadata


def _compute_tree_metadata(dirname, hashes):
    """Given a dirname, compute the git metadata.

    Args:
        dirname: absolute pathname of the directory.
        hashes: list of tree dirname's entries with keys:
            - sha1_git: the tree entry's sha1
            - name: file or subdir's name
            - perms: the tree entry's sha1 permissions

    Returns:
        Dictionary of values:
            - sha1_git: tree's sha1 git
            - name: basename of the directory
            - perms: git permission for directory
            - type: git type for directory
            - path: absolute path to directory on filesystem

    """
    return {
        'sha1_git': _compute_directory_git_sha1(hashes),
        'name': os.path.basename(dirname),
        'perms': GitPerm.TREE,
        'type': GitType.TREE,
        'path': dirname
    }


def compute_tree_metadata(dirname, ls_hashes):
    """Given a dirname, compute the git metadata.

    Args:
        dirname: absolute pathname of the directory.
        ls_hashes: dictionary of path, hashes

    Returns:
        Dictionary of values:
            - sha1_git: tree's sha1 git
            - name: basename of the directory
            - perms: git permission for directory
            - type: git type for directory
            - path: absolute path to directory on filesystem

    """
    return _compute_tree_metadata(dirname, ls_hashes[dirname])


def default_validation_dir(dirpath):
    """Default validation function.
       This is the equivalent of the identity function.

    Args:
        dirpath: Path to validate

    Returns: True

    """
    return True


def _walk(rootdir,
          dir_ok_fn=default_validation_dir,
          remove_empty_folder=False):
    """Walk the filesystem and yields a 3 tuples (dirpath, dirnames as set
    of absolute paths, filenames as set of abslute paths)

       Ignore files which won't pass the dir_ok_fn validation.

       If remove_empty_folder is True, remove and ignore any
       encountered empty folder.

    Args:
        - rootdir: starting walk root directory path
        - dir_ok_fn: validation function. if folder encountered are
        not ok, they are ignored.  Default to default_validation_dir
        which does nothing.
         - remove_empty_folder: Flag to remove and ignore any
          encountered empty folders.

    Yields:
        3 tuples dirpath, set of absolute children dirname paths, set
        of absolute filename paths.

    """
    def basic_gen_dir(rootdir):
        for dp, dns, fns in os.walk(rootdir, topdown=False):
            yield (dp,
                   set((os.path.join(dp, dn) for dn in dns)),
                   set((os.path.join(dp, fn) for fn in fns)))

    if dir_ok_fn == default_validation_dir:
        if not remove_empty_folder:  # os.walk
            yield from basic_gen_dir(rootdir)
        else:                        # os.walk + empty dir cleanup
            empty_folders = set()
            for dp, dns, fns in basic_gen_dir(rootdir):
                if not dns and not fns:
                    empty_folders.add(dp)
                    # need to remove it because folder of empty folder
                    # is an empty folder!!!
                    if os.path.islink(dp):
                        os.remove(dp)
                    else:
                        os.rmdir(dp)
                    parent = os.path.dirname(dp)
                    # edge case about parent containing one empty
                    # folder which become an empty one
                    while not os.listdir(parent):
                        empty_folders.add(parent)
                        if os.path.islink(parent):
                            os.remove(parent)
                        else:
                            os.rmdir(parent)
                        parent = os.path.dirname(parent)
                    continue
                yield (dp, dns - empty_folders, fns)
    else:
        def filtfn(dirnames):
            return set(filter(dir_ok_fn, dirnames))

        gen_dir = ((dp, dns, fns) for dp, dns, fns
                   in basic_gen_dir(rootdir) if dir_ok_fn(dp))

        if not remove_empty_folder:  # os.walk + filtering
            for dp, dns, fns in gen_dir:
                yield (dp, filtfn(dns), fns)
        else:                        # os.walk + filtering + empty dir cleanup
            empty_folders = set()
            for dp, dns, fns in gen_dir:
                dps = filtfn(dns)

                if not dps and not fns:
                    empty_folders.add(dp)
                    # need to remove it because folder of empty folder
                    # is an empty folder!!!
                    if os.path.islink(dp):
                        os.remove(dp)
                    else:
                        os.rmdir(dp)
                    parent = os.path.dirname(dp)
                    # edge case about parent containing one empty
                    # folder which become an empty one
                    while not os.listdir(parent):
                        empty_folders.add(parent)
                        if os.path.islink(parent):
                            os.remove(parent)
                        else:
                            os.rmdir(parent)
                        parent = os.path.dirname(parent)
                    continue
                yield dp, dps - empty_folders, fns


def walk_and_compute_sha1_from_directory(rootdir,
                                         dir_ok_fn=default_validation_dir,
                                         with_root_tree=True,
                                         remove_empty_folder=False):
    """(Deprecated) TODO migrate the code to
    compute_hashes_from_directory.

    Compute git sha1 from directory rootdir.

    Args:
        - rootdir: Root directory from which beginning the git hash computation

        - dir_ok_fn: Filter function to filter directory according to rules
        defined in the function. By default, all folders are ok.
        Example override: dir_ok_fn = lambda dirpath: b'svn' not in dirpath

        - with_root_tree: Determine if we compute the upper root tree's
          checksums. As a default, we want it. One possible use case where this
          is not useful is the update (cf. `update_checksums_from`)

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

    if rootdir.endswith(b'/'):
        rootdir = rootdir.rstrip(b'/')

    for dirpath, dirnames, filenames in _walk(
            rootdir, dir_ok_fn, remove_empty_folder):
        hashes = []

        links = (file
                 for file in filenames.union(dirnames)
                 if os.path.islink(file))

        for linkpath in links:
            all_links.add(linkpath)
            m_hashes = compute_link_metadata(linkpath)
            hashes.append(m_hashes)

        for filepath in (file for file in filenames if file not in all_links):
            m_hashes = compute_blob_metadata(filepath)
            hashes.append(m_hashes)

        ls_hashes[dirpath] = hashes

        dir_hashes = []
        for fulldirname in (dir for dir in dirnames if dir not in all_links):
            tree_hash = _compute_tree_metadata(fulldirname,
                                               ls_hashes[fulldirname])
            dir_hashes.append(tree_hash)

        ls_hashes[dirpath].extend(dir_hashes)

    if with_root_tree:
        # compute the current directory hashes
        root_hash = {
            'sha1_git': _compute_directory_git_sha1(ls_hashes[rootdir]),
            'path': rootdir,
            'name': os.path.basename(rootdir),
            'perms': GitPerm.TREE,
            'type': GitType.TREE
        }
        ls_hashes[ROOT_TREE_KEY] = [root_hash]

    return ls_hashes


def compute_hashes_from_directory(rootdir,
                                  dir_ok_fn=default_validation_dir,
                                  remove_empty_folder=False):
    """Compute git sha1 from directory rootdir.

    Args:
        - rootdir: Root directory from which beginning the git hash
          computation

        - dir_ok_fn: Filter function to filter directory according to rules
        defined in the function. By default, all folders are ok.
        Example override: dir_ok_fn = lambda dirpath: b'svn' not in dirpath

    Returns:
        Dictionary of entries with keys absolute path name.
        Path-name can be a file/link or directory.
        The associated value is a dictionary with:
        - checksums: the dictionary with the hashes for the link/file/dir
        Those are list of dictionary with keys:
          - 'perms'
          - 'type'
          - 'name'
          - 'sha1_git'
          - and specifically content: 'sha1', 'sha256', ...

        - children: Only for a directory, the set of children paths

    Note:
        One special key is the / which indicates the upper root of
        the directory (this is the revision's directory).

    Raises:
        Nothing
        If something is raised, this is a programmatic error.

    """
    def _get_dict_from_dirpath(_dict, path):
        """Retrieve the default associated value for key path.

        """
        return _dict.get(path, dict(children=set(), checksums=None))

    def _get_dict_from_filepath(_dict, path):
        """Retrieve the default associated value for key path.

        """
        return _dict.get(path, dict(checksums=None))

    ls_hashes = {}
    all_links = set()

    if rootdir.endswith(b'/'):
        rootdir = rootdir.rstrip(b'/')

    for dirpath, dirnames, filenames in _walk(
            rootdir, dir_ok_fn, remove_empty_folder):

        dir_entry = _get_dict_from_dirpath(ls_hashes, dirpath)
        children = dir_entry['children']

        links = (file
                 for file in filenames.union(dirnames)
                 if os.path.islink(file))

        for linkpath in links:
            all_links.add(linkpath)
            m_hashes = compute_link_metadata(linkpath)
            d = _get_dict_from_filepath(ls_hashes, linkpath)
            d['checksums'] = m_hashes
            ls_hashes[linkpath] = d
            children.add(linkpath)

        for filepath in (file for file in filenames if file not in all_links):
            m_hashes = compute_blob_metadata(filepath)
            d = _get_dict_from_filepath(ls_hashes, filepath)
            d['checksums'] = m_hashes
            ls_hashes[filepath] = d
            children.add(filepath)

        for fulldirname in (dir for dir in dirnames if dir not in all_links):
            d_hashes = _get_dict_from_dirpath(ls_hashes, fulldirname)
            tree_hash = _compute_tree_metadata(
                fulldirname,
                (ls_hashes[p]['checksums'] for p in d_hashes['children'])
            )
            d = _get_dict_from_dirpath(ls_hashes, fulldirname)
            d['checksums'] = tree_hash
            ls_hashes[fulldirname] = d
            children.add(fulldirname)

        dir_entry['children'] = children
        ls_hashes[dirpath] = dir_entry

    # compute the current directory hashes
    d_hashes = _get_dict_from_dirpath(ls_hashes, rootdir)
    root_hash = {
        'sha1_git': _compute_directory_git_sha1(
            (ls_hashes[p]['checksums'] for p in d_hashes['children'])
        ),
        'path': rootdir,
        'name': os.path.basename(rootdir),
        'perms': GitPerm.TREE,
        'type': GitType.TREE
    }
    d_hashes['checksums'] = root_hash
    ls_hashes[rootdir] = d_hashes

    return ls_hashes


def children_hashes(children, objects):
    """Given a collection of children path, yield the corresponding
    hashes.

    Args:
        objects: objects hash as returned by git.compute_hashes_from_directory.
        children: collection of bytes path

    Yields:
        Dictionary hashes

    """
    for p in children:
        c = objects.get(p)
        if c:
            h = c.get('checksums')
            if h:
                yield h


def objects_per_type(filter_type, objects_per_path):
    """Given an object dictionary returned by
    `swh.model.git.compute_hashes_from_directory`, yields
    corresponding element type's hashes

    Args:
        filter_type: one of GitType enum
        objects_per_path:

    Yields:
        Elements of type filter_type's hashes

    """
    for path, obj in objects_per_path.items():
        o = obj['checksums']
        if o['type'] == filter_type:
            if 'children' in obj:  # for trees
                if obj['children']:
                    o['children'] = children_hashes(obj['children'],
                                                    objects_per_path)
                else:
                    o['children'] = []
            yield o
