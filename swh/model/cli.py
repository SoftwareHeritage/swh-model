# Copyright (C) 2018-2020  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import sys
from typing import Dict, Iterable, Optional

# WARNING: do not import unnecessary things here to keep cli startup time under
# control
try:
    import click
except ImportError:
    print(
        "Cannot run swh-identify; the Click package is not installed."
        "Please install 'swh.model[cli]' for full functionality.",
        file=sys.stderr,
    )
    exit(1)

try:
    from swh.core.cli import swh as swh_cli_group
except ImportError:
    # stub so that swh-identify can be used when swh-core isn't installed
    swh_cli_group = click  # type: ignore

from swh.model.from_disk import Directory
from swh.model.swhids import CoreSWHID

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# Mapping between dulwich types and Software Heritage ones. Used by snapshot ID
# computation.
_DULWICH_TYPES = {
    b"blob": "content",
    b"tree": "directory",
    b"commit": "revision",
    b"tag": "release",
}


class CoreSWHIDParamType(click.ParamType):
    """Click argument that accepts a core SWHID and returns them as
    :class:`swh.model.swhids.CoreSWHID` instances"""

    name = "SWHID"

    def convert(self, value, param, ctx) -> CoreSWHID:
        from swh.model.exceptions import ValidationError

        try:
            return CoreSWHID.from_string(value)
        except ValidationError as e:
            self.fail(f'"{value}" is not a valid core SWHID: {e}', param, ctx)


def swhid_of_file(path) -> CoreSWHID:
    from swh.model.from_disk import Content

    object = Content.from_file(path=path)
    return object.swhid()


def swhid_of_file_content(data) -> CoreSWHID:
    from swh.model.from_disk import Content

    object = Content.from_bytes(mode=644, data=data)
    return object.swhid()


def model_of_dir(path: bytes, exclude_patterns: Iterable[bytes] = None) -> Directory:
    from swh.model.from_disk import accept_all_directories, ignore_directories_patterns

    dir_filter = (
        ignore_directories_patterns(path, exclude_patterns)
        if exclude_patterns
        else accept_all_directories
    )

    return Directory.from_disk(path=path, dir_filter=dir_filter)


def swhid_of_dir(path: bytes, exclude_patterns: Iterable[bytes] = None) -> CoreSWHID:
    obj = model_of_dir(path, exclude_patterns)
    return obj.swhid()


def swhid_of_origin(url):
    from swh.model.model import Origin

    return Origin(url).swhid()


def swhid_of_git_repo(path) -> CoreSWHID:
    try:
        import dulwich.repo
    except ImportError:
        raise click.ClickException(
            "Cannot compute snapshot identifier; the Dulwich package is not installed. "
            "Please install 'swh.model[cli]' for full functionality.",
        )

    from swh.model import hashutil
    from swh.model.model import Snapshot

    repo = dulwich.repo.Repo(path)

    branches: Dict[bytes, Optional[Dict]] = {}
    for ref, target in repo.refs.as_dict().items():
        obj = repo[target]
        if obj:
            branches[ref] = {
                "target": hashutil.bytehex_to_hash(target),
                "target_type": _DULWICH_TYPES[obj.type_name],
            }
        else:
            branches[ref] = None

    for ref, target in repo.refs.get_symrefs().items():
        branches[ref] = {
            "target": target,
            "target_type": "alias",
        }

    snapshot = {"branches": branches}

    return Snapshot.from_dict(snapshot).swhid()


def identify_object(
    obj_type: str, follow_symlinks: bool, exclude_patterns: Iterable[bytes], obj
) -> str:
    from urllib.parse import urlparse

    if obj_type == "auto":
        if obj == "-" or os.path.isfile(obj):
            obj_type = "content"
        elif os.path.isdir(obj):
            obj_type = "directory"
        else:
            try:  # URL parsing
                if urlparse(obj).scheme:
                    obj_type = "origin"
                else:
                    raise ValueError
            except ValueError:
                raise click.BadParameter("cannot detect object type for %s" % obj)

    if obj == "-":
        content = sys.stdin.buffer.read()
        swhid = str(swhid_of_file_content(content))
    elif obj_type in ["content", "directory"]:
        path = obj.encode(sys.getfilesystemencoding())
        if follow_symlinks and os.path.islink(obj):
            path = os.path.realpath(obj)
        if obj_type == "content":
            swhid = str(swhid_of_file(path))
        elif obj_type == "directory":
            swhid = str(swhid_of_dir(path, exclude_patterns))
    elif obj_type == "origin":
        swhid = str(swhid_of_origin(obj))
    elif obj_type == "snapshot":
        swhid = str(swhid_of_git_repo(obj))
    else:  # shouldn't happen, due to option validation
        raise click.BadParameter("invalid object type: " + obj_type)

    # note: we return original obj instead of path here, to preserve user-given
    # file name in output
    return swhid


@swh_cli_group.command(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--dereference/--no-dereference",
    "follow_symlinks",
    default=True,
    help="follow (or not) symlinks for OBJECTS passed as arguments "
    + "(default: follow)",
)
@click.option(
    "--filename/--no-filename",
    "show_filename",
    default=True,
    help="show/hide file name (default: show)",
)
@click.option(
    "--type",
    "-t",
    "obj_type",
    default="auto",
    type=click.Choice(["auto", "content", "directory", "origin", "snapshot"]),
    help="type of object to identify (default: auto)",
)
@click.option(
    "--exclude",
    "-x",
    "exclude_patterns",
    metavar="PATTERN",
    multiple=True,
    help="Exclude directories using glob patterns \
    (e.g., ``*.git`` to exclude all .git directories)",
)
@click.option(
    "--verify",
    "-v",
    metavar="SWHID",
    type=CoreSWHIDParamType(),
    help="reference identifier to be compared with computed one",
)
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help="compute SWHID recursively",
)
@click.argument("objects", nargs=-1, required=True)
def identify(
    obj_type,
    verify,
    show_filename,
    follow_symlinks,
    objects,
    exclude_patterns,
    recursive,
):
    """Compute the Software Heritage persistent identifier (SWHID) for the given
    source code object(s).

    For more details about SWHIDs see:

    https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html

    Tip: you can pass "-" to identify the content of standard input.

    Examples::

      $ swh identify fork.c kmod.c sched/deadline.c
      swh:1:cnt:2e391c754ae730bd2d8520c2ab497c403220c6e3    fork.c
      swh:1:cnt:0277d1216f80ae1adeed84a686ed34c9b2931fc2    kmod.c
      swh:1:cnt:57b939c81bce5d06fa587df8915f05affbe22b82    sched/deadline.c

      $ swh identify --no-filename /usr/src/linux/kernel/
      swh:1:dir:f9f858a48d663b3809c9e2f336412717496202ab

      $ git clone --mirror https://forge.softwareheritage.org/source/helloworld.git

      $ swh identify --type snapshot helloworld.git/
      swh:1:snp:510aa88bdc517345d258c1fc2babcd0e1f905e93    helloworld.git

    """
    from functools import partial
    import logging

    if exclude_patterns:
        exclude_patterns = set(pattern.encode() for pattern in exclude_patterns)

    if verify and len(objects) != 1:
        raise click.BadParameter("verification requires a single object")

    if recursive and not os.path.isdir(objects[0]):
        recursive = False
        logging.warn("recursive option disabled, input is not a directory object")

    if recursive:
        if verify:
            raise click.BadParameter(
                "verification of recursive object identification is not supported"
            )

        if not obj_type == ("auto" or "directory"):
            raise click.BadParameter(
                "recursive identification is supported only for directories"
            )

        path = os.fsencode(objects[0])
        dir_obj = model_of_dir(path, exclude_patterns)
        for sub_obj in dir_obj.iter_tree():
            path_name = "path" if "path" in sub_obj.data.keys() else "data"
            path = os.fsdecode(sub_obj.data[path_name])
            swhid = str(sub_obj.swhid())
            msg = f"{swhid}\t{path}" if show_filename else f"{swhid}"
            click.echo(msg)
    else:
        results = zip(
            objects,
            map(
                partial(identify_object, obj_type, follow_symlinks, exclude_patterns),
                objects,
            ),
        )

        if verify:
            swhid = next(results)[1]
            if str(verify) == swhid:
                click.echo("SWHID match: %s" % swhid)
                sys.exit(0)
            else:
                click.echo("SWHID mismatch: %s != %s" % (verify, swhid))
                sys.exit(1)
        else:
            for (obj, swhid) in results:
                msg = swhid
                if show_filename:
                    msg = "%s\t%s" % (swhid, os.fsdecode(obj))
                click.echo(msg)


if __name__ == "__main__":
    identify()
