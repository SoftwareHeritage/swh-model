# Copyright (C) 2018-2020  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import os
import sys
from typing import List

# WARNING: do not import unnecessary things here to keep cli startup time under
# control
import click

from swh.core.cli import swh as swh_cli_group
from swh.model.identifiers import SWHID

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# Mapping between dulwich types and Software Heritage ones. Used by snapshot ID
# computation.
_DULWICH_TYPES = {
    b"blob": "content",
    b"tree": "directory",
    b"commit": "revision",
    b"tag": "release",
}


class SWHIDParamType(click.ParamType):
    """Click argument that accepts SWHID and return them as
    :class:`swh.model.identifiers.SWHID` instances """

    name = "SWHID"

    def convert(self, value, param, ctx) -> SWHID:
        from swh.model.exceptions import ValidationError
        from swh.model.identifiers import parse_swhid

        try:
            return parse_swhid(value)
        except ValidationError as e:
            self.fail(f'"{value}" is not a valid SWHID: {e}', param, ctx)


def swhid_of_file(path):
    from swh.model.from_disk import Content
    from swh.model.identifiers import CONTENT, swhid

    object = Content.from_file(path=path).get_data()
    return swhid(CONTENT, object)


def swhid_of_file_content(data):
    from swh.model.from_disk import Content
    from swh.model.identifiers import CONTENT, swhid

    object = Content.from_bytes(mode=644, data=data).get_data()
    return swhid(CONTENT, object)


def swhid_of_dir(path: bytes, exclude_patterns: List[bytes] = None) -> str:
    from swh.model.from_disk import (
        Directory,
        accept_all_directories,
        ignore_directories_patterns,
    )
    from swh.model.identifiers import DIRECTORY, swhid

    dir_filter = (
        ignore_directories_patterns(path, exclude_patterns)
        if exclude_patterns
        else accept_all_directories
    )

    object = Directory.from_disk(path=path, dir_filter=dir_filter).get_data()
    return swhid(DIRECTORY, object)


def swhid_of_origin(url):
    from swh.model.identifiers import SWHID, origin_identifier

    return str(SWHID(object_type="origin", object_id=origin_identifier({"url": url})))


def swhid_of_git_repo(path):
    import dulwich.repo

    from swh.model import hashutil
    from swh.model.identifiers import SWHID, snapshot_identifier

    repo = dulwich.repo.Repo(path)

    branches = {}
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

    return str(SWHID(object_type="snapshot", object_id=snapshot_identifier(snapshot)))


def identify_object(obj_type, follow_symlinks, exclude_patterns, obj):
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

    swhid = None

    if obj == "-":
        content = sys.stdin.buffer.read()
        swhid = swhid_of_file_content(content)
    elif obj_type in ["content", "directory"]:
        path = obj.encode(sys.getfilesystemencoding())
        if follow_symlinks and os.path.islink(obj):
            path = os.path.realpath(obj)
        if obj_type == "content":
            swhid = swhid_of_file(path)
        elif obj_type == "directory":
            swhid = swhid_of_dir(
                path, [pattern.encode() for pattern in exclude_patterns]
            )
    elif obj_type == "origin":
        swhid = swhid_of_origin(obj)
    elif obj_type == "snapshot":
        swhid = swhid_of_git_repo(obj)
    else:  # shouldn't happen, due to option validation
        raise click.BadParameter("invalid object type: " + obj_type)

    # note: we return original obj instead of path here, to preserve user-given
    # file name in output
    return (obj, swhid)


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
    (e.g., '*.git' to exclude all .git directories)",
)
@click.option(
    "--verify",
    "-v",
    metavar="SWHID",
    type=SWHIDParamType(),
    help="reference identifier to be compared with computed one",
)
@click.argument("objects", nargs=-1, required=True)
def identify(
    obj_type, verify, show_filename, follow_symlinks, objects, exclude_patterns,
):
    """Compute the Software Heritage persistent identifier (SWHID) for the given
    source code object(s).

    For more details about SWHIDs see:

    \b
    https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html

    Tip: you can pass "-" to identify the content of standard input.

    \b
    Examples:

    \b
      $ swh identify fork.c kmod.c sched/deadline.c
      swh:1:cnt:2e391c754ae730bd2d8520c2ab497c403220c6e3    fork.c
      swh:1:cnt:0277d1216f80ae1adeed84a686ed34c9b2931fc2    kmod.c
      swh:1:cnt:57b939c81bce5d06fa587df8915f05affbe22b82    sched/deadline.c

    \b
      $ swh identify --no-filename /usr/src/linux/kernel/
      swh:1:dir:f9f858a48d663b3809c9e2f336412717496202ab

    \b
      $ git clone --mirror https://forge.softwareheritage.org/source/helloworld.git
      $ swh identify --type snapshot helloworld.git/
      swh:1:snp:510aa88bdc517345d258c1fc2babcd0e1f905e93	helloworld.git

    """  # NoQA  # overlong lines in shell examples are fine
    from functools import partial

    if verify and len(objects) != 1:
        raise click.BadParameter("verification requires a single object")

    results = map(
        partial(identify_object, obj_type, follow_symlinks, exclude_patterns), objects,
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
