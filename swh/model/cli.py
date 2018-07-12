# Copyright (C) 2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import click
import os
import sys

from functools import partial

from swh.model import identifiers as pids
from swh.model.exceptions import ValidationError
from swh.model.from_disk import Content, Directory


class PidParamType(click.ParamType):
    name = 'persistent identifier'

    def convert(self, value, param, ctx):
        try:
            pids.parse_persistent_identifier(value)
            return value  # return as string, as we need just that
        except ValidationError as e:
            self.fail('%s is not a valid PID. %s.' % (value, e), param, ctx)


def pid_of_file(path):
    object = Content.from_file(path=path).get_data()
    return pids.persistent_identifier(pids.CONTENT, object)


def pid_of_dir(path):
    object = Directory.from_disk(path=path).get_data()
    return pids.persistent_identifier(pids.DIRECTORY, object)


def identify_object(obj_type, follow_symlinks, obj):
    if obj_type == 'auto':
        if os.path.isfile(obj):
            obj_type = 'content'
        elif os.path.isdir(obj):
            obj_type = 'directory'
        else:  # shouldn't happen, due to path validation
            raise click.BadParameter('%s is neither a file nor a directory' %
                                     obj)

    path = obj
    if follow_symlinks and os.path.islink(obj):
        path = os.path.realpath(obj)

    pid = None
    if obj_type == 'content':
        pid = pid_of_file(path)
    elif obj_type == 'directory':
        pid = pid_of_dir(path)
    else:  # shouldn't happen, due to option validation
        raise click.BadParameter('invalid object type: ' + obj_type)

    # note: we return original obj instead of path here, to preserve user-given
    # file name in output
    return (obj, pid)


@click.command()
@click.option('--dereference/--no-dereference', 'follow_symlinks',
              default=True,
              help='follow (or not) symlinks for OBJECTS passed as arguments '
              + '(default: follow)')
@click.option('--filename/--no-filename', 'show_filename', default=True,
              help='show/hide file name (default: show)')
@click.option('--type', '-t', 'obj_type', default='auto',
              type=click.Choice(['auto', 'content', 'directory']),
              help='type of object to identify (default: auto)')
@click.option('--verify', '-v', metavar='PID', type=PidParamType(),
              help='reference identifier to be compared with computed one')
@click.argument('objects', nargs=-1,
                type=click.Path(exists=True, readable=True,
                                allow_dash=True, path_type=bytes))
def identify(obj_type, verify, show_filename, follow_symlinks, objects):
    """Compute the Software Heritage persistent identifier (PID) for the given
    source code object(s).

    For more details about Software Heritage PIDs see:

    \b
    https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html

    \b
    Examples:

    \b
      $ swh-identify fork.c kmod.c sched/deadline.c
      swh:1:cnt:2e391c754ae730bd2d8520c2ab497c403220c6e3    fork.c
      swh:1:cnt:0277d1216f80ae1adeed84a686ed34c9b2931fc2    kmod.c
      swh:1:cnt:57b939c81bce5d06fa587df8915f05affbe22b82    sched/deadline.c

    \b
      $ swh-identify --no-filename /usr/src/linux/kernel/
      swh:1:dir:f9f858a48d663b3809c9e2f336412717496202ab

    """
    if verify and len(objects) != 1:
        raise click.BadParameter('verification requires a single object')

    results = map(partial(identify_object, obj_type, follow_symlinks), objects)

    if verify:
        pid = next(results)[1]
        if verify == pid:
            click.echo('PID match: %s' % pid)
            sys.exit(0)
        else:
            click.echo('PID mismatch: %s != %s' % (verify, pid))
            sys.exit(1)
    else:
        for (obj, pid) in results:
            msg = pid
            if show_filename:
                msg = '%s\t%s' % (pid, os.fsdecode(obj))
            click.echo(msg)


if __name__ == '__main__':
    identify()
