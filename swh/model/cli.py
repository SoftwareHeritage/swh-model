# Copyright (C) 2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

import click
import locale
import os
import sys

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


@click.command()
@click.option('--type', '-t', default='auto',
              type=click.Choice(['auto', 'content', 'directory']),
              help='type of object to identify (default: auto)')
@click.option('--verify', '-v', metavar='PID', type=PidParamType(),
              help='reference identifier to be compared with computed one')
@click.option('--filename/--no-filename', 'show_filename', default=True,
              help='show/hide file name (default: show)')
@click.argument('object',
                type=click.Path(exists=True, readable=True,
                                allow_dash=True, path_type=bytes))
def identify(type, verify, show_filename, object):
    """Compute the Software Heritage persistent identifier (PID) for a given
    source code object.

    For more details about Software Heritage PIDs see:

    \b
    https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html

    \b
    Examples:

    \b
      $ swh-identify /usr/src/linux/kernel/
      swh:1:dir:f9f858a48d663b3809c9e2f336412717496202ab

    \b
      $ swh-identify /usr/src/linux/kernel/sched/deadline.c
      swh:1:cnt:57b939c81bce5d06fa587df8915f05affbe22b82

    """
    if type == 'auto':
        if os.path.isfile(object):
            type = 'content'
        elif os.path.isdir(object):
            type = 'directory'
        else:  # shouldn't happen, due to path validation
            raise click.BadParameter('%s is neither a file nor a directory' %
                                     object)

    pid = None
    if type == 'content':
        pid = pid_of_file(object)
    elif type == 'directory':
        pid = pid_of_dir(object)
    else:  # shouldn't happen, due to option validation
        raise click.BadParameter('invalid object type: ' + type)

    if verify:
        if verify == pid:
            click.echo('PID match: %s' % pid)
            sys.exit(0)
        else:
            click.echo('PID mismatch: %s != %s' % (verify, pid))
            sys.exit(1)
    else:
        msg = pid
        if show_filename:
            encoding = locale.getpreferredencoding(do_setlocale=False)
            msg = '%s\t%s' % (pid, object.decode(encoding))
        click.echo(msg)


if __name__ == '__main__':
    identify()
