# Copyright (C) 2017 The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from operator import itemgetter
import os
import sys

from swh.model.from_disk import Directory, DentryPerms
from swh.model.hashutil import ALGORITHMS, hash_to_hex


def generate_from_directory(varname, directory, indent=0):
    """Generate test data from a given directory"""
    def get_data(member, path):
        yield (path, member.get_data())
        if isinstance(member, Directory):
            for name, child in member.items():
                yield from get_data(child, os.path.join(path, name))

    data = dict(get_data(directory, b''))
    out = []

    def format_hash(h, indent=0):
        spindent = ' ' * indent
        if len(h) > 20:
            cutoff = len(h)//2
            parts = h[:cutoff], h[cutoff:]
        else:
            parts = [h]

        out.append('hash_to_bytes(\n')
        for part in parts:
            out.append(spindent + '    %s\n' % repr(hash_to_hex(part)))
        out.append(spindent + ')')

    def format_dict_items(d, indent=0):
        spindent = ' ' * indent
        for key, value in sorted(d.items()):
            if isinstance(key, bytes):
                out.append(spindent + repr(key) + ': {\n')
                format_dict_items(value, indent=indent + 4)
                out.append(spindent + '}')
            else:
                out.append(spindent + repr(key) + ': ')
                if key == 'entries':
                    if not value:
                        out.append('[]')
                    else:
                        out.append('[')
                        last_index = len(value) - 1
                        for i, entry in enumerate(
                                sorted(value, key=itemgetter('name'))):
                            if i:
                                out.append(' ')
                            out.append('{\n')
                            format_dict_items(entry, indent=indent + 4)
                            if i != last_index:
                                out.append(spindent + '},')
                        out.append(spindent + '}]')
                elif key in ALGORITHMS | {'id', 'target'}:
                    format_hash(value, indent=indent)
                elif isinstance(value, DentryPerms):
                    out.append(str(value))
                else:
                    out.append(repr(value))
            out.append(',\n')

    spindent = ' ' * indent
    out.append(spindent + '%s = {\n' % varname)
    format_dict_items(data, indent=4 + indent)
    out.append(spindent + '}')

    return ''.join(out)


if __name__ == '__main__':
    if not sys.argv[1:]:
        print("Usage: %s dir1 dir2" % sys.argv[0], file=sys.stderr)
        exit(2)

    for dirname in sys.argv[1:]:
        basename = os.path.basename(dirname)
        varname = 'expected_%s' % basename
        testdata = generate_from_directory(
            varname,
            Directory.from_disk(path=os.fsencode(dirname)),
            indent=8
        )
        print(testdata)
        print()
