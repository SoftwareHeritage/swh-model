#!/usr/bin/env python3
# Copyright (C) 2015-2018  The Software Heritage developers
# See the AUTHORS file at the top-level directory of this distribution
# License: GNU General Public License version 3, or any later version
# See top-level LICENSE file for more information

from setuptools import setup, find_packages
import hashlib

from os import path
from io import open

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


def parse_requirements(name=None):
    if name:
        reqf = 'requirements-%s.txt' % name
    else:
        reqf = 'requirements.txt'

    requirements = []
    if not path.exists(reqf):
        return requirements

    with open(reqf) as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            requirements.append(line)
    return requirements


blake2_requirements = []

pyblake2_hash_sets = [
    # Built-in implementation in Python 3.6+
    {'blake2s', 'blake2b'},
    # Potentially shipped by OpenSSL 1.1 (e.g. Python 3.5 in Debian stretch
    # has these)
    {'blake2s256', 'blake2b512'},
]

for pyblake2_hashes in pyblake2_hash_sets:
    if not pyblake2_hashes - set(hashlib.algorithms_available):
        # The required blake2 hashes have been found
        break
else:
    # None of the possible sets of blake2 hashes are available.
    # use pyblake2 instead
    blake2_requirements.append('pyblake2')

setup(
    name='swh.model',
    description='Software Heritage data model',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Software Heritage developers',
    author_email='swh-devel@inria.fr',
    url='https://forge.softwareheritage.org/diffusion/DMOD/',
    packages=find_packages(),
    setup_requires=['vcversioner'],
    install_requires=(parse_requirements() + parse_requirements('swh') +
                      blake2_requirements),
    extras_require={'testing': parse_requirements('test')},
    vcversioner={},
    include_package_data=True,
    entry_points='''
        [console_scripts]
        swh-identify=swh.model.cli:identify
    ''',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
    ],
    project_urls={
        'Bug Reports': 'https://forge.softwareheritage.org/maniphest',
        'Funding': 'https://www.softwareheritage.org/donate',
        'Source': 'https://forge.softwareheritage.org/source/swh-model',
    },
)
