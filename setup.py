import hashlib

from setuptools import setup, find_packages


def parse_requirements():
    requirements = []
    for reqf in ('requirements.txt', 'requirements-swh.txt'):
        with open(reqf) as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                requirements.append(line)
    return requirements


extra_requirements = []

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
    extra_requirements.append('pyblake2')

setup(
    name='swh.model',
    description='Software Heritage data model',
    author='Software Heritage developers',
    author_email='swh-devel@inria.fr',
    url='https://forge.softwareheritage.org/diffusion/DMOD/',
    packages=find_packages(),  # packages's modules
    scripts=[],   # scripts to package
    install_requires=parse_requirements() + extra_requirements,
    entry_points='''
        [console_scripts]
        swh-identify=swh.model.cli:identify
    ''',
    setup_requires=['vcversioner'],
    vcversioner={},
    include_package_data=True,
)
