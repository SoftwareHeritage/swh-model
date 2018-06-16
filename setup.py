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


pyblake2_hashes = {'blake2s256', 'blake2b512'}
if pyblake2_hashes - set(hashlib.algorithms_available):
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
