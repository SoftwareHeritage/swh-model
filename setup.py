import sys

from setuptools import setup


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
if sys.version_info < (3, 5):
    extra_requirements = ['pyblake2']

setup(
    name='swh.model',
    description='Software Heritage data model',
    author='Software Heritage developers',
    author_email='swh-devel@inria.fr',
    url='https://forge.softwareheritage.org/diffusion/DMOD/',
    packages=[
        'swh.model', 'swh.model.fields',
        'swh.model.tests', 'swh.model.tests.fields',
    ],  # packages's modules
    scripts=[],   # scripts to package
    install_requires=parse_requirements() + extra_requirements,
    setup_requires=['vcversioner'],
    vcversioner={},
    include_package_data=True,
)
