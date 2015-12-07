from setuptools import setup


def parse_requirements():
    requirements = []
    with open('requirements.txt') as f:
        for line in f.readlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            requirements.append(line)

    return requirements


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
    install_requires=parse_requirements(),
    setup_requires=['vcversioner'],
    vcversioner={},
    include_package_data=True,
)
