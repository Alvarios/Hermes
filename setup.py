import pathlib
import subprocess

from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.develop import develop

__requires__ = ['pipenv']

packages = find_packages(exclude=['tests'])
base_dir = pathlib.Path(__file__).parent

pipenv_command = ['pipenv', 'install', '--deploy', '--system']
pipenv_command_dev = ['pipenv', 'install', '--dev', '--deploy', '--system']


class PostDevelopCommand(develop):
    """Post-installation for development mode."""

    def run(self):
        subprocess.check_call(pipenv_command_dev)
        develop.run(self)


class PostInstallCommand(install):
    """Post-installation for installation mode."""

    def run(self):
        subprocess.check_call(pipenv_command)
        install.run(self)


with open(base_dir / 'README.md', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="Hermes",
    version="0.0.3",
    author="CDulouard",
    author_email="clement.dulouard@alvarios.com",
    description="Network tools for python.",
    long_description=long_description,
    url="https://github.com/Alvarios/Hermes",
    packages=packages,
    setup_requires=['pipenv'],
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand,
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)

# python setup.py egg_info --egg-base=./
