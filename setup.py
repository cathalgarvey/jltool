import os
import sys
import jltool
from setuptools import setup

if sys.version_info < (3,):
    raise NotImplementedError("jltool is Python 3 only. This is not a bug.")

with open(os.path.join(os.path.dirname(__file__), "Readme.md")) as readme:
    long_description = readme.read()

setup(
    name='jltool',
    description="Tools for inspecting, comparing, & cleaning JSON-Lines files",
    long_description=long_description,
    version=jltool.__version__,
    url="https://github.com/cathalgarvey/jltool",
    author="Cathal Garvey",
    author_email="cathalgarvey@cathalgarvey.me",
    maintainer="Cathal Garvey",
    maintainer_email="cathalgarvey@cathalgarvey.me",
    license="GNU Affero General Public License v3",
    packages = [
        'jltool'
    ],
    install_requires = ['objectpath'],
    entry_points = {
        'console_scripts': ['jltool=jltool:_main']
    },
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
    ]
)
