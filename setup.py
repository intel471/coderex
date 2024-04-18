# Copyright (C) 2024  Intel 471 Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup
from setuptools import find_packages

setup(
    name='coderex',
    version='0.0.1',
    description='Automated generation of generic regular expressions for x86 and x86-64 instructions to handle common '
                'variations in compiled code.',
    author='Souhail Hammou',
    author_email='shammou@intel471.com',
    license='GNU AGPLv3',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'coderex = coderex.main:main',
        ],
    },
    install_requires=[
        'iced-x86==1.21.0'
    ]
)
