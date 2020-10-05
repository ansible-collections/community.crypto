# -*- coding: utf-8 -*-
#
# (c) 2020, Doug Stanley <doug+ansible@technologixllc.com>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import re


def parse_openssh_version(version_string):
    """Parse the version output of ssh -V and return version numbers that can be compared"""

    parsed_result = re.match(
        r"^.*openssh_(?P<version>[0-9.]+)(p?[0-9]+)[^0-9]*.*$", version_string.lower()
    )
    if parsed_result is not None:
        version = parsed_result.group("version").strip()
    else:
        version = None

    return version
