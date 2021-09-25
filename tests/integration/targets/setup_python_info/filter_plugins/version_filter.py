# (c) 2021, Felix Fontein <felix@fontein.de>
#
# This file is part of Ansible
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


def get_major_minor_version(version):
    parts = version.split('.')[:2]
    return '.'.join(parts)


def version_lookup(data, distribution, os_family, distribution_version, distribution_major_version, python_version, default_value=False):
    if distribution in data:
        data = data[distribution]
    elif os_family in data:
        data = data[os_family]
    else:
        return default_value

    if distribution_version in data:
        data = data[distribution_version]
    elif get_major_minor_version(distribution_version) in data:
        data = data[get_major_minor_version(distribution_version)]
    elif str(distribution_major_version) in data:
        data = data[str(distribution_major_version)]
    else:
        return default_value

    return python_version in data


class FilterModule(object):
    """ IP address and network manipulation filters """

    def filters(self):
        return {
            'internal__get_major_minor_version': get_major_minor_version,
            'internal__version_lookup': version_lookup,
        }
