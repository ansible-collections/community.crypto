# Copyright (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


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


class FilterModule:
    """ IP address and network manipulation filters """

    def filters(self):
        return {
            'internal__get_major_minor_version': get_major_minor_version,
            'internal__version_lookup': version_lookup,
        }
