# -*- coding: utf-8 -*-
#
# (c) 2019, Felix Fontein <felix@fontein.de>
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


from ._objects_data import OID_MAP

OID_LOOKUP = dict()
NORMALIZE_NAMES = dict()
NORMALIZE_NAMES_SHORT = dict()

for dotted, names in OID_MAP.items():
    for name in names:
        if name in NORMALIZE_NAMES and OID_LOOKUP[name] != dotted:
            raise AssertionError(
                'Name collision during setup: "{0}" for OIDs {1} and {2}'
                .format(name, dotted, OID_LOOKUP[name])
            )
        NORMALIZE_NAMES[name] = names[0]
        NORMALIZE_NAMES_SHORT[name] = names[-1]
        OID_LOOKUP[name] = dotted
for alias, original in [('userID', 'userId')]:
    if alias in NORMALIZE_NAMES:
        raise AssertionError(
            'Name collision during adding aliases: "{0}" (alias for "{1}") is already mapped to OID {2}'
            .format(alias, original, OID_LOOKUP[alias])
        )
    NORMALIZE_NAMES[alias] = original
    NORMALIZE_NAMES_SHORT[alias] = NORMALIZE_NAMES_SHORT[original]
    OID_LOOKUP[alias] = OID_LOOKUP[original]
