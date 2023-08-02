# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


# Added in ansible-core 2.11
def compatibility_split_filter(text, by_what):
    return text.split(by_what)


class FilterModule:
    ''' Jinja2 compat filters '''

    def filters(self):
        return {
            'split': compatibility_split_filter,
        }
