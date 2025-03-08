# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import itertools


def openssl_signatures_combiner(list_of_dicts):
    result = []
    for entry_dicts in itertools.product(*list_of_dicts):
        entry = {}
        for entry_dict in entry_dicts:
            entry.update(entry_dict)
        result.append(entry)
    return result


class FilterModule:
    ''' Jinja2 compat filters '''

    def filters(self):
        return {
            'openssl_signatures_combiner': openssl_signatures_combiner,
        }
