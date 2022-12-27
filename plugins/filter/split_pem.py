# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
name: split_pem
short_description: Split PEM file contents into multiple objects
version_added: 2.10.0
author:
    - Felix Fontein (@felixfontein)
description:
    - Split PEM file contents into multiple PEM objects. Comments or invalid parts are ignored.
options:
    _input:
        description:
            - The PEM contents to split.
        type: string
        required: true
'''

EXAMPLES = '''
- name: Print all CA certificates
  ansible.builtin.debug:
    msg: '{{ item }}'
  loop: >-
    {{ lookup('ansible.builtin.file', '/path/to/ca-bundle.pem') | community.crypto.split_pem }}
'''

RETURN = '''
_value:
    description:
        - A list of PEM file contents.
    type: list
    elements: string
'''

from ansible.errors import AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import split_pem_list


def split_pem_filter(data):
    '''Split PEM file.'''
    if not isinstance(data, string_types):
        raise AnsibleFilterError('The community.crypto.split_pem input must be a text type, not %s' % type(data))

    data = to_text(data)
    return split_pem_list(data)


class FilterModule(object):
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'split_pem': split_pem_filter,
        }
