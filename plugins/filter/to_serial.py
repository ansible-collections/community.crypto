# -*- coding: utf-8 -*-
# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = r"""
name: to_serial
short_description: Convert an integer to a colon-separated list of hex numbers
author: Felix Fontein (@felixfontein)
version_added: 2.18.0
description:
  - Converts an integer to a colon-separated list of hex numbers of the form C(00:11:22:33).
options:
  _input:
    description:
      - The non-negative integer to convert.
    type: int
    required: true
seealso:
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Convert integer to serial number
  ansible.builtin.debug:
    msg: "{{ 1234567 | community.crypto.to_serial }}"
"""

RETURN = r"""
_value:
  description:
    - A colon-separated list of hexadecimal numbers.
    - Letters are upper-case, and all numbers have exactly two digits.
    - The string is never empty. The representation of C(0) is C("00").
  type: string
"""

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.six import integer_types
from ansible_collections.community.crypto.plugins.module_utils.serial import to_serial


def to_serial_filter(input):
    if not isinstance(input, integer_types):
        raise AnsibleFilterError(
            "The input for the community.crypto.to_serial filter must be an integer; got {type} instead".format(
                type=type(input)
            )
        )
    if input < 0:
        raise AnsibleFilterError(
            "The input for the community.crypto.to_serial filter must not be negative"
        )
    try:
        return to_serial(input)
    except ValueError as exc:
        raise AnsibleFilterError(to_native(exc))


class FilterModule(object):
    """Ansible jinja2 filters"""

    def filters(self):
        return {
            "to_serial": to_serial_filter,
        }
