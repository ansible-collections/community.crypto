# -*- coding: utf-8 -*-
#
# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.crypto.math import (
    convert_int_to_hex,
)


def th(number):
    abs_number = abs(number)
    mod_10 = abs_number % 10
    mod_100 = abs_number % 100
    if mod_100 not in (11, 12, 13):
        if mod_10 == 1:
            return "st"
        if mod_10 == 2:
            return "nd"
        if mod_10 == 3:
            return "rd"
    return "th"


def parse_serial(value):
    """
    Given a colon-separated string of hexadecimal byte values, converts it to an integer.
    """
    value = to_native(value)
    result = 0
    for i, part in enumerate(value.split(":")):
        try:
            part_value = int(part, 16)
            if part_value < 0 or part_value > 255:
                raise ValueError("the value is not in range [0, 255]")
        except ValueError as exc:
            raise ValueError(
                "The {idx}{th} part {part!r} is not a hexadecimal number in range [0, 255]: {exc}".format(
                    idx=i + 1, th=th(i + 1), part=part, exc=exc
                )
            )
        result = (result << 8) | part_value
    return result


def to_serial(value):
    """
    Given an integer, converts its absolute value to a colon-separated string of hexadecimal byte values.
    """
    value = convert_int_to_hex(value).upper()
    if len(value) % 2 != 0:
        value = "0" + value
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2))
