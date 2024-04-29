# -*- coding: utf-8 -*-

# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.community.crypto.plugins.module_utils.crypto.math import (
    binary_exp_mod,
    simple_gcd,
    quick_is_not_prime,
)


@pytest.mark.parametrize('f, e, m, result', [
    (0, 0, 5, 1),
    (0, 1, 5, 0),
    (2, 1, 5, 2),
    (2, 2, 5, 4),
    (2, 3, 5, 3),
    (2, 10, 5, 4),
])
def test_binary_exp_mod(f, e, m, result):
    value = binary_exp_mod(f, e, m)
    print(value)
    assert value == result


@pytest.mark.parametrize('a, b, result', [
    (0, -123, -123),
    (0, 123, 123),
    (-123, 0, -123),
    (123, 0, 123),
    (-123, 1, 1),
    (123, 1, 1),
    (1, -123, -1),
    (1, 123, 1),
    (1024, 10, 2),
])
def test_simple_gcd(a, b, result):
    value = simple_gcd(a, b)
    print(value)
    assert value == result


@pytest.mark.parametrize('n, result', [
    (-2, True),
    (0, True),
    (1, True),
    (2, False),
    (3, False),
    (4, True),
    (5, False),
    (6, True),
    (7, False),
    (8, True),
    (9, True),
    (10, True),
    (211, False),  # the smallest prime number >= 200
])
def test_quick_is_not_prime(n, result):
    value = quick_is_not_prime(n)
    print(value)
    assert value == result
