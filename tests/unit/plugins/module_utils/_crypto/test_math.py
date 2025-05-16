# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pytest
from ansible_collections.community.crypto.plugins.module_utils._crypto.math import (
    binary_exp_mod,
    convert_bytes_to_int,
    convert_int_to_bytes,
    convert_int_to_hex,
    quick_is_not_prime,
    simple_gcd,
)


@pytest.mark.parametrize(
    "f, e, m, result",
    [
        (0, 0, 5, 1),
        (0, 1, 5, 0),
        (2, 1, 5, 2),
        (2, 2, 5, 4),
        (2, 3, 5, 3),
        (2, 10, 5, 4),
    ],
)
def test_binary_exp_mod(f: int, e: int, m: int, result: int) -> None:
    value = binary_exp_mod(f, e, m=m)
    print(value)
    assert value == result


@pytest.mark.parametrize(
    "a, b, result",
    [
        (0, -123, -123),
        (0, 123, 123),
        (-123, 0, -123),
        (123, 0, 123),
        (-123, 1, 1),
        (123, 1, 1),
        (1, -123, -1),
        (1, 123, 1),
        (1024, 10, 2),
    ],
)
def test_simple_gcd(a: int, b: int, result: int) -> None:
    value = simple_gcd(a, b)
    print(value)
    assert value == result


@pytest.mark.parametrize(
    "n, result",
    [
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
    ],
)
def test_quick_is_not_prime(n: int, result: bool) -> None:
    value = quick_is_not_prime(n)
    print(value)
    assert value == result


@pytest.mark.parametrize(
    "no, count, result",
    [
        (0, None, b""),
        (0, 1, b"\x00"),
        (0, 2, b"\x00\x00"),
        (1, None, b"\x01"),
        (1, 2, b"\x00\x01"),
        (255, None, b"\xff"),
        (256, None, b"\x01\x00"),
    ],
)
def test_convert_int_to_bytes(no: int, count: int | None, result: bytes) -> None:
    value = convert_int_to_bytes(no, count=count)
    print(value)
    assert value == result


@pytest.mark.parametrize(
    "no, digits, result",
    [
        (0, None, "0"),
        (1, None, "1"),
        (16, None, "10"),
        (1, 3, "001"),
        (255, None, "ff"),
        (256, None, "100"),
        (256, 2, "100"),
        (256, 3, "100"),
        (256, 4, "0100"),
    ],
)
def test_convert_int_to_hex(no: int, digits: int | None, result: str) -> None:
    value = convert_int_to_hex(no, digits=digits)
    print(value)
    assert value == result


@pytest.mark.parametrize(
    "data, result",
    [
        (b"", 0),
        (b"\x00", 0),
        (b"\x00\x01", 1),
        (b"\x01", 1),
        (b"\xff", 255),
        (b"\x01\x00", 256),
    ],
)
def test_convert_bytes_to_int(data: bytes, result: int) -> None:
    value = convert_bytes_to_int(data)
    print(value)
    assert value == result
