# Copyright (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import pathlib
import re
import subprocess

import pytest
from ansible_collections.community.crypto.plugins.module_utils._crypto._asn1 import (
    serialize_asn1_string_as_der,
)


TEST_CASES: list[tuple[str, bytes]] = [
    ("UTF8:Hello World", b"\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"),
    (
        "EXPLICIT:10,UTF8:Hello World",
        b"\xaa\x0d\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "EXPLICIT:12U,UTF8:Hello World",
        b"\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "EXPLICIT:10A,UTF8:Hello World",
        b"\x6a\x0d\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "EXPLICIT:10P,UTF8:Hello World",
        b"\xea\x0d\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "EXPLICIT:10C,UTF8:Hello World",
        b"\xaa\x0d\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "EXPLICIT:1024P,UTF8:Hello World",
        b"\xff\x88\x00\x0d\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:10,UTF8:Hello World",
        b"\x8a\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:12U,UTF8:Hello World",
        b"\x0c\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:10A,UTF8:Hello World",
        b"\x4a\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:10P,UTF8:Hello World",
        b"\xca\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:10C,UTF8:Hello World",
        b"\x8a\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    (
        "IMPLICIT:1024P,UTF8:Hello World",
        b"\xdf\x88\x00\x0b\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64",
    ),
    # Tests large data lengths, special logic for the length octet encoding.
    ("UTF8:" + ("A" * 600), b"\x0c\x82\x02\x58" + (b"\x41" * 600)),
    # This isn't valid with openssl asn1parse but has been validated against an ASN.1 parser. OpenSSL seems to read the
    # data u"café" encoded as UTF-8 bytes b"caf\xc3\xa9", decodes that internally with latin-1 (or similar variant) as
    # u"cafÃ©" then encodes that to UTF-8 b"caf\xc3\x83\xc2\xa9" for the UTF8String. Ultimately openssl is wrong here
    # so we keep our assertion happening.
    ("UTF8:café", b"\x0c\x05\x63\x61\x66\xc3\xa9"),
]


@pytest.mark.parametrize("value, expected", TEST_CASES)
def test_serialize_asn1_string_as_der(value: str, expected: bytes) -> None:
    actual = serialize_asn1_string_as_der(value)
    print(f"{value} | {base64.b16encode(actual).decode()}")
    assert actual == expected


@pytest.mark.parametrize(
    "value",
    [
        "invalid",
        "EXPLICIT,UTF:value",
    ],
)
def test_serialize_asn1_string_as_der_invalid_format(value: str) -> None:
    expected = (
        "The ASN.1 serialized string must be in the format [modifier,]type[:value]"
    )
    with pytest.raises(ValueError, match=re.escape(expected)):
        serialize_asn1_string_as_der(value)


def test_serialize_asn1_string_as_der_invalid_type() -> None:
    expected = 'The ASN.1 serialized string is not a known type "OID", only UTF8 types are supported'
    with pytest.raises(ValueError, match=re.escape(expected)):
        serialize_asn1_string_as_der("OID:1.2.3.4")


@pytest.mark.skip()  # This is to just to build the test case assertions and shouldn't run normally.
@pytest.mark.parametrize("value, expected", TEST_CASES)
def test_test_cases(value: str, expected: bytes, tmp_path: pathlib.Path) -> None:
    test_file = tmp_path / "test.der"
    subprocess.run(
        ["openssl", "asn1parse", "-genstr", value, "-noout", "-out", test_file],
        check=True,
    )

    with open(test_file, mode="rb") as fd:
        b_data = fd.read()

    hex_str = base64.b16encode(b_data).decode().lower()
    value = "\\x".join([hex_str[i : i + 2] for i in range(0, len(hex_str), 2)])
    print(f"{value} | \\x{value}")

    # This is a know edge case where openssl asn1parse does not work properly.
    if value != "UTF8:café":
        assert b_data == expected
