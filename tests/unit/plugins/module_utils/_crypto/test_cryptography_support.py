# Copyright (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re
import typing as t

import cryptography
import pytest
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    _adjust_idn,
    _parse_dn,
    _parse_dn_component,
    cryptography_get_name,
)
from ansible_collections.community.crypto.plugins.module_utils._version import (
    LooseVersion,
)
from cryptography.x509 import NameAttribute, OtherName, oid


@pytest.mark.parametrize(
    "unicode, idna, cycled_unicode",
    [
        ("..", "..", None),
        ("foo.com", "foo.com", None),
        (".foo.com.", ".foo.com.", None),
        ("*.foo.com", "*.foo.com", None),
        ("straße", "xn--strae-oqa", None),
        ("ﬀóò.ḃâŗ.çøṁ", "xn--ff-3jad.xn--2ca8uh37e.xn--7ca8a981n", "ffóò.ḃâŗ.çøṁ"),
        ("*.☺.", "*.xn--74h.", None),
    ],
)
def test_adjust_idn(unicode: str, idna: str, cycled_unicode: str | None) -> None:
    if cycled_unicode is None:
        cycled_unicode = unicode

    result = _adjust_idn(unicode, idn_rewrite="ignore")
    print(result, unicode)
    assert result == unicode

    result = _adjust_idn(idna, idn_rewrite="ignore")
    print(result, idna)
    assert result == idna

    result = _adjust_idn(unicode, idn_rewrite="unicode")
    print(result, unicode)
    assert result == unicode

    result = _adjust_idn(idna, idn_rewrite="unicode")
    print(result, cycled_unicode)
    assert result == cycled_unicode

    result = _adjust_idn(unicode, idn_rewrite="idna")
    print(result, idna)
    assert result == idna

    result = _adjust_idn(idna, idn_rewrite="idna")
    print(result, idna)
    assert result == idna


@pytest.mark.parametrize(
    "value, idn_rewrite, message",
    [
        ("bar", "foo", re.escape('Invalid value for idn_rewrite: "foo"')),
    ],
)
def test_adjust_idn_fail_valueerror(value: str, idn_rewrite: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        idn_rewrite_: t.Literal["ignore", "idna", "unicode"] = idn_rewrite  # type: ignore
        _adjust_idn(value, idn_rewrite=idn_rewrite_)


@pytest.mark.parametrize(
    "value, idn_rewrite, message",
    [
        (
            "xn--a",
            "unicode",
            """^Error while transforming part u?"xn\\-\\-a" of IDNA DNS name u?"xn\\-\\-a" to Unicode\\."""
            """ IDNA2008 transformation resulted in "Codepoint U\\+0080 at position 1 of u?'\\\\x80' not allowed","""
            """ IDNA2003 transformation resulted in "(decoding with 'idna' codec failed"""
            """ \\(UnicodeError: |'idna' codec can't decode byte 0x78 in position 0: )?Invalid character u?'\\\\x80'\\)?"\\.$""",
        ),
    ],
)
def test_adjust_idn_fail_user_error(value: str, idn_rewrite: str, message: str) -> None:
    with pytest.raises(OpenSSLObjectError, match=message):
        idn_rewrite_: t.Literal["ignore", "idna", "unicode"] = idn_rewrite  # type: ignore
        _adjust_idn(value, idn_rewrite=idn_rewrite_)


def test_cryptography_get_name_invalid_prefix() -> None:
    with pytest.raises(
        OpenSSLObjectError, match="^Cannot parse Subject Alternative Name"
    ):
        cryptography_get_name("fake:value")


def test_cryptography_get_name_other_name_no_oid() -> None:
    with pytest.raises(
        OpenSSLObjectError, match="Cannot parse Subject Alternative Name otherName"
    ):
        cryptography_get_name("otherName:value")


def test_cryptography_get_name_other_name_utfstring() -> None:
    actual = cryptography_get_name("otherName:1.3.6.1.4.1.311.20.2.3;UTF8:Hello World")
    assert isinstance(actual, OtherName)
    assert actual.type_id.dotted_string == "1.3.6.1.4.1.311.20.2.3"
    assert actual.value == b"\x0c\x0bHello World"


@pytest.mark.parametrize(
    "name, options, expected",
    [
        (b"CN=x ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "x "), b"")),
        (b"CN=\\ ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, " "), b"")),
        (b"CN=\\#", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "#"), b"")),
        (b"CN=#402032", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "@ 2"), b"")),
        (b"CN = x ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "x "), b"")),
        (b"CN = x\\, ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "x, "), b"")),
        (b"CN = x\\40 ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, "x@ "), b"")),
        (
            b"CN  =  \\  , / ",
            {},
            (NameAttribute(oid.NameOID.COMMON_NAME, "  "), b", / "),
        ),
        (
            b"CN  =  \\  , / ",
            {"sep": b"/"},
            (NameAttribute(oid.NameOID.COMMON_NAME, "  , "), b"/ "),
        ),
        (
            b"CN  =  \\  , / ",
            {"decode_remainder": False},
            (NameAttribute(oid.NameOID.COMMON_NAME, "\\  , / "), b""),
        ),
        # Some examples from https://datatracker.ietf.org/doc/html/rfc4514#section-4:
        (
            b'CN=James \\"Jim\\" Smith\\, III',
            {},
            (NameAttribute(oid.NameOID.COMMON_NAME, 'James "Jim" Smith, III'), b""),
        ),
        (
            b"CN=Before\\0dAfter",
            {},
            (NameAttribute(oid.NameOID.COMMON_NAME, "Before\x0dAfter"), b""),
        ),
        (
            b"1.3.6.1.4.1.1466.0=#04024869",
            {},
            (
                NameAttribute(oid.ObjectIdentifier("1.3.6.1.4.1.1466.0"), "\x04\x02Hi"),
                b"",
            ),
        ),
        (
            b"CN=Lu\\C4\\8Di\\C4\\87",
            {},
            (NameAttribute(oid.NameOID.COMMON_NAME, "Lučić"), b""),
        ),
    ],
)
def test_parse_dn_component(
    name: bytes, options: dict[str, t.Any], expected: tuple[NameAttribute, bytes]
) -> None:
    result = _parse_dn_component(name, **options)
    print(result, expected)
    assert result == expected


# Cryptography < 2.9 does not allow empty strings
# (https://github.com/pyca/cryptography/commit/87b2749c52e688c809f1861e55d958c64147493c)
# Cryptoraphy 43.0.0+ also doesn't allow this anymore
if (
    LooseVersion("2.9")
    <= LooseVersion(cryptography.__version__)
    < LooseVersion("43.0.0")
):

    @pytest.mark.parametrize(
        "name, options, expected",
        [
            (b"CN=", {}, (NameAttribute(oid.NameOID.COMMON_NAME, ""), b"")),
            (b"CN= ", {}, (NameAttribute(oid.NameOID.COMMON_NAME, ""), b"")),
        ],
    )
    def test_parse_dn_component_not_py26(
        name: bytes, options: dict[str, t.Any], expected: tuple[NameAttribute, bytes]
    ) -> None:
        result = _parse_dn_component(name, **options)
        print(result, expected)
        assert result == expected


@pytest.mark.parametrize(
    "name, options, message",
    [
        (b"CN=\\0", {}, 'Hex escape sequence "\\0" incomplete at end of string'),
        (b"CN=\\0,", {}, 'Hex escape sequence "\\0," has invalid second letter'),
        (b"CN=#0,", {}, 'Invalid hex sequence entry "0,"'),
    ],
)
def test_parse_dn_component_failure(
    name: bytes, options: dict[str, t.Any], message: str
) -> None:
    with pytest.raises(OpenSSLObjectError, match=f"^{re.escape(message)}$"):
        _parse_dn_component(name, **options)


@pytest.mark.parametrize(
    "name, expected",
    [
        (b"CN=foo", [NameAttribute(oid.NameOID.COMMON_NAME, "foo")]),
        (
            b"CN=foo,CN=bar",
            [
                NameAttribute(oid.NameOID.COMMON_NAME, "foo"),
                NameAttribute(oid.NameOID.COMMON_NAME, "bar"),
            ],
        ),
        (
            b"CN  =  foo ,  CN  =  bar",
            [
                NameAttribute(oid.NameOID.COMMON_NAME, "foo "),
                NameAttribute(oid.NameOID.COMMON_NAME, "bar"),
            ],
        ),
    ],
)
def test_parse_dn(name: bytes, expected: list[NameAttribute]) -> None:
    result = _parse_dn(name)
    print(result, expected)
    assert result == expected


@pytest.mark.parametrize(
    "name, message",
    [
        (
            b"CN=\\0",
            "Error while parsing distinguished name 'CN=\\\\0': Hex escape sequence \"\\0\" incomplete at end of string",
        ),
        (
            b"CN=x,",
            "Error while parsing distinguished name 'CN=x,': unexpected end of string",
        ),
    ],
)
def test_parse_dn_failure(name: bytes, message: str) -> None:
    with pytest.raises(OpenSSLObjectError, match=f"^{re.escape(message)}$"):
        _parse_dn(name)
