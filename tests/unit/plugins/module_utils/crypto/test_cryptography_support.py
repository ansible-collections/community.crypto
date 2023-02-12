# -*- coding: utf-8 -*-

# Copyright (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

import cryptography
import pytest

from cryptography.x509 import NameAttribute, oid

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_get_name,
    _adjust_idn,
    _parse_dn_component,
    _parse_dn,
)

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion


@pytest.mark.parametrize('unicode, idna, cycled_unicode', [
    (u'..', u'..', None),
    (u'foo.com', u'foo.com', None),
    (u'.foo.com.', u'.foo.com.', None),
    (u'*.foo.com', u'*.foo.com', None),
    (u'straße', u'xn--strae-oqa', None),
    (u'ﬀóò.ḃâŗ.çøṁ', u'xn--ff-3jad.xn--2ca8uh37e.xn--7ca8a981n', u'ffóò.ḃâŗ.çøṁ'),
    (u'*.☺.', u'*.xn--74h.', None),
])
def test_adjust_idn(unicode, idna, cycled_unicode):
    if cycled_unicode is None:
        cycled_unicode = unicode

    result = _adjust_idn(unicode, 'ignore')
    print(result, unicode)
    assert result == unicode

    result = _adjust_idn(idna, 'ignore')
    print(result, idna)
    assert result == idna

    result = _adjust_idn(unicode, 'unicode')
    print(result, unicode)
    assert result == unicode

    result = _adjust_idn(idna, 'unicode')
    print(result, cycled_unicode)
    assert result == cycled_unicode

    result = _adjust_idn(unicode, 'idna')
    print(result, idna)
    assert result == idna

    result = _adjust_idn(idna, 'idna')
    print(result, idna)
    assert result == idna


@pytest.mark.parametrize('value, idn_rewrite, message', [
    (u'bar', 'foo', re.escape(u'Invalid value for idn_rewrite: "foo"')),
])
def test_adjust_idn_fail_valueerror(value, idn_rewrite, message):
    with pytest.raises(ValueError, match=message):
        result = _adjust_idn(value, idn_rewrite)


@pytest.mark.parametrize('value, idn_rewrite, message', [
    (
        u'xn--a',
        'unicode',
        u'''^Error while transforming part u?"xn\\-\\-a" of IDNA DNS name u?"xn\\-\\-a" to Unicode\\.'''
        u''' IDNA2008 transformation resulted in "Codepoint U\\+0080 at position 1 of u?'\\\\x80' not allowed",'''
        u''' IDNA2003 transformation resulted in "(decoding with 'idna' codec failed'''
        u''' \\(UnicodeError: )?Invalid character u?'\\\\x80'\\)?"\\.$'''
    ),
])
def test_adjust_idn_fail_user_error(value, idn_rewrite, message):
    with pytest.raises(OpenSSLObjectError, match=message):
        result = _adjust_idn(value, idn_rewrite)


def test_cryptography_get_name_invalid_prefix():
    with pytest.raises(OpenSSLObjectError, match="^Cannot parse Subject Alternative Name"):
        cryptography_get_name('fake:value')


def test_cryptography_get_name_other_name_no_oid():
    with pytest.raises(OpenSSLObjectError, match="Cannot parse Subject Alternative Name otherName"):
        cryptography_get_name('otherName:value')


def test_cryptography_get_name_other_name_utfstring():
    actual = cryptography_get_name('otherName:1.3.6.1.4.1.311.20.2.3;UTF8:Hello World')
    assert actual.type_id.dotted_string == '1.3.6.1.4.1.311.20.2.3'
    assert actual.value == b'\x0c\x0bHello World'


@pytest.mark.parametrize('name, options, expected', [
    (b'CN=x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x '), b'')),
    (b'CN=\\ ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u' '), b'')),
    (b'CN=\\#', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'#'), b'')),
    (b'CN=#402032', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'@ 2'), b'')),
    (b'CN = x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x '), b'')),
    (b'CN = x\\, ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x, '), b'')),
    (b'CN = x\\40 ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x@ '), b'')),
    (b'CN  =  \\  , / ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'  '), b', / ')),
    (b'CN  =  \\  , / ', {'sep': b'/'}, (NameAttribute(oid.NameOID.COMMON_NAME, u'  , '), b'/ ')),
    (b'CN  =  \\  , / ', {'decode_remainder': False}, (NameAttribute(oid.NameOID.COMMON_NAME, u'\\  , / '), b'')),
    # Some examples from https://datatracker.ietf.org/doc/html/rfc4514#section-4:
    (b'CN=James \\"Jim\\" Smith\\, III', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'James "Jim" Smith, III'), b'')),
    (b'CN=Before\\0dAfter', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'Before\x0dAfter'), b'')),
    (b'1.3.6.1.4.1.1466.0=#04024869', {}, (NameAttribute(oid.ObjectIdentifier(u'1.3.6.1.4.1.1466.0'), u'\x04\x02Hi'), b'')),
    (b'CN=Lu\\C4\\8Di\\C4\\87', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'Lučić'), b'')),
])
def test_parse_dn_component(name, options, expected):
    result = _parse_dn_component(name, **options)
    print(result, expected)
    assert result == expected


# Cryptography < 2.9 does not allow empty strings
# (https://github.com/pyca/cryptography/commit/87b2749c52e688c809f1861e55d958c64147493c)
if LooseVersion(cryptography.__version__) >= LooseVersion('2.9'):
    @pytest.mark.parametrize('name, options, expected', [
        (b'CN=', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u''), b'')),
        (b'CN= ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u''), b'')),
    ])
    def test_parse_dn_component_not_py26(name, options, expected):
        result = _parse_dn_component(name, **options)
        print(result, expected)
        assert result == expected


@pytest.mark.parametrize('name, options, message', [
    (b'CN=\\0', {}, u'Hex escape sequence "\\0" incomplete at end of string'),
    (b'CN=\\0,', {}, u'Hex escape sequence "\\0," has invalid second letter'),
    (b'CN=#0,', {}, u'Invalid hex sequence entry "0,"'),
])
def test_parse_dn_component_failure(name, options, message):
    with pytest.raises(OpenSSLObjectError, match=u'^%s$' % re.escape(message)):
        result = _parse_dn_component(name, **options)


@pytest.mark.parametrize('name, expected', [
    (b'CN=foo', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo')]),
    (b'CN=foo,CN=bar', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo'), NameAttribute(oid.NameOID.COMMON_NAME, u'bar')]),
    (b'CN  =  foo ,  CN  =  bar', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo '), NameAttribute(oid.NameOID.COMMON_NAME, u'bar')]),
])
def test_parse_dn(name, expected):
    result = _parse_dn(name)
    print(result, expected)
    assert result == expected


@pytest.mark.parametrize('name, message', [
    (b'CN=\\0', u'Error while parsing distinguished name "CN=\\0": Hex escape sequence "\\0" incomplete at end of string'),
    (b'CN=x,', u'Error while parsing distinguished name "CN=x,": unexpected end of string'),
])
def test_parse_dn_failure(name, message):
    with pytest.raises(OpenSSLObjectError, match=u'^%s$' % re.escape(message)):
        result = _parse_dn(name)
