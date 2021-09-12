# -*- coding: utf-8 -*-

# (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

import pytest

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_get_name,
    _parse_dn_component,
    _parse_dn,
)

from cryptography.x509 import NameAttribute, oid


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
    (r'CN=', {}, (NameAttribute(oid.NameOID.COMMON_NAME, ''), '')),
    (r'CN= ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, ''), '')),
    (r'CN=x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, 'x '), '')),
    (r'CN=\ ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, ' '), '')),
    (r'CN=\#', {}, (NameAttribute(oid.NameOID.COMMON_NAME, '#'), '')),
    (r'CN=#402032', {}, (NameAttribute(oid.NameOID.COMMON_NAME, '@ 2'), '')),
    (r'CN = x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, 'x '), '')),
    (r'CN = x\, ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, 'x, '), '')),
    (r'CN = x\40 ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, 'x@ '), '')),
    (r'CN  =  \  , / ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, '  '), ', / ')),
    (r'CN  =  \  , / ', {'sep': '/'}, (NameAttribute(oid.NameOID.COMMON_NAME, '  , '), '/ ')),
    (r'CN  =  \  , / ', {'decode_remainder': False}, (NameAttribute(oid.NameOID.COMMON_NAME, r'\  , / '), '')),
])
def test_parse_dn_component(name, options, expected):
    result = _parse_dn_component(name, **options)
    print(result, expected)
    assert result == expected


@pytest.mark.parametrize('name, options, message', [
    (r'CN=\0', {}, r'Hex escape sequence "\0" incomplete at end of string'),
    (r'CN=\0,', {}, r'Hex escape sequence "\0," has invalid second letter'),
    (r'CN=#0,', {}, r'Invalid hex sequence entry "0,"'),
])
def test_parse_dn_component_failure(name, options, message):
    with pytest.raises(OpenSSLObjectError, match='^%s$' % re.escape(message)):
        result = _parse_dn_component(name, **options)


@pytest.mark.parametrize('name, expected', [
    (r'CN=', [NameAttribute(oid.NameOID.COMMON_NAME, '')]),
    (r'CN=,CN=', [NameAttribute(oid.NameOID.COMMON_NAME, ''), NameAttribute(oid.NameOID.COMMON_NAME, '')]),
    (r'CN  =  ,  CN  =  ', [NameAttribute(oid.NameOID.COMMON_NAME, ''), NameAttribute(oid.NameOID.COMMON_NAME, '')]),
])
def test_parse_dn(name, expected):
    result = _parse_dn(name)
    print(result, expected)
    assert result == expected


@pytest.mark.parametrize('name, message', [
    (r'CN=\0', r'Error while parsing distinguished name "CN=\0": Hex escape sequence "\0" incomplete at end of string'),
    (r'CN=,', r'Error while parsing distinguished name "CN=,": unexpected end of string'),
])
def test_parse_dn_failure(name, message):
    with pytest.raises(OpenSSLObjectError, match='^%s$' % re.escape(message)):
        result = _parse_dn(name)
