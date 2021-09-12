# -*- coding: utf-8 -*-

# (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re
import sys

from distutils.version import LooseVersion

import cryptography
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
    (u'CN=x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x '), u'')),
    (u'CN=\\ ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u' '), u'')),
    (u'CN=\\#', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'#'), u'')),
    (u'CN=#402032', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'@ 2'), u'')),
    (u'CN = x ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x '), u'')),
    (u'CN = x\\, ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x, '), u'')),
    (u'CN = x\\40 ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'x@ '), u'')),
    (u'CN  =  \\  , / ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u'  '), u', / ')),
    (u'CN  =  \\  , / ', {'sep': '/'}, (NameAttribute(oid.NameOID.COMMON_NAME, u'  , '), u'/ ')),
    (u'CN  =  \\  , / ', {'decode_remainder': False}, (NameAttribute(oid.NameOID.COMMON_NAME, u'\\  , / '), u'')),
])
def test_parse_dn_component(name, options, expected):
    result = _parse_dn_component(name, **options)
    print(result, expected)
    assert result == expected


# Cryptography < 2.9 does not allow empty strings
# (https://github.com/pyca/cryptography/commit/87b2749c52e688c809f1861e55d958c64147493c)
if LooseVersion(cryptography.__version__) >= LooseVersion('2.9'):
    @pytest.mark.parametrize('name, options, expected', [
        (u'CN=', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u''), u'')),
        (u'CN= ', {}, (NameAttribute(oid.NameOID.COMMON_NAME, u''), u'')),
    ])
    def test_parse_dn_component_not_py26(name, options, expected):
        result = _parse_dn_component(name, **options)
        print(result, expected)
        assert result == expected


@pytest.mark.parametrize('name, options, message', [
    (u'CN=\\0', {}, u'Hex escape sequence "\\0" incomplete at end of string'),
    (u'CN=\\0,', {}, u'Hex escape sequence "\\0," has invalid second letter'),
    (u'CN=#0,', {}, u'Invalid hex sequence entry "0,"'),
])
def test_parse_dn_component_failure(name, options, message):
    with pytest.raises(OpenSSLObjectError, match=u'^%s$' % re.escape(message)):
        result = _parse_dn_component(name, **options)


@pytest.mark.parametrize('name, expected', [
    (u'CN=foo', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo')]),
    (u'CN=foo,CN=bar', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo'), NameAttribute(oid.NameOID.COMMON_NAME, u'bar')]),
    (u'CN  =  foo ,  CN  =  bar', [NameAttribute(oid.NameOID.COMMON_NAME, u'foo '), NameAttribute(oid.NameOID.COMMON_NAME, u'bar')]),
])
def test_parse_dn(name, expected):
    result = _parse_dn(name)
    print(result, expected)
    assert result == expected


@pytest.mark.parametrize('name, message', [
    (u'CN=\\0', u'Error while parsing distinguished name "CN=\\0": Hex escape sequence "\\0" incomplete at end of string'),
    (u'CN=x,', u'Error while parsing distinguished name "CN=x,": unexpected end of string'),
])
def test_parse_dn_failure(name, message):
    with pytest.raises(OpenSSLObjectError, match=u'^%s$' % re.escape(message)):
        result = _parse_dn(name)
