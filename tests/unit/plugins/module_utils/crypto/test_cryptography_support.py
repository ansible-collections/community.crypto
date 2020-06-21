# -*- coding: utf-8 -*-

# (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_get_name,
)


def test_cryptography_get_name_invalid_prefix():
    with pytest.raises(OpenSSLObjectError, match="Cannot parse Subject Alternative Name"):
        cryptography_get_name('fake:value')


def test_cryptography_get_name_other_name_no_oid():
    with pytest.raises(OpenSSLObjectError, match="Cannot parse Subject Alternative Name otherName"):
        cryptography_get_name('otherName:value')


def test_cryptography_get_name_other_name_utfstring():
    actual = cryptography_get_name('otherName:1.3.6.1.4.1.311.20.2.3;UTF8:Hello World')
    assert actual.type_id.dotted_string == '1.3.6.1.4.1.311.20.2.3'
    assert actual.value == b'\x0c\x0bHello World'
