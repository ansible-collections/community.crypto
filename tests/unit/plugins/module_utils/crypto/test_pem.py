# -*- coding: utf-8 -*-

# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import pytest
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    extract_first_pem,
    identify_pem_format,
    identify_private_key_format,
    split_pem_list,
)


PEM_TEST_CASES = [
    (b"", [], False, "raw"),
    (b"random stuff\nblabla", [], False, "raw"),
    (b"-----BEGIN PRIVATE KEY-----", [], False, "raw"),
    (
        b"-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
        ["-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"],
        True,
        "pkcs8",
    ),
    (
        b"foo=bar\n# random stuff\n-----BEGIN RSA PRIVATE KEY-----\nblabla\n-----END RSA PRIVATE KEY-----\nmore stuff\n",
        ["-----BEGIN RSA PRIVATE KEY-----\nblabla\n-----END RSA PRIVATE KEY-----\n"],
        True,
        "pkcs1",
    ),
    (
        b"foo=bar\n# random stuff\n-----BEGIN CERTIFICATE-----\nblabla\n-----END CERTIFICATE-----\nmore stuff\n"
        b"\n-----BEGIN CERTIFICATE-----\nfoobar\n-----END CERTIFICATE-----",
        [
            "-----BEGIN CERTIFICATE-----\nblabla\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nfoobar\n-----END CERTIFICATE-----",
        ],
        True,
        "unknown-pem",
    ),
    (
        b"-----BEGINCERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n-----BEGINCERTIFICATE-----\n-----END CERTIFICATE-----\n-----BEGINCERTIFICATE-----\n",
        [
            "-----BEGIN CERTIFICATE-----\n-----BEGINCERTIFICATE-----\n-----END CERTIFICATE-----\n",
        ],
        True,
        "unknown-pem",
    ),
]


@pytest.mark.parametrize("data, pems, is_pem, private_key_type", PEM_TEST_CASES)
def test_pem_handling(data, pems, is_pem, private_key_type):
    assert identify_pem_format(data) == is_pem
    assert identify_private_key_format(data) == private_key_type
    try:
        text = data.decode("utf-8")
        assert split_pem_list(text) == pems
        first_pem = pems[0] if pems else None
        assert extract_first_pem(text) == first_pem
    except UnicodeDecodeError:
        pass
