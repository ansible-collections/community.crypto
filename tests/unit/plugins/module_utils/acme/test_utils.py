# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import datetime

import pytest
from ansible_collections.community.crypto.plugins.module_utils.acme.backends import (
    CertificateInformation,
)
from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    compute_cert_id,
    nopad_b64,
    parse_retry_after,
    pem_to_der,
    process_links,
)

from .backend_data import TEST_PEM_DERS


NOPAD_B64 = [
    ("", ""),
    ("\n", "Cg"),
    ("123", "MTIz"),
    ("Lorem?ipsum", "TG9yZW0_aXBzdW0"),
]


TEST_LINKS_HEADER = [
    (
        {},
        [],
    ),
    (
        {"link": '<foo>; rel="bar"'},
        [
            ("foo", "bar"),
        ],
    ),
    (
        {"link": '<foo>; rel="bar", <baz>; rel="bam"'},
        [
            ("foo", "bar"),
            ("baz", "bam"),
        ],
    ),
    (
        {
            "link": '<https://one.example.com>; rel="preconnect", <https://two.example.com>; rel="preconnect", <https://three.example.com>; rel="preconnect"'
        },
        [
            ("https://one.example.com", "preconnect"),
            ("https://two.example.com", "preconnect"),
            ("https://three.example.com", "preconnect"),
        ],
    ),
]


TEST_RETRY_AFTER_HEADER = [
    ("120", datetime.datetime(2024, 4, 29, 0, 2, 0)),
    ("Wed, 21 Oct 2015 07:28:00 GMT", datetime.datetime(2015, 10, 21, 7, 28, 0)),
]


TEST_COMPUTE_CERT_ID = [
    (
        CertificateInformation(
            not_valid_after=datetime.datetime(2018, 11, 26, 15, 28, 24),
            not_valid_before=datetime.datetime(2018, 11, 25, 15, 28, 23),
            serial_number=1,
            subject_key_identifier=None,
            authority_key_identifier=b"\x00\xff",
        ),
        "AP8.AQ",
    ),
    (
        # AKI, serial number, and expected result taken from
        # https://letsencrypt.org/2024/04/25/guide-to-integrating-ari-into-existing-acme-clients.html#step-3-constructing-the-ari-certid
        CertificateInformation(
            not_valid_after=datetime.datetime(2018, 11, 26, 15, 28, 24),
            not_valid_before=datetime.datetime(2018, 11, 25, 15, 28, 23),
            serial_number=0x87654321,
            subject_key_identifier=None,
            authority_key_identifier=b"\x69\x88\x5b\x6b\x87\x46\x40\x41\xe1\xb3\x7b\x84\x7b\xa0\xae\x2c\xde\x01\xc8\xd4",
        ),
        "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE",
    ),
]


@pytest.mark.parametrize("value, result", NOPAD_B64)
def test_nopad_b64(value, result):
    assert nopad_b64(value.encode("utf-8")) == result


@pytest.mark.parametrize("pem, der", TEST_PEM_DERS)
def test_pem_to_der(pem, der, tmpdir):
    fn = tmpdir / "test.pem"
    fn.write(pem)
    assert pem_to_der(str(fn)) == der


@pytest.mark.parametrize("value, expected_result", TEST_LINKS_HEADER)
def test_process_links(value, expected_result):
    data = []

    def callback(url, rel):
        data.append((url, rel))

    process_links(value, callback)

    assert expected_result == data


@pytest.mark.parametrize("value, expected_result", TEST_RETRY_AFTER_HEADER)
def test_parse_retry_after(value, expected_result):
    assert expected_result == parse_retry_after(
        value, now=datetime.datetime(2024, 4, 29, 0, 0, 0)
    )


@pytest.mark.parametrize("cert_info, expected_result", TEST_COMPUTE_CERT_ID)
def test_compute_cert_id(cert_info, expected_result):
    assert expected_result == compute_cert_id(backend=None, cert_info=cert_info)
