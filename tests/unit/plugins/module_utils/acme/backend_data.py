# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import datetime
import os
import sys

from ansible_collections.community.crypto.plugins.module_utils.acme.backends import (
    CertificateInformation,
    CryptoBackend,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    BackendException,
)


def load_fixture(name):
    with open(os.path.join(os.path.dirname(__file__), 'fixtures', name)) as f:
        return f.read()


TEST_PEM_DERS = [
    (
        load_fixture('privatekey_1.pem'),
        base64.b64decode('MHcCAQEEIDWajU0PyhYKeulfy/luNtkAve7DkwQ01bXJ97zbxB66oAo'
                         'GCCqGSM49AwEHoUQDQgAEAJz0yAAXAwEmOhTRkjXxwgedbWO6gobYM3'
                         'lWszrS68G8QSzhXR6AmQ3IzZDimnTTXO7XhVylDT8SLzE44/Epmw==')
    )
]


TEST_KEYS = [
    (
        load_fixture('privatekey_1.pem'),
        {
            'alg': 'ES256',
            'hash': 'sha256',
            'jwk': {
                'crv': 'P-256',
                'kty': 'EC',
                'x': 'AJz0yAAXAwEmOhTRkjXxwgedbWO6gobYM3lWszrS68E',
                'y': 'vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs',
            },
            'point_size': 32,
            'type': 'ec',
        },
        load_fixture('privatekey_1.txt'),
    )
]


TEST_CSRS = [
    (
        load_fixture('csr_1.pem'),
        set([
            ('dns', 'ansible.com'),
            ('dns', 'example.com'),
            ('dns', 'example.org')
        ]),
        load_fixture('csr_1.txt'),
    ),
    (
        load_fixture('csr_2.pem'),
        set([
            ('dns', 'ansible.com'),
            ('ip', '127.0.0.1'),
            ('ip', '::1'),
            ('ip', '2001:d88:ac10:fe01::'),
            ('ip', '2001:1234:5678:abcd:9876:5432:10fe:dcba')
        ]),
        load_fixture('csr_2.txt'),
    ),
]


TEST_CERT = load_fixture("cert_1.pem")
TEST_CERT_2 = load_fixture("cert_2.pem")


TEST_CERT_OPENSSL_OUTPUT = load_fixture("cert_1.txt")  # OpenSSL 3.3.0 output
TEST_CERT_OPENSSL_OUTPUT_2 = load_fixture("cert_2.txt")  # OpenSSL 3.3.0 output
TEST_CERT_OPENSSL_OUTPUT_2B = load_fixture("cert_2-b.txt")  # OpenSSL 1.1.1f output


TEST_CERT_DAYS = [
    (datetime.datetime(2018, 11, 15, 1, 2, 3), 11),
    (datetime.datetime(2018, 11, 25, 15, 20, 0), 1),
    (datetime.datetime(2018, 11, 25, 15, 30, 0), 0),
]


TEST_CERT_INFO = CertificateInformation(
    not_valid_after=datetime.datetime(2018, 11, 26, 15, 28, 24),
    not_valid_before=datetime.datetime(2018, 11, 25, 15, 28, 23),
    serial_number=1,
    subject_key_identifier=b'\x98\xD2\xFD\x3C\xCC\xCD\x69\x45\xFB\xE2\x8C\x30\x2C\x54\x62\x18\x34\xB7\x07\x73',
    authority_key_identifier=None,
)


TEST_CERT_INFO_2 = CertificateInformation(
    not_valid_before=datetime.datetime(2024, 5, 4, 20, 42, 21),
    not_valid_after=datetime.datetime(2029, 5, 4, 20, 42, 20),
    serial_number=4218235397573492796,
    subject_key_identifier=b'\x17\xE5\x83\x22\x14\xEF\x74\xD3\xBE\x7E\x30\x76\x56\x1F\x51\x74\x65\x1F\xE9\xF0',
    authority_key_identifier=b'\x13\xC3\x4C\x3E\x59\x45\xDD\xE3\x63\x51\xA3\x46\x80\xC4\x08\xC7\x14\xC0\x64\x4E',
)


TEST_CERT_INFO = [
    (TEST_CERT, TEST_CERT_INFO, TEST_CERT_OPENSSL_OUTPUT),
    (TEST_CERT_2, TEST_CERT_INFO_2, TEST_CERT_OPENSSL_OUTPUT_2),
    (TEST_CERT_2, TEST_CERT_INFO_2, TEST_CERT_OPENSSL_OUTPUT_2B),
]


TEST_PARSE_ACME_TIMESTAMP = [
    (
        '2024-01-01T00:11:22Z',
        dict(year=2024, month=1, day=1, hour=0, minute=11, second=22),
    ),
    (
        '2024-01-01T00:11:22.123Z',
        dict(year=2024, month=1, day=1, hour=0, minute=11, second=22, microsecond=123000),
    ),
    (
        '2024-04-17T06:54:13.333333334Z',
        dict(year=2024, month=4, day=17, hour=6, minute=54, second=13, microsecond=333333),
    ),
]

if sys.version_info >= (3, 5):
    TEST_PARSE_ACME_TIMESTAMP.extend([
        (
            '2024-01-01T00:11:22+0100',
            dict(year=2023, month=12, day=31, hour=23, minute=11, second=22),
        ),
        (
            '2024-01-01T00:11:22.123+0100',
            dict(year=2023, month=12, day=31, hour=23, minute=11, second=22, microsecond=123000),
        ),
    ])


TEST_INTERPOLATE_TIMESTAMP = [
    (
        dict(year=2024, month=1, day=1, hour=0, minute=0, second=0),
        dict(year=2024, month=1, day=1, hour=1, minute=0, second=0),
        0.0,
        dict(year=2024, month=1, day=1, hour=0, minute=0, second=0),
    ),
    (
        dict(year=2024, month=1, day=1, hour=0, minute=0, second=0),
        dict(year=2024, month=1, day=1, hour=1, minute=0, second=0),
        0.5,
        dict(year=2024, month=1, day=1, hour=0, minute=30, second=0),
    ),
    (
        dict(year=2024, month=1, day=1, hour=0, minute=0, second=0),
        dict(year=2024, month=1, day=1, hour=1, minute=0, second=0),
        1.0,
        dict(year=2024, month=1, day=1, hour=1, minute=0, second=0),
    ),
]


class FakeBackend(CryptoBackend):
    def parse_key(self, key_file=None, key_content=None, passphrase=None):
        raise BackendException('Not implemented in fake backend')

    def sign(self, payload64, protected64, key_data):
        raise BackendException('Not implemented in fake backend')

    def create_mac_key(self, alg, key):
        raise BackendException('Not implemented in fake backend')

    def get_ordered_csr_identifiers(self, csr_filename=None, csr_content=None):
        raise BackendException('Not implemented in fake backend')

    def get_csr_identifiers(self, csr_filename=None, csr_content=None):
        raise BackendException('Not implemented in fake backend')

    def get_cert_days(self, cert_filename=None, cert_content=None, now=None):
        raise BackendException('Not implemented in fake backend')

    def create_chain_matcher(self, criterium):
        raise BackendException('Not implemented in fake backend')

    def get_cert_information(self, cert_filename=None, cert_content=None):
        raise BackendException('Not implemented in fake backend')
