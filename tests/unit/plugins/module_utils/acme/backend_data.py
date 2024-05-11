# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import datetime
import os

from ansible_collections.community.crypto.plugins.module_utils.acme.backends import (
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


TEST_CERT_DAYS = [
    (datetime.datetime(2018, 11, 15, 1, 2, 3), 11),
    (datetime.datetime(2018, 11, 25, 15, 20, 0), 1),
    (datetime.datetime(2018, 11, 25, 15, 30, 0), 0),
]


class FakeBackend(CryptoBackend):
    def parse_key(self, key_file=None, key_content=None, passphrase=None):
        raise BackendException('Not implemented in fake backend')

    def sign(self, payload64, protected64, key_data):
        raise BackendException('Not implemented in fake backend')

    def create_mac_key(self, alg, key):
        raise BackendException('Not implemented in fake backend')

    def get_csr_identifiers(self, csr_filename=None, csr_content=None):
        raise BackendException('Not implemented in fake backend')

    def get_cert_days(self, cert_filename=None, cert_content=None, now=None):
        raise BackendException('Not implemented in fake backend')

    def create_chain_matcher(self, criterium):
        raise BackendException('Not implemented in fake backend')
