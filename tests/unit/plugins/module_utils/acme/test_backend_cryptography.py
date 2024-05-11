# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import pytest

from ansible_collections.community.crypto.tests.unit.compat.mock import MagicMock


from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import (
    HAS_CURRENT_CRYPTOGRAPHY,
    CryptographyBackend,
)

from .backend_data import (
    TEST_KEYS,
    TEST_CSRS,
    TEST_CERT,
    TEST_CERT_DAYS,
)


if not HAS_CURRENT_CRYPTOGRAPHY:
    pytest.skip('cryptography not found')


@pytest.mark.parametrize("pem, result, dummy", TEST_KEYS)
def test_eckeyparse_cryptography(pem, result, dummy, tmpdir):
    fn = tmpdir / 'test.pem'
    fn.write(pem)
    module = MagicMock()
    backend = CryptographyBackend(module)
    key = backend.parse_key(key_file=str(fn))
    key.pop('key_obj')
    assert key == result
    key = backend.parse_key(key_content=pem)
    key.pop('key_obj')
    assert key == result


@pytest.mark.parametrize("csr, result, openssl_output", TEST_CSRS)
def test_csridentifiers_cryptography(csr, result, openssl_output, tmpdir):
    fn = tmpdir / 'test.csr'
    fn.write(csr)
    module = MagicMock()
    backend = CryptographyBackend(module)
    identifiers = backend.get_csr_identifiers(csr_filename=str(fn))
    assert identifiers == result
    identifiers = backend.get_csr_identifiers(csr_content=csr)
    assert identifiers == result


@pytest.mark.parametrize("now, expected_days", TEST_CERT_DAYS)
def test_certdays_cryptography(now, expected_days, tmpdir):
    fn = tmpdir / 'test-cert.pem'
    fn.write(TEST_CERT)
    module = MagicMock()
    backend = CryptographyBackend(module)
    days = backend.get_cert_days(cert_filename=str(fn), now=now)
    assert days == expected_days
    days = backend.get_cert_days(cert_content=TEST_CERT, now=now)
    assert days == expected_days
