from __future__ import absolute_import, division, print_function
__metaclass__ = type


import pytest

from mock import MagicMock


from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)

from .backend_data import (
    TEST_KEYS,
    TEST_CSRS,
)


TEST_IPS = [
    ("0:0:0:0:0:0:0:1", "::1"),
    ("1::0:2", "1::2"),
    ("0000:0001:0000:0000:0000:0000:0000:0001", "0:1::1"),
    ("0000:0001:0000:0000:0001:0000:0000:0001", "0:1::1:0:0:1"),
    ("0000:0001:0000:0001:0000:0001:0000:0001", "0:1:0:1:0:1:0:1"),
    ("0.0.0.0", "0.0.0.0"),
    ("2001:d88:ac10:fe01:0:0:0:0", "2001:d88:ac10:fe01::"),
    ("0000:0000:0000:0000:0000:0000:0000:0000", "::"),
]


@pytest.mark.parametrize("pem, result, openssl_output", TEST_KEYS)
def test_eckeyparse_openssl(pem, result, openssl_output, tmpdir):
    fn = tmpdir / 'test.key'
    fn.write(pem)
    module = MagicMock()
    module.run_command = MagicMock(return_value=(0, openssl_output, 0))
    backend = OpenSSLCLIBackend(module, openssl_binary='openssl')
    key = backend.parse_key(key_file=str(fn))
    key.pop('key_file')
    assert key == result


@pytest.mark.parametrize("csr, result, openssl_output", TEST_CSRS)
def test_csridentifiers_openssl(csr, result, openssl_output, tmpdir):
    fn = tmpdir / 'test.csr'
    fn.write(csr)
    module = MagicMock()
    module.run_command = MagicMock(return_value=(0, openssl_output, 0))
    backend = OpenSSLCLIBackend(module, openssl_binary='openssl')
    identifiers = backend.get_csr_identifiers(str(fn))
    assert identifiers == result


@pytest.mark.parametrize("ip, result", TEST_IPS)
def test_normalize_ip(ip, result):
    module = MagicMock()
    backend = OpenSSLCLIBackend(module, openssl_binary='openssl')
    assert backend._normalize_ip(ip) == result
