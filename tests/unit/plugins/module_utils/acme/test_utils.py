from __future__ import absolute_import, division, print_function
__metaclass__ = type


import pytest


from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
    pem_to_der,
)

from .backend_data import (
    TEST_PEM_DERS,
)


NOPAD_B64 = [
    ("", ""),
    ("\n", "Cg"),
    ("123", "MTIz"),
    ("Lorem?ipsum", "TG9yZW0_aXBzdW0"),
]


@pytest.mark.parametrize("value, result", NOPAD_B64)
def test_nopad_b64(value, result):
    assert nopad_b64(value.encode('utf-8')) == result


@pytest.mark.parametrize("pem, der", TEST_PEM_DERS)
def test_pem_to_der(pem, der, tmpdir):
    fn = tmpdir / 'test.pem'
    fn.write(pem)
    assert pem_to_der(str(fn)) == der
