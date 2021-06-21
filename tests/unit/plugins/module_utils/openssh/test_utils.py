# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    parse_openssh_version,
    OpensshParser,
    _OpensshWriter
)

SSH_VERSION_STRING = "OpenSSH_7.9p1, OpenSSL 1.1.0i-fips  14 Aug 2018"
SSH_VERSION_NUMBER = "7.9"

VALID_BOOLEAN = [
    True,
    False
]
INVALID_BOOLEAN = [
    0x02
]
VALID_UINT32 = [
    0x00,
    0x01,
    0x01234567,
    0xFFFFFFFF,
]
INVALID_UINT32 = [
    0xFFFFFFFFF,
    -1,
]
VALID_UINT64 = [
    0x00,
    0x01,
    0x0123456789ABCDEF,
    0xFFFFFFFFFFFFFFFF,
]
INVALID_UINT64 = [
    0xFFFFFFFFFFFFFFFFF,
    -1,
]
VALID_STRING = [
    b'test string',
]
INVALID_STRING = [
    [],
]
# See https://datatracker.ietf.org/doc/html/rfc4251#section-5 for examples source
VALID_MPINT = [
    0x00,
    0x9a378f9b2e332a7,
    0x80,
    -0x1234,
    -0xdeadbeef,
    # Additional large int test
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
]
INVALID_MPINT = [
    [],
]


def test_parse_openssh_version():
    assert parse_openssh_version(SSH_VERSION_STRING) == SSH_VERSION_NUMBER


@pytest.mark.parametrize("boolean", VALID_BOOLEAN)
def test_valid_boolean(boolean):
    assert OpensshParser(_OpensshWriter().boolean(boolean).bytes()).boolean() == boolean


@pytest.mark.parametrize("boolean", INVALID_BOOLEAN)
def test_invalid_boolean(boolean):
    with pytest.raises(TypeError):
        _OpensshWriter().boolean(boolean)


@pytest.mark.parametrize("uint32", VALID_UINT32)
def test_valid_uint32(uint32):
    assert OpensshParser(_OpensshWriter().uint32(uint32).bytes()).uint32() == uint32


@pytest.mark.parametrize("uint32", INVALID_UINT32)
def test_invalid_uint32(uint32):
    with pytest.raises(ValueError):
        _OpensshWriter().uint32(uint32)


@pytest.mark.parametrize("uint64", VALID_UINT64)
def test_valid_uint64(uint64):
    assert OpensshParser(_OpensshWriter().uint64(uint64).bytes()).uint64() == uint64


@pytest.mark.parametrize("uint64", INVALID_UINT64)
def test_invalid_uint64(uint64):
    with pytest.raises(ValueError):
        _OpensshWriter().uint64(uint64)


@pytest.mark.parametrize("ssh_string", VALID_STRING)
def test_valid_string(ssh_string):
    assert OpensshParser(_OpensshWriter().string(ssh_string).bytes()).string() == ssh_string


@pytest.mark.parametrize("ssh_string", INVALID_STRING)
def test_invalid_string(ssh_string):
    with pytest.raises(TypeError):
        _OpensshWriter().string(ssh_string)


@pytest.mark.parametrize("mpint", VALID_MPINT)
def test_valid_mpint(mpint):
    assert OpensshParser(_OpensshWriter().mpint(mpint).bytes()).mpint() == mpint


@pytest.mark.parametrize("mpint", INVALID_MPINT)
def test_invalid_mpint(mpint):
    with pytest.raises(TypeError):
        _OpensshWriter().mpint(mpint)


def test_valid_seek():
    buffer = bytearray(b'buffer')
    parser = OpensshParser(buffer)
    parser.seek(len(buffer))
    assert parser.remaining_bytes() == 0
    parser.seek(-len(buffer))
    assert parser.remaining_bytes() == len(buffer)


def test_invalid_seek():
    result = False
    buffer = b'buffer'
    parser = OpensshParser(buffer)

    with pytest.raises(ValueError):
        parser.seek(len(buffer) + 1)

    with pytest.raises(ValueError):
        parser.seek(-1)


def test_writer_bytes():
    buffer = bytearray(b'buffer')
    assert _OpensshWriter(buffer).bytes() == buffer
