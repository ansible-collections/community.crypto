# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import datetime

import pytest
from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)
from ansible_collections.community.crypto.plugins.module_utils.time import (
    UTC,
    ensure_utc_timezone,
)
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import (
    MagicMock,
)
from freezegun import freeze_time

from .backend_data import (
    TEST_CERT,
    TEST_CERT_DAYS,
    TEST_CERT_INFO,
    TEST_CERT_OPENSSL_OUTPUT,
    TEST_CSRS,
    TEST_INTERPOLATE_TIMESTAMP,
    TEST_KEYS,
    TEST_PARSE_ACME_TIMESTAMP,
)


# from ..test_time import TIMEZONES


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
    fn = tmpdir / "test.key"
    fn.write(pem)
    module = MagicMock()
    module.run_command = MagicMock(return_value=(0, openssl_output, 0))
    backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
    key = backend.parse_key(key_file=str(fn))
    key.pop("key_file")
    assert key == result


@pytest.mark.parametrize("csr, result, openssl_output", TEST_CSRS)
def test_csridentifiers_openssl(csr, result, openssl_output, tmpdir):
    fn = tmpdir / "test.csr"
    fn.write(csr)
    module = MagicMock()
    module.run_command = MagicMock(return_value=(0, openssl_output, 0))
    backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
    identifiers = backend.get_csr_identifiers(str(fn))
    assert identifiers == result


@pytest.mark.parametrize("ip, result", TEST_IPS)
def test_normalize_ip(ip, result):
    module = MagicMock()
    backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
    assert backend._normalize_ip(ip) == result


@pytest.mark.parametrize("timezone, now, expected_days", TEST_CERT_DAYS)
def test_certdays_cryptography(timezone, now, expected_days, tmpdir):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        fn = tmpdir / "test-cert.pem"
        fn.write(TEST_CERT)
        module = MagicMock()
        module.run_command = MagicMock(return_value=(0, TEST_CERT_OPENSSL_OUTPUT, 0))
        backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
        days = backend.get_cert_days(cert_filename=str(fn), now=now)
        assert days == expected_days
        days = backend.get_cert_days(cert_content=TEST_CERT, now=now)
        assert days == expected_days


@pytest.mark.parametrize(
    "cert_content, expected_cert_info, openssl_output", TEST_CERT_INFO
)
def test_get_cert_information(cert_content, expected_cert_info, openssl_output, tmpdir):
    fn = tmpdir / "test-cert.pem"
    fn.write(cert_content)
    module = MagicMock()
    module.run_command = MagicMock(return_value=(0, openssl_output, 0))
    backend = OpenSSLCLIBackend(module, openssl_binary="openssl")

    expected_cert_info = expected_cert_info._replace(
        not_valid_after=ensure_utc_timezone(expected_cert_info.not_valid_after),
        not_valid_before=ensure_utc_timezone(expected_cert_info.not_valid_before),
    )

    cert_info = backend.get_cert_information(cert_filename=str(fn))
    assert cert_info == expected_cert_info
    cert_info = backend.get_cert_information(cert_content=cert_content)
    assert cert_info == expected_cert_info


# @pytest.mark.parametrize("timezone", TIMEZONES)
# Due to a bug in freezegun (https://github.com/spulec/freezegun/issues/348, https://github.com/spulec/freezegun/issues/553)
# this only works with timezone = UTC if CRYPTOGRAPHY_TIMEZONE is truish
@pytest.mark.parametrize("timezone", [datetime.timedelta(hours=0)])
def test_now(timezone):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        module = MagicMock()
        backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
        now = backend.get_now()
        assert now.tzinfo is not None
        assert now == datetime.datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC)


@pytest.mark.parametrize("timezone, input, expected", TEST_PARSE_ACME_TIMESTAMP)
def test_parse_acme_timestamp(timezone, input, expected):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        module = MagicMock()
        backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
        ts_expected = backend.get_utc_datetime(**expected)
        timestamp = backend.parse_acme_timestamp(input)
        assert ts_expected == timestamp


@pytest.mark.parametrize(
    "timezone, start, end, percentage, expected", TEST_INTERPOLATE_TIMESTAMP
)
def test_interpolate_timestamp(timezone, start, end, percentage, expected):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        module = MagicMock()
        backend = OpenSSLCLIBackend(module, openssl_binary="openssl")
        ts_start = backend.get_utc_datetime(**start)
        ts_end = backend.get_utc_datetime(**end)
        ts_expected = backend.get_utc_datetime(**expected)
        timestamp = backend.interpolate_timestamp(ts_start, ts_end, percentage)
        assert ts_expected == timestamp
