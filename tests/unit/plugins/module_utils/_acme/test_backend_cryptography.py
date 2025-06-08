# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import datetime
import pathlib
import typing as t
from unittest.mock import (
    MagicMock,
)

import pytest
from ansible_collections.community.crypto.plugins.module_utils._acme.backend_cryptography import (
    HAS_CURRENT_CRYPTOGRAPHY,
    CryptographyBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    UTC,
    ensure_utc_timezone,
)
from freezegun import freeze_time

from ..test__time import TIMEZONES
from .backend_data import (
    TEST_CERT,
    TEST_CERT_DAYS,
    TEST_CERT_INFO,
    TEST_CSRS,
    TEST_INTERPOLATE_TIMESTAMP,
    TEST_KEYS,
    TEST_PARSE_ACME_TIMESTAMP,
)


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (  # pragma: no cover
        CertificateInformation,
    )

    from .backend_data import DatetimeKwarg  # pragma: no cover


if not HAS_CURRENT_CRYPTOGRAPHY:
    pytest.skip("cryptography not found")


@pytest.mark.parametrize("pem, result, dummy", TEST_KEYS)
def test_eckeyparse_cryptography(
    pem: str, result: dict[str, t.Any], dummy: str, tmp_path: pathlib.Path
) -> None:
    fn = tmp_path / "test.pem"
    fn.write_text(pem)
    module = MagicMock()
    backend = CryptographyBackend(module=module)
    key = backend.parse_key(key_file=str(fn))
    key.pop("key_obj")
    assert key == result
    key = backend.parse_key(key_content=pem)
    key.pop("key_obj")
    assert key == result


@pytest.mark.parametrize("csr, result, openssl_output", TEST_CSRS)
def test_csridentifiers_cryptography(
    csr: str, result: set[tuple[str, str]], openssl_output: str, tmp_path: pathlib.Path
) -> None:
    fn = tmp_path / "test.csr"
    fn.write_text(csr)
    module = MagicMock()
    backend = CryptographyBackend(module=module)
    identifiers = backend.get_csr_identifiers(csr_filename=str(fn))
    assert identifiers == result
    identifiers = backend.get_csr_identifiers(csr_content=csr)
    assert identifiers == result


@pytest.mark.parametrize("timezone, now, expected_days", TEST_CERT_DAYS)
def test_certdays_cryptography(
    timezone: datetime.timedelta,
    now: datetime.datetime,
    expected_days: int,
    tmp_path: pathlib.Path,
) -> None:
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        fn = tmp_path / "test-cert.pem"
        fn.write_text(TEST_CERT)
        module = MagicMock()
        backend = CryptographyBackend(module=module)
        days = backend.get_cert_days(cert_filename=str(fn), now=now)
        assert days == expected_days
        days = backend.get_cert_days(cert_content=TEST_CERT, now=now)
        assert days == expected_days


@pytest.mark.parametrize(
    "cert_content, expected_cert_info, openssl_output", TEST_CERT_INFO
)
def test_get_cert_information(
    cert_content: str,
    expected_cert_info: CertificateInformation,
    openssl_output: str,
    tmp_path: pathlib.Path,
) -> None:
    fn = tmp_path / "test-cert.pem"
    fn.write_text(cert_content)
    module = MagicMock()
    backend = CryptographyBackend(module=module)

    if CRYPTOGRAPHY_TIMEZONE:
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
@pytest.mark.parametrize(
    "timezone", [datetime.timedelta(hours=0)] if CRYPTOGRAPHY_TIMEZONE else TIMEZONES
)
def test_now(timezone: datetime.timedelta) -> None:
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        module = MagicMock()
        backend = CryptographyBackend(module=module)
        now = backend.get_now()
        if CRYPTOGRAPHY_TIMEZONE:
            assert now.tzinfo is not None
            assert now == datetime.datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC)
        else:
            assert now.tzinfo is None
            assert now == datetime.datetime(2024, 2, 3, 4, 5, 6)


@pytest.mark.parametrize("timezone, timestamp_str, expected", TEST_PARSE_ACME_TIMESTAMP)
def test_parse_acme_timestamp(
    timezone: datetime.timedelta, timestamp_str: str, expected: DatetimeKwarg
) -> None:
    with freeze_time("2024-02-03 04:05:06 +00:00", tz_offset=timezone):
        module = MagicMock()
        backend = CryptographyBackend(module=module)
        ts_expected = backend.get_utc_datetime(**expected)
        timestamp = backend.parse_acme_timestamp(timestamp_str)
        assert ts_expected == timestamp


@pytest.mark.parametrize(
    "timezone, start, end, percentage, expected", TEST_INTERPOLATE_TIMESTAMP
)
def test_interpolate_timestamp(
    timezone: datetime.timedelta,
    start: DatetimeKwarg,
    end: DatetimeKwarg,
    percentage: float,
    expected: DatetimeKwarg,
) -> None:
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        module = MagicMock()
        backend = CryptographyBackend(module=module)
        ts_start = backend.get_utc_datetime(**start)
        ts_end = backend.get_utc_datetime(**end)
        ts_expected = backend.get_utc_datetime(**expected)
        timestamp = backend.interpolate_timestamp(
            ts_start, ts_end, percentage=percentage
        )
        assert ts_expected == timestamp
