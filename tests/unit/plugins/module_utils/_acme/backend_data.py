# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import datetime
import os
import typing as t

from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (
    CertificateInformation,
    CryptoBackend,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    BackendException,
)

from ..test__time import TIMEZONES, cartesian_product


if t.TYPE_CHECKING:
    from ansible_collections.community.crypto.plugins.module_utils._acme.backends import (  # pragma: no cover
        Criterium,
    )

    class DatetimeKwarg(t.TypedDict):  # pragma: no cover
        year: int
        month: int
        day: int
        hour: t.NotRequired[int]
        minute: t.NotRequired[int]
        second: t.NotRequired[int]
        microsecond: t.NotRequired[int]
        tzinfo: t.NotRequired[datetime.timezone | None]


def load_fixture(name: str) -> str:
    with open(
        os.path.join(os.path.dirname(__file__), "fixtures", name), encoding="utf-8"
    ) as f:
        return f.read()


TEST_PEM_DERS: list[tuple[str, bytes]] = [
    (
        load_fixture("privatekey_1.pem"),
        base64.b64decode(
            "MHcCAQEEIDWajU0PyhYKeulfy/luNtkAve7DkwQ01bXJ97zbxB66oAo"
            "GCCqGSM49AwEHoUQDQgAEAJz0yAAXAwEmOhTRkjXxwgedbWO6gobYM3"
            "lWszrS68G8QSzhXR6AmQ3IzZDimnTTXO7XhVylDT8SLzE44/Epmw=="
        ),
    )
]


TEST_KEYS: list[tuple[str, dict[str, t.Any], str]] = [
    (
        load_fixture("privatekey_1.pem"),
        {
            "alg": "ES256",
            "hash": "sha256",
            "jwk": {
                "crv": "P-256",
                "kty": "EC",
                "x": "AJz0yAAXAwEmOhTRkjXxwgedbWO6gobYM3lWszrS68E",
                "y": "vEEs4V0egJkNyM2Q4pp001zu14VcpQ0_Ei8xOOPxKZs",
            },
            "point_size": 32,
            "type": "ec",
        },
        load_fixture("privatekey_1.txt"),
    )
]


TEST_CSRS: list[tuple[str, set[tuple[str, str]], str]] = [
    (
        load_fixture("csr_1.pem"),
        set([("dns", "ansible.com"), ("dns", "example.com"), ("dns", "example.org")]),
        load_fixture("csr_1.txt"),
    ),
    (
        load_fixture("csr_2.pem"),
        set(
            [
                ("dns", "ansible.com"),
                ("ip", "127.0.0.1"),
                ("ip", "::1"),
                ("ip", "2001:d88:ac10:fe01::"),
                ("ip", "2001:1234:5678:abcd:9876:5432:10fe:dcba"),
            ]
        ),
        load_fixture("csr_2.txt"),
    ),
]


TEST_CERT = load_fixture("cert_1.pem")
TEST_CERT_2 = load_fixture("cert_2.pem")


TEST_CERT_OPENSSL_OUTPUT = load_fixture("cert_1.txt")  # OpenSSL 3.3.0 output
TEST_CERT_OPENSSL_OUTPUT_2 = load_fixture("cert_2.txt")  # OpenSSL 3.3.0 output
TEST_CERT_OPENSSL_OUTPUT_2B = load_fixture("cert_2-b.txt")  # OpenSSL 1.1.1f output


TEST_CERT_DAYS: list[tuple[datetime.timedelta, datetime.datetime, int]] = (
    cartesian_product(
        TIMEZONES,
        [
            (datetime.datetime(2018, 11, 15, 1, 2, 3), 11),
            (datetime.datetime(2018, 11, 25, 15, 20, 0), 1),
            (datetime.datetime(2018, 11, 25, 15, 30, 0), 0),
        ],
    )
)


TEST_CERT_INFO_1 = CertificateInformation(
    not_valid_after=datetime.datetime(2018, 11, 26, 15, 28, 24),
    not_valid_before=datetime.datetime(2018, 11, 25, 15, 28, 23),
    serial_number=1,
    subject_key_identifier=b"\x98\xd2\xfd\x3c\xcc\xcd\x69\x45\xfb\xe2\x8c\x30\x2c\x54\x62\x18\x34\xb7\x07\x73",
    authority_key_identifier=None,
)


TEST_CERT_INFO_2 = CertificateInformation(
    not_valid_before=datetime.datetime(2024, 5, 4, 20, 42, 21),
    not_valid_after=datetime.datetime(2029, 5, 4, 20, 42, 20),
    serial_number=4218235397573492796,
    subject_key_identifier=b"\x17\xe5\x83\x22\x14\xef\x74\xd3\xbe\x7e\x30\x76\x56\x1f\x51\x74\x65\x1f\xe9\xf0",
    authority_key_identifier=b"\x13\xc3\x4c\x3e\x59\x45\xdd\xe3\x63\x51\xa3\x46\x80\xc4\x08\xc7\x14\xc0\x64\x4e",
)


TEST_CERT_INFO: list[tuple[str, CertificateInformation, str]] = [
    (TEST_CERT, TEST_CERT_INFO_1, TEST_CERT_OPENSSL_OUTPUT),
    (TEST_CERT_2, TEST_CERT_INFO_2, TEST_CERT_OPENSSL_OUTPUT_2),
    (TEST_CERT_2, TEST_CERT_INFO_2, TEST_CERT_OPENSSL_OUTPUT_2B),
]


TEST_PARSE_ACME_TIMESTAMP: list[tuple[datetime.timedelta, str, DatetimeKwarg]] = (
    cartesian_product(
        TIMEZONES,
        [
            (
                "2024-01-01T00:11:22Z",
                {
                    "year": 2024,
                    "month": 1,
                    "day": 1,
                    "hour": 0,
                    "minute": 11,
                    "second": 22,
                },
            ),
            (
                "2024-01-01T00:11:22.123Z",
                {
                    "year": 2024,
                    "month": 1,
                    "day": 1,
                    "hour": 0,
                    "minute": 11,
                    "second": 22,
                    "microsecond": 123000,
                },
            ),
            (
                "2024-04-17T06:54:13.333333334Z",
                {
                    "year": 2024,
                    "month": 4,
                    "day": 17,
                    "hour": 6,
                    "minute": 54,
                    "second": 13,
                    "microsecond": 333333,
                },
            ),
            (
                "2024-01-01T00:11:22+0100",
                {
                    "year": 2023,
                    "month": 12,
                    "day": 31,
                    "hour": 23,
                    "minute": 11,
                    "second": 22,
                },
            ),
            (
                "2024-01-01T00:11:22.123+0100",
                {
                    "year": 2023,
                    "month": 12,
                    "day": 31,
                    "hour": 23,
                    "minute": 11,
                    "second": 22,
                    "microsecond": 123000,
                },
            ),
        ],
    )
)


TEST_INTERPOLATE_TIMESTAMP: list[
    tuple[datetime.timedelta, DatetimeKwarg, DatetimeKwarg, float, DatetimeKwarg]
] = cartesian_product(
    TIMEZONES,
    [
        (
            {"year": 2024, "month": 1, "day": 1, "hour": 0, "minute": 0, "second": 0},
            {"year": 2024, "month": 1, "day": 1, "hour": 1, "minute": 0, "second": 0},
            0.0,
            {"year": 2024, "month": 1, "day": 1, "hour": 0, "minute": 0, "second": 0},
        ),
        (
            {"year": 2024, "month": 1, "day": 1, "hour": 0, "minute": 0, "second": 0},
            {"year": 2024, "month": 1, "day": 1, "hour": 1, "minute": 0, "second": 0},
            0.5,
            {"year": 2024, "month": 1, "day": 1, "hour": 0, "minute": 30, "second": 0},
        ),
        (
            {"year": 2024, "month": 1, "day": 1, "hour": 0, "minute": 0, "second": 0},
            {"year": 2024, "month": 1, "day": 1, "hour": 1, "minute": 0, "second": 0},
            1.0,
            {"year": 2024, "month": 1, "day": 1, "hour": 1, "minute": 0, "second": 0},
        ),
    ],
)


class FakeBackend(CryptoBackend):
    def parse_key(
        self,
        *,
        key_file: str | os.PathLike | None = None,
        key_content: str | None = None,
        passphrase: str | None = None,
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def sign(
        self, *, payload64: str, protected64: str, key_data: dict[str, t.Any] | None
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def create_mac_key(self, *, alg: str, key: str) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def get_ordered_csr_identifiers(
        self,
        *,
        csr_filename: str | os.PathLike | None = None,
        csr_content: str | bytes | None = None,
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def get_csr_identifiers(
        self,
        *,
        csr_filename: str | os.PathLike | None = None,
        csr_content: str | bytes | None = None,
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def get_cert_days(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
        now: datetime.datetime | None = None,
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def create_chain_matcher(self, *, criterium: Criterium) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover

    def get_cert_information(
        self,
        *,
        cert_filename: str | os.PathLike | None = None,
        cert_content: str | bytes | None = None,
    ) -> t.NoReturn:
        raise BackendException("Not implemented in fake backend")  # pragma: no cover
