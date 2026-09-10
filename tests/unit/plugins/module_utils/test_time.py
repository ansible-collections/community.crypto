# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import datetime
import sys

import pytest
from ansible.module_utils.common.collections import is_sequence
from ansible_collections.community.crypto.plugins.module_utils.time import (
    UTC,
    add_or_remove_timezone,
    convert_relative_to_datetime,
    ensure_utc_timezone,
    from_epoch_seconds,
    get_epoch_seconds,
    get_now_datetime,
    get_relative_time_option,
    remove_timezone,
)
from freezegun import freeze_time


TIMEZONES = [
    datetime.timedelta(hours=0),
    datetime.timedelta(hours=1),
    datetime.timedelta(hours=2),
    datetime.timedelta(hours=-6),
]


def cartesian_product(list1, list2):
    result = []
    for item1 in list1:
        if not is_sequence(item1):
            item1 = (item1,)
        elif not isinstance(item1, tuple):
            item1 = tuple(item1)
        for item2 in list2:
            if not is_sequence(item2):
                item2 = (item2,)
            elif not isinstance(item2, tuple):
                item2 = tuple(item2)
            result.append(item1 + item2)
    return result


TEST_REMOVE_TIMEZONE = cartesian_product(
    TIMEZONES,
    [
        (
            datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=UTC),
            datetime.datetime(2024, 1, 1, 0, 1, 2),
        ),
        (
            datetime.datetime(2024, 1, 1, 0, 1, 2),
            datetime.datetime(2024, 1, 1, 0, 1, 2),
        ),
    ],
)

TEST_UTC_TIMEZONE = cartesian_product(
    TIMEZONES,
    [
        (
            datetime.datetime(2024, 1, 1, 0, 1, 2),
            datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=UTC),
        ),
        (
            datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=UTC),
            datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=UTC),
        ),
    ],
)

TEST_EPOCH_SECONDS = cartesian_product(
    TIMEZONES,
    [
        (0, dict(year=1970, day=1, month=1, hour=0, minute=0, second=0, microsecond=0)),
        (
            1e-6,
            dict(year=1970, day=1, month=1, hour=0, minute=0, second=0, microsecond=1),
        ),
        (
            1e-3,
            dict(
                year=1970, day=1, month=1, hour=0, minute=0, second=0, microsecond=1000
            ),
        ),
        (
            3691.2,
            dict(
                year=1970,
                day=1,
                month=1,
                hour=1,
                minute=1,
                second=31,
                microsecond=200000,
            ),
        ),
    ],
)

TEST_EPOCH_TO_SECONDS = cartesian_product(
    TIMEZONES,
    [
        (datetime.datetime(1970, 1, 1, 0, 1, 2, 0), 62),
        (datetime.datetime(1970, 1, 1, 0, 1, 2, 0, tzinfo=UTC), 62),
    ],
)

TEST_CONVERT_RELATIVE_TO_DATETIME = cartesian_product(
    TIMEZONES,
    [
        (
            "+0",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 1, 0, 0, 0),
        ),
        (
            "+1s",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            datetime.datetime(2024, 1, 1, 0, 0, 1),
        ),
        (
            "-10w20d30h40m50s",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            datetime.datetime(2023, 10, 1, 17, 19, 10),
        ),
        (
            "+0",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
        ),
        (
            "+1s",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            datetime.datetime(2024, 1, 1, 0, 0, 1, tzinfo=UTC),
        ),
        (
            "-10w20d30h40m50s",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2023, 10, 1, 17, 19, 10, tzinfo=UTC),
        ),
    ],
)

TEST_GET_RELATIVE_TIME_OPTION = cartesian_product(
    TIMEZONES,
    [
        (
            "+1d2h3m4s",
            "foo",
            "cryptography",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 2, 3, 4),
        ),
        (
            "-1w10d24h",
            "foo",
            "cryptography",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2023, 12, 14, 0, 0, 0),
        ),
        (
            "20240102040506Z",
            "foo",
            "cryptography",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 4, 5, 6),
        ),
        (
            "202401020405Z",
            "foo",
            "cryptography",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 4, 5, 0),
        ),
        (
            "+1d2h3m4s",
            "foo",
            "cryptography",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 2, 3, 4, tzinfo=UTC),
        ),
        (
            "-1w10d24h",
            "foo",
            "cryptography",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2023, 12, 14, 0, 0, 0, tzinfo=UTC),
        ),
        (
            "20240102040506Z",
            "foo",
            "cryptography",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 4, 5, 6, tzinfo=UTC),
        ),
        (
            "202401020405Z",
            "foo",
            "cryptography",
            True,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            datetime.datetime(2024, 1, 2, 4, 5, 0, tzinfo=UTC),
        ),
        (
            "+1d2h3m4s",
            "foo",
            "pyopenssl",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            "20240102020304Z",
        ),
        (
            "-1w10d24h",
            "foo",
            "pyopenssl",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            "20231214000000Z",
        ),
        (
            "20240102040506Z",
            "foo",
            "pyopenssl",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            "20240102040506Z",
        ),
        (
            "202401020405Z",
            "foo",
            "pyopenssl",
            False,
            datetime.datetime(2024, 1, 1, 0, 0, 0),
            "202401020405Z",
        ),
    ],
)


if sys.version_info >= (3, 5):
    ONE_HOUR_PLUS = datetime.timezone(datetime.timedelta(hours=1))

    TEST_REMOVE_TIMEZONE.extend(
        cartesian_product(
            TIMEZONES,
            [
                (
                    datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=ONE_HOUR_PLUS),
                    datetime.datetime(2023, 12, 31, 23, 1, 2),
                ),
            ],
        )
    )
    TEST_UTC_TIMEZONE.extend(
        cartesian_product(
            TIMEZONES,
            [
                (
                    datetime.datetime(2024, 1, 1, 0, 1, 2, tzinfo=ONE_HOUR_PLUS),
                    datetime.datetime(2023, 12, 31, 23, 1, 2, tzinfo=UTC),
                ),
            ],
        )
    )
    TEST_EPOCH_TO_SECONDS.extend(
        cartesian_product(
            TIMEZONES,
            [
                (
                    datetime.datetime(1970, 1, 1, 0, 1, 2, 0, tzinfo=ONE_HOUR_PLUS),
                    62 - 3600,
                ),
            ],
        )
    )
    TEST_GET_RELATIVE_TIME_OPTION.extend(
        cartesian_product(
            TIMEZONES,
            [
                (
                    "20240102040506+0100",
                    "foo",
                    "cryptography",
                    False,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    datetime.datetime(2024, 1, 2, 3, 5, 6),
                ),
                (
                    "202401020405+0100",
                    "foo",
                    "cryptography",
                    False,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    datetime.datetime(2024, 1, 2, 3, 5, 0),
                ),
                (
                    "20240102040506+0100",
                    "foo",
                    "cryptography",
                    True,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    datetime.datetime(2024, 1, 2, 3, 5, 6, tzinfo=UTC),
                ),
                (
                    "202401020405+0100",
                    "foo",
                    "cryptography",
                    True,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    datetime.datetime(2024, 1, 2, 3, 5, 0, tzinfo=UTC),
                ),
                (
                    "20240102040506+0100",
                    "foo",
                    "pyopenssl",
                    False,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    "20240102040506+0100",
                ),
                (
                    "202401020405+0100",
                    "foo",
                    "pyopenssl",
                    False,
                    datetime.datetime(2024, 1, 1, 0, 0, 0),
                    "202401020405+0100",
                ),
            ],
        )
    )


@pytest.mark.parametrize("timezone, input, expected", TEST_REMOVE_TIMEZONE)
def test_remove_timezone(timezone, input, expected):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output_1 = remove_timezone(input)
        assert expected == output_1
        output_2 = add_or_remove_timezone(input, with_timezone=False)
        assert expected == output_2


@pytest.mark.parametrize("timezone, input, expected", TEST_UTC_TIMEZONE)
def test_utc_timezone(timezone, input, expected):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output_1 = ensure_utc_timezone(input)
        assert expected == output_1
        output_2 = add_or_remove_timezone(input, with_timezone=True)
        assert expected == output_2


# @pytest.mark.parametrize("timezone", TIMEZONES)
# Due to a bug in freezegun (https://github.com/spulec/freezegun/issues/348, https://github.com/spulec/freezegun/issues/553)
# this only works with timezone = UTC
@pytest.mark.parametrize("timezone", [datetime.timedelta(hours=0)])
def test_get_now_datetime_w_timezone(timezone):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output_2 = get_now_datetime(with_timezone=True)
        assert output_2.tzinfo is not None
        assert output_2.tzinfo == UTC
        assert output_2 == datetime.datetime(2024, 2, 3, 4, 5, 6, tzinfo=UTC)


@pytest.mark.parametrize("timezone", TIMEZONES)
def test_get_now_datetime_wo_timezone(timezone):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output_1 = get_now_datetime(with_timezone=False)
        assert output_1.tzinfo is None
        assert output_1 == datetime.datetime(2024, 2, 3, 4, 5, 6)


@pytest.mark.parametrize("timezone, seconds, timestamp", TEST_EPOCH_SECONDS)
def test_epoch_seconds(timezone, seconds, timestamp):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        ts_wo_tz = datetime.datetime(**timestamp)
        assert seconds == get_epoch_seconds(ts_wo_tz)
        timestamp_w_tz = dict(timestamp)
        timestamp_w_tz["tzinfo"] = UTC
        ts_w_tz = datetime.datetime(**timestamp_w_tz)
        assert seconds == get_epoch_seconds(ts_w_tz)
        output_1 = from_epoch_seconds(seconds, with_timezone=False)
        assert ts_wo_tz == output_1
        output_2 = from_epoch_seconds(seconds, with_timezone=True)
        assert ts_w_tz == output_2


@pytest.mark.parametrize("timezone, timestamp, expected_seconds", TEST_EPOCH_TO_SECONDS)
def test_epoch_to_seconds(timezone, timestamp, expected_seconds):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        assert expected_seconds == get_epoch_seconds(timestamp)


@pytest.mark.parametrize(
    "timezone, relative_time_string, with_timezone, now, expected",
    TEST_CONVERT_RELATIVE_TO_DATETIME,
)
def test_convert_relative_to_datetime(
    timezone, relative_time_string, with_timezone, now, expected
):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output = convert_relative_to_datetime(
            relative_time_string, with_timezone=with_timezone, now=now
        )
        assert expected == output


@pytest.mark.parametrize(
    "timezone, input_string, input_name, backend, with_timezone, now, expected",
    TEST_GET_RELATIVE_TIME_OPTION,
)
def test_get_relative_time_option(
    timezone, input_string, input_name, backend, with_timezone, now, expected
):
    with freeze_time("2024-02-03 04:05:06", tz_offset=timezone):
        output = get_relative_time_option(
            input_string,
            input_name,
            backend=backend,
            with_timezone=with_timezone,
            now=now,
        )
        assert expected == output
