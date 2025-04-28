# -*- coding: utf-8 -*-
#
# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import datetime
import re
import sys

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)


try:
    UTC = datetime.timezone.utc
except AttributeError:
    _DURATION_ZERO = datetime.timedelta(0)

    class _UTCClass(datetime.tzinfo):
        def utcoffset(self, dt):
            return _DURATION_ZERO

        def dst(self, dt):
            return _DURATION_ZERO

        def tzname(self, dt):
            return "UTC"

        def fromutc(self, dt):
            return dt

        def __repr__(self):
            return "UTC"

    UTC = _UTCClass()


def get_now_datetime(with_timezone):
    if with_timezone:
        return datetime.datetime.now(tz=UTC)
    return datetime.datetime.utcnow()


def ensure_utc_timezone(timestamp):
    if timestamp.tzinfo is UTC:
        return timestamp
    if timestamp.tzinfo is None:
        # We assume that naive datetime objects use timezone UTC!
        return timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def remove_timezone(timestamp):
    # Convert to native datetime object
    if timestamp.tzinfo is None:
        return timestamp
    if timestamp.tzinfo is not UTC:
        timestamp = timestamp.astimezone(UTC)
    return timestamp.replace(tzinfo=None)


def add_or_remove_timezone(timestamp, with_timezone):
    return (
        ensure_utc_timezone(timestamp) if with_timezone else remove_timezone(timestamp)
    )


if sys.version_info < (3, 3):

    def get_epoch_seconds(timestamp):
        epoch = datetime.datetime(
            1970, 1, 1, tzinfo=UTC if timestamp.tzinfo is not None else None
        )
        delta = timestamp - epoch
        try:
            return delta.total_seconds()
        except AttributeError:
            # Python 2.6 and earlier: total_seconds() does not yet exist, so we use the formula from
            # https://docs.python.org/2/library/datetime.html#datetime.timedelta.total_seconds
            return (
                delta.microseconds + (delta.seconds + delta.days * 24 * 3600) * 10**6
            ) / 10**6

else:

    def get_epoch_seconds(timestamp):
        if timestamp.tzinfo is None:
            # timestamp.timestamp() is offset by the local timezone if timestamp has no timezone
            timestamp = ensure_utc_timezone(timestamp)
        return timestamp.timestamp()


def from_epoch_seconds(timestamp, with_timezone):
    if with_timezone:
        return datetime.datetime.fromtimestamp(timestamp, UTC)
    return datetime.datetime.utcfromtimestamp(timestamp)


def convert_relative_to_datetime(relative_time_string, with_timezone=False, now=None):
    """Get a datetime.datetime or None from a string in the time format described in sshd_config(5)"""

    parsed_result = re.match(
        r"^(?P<prefix>[+-])((?P<weeks>\d+)[wW])?((?P<days>\d+)[dD])?((?P<hours>\d+)[hH])?((?P<minutes>\d+)[mM])?((?P<seconds>\d+)[sS]?)?$",
        relative_time_string,
    )

    if parsed_result is None or len(relative_time_string) == 1:
        # not matched or only a single "+" or "-"
        return None

    offset = datetime.timedelta(0)
    if parsed_result.group("weeks") is not None:
        offset += datetime.timedelta(weeks=int(parsed_result.group("weeks")))
    if parsed_result.group("days") is not None:
        offset += datetime.timedelta(days=int(parsed_result.group("days")))
    if parsed_result.group("hours") is not None:
        offset += datetime.timedelta(hours=int(parsed_result.group("hours")))
    if parsed_result.group("minutes") is not None:
        offset += datetime.timedelta(minutes=int(parsed_result.group("minutes")))
    if parsed_result.group("seconds") is not None:
        offset += datetime.timedelta(seconds=int(parsed_result.group("seconds")))

    if now is None:
        now = get_now_datetime(with_timezone=with_timezone)
    else:
        now = add_or_remove_timezone(now, with_timezone=with_timezone)

    if parsed_result.group("prefix") == "+":
        return now + offset
    else:
        return now - offset


def get_relative_time_option(
    input_string, input_name, backend="cryptography", with_timezone=False, now=None
):
    """Return an absolute timespec if a relative timespec or an ASN1 formatted
    string is provided.

    The return value will be a datetime object for the cryptography backend,
    and a ASN1 formatted string for the pyopenssl backend."""
    result = to_native(input_string)
    if result is None:
        raise OpenSSLObjectError(
            'The timespec "%s" for %s is not valid' % input_string, input_name
        )
    # Relative time
    if result.startswith("+") or result.startswith("-"):
        result_datetime = convert_relative_to_datetime(
            result, with_timezone=with_timezone, now=now
        )
        if backend == "pyopenssl":
            return result_datetime.strftime("%Y%m%d%H%M%SZ")
        elif backend == "cryptography":
            return result_datetime
    # Absolute time
    if backend == "pyopenssl":
        return input_string
    elif backend == "cryptography":
        for date_fmt, length in [
            (
                "%Y%m%d%H%M%SZ",
                15,
            ),  # this also parses '202401020304Z', but as datetime(2024, 1, 2, 3, 0, 4)
            ("%Y%m%d%H%MZ", 13),
            (
                "%Y%m%d%H%M%S%z",
                14 + 5,
            ),  # this also parses '202401020304+0000', but as datetime(2024, 1, 2, 3, 0, 4, tzinfo=...)
            ("%Y%m%d%H%M%z", 12 + 5),
        ]:
            if len(result) != length:
                continue
            try:
                res = datetime.datetime.strptime(result, date_fmt)
            except ValueError:
                pass
            else:
                return add_or_remove_timezone(res, with_timezone=with_timezone)

        raise OpenSSLObjectError(
            'The time spec "%s" for %s is invalid' % (input_string, input_name)
        )
