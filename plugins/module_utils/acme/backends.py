# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import abc
import datetime
import re
from collections import namedtuple

from ansible.module_utils import six
from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    BackendException,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.time import (
    UTC,
    ensure_utc_timezone,
    from_epoch_seconds,
    get_epoch_seconds,
    get_now_datetime,
    get_relative_time_option,
    remove_timezone,
)


CertificateInformation = namedtuple(
    "CertificateInformation",
    (
        "not_valid_after",
        "not_valid_before",
        "serial_number",
        "subject_key_identifier",
        "authority_key_identifier",
    ),
)


_FRACTIONAL_MATCHER = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(|\.\d+)(Z|[+-]\d{2}:?\d{2}.*)$"
)


def _reduce_fractional_digits(timestamp_str):
    """
    Given a RFC 3339 timestamp that includes too many digits for the fractional seconds part, reduces these to at most 6.
    """
    # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
    m = _FRACTIONAL_MATCHER.match(timestamp_str)
    if not m:
        raise BackendException(f"Cannot parse ISO 8601 timestamp {timestamp_str!r}")
    timestamp, fractional, timezone = m.groups()
    if len(fractional) > 7:
        # Python does not support anything smaller than microseconds
        # (Golang supports nanoseconds, Boulder often emits more fractional digits, which Python chokes on)
        fractional = fractional[:7]
    return f"{timestamp}{fractional}{timezone}"


def _parse_acme_timestamp(timestamp_str, with_timezone):
    """
    Parses a RFC 3339 timestamp.
    """
    # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
    timestamp_str = _reduce_fractional_digits(timestamp_str)
    for format in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ):
        try:
            result = datetime.datetime.strptime(timestamp_str, format)
        except ValueError:
            pass
        else:
            return (
                ensure_utc_timezone(result)
                if with_timezone
                else remove_timezone(result)
            )
    raise BackendException(f"Cannot parse ISO 8601 timestamp {timestamp_str!r}")


@six.add_metaclass(abc.ABCMeta)
class CryptoBackend:
    def __init__(self, module, with_timezone=False):
        self.module = module
        self._with_timezone = with_timezone

    def get_now(self):
        return get_now_datetime(with_timezone=self._with_timezone)

    def parse_acme_timestamp(self, timestamp_str):
        # RFC 3339 (https://www.rfc-editor.org/info/rfc3339)
        return _parse_acme_timestamp(timestamp_str, with_timezone=self._with_timezone)

    def parse_module_parameter(self, value, name):
        try:
            return get_relative_time_option(
                value, name, with_timezone=self._with_timezone
            )
        except OpenSSLObjectError as exc:
            raise BackendException(str(exc))

    def interpolate_timestamp(self, timestamp_start, timestamp_end, percentage):
        start = get_epoch_seconds(timestamp_start)
        end = get_epoch_seconds(timestamp_end)
        return from_epoch_seconds(
            start + percentage * (end - start), with_timezone=self._with_timezone
        )

    def get_utc_datetime(self, *args, **kwargs):
        kwargs_ext = dict(kwargs)
        if self._with_timezone and ("tzinfo" not in kwargs_ext and len(args) < 8):
            kwargs_ext["tzinfo"] = UTC
        result = datetime.datetime(*args, **kwargs_ext)
        if self._with_timezone and ("tzinfo" in kwargs or len(args) >= 8):
            result = ensure_utc_timezone(result)
        return result

    @abc.abstractmethod
    def parse_key(self, key_file=None, key_content=None, passphrase=None):
        """
        Parses an RSA or Elliptic Curve key file in PEM format and returns key_data.
        Raises KeyParsingError in case of errors.
        """

    @abc.abstractmethod
    def sign(self, payload64, protected64, key_data):
        pass

    @abc.abstractmethod
    def create_mac_key(self, alg, key):
        """Create a MAC key."""

    @abc.abstractmethod
    def get_ordered_csr_identifiers(self, csr_filename=None, csr_content=None):
        """
        Return a list of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.

        The list is deduplicated, and if a CNAME is present, it will be returned
        as the first element in the result.
        """

    @abc.abstractmethod
    def get_csr_identifiers(self, csr_filename=None, csr_content=None):
        """
        Return a set of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.
        """

    @abc.abstractmethod
    def get_cert_days(self, cert_filename=None, cert_content=None, now=None):
        """
        Return the days the certificate in cert_filename remains valid and -1
        if the file was not found. If cert_filename contains more than one
        certificate, only the first one will be considered.

        If now is not specified, datetime.datetime.now() is used.
        """

    @abc.abstractmethod
    def create_chain_matcher(self, criterium):
        """
        Given a Criterium object, creates a ChainMatcher object.
        """

    @abc.abstractmethod
    def get_cert_information(self, cert_filename=None, cert_content=None):
        """
        Return some information on a X.509 certificate as a CertificateInformation object.
        """
