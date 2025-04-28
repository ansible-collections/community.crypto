# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import abc
import datetime
import re
from collections import namedtuple

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native
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
        raise BackendException(
            "Cannot parse ISO 8601 timestamp {0!r}".format(timestamp_str)
        )
    timestamp, fractional, timezone = m.groups()
    if len(fractional) > 7:
        # Python does not support anything smaller than microseconds
        # (Golang supports nanoseconds, Boulder often emits more fractional digits, which Python chokes on)
        fractional = fractional[:7]
    return "%s%s%s" % (timestamp, fractional, timezone)


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
        # Note that %z will not work with Python 2... https://stackoverflow.com/a/27829491
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
    raise BackendException(
        "Cannot parse ISO 8601 timestamp {0!r}".format(timestamp_str)
    )


@six.add_metaclass(abc.ABCMeta)
class CryptoBackend(object):
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
                value, name, backend="cryptography", with_timezone=self._with_timezone
            )
        except OpenSSLObjectError as exc:
            raise BackendException(to_native(exc))

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

    def get_ordered_csr_identifiers(self, csr_filename=None, csr_content=None):
        """
        Return a list of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.

        The list is deduplicated, and if a CNAME is present, it will be returned
        as the first element in the result.
        """
        self.module.deprecate(
            "Every backend must override the get_ordered_csr_identifiers() method."
            " The default implementation will be removed in 3.0.0 and this method will be marked as `abstractmethod` by then.",
            version="3.0.0",
            collection_name="community.crypto",
        )
        return sorted(
            self.get_csr_identifiers(csr_filename=csr_filename, csr_content=csr_content)
        )

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

    def get_cert_information(self, cert_filename=None, cert_content=None):
        """
        Return some information on a X.509 certificate as a CertificateInformation object.
        """
        # Not implementing this method in a backend is DEPRECATED and will be
        # disallowed in community.crypto 3.0.0. This method will be marked as
        # @abstractmethod by then.
        raise BackendException("This backend does not support get_cert_information()")
