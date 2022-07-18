# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

# Protocol References
# -------------------
# https://datatracker.ietf.org/doc/html/rfc4251
# https://datatracker.ietf.org/doc/html/rfc4253
# https://datatracker.ietf.org/doc/html/rfc5656
# https://datatracker.ietf.org/doc/html/rfc8032
# https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
#
# Inspired by:
# ------------
# https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py
# https://github.com/paramiko/paramiko/blob/master/paramiko/message.py

import abc
import binascii
import os
from base64 import b64encode
from datetime import datetime
from hashlib import sha256

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import convert_relative_to_datetime
from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    OpensshParser,
    _OpensshWriter,
)

# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
_USER_TYPE = 1
_HOST_TYPE = 2

_SSH_TYPE_STRINGS = {
    'rsa': b"ssh-rsa",
    'dsa': b"ssh-dss",
    'ecdsa-nistp256': b"ecdsa-sha2-nistp256",
    'ecdsa-nistp384': b"ecdsa-sha2-nistp384",
    'ecdsa-nistp521': b"ecdsa-sha2-nistp521",
    'ed25519': b"ssh-ed25519",
}
_CERT_SUFFIX_V01 = b"-cert-v01@openssh.com"

# See https://datatracker.ietf.org/doc/html/rfc5656#section-6.1
_ECDSA_CURVE_IDENTIFIERS = {
    'ecdsa-nistp256': b'nistp256',
    'ecdsa-nistp384': b'nistp384',
    'ecdsa-nistp521': b'nistp521',
}
_ECDSA_CURVE_IDENTIFIERS_LOOKUP = {
    b'nistp256': 'ecdsa-nistp256',
    b'nistp384': 'ecdsa-nistp384',
    b'nistp521': 'ecdsa-nistp521',
}

_ALWAYS = datetime(1970, 1, 1)
_FOREVER = datetime.max

_CRITICAL_OPTIONS = (
    'force-command',
    'source-address',
    'verify-required',
)

_DIRECTIVES = (
    'clear',
    'no-x11-forwarding',
    'no-agent-forwarding',
    'no-port-forwarding',
    'no-pty',
    'no-user-rc',
)

_EXTENSIONS = (
    'permit-x11-forwarding',
    'permit-agent-forwarding',
    'permit-port-forwarding',
    'permit-pty',
    'permit-user-rc'
)

if six.PY3:
    long = int


class OpensshCertificateTimeParameters(object):
    def __init__(self, valid_from, valid_to):
        self._valid_from = self.to_datetime(valid_from)
        self._valid_to = self.to_datetime(valid_to)

        if self._valid_from > self._valid_to:
            raise ValueError("Valid from: %s must not be greater than Valid to: %s" % (valid_from, valid_to))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        else:
            return self._valid_from == other._valid_from and self._valid_to == other._valid_to

    def __ne__(self, other):
        return not self == other

    @property
    def validity_string(self):
        if not (self._valid_from == _ALWAYS and self._valid_to == _FOREVER):
            return "%s:%s" % (
                self.valid_from(date_format='openssh'), self.valid_to(date_format='openssh')
            )
        return ""

    def valid_from(self, date_format):
        return self.format_datetime(self._valid_from, date_format)

    def valid_to(self, date_format):
        return self.format_datetime(self._valid_to, date_format)

    def within_range(self, valid_at):
        if valid_at is not None:
            valid_at_datetime = self.to_datetime(valid_at)
            return self._valid_from <= valid_at_datetime <= self._valid_to
        return True

    @staticmethod
    def format_datetime(dt, date_format):
        if date_format in ('human_readable', 'openssh'):
            if dt == _ALWAYS:
                result = 'always'
            elif dt == _FOREVER:
                result = 'forever'
            else:
                result = dt.isoformat() if date_format == 'human_readable' else dt.strftime("%Y%m%d%H%M%S")
        elif date_format == 'timestamp':
            td = dt - _ALWAYS
            result = int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6)
        else:
            raise ValueError("%s is not a valid format" % date_format)
        return result

    @staticmethod
    def to_datetime(time_string_or_timestamp):
        try:
            if isinstance(time_string_or_timestamp, six.string_types):
                result = OpensshCertificateTimeParameters._time_string_to_datetime(time_string_or_timestamp.strip())
            elif isinstance(time_string_or_timestamp, (long, int)):
                result = OpensshCertificateTimeParameters._timestamp_to_datetime(time_string_or_timestamp)
            else:
                raise ValueError(
                    "Value must be of type (str, unicode, int, long) not %s" % type(time_string_or_timestamp)
                )
        except ValueError:
            raise
        return result

    @staticmethod
    def _timestamp_to_datetime(timestamp):
        if timestamp == 0x0:
            result = _ALWAYS
        elif timestamp == 0xFFFFFFFFFFFFFFFF:
            result = _FOREVER
        else:
            try:
                result = datetime.utcfromtimestamp(timestamp)
            except OverflowError as e:
                raise ValueError
        return result

    @staticmethod
    def _time_string_to_datetime(time_string):
        result = None
        if time_string == 'always':
            result = _ALWAYS
        elif time_string == 'forever':
            result = _FOREVER
        elif is_relative_time_string(time_string):
            result = convert_relative_to_datetime(time_string)
        else:
            for time_format in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                try:
                    result = datetime.strptime(time_string, time_format)
                except ValueError:
                    pass
            if result is None:
                raise ValueError
        return result


class OpensshCertificateOption(object):
    def __init__(self, option_type, name, data):
        if option_type not in ('critical', 'extension'):
            raise ValueError("type must be either 'critical' or 'extension'")

        if not isinstance(name, six.string_types):
            raise TypeError("name must be a string not %s" % type(name))

        if not isinstance(data, six.string_types):
            raise TypeError("data must be a string not %s" % type(data))

        self._option_type = option_type
        self._name = name.lower()
        self._data = data

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented

        return all([
            self._option_type == other._option_type,
            self._name == other._name,
            self._data == other._data,
        ])

    def __hash__(self):
        return hash((self._option_type, self._name, self._data))

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self._data:
            return "%s=%s" % (self._name, self._data)
        return self._name

    @property
    def data(self):
        return self._data

    @property
    def name(self):
        return self._name

    @property
    def type(self):
        return self._option_type

    @classmethod
    def from_string(cls, option_string):
        if not isinstance(option_string, six.string_types):
            raise ValueError("option_string must be a string not %s" % type(option_string))
        option_type = None

        if ':' in option_string:
            option_type, value = option_string.strip().split(':', 1)
            if '=' in value:
                name, data = value.split('=', 1)
            else:
                name, data = value, ''
        elif '=' in option_string:
            name, data = option_string.strip().split('=', 1)
        else:
            name, data = option_string.strip(), ''

        return cls(
            option_type=option_type or get_option_type(name.lower()),
            name=name,
            data=data
        )


@six.add_metaclass(abc.ABCMeta)
class OpensshCertificateInfo:
    """Encapsulates all certificate information which is signed by a CA key"""
    def __init__(self,
                 nonce=None,
                 serial=None,
                 cert_type=None,
                 key_id=None,
                 principals=None,
                 valid_after=None,
                 valid_before=None,
                 critical_options=None,
                 extensions=None,
                 reserved=None,
                 signing_key=None):
        self.nonce = nonce
        self.serial = serial
        self._cert_type = cert_type
        self.key_id = key_id
        self.principals = principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical_options = critical_options
        self.extensions = extensions
        self.reserved = reserved
        self.signing_key = signing_key

        self.type_string = None

    @property
    def cert_type(self):
        if self._cert_type == _USER_TYPE:
            return 'user'
        elif self._cert_type == _HOST_TYPE:
            return 'host'
        else:
            return ''

    @cert_type.setter
    def cert_type(self, cert_type):
        if cert_type == 'user' or cert_type == _USER_TYPE:
            self._cert_type = _USER_TYPE
        elif cert_type == 'host' or cert_type == _HOST_TYPE:
            self._cert_type = _HOST_TYPE
        else:
            raise ValueError("%s is not a valid certificate type" % cert_type)

    def signing_key_fingerprint(self):
        return fingerprint(self.signing_key)

    @abc.abstractmethod
    def public_key_fingerprint(self):
        pass

    @abc.abstractmethod
    def parse_public_numbers(self, parser):
        pass


class OpensshRSACertificateInfo(OpensshCertificateInfo):
    def __init__(self, e=None, n=None, **kwargs):
        super(OpensshRSACertificateInfo, self).__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS['rsa'] + _CERT_SUFFIX_V01
        self.e = e
        self.n = n

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self):
        if any([self.e is None, self.n is None]):
            return b''

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS['rsa'])
        writer.mpint(self.e)
        writer.mpint(self.n)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser):
        self.e = parser.mpint()
        self.n = parser.mpint()


class OpensshDSACertificateInfo(OpensshCertificateInfo):
    def __init__(self, p=None, q=None, g=None, y=None, **kwargs):
        super(OpensshDSACertificateInfo, self).__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS['dsa'] + _CERT_SUFFIX_V01
        self.p = p
        self.q = q
        self.g = g
        self.y = y

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self):
        if any([self.p is None, self.q is None, self.g is None, self.y is None]):
            return b''

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS['dsa'])
        writer.mpint(self.p)
        writer.mpint(self.q)
        writer.mpint(self.g)
        writer.mpint(self.y)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser):
        self.p = parser.mpint()
        self.q = parser.mpint()
        self.g = parser.mpint()
        self.y = parser.mpint()


class OpensshECDSACertificateInfo(OpensshCertificateInfo):
    def __init__(self, curve=None, public_key=None, **kwargs):
        super(OpensshECDSACertificateInfo, self).__init__(**kwargs)
        self._curve = None
        if curve is not None:
            self.curve = curve

        self.public_key = public_key

    @property
    def curve(self):
        return self._curve

    @curve.setter
    def curve(self, curve):
        if curve in _ECDSA_CURVE_IDENTIFIERS.values():
            self._curve = curve
            self.type_string = _SSH_TYPE_STRINGS[_ECDSA_CURVE_IDENTIFIERS_LOOKUP[curve]] + _CERT_SUFFIX_V01
        else:
            raise ValueError(
                "Curve must be one of %s" % (b','.join(list(_ECDSA_CURVE_IDENTIFIERS.values()))).decode('UTF-8')
            )

    # See https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
    def public_key_fingerprint(self):
        if any([self.curve is None, self.public_key is None]):
            return b''

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS[_ECDSA_CURVE_IDENTIFIERS_LOOKUP[self.curve]])
        writer.string(self.curve)
        writer.string(self.public_key)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser):
        self.curve = parser.string()
        self.public_key = parser.string()


class OpensshED25519CertificateInfo(OpensshCertificateInfo):
    def __init__(self, pk=None, **kwargs):
        super(OpensshED25519CertificateInfo, self).__init__(**kwargs)
        self.type_string = _SSH_TYPE_STRINGS['ed25519'] + _CERT_SUFFIX_V01
        self.pk = pk

    def public_key_fingerprint(self):
        if self.pk is None:
            return b''

        writer = _OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS['ed25519'])
        writer.string(self.pk)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser):
        self.pk = parser.string()


# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
class OpensshCertificate(object):
    """Encapsulates a formatted OpenSSH certificate including signature and signing key"""
    def __init__(self, cert_info, signature):

        self._cert_info = cert_info
        self.signature = signature

    @classmethod
    def load(cls, path):
        if not os.path.exists(path):
            raise ValueError("%s is not a valid path." % path)

        try:
            with open(path, 'rb') as cert_file:
                data = cert_file.read()
        except (IOError, OSError) as e:
            raise ValueError("%s cannot be opened for reading: %s" % (path, e))

        try:
            format_identifier, b64_cert = data.split(b' ')[:2]
            cert = binascii.a2b_base64(b64_cert)
        except (binascii.Error, ValueError):
            raise ValueError("Certificate not in OpenSSH format")

        for key_type, string in _SSH_TYPE_STRINGS.items():
            if format_identifier == string + _CERT_SUFFIX_V01:
                pub_key_type = key_type
                break
        else:
            raise ValueError("Invalid certificate format identifier: %s" % format_identifier)

        parser = OpensshParser(cert)

        if format_identifier != parser.string():
            raise ValueError("Certificate formats do not match")

        try:
            cert_info = cls._parse_cert_info(pub_key_type, parser)
            signature = parser.string()
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid certificate data: %s" % e)

        if parser.remaining_bytes():
            raise ValueError(
                "%s bytes of additional data was not parsed while loading %s" % (parser.remaining_bytes(), path)
            )

        return cls(
            cert_info=cert_info,
            signature=signature,
        )

    @property
    def type_string(self):
        return to_text(self._cert_info.type_string)

    @property
    def nonce(self):
        return self._cert_info.nonce

    @property
    def public_key(self):
        return to_text(self._cert_info.public_key_fingerprint())

    @property
    def serial(self):
        return self._cert_info.serial

    @property
    def type(self):
        return self._cert_info.cert_type

    @property
    def key_id(self):
        return to_text(self._cert_info.key_id)

    @property
    def principals(self):
        return [to_text(p) for p in self._cert_info.principals]

    @property
    def valid_after(self):
        return self._cert_info.valid_after

    @property
    def valid_before(self):
        return self._cert_info.valid_before

    @property
    def critical_options(self):
        return [
            OpensshCertificateOption('critical', to_text(n), to_text(d)) for n, d in self._cert_info.critical_options
        ]

    @property
    def extensions(self):
        return [OpensshCertificateOption('extension', to_text(n), to_text(d)) for n, d in self._cert_info.extensions]

    @property
    def reserved(self):
        return self._cert_info.reserved

    @property
    def signing_key(self):
        return to_text(self._cert_info.signing_key_fingerprint())

    @property
    def signature_type(self):
        signature_data = OpensshParser.signature_data(self.signature)
        return to_text(signature_data['signature_type'])

    @staticmethod
    def _parse_cert_info(pub_key_type, parser):
        cert_info = get_cert_info_object(pub_key_type)
        cert_info.nonce = parser.string()
        cert_info.parse_public_numbers(parser)
        cert_info.serial = parser.uint64()
        cert_info.cert_type = parser.uint32()
        cert_info.key_id = parser.string()
        cert_info.principals = parser.string_list()
        cert_info.valid_after = parser.uint64()
        cert_info.valid_before = parser.uint64()
        cert_info.critical_options = parser.option_list()
        cert_info.extensions = parser.option_list()
        cert_info.reserved = parser.string()
        cert_info.signing_key = parser.string()

        return cert_info

    def to_dict(self):
        time_parameters = OpensshCertificateTimeParameters(
            valid_from=self.valid_after,
            valid_to=self.valid_before
        )
        return {
            'type_string': self.type_string,
            'nonce': self.nonce,
            'serial': self.serial,
            'cert_type': self.type,
            'identifier': self.key_id,
            'principals': self.principals,
            'valid_after': time_parameters.valid_from(date_format='human_readable'),
            'valid_before': time_parameters.valid_to(date_format='human_readable'),
            'critical_options': [str(critical_option) for critical_option in self.critical_options],
            'extensions': [str(extension) for extension in self.extensions],
            'reserved': self.reserved,
            'public_key': self.public_key,
            'signing_key': self.signing_key,
        }


def apply_directives(directives):
    if any(d not in _DIRECTIVES for d in directives):
        raise ValueError("directives must be one of %s" % ", ".join(_DIRECTIVES))

    directive_to_option = {
        'no-x11-forwarding': OpensshCertificateOption('extension', 'permit-x11-forwarding', ''),
        'no-agent-forwarding': OpensshCertificateOption('extension', 'permit-agent-forwarding', ''),
        'no-port-forwarding': OpensshCertificateOption('extension', 'permit-port-forwarding', ''),
        'no-pty': OpensshCertificateOption('extension', 'permit-pty', ''),
        'no-user-rc': OpensshCertificateOption('extension', 'permit-user-rc', ''),
    }

    if 'clear' in directives:
        return []
    else:
        return list(set(default_options()) - set(directive_to_option[d] for d in directives))


def default_options():
    return [OpensshCertificateOption('extension', name, '') for name in _EXTENSIONS]


def fingerprint(public_key):
    """Generates a SHA256 hash and formats output to resemble ``ssh-keygen``"""
    h = sha256()
    h.update(public_key)
    return b'SHA256:' + b64encode(h.digest()).rstrip(b'=')


def get_cert_info_object(key_type):
    if key_type == 'rsa':
        cert_info = OpensshRSACertificateInfo()
    elif key_type == 'dsa':
        cert_info = OpensshDSACertificateInfo()
    elif key_type in ('ecdsa-nistp256', 'ecdsa-nistp384', 'ecdsa-nistp521'):
        cert_info = OpensshECDSACertificateInfo()
    elif key_type == 'ed25519':
        cert_info = OpensshED25519CertificateInfo()
    else:
        raise ValueError("%s is not a valid key type" % key_type)

    return cert_info


def get_option_type(name):
    if name in _CRITICAL_OPTIONS:
        result = 'critical'
    elif name in _EXTENSIONS:
        result = 'extension'
    else:
        raise ValueError("%s is not a valid option. " % name +
                         "Custom options must start with 'critical:' or 'extension:' to indicate type")
    return result


def is_relative_time_string(time_string):
    return time_string.startswith("+") or time_string.startswith("-")


def parse_option_list(option_list):
    critical_options = []
    directives = []
    extensions = []

    for option in option_list:
        if option.lower() in _DIRECTIVES:
            directives.append(option.lower())
        else:
            option_object = OpensshCertificateOption.from_string(option)
            if option_object.type == 'critical':
                critical_options.append(option_object)
            else:
                extensions.append(option_object)

    return critical_options, list(set(extensions + apply_directives(directives)))
