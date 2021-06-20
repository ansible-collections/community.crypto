# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

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
from hashlib import sha256

from ansible.module_utils import six
from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    OpensshParser,
    OpensshWriter,
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
                 reserved=None):
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

        writer = OpensshWriter()
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

        writer = OpensshWriter()
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

        writer = OpensshWriter()
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

        writer = OpensshWriter()
        writer.string(_SSH_TYPE_STRINGS['ed25519'])
        writer.string(self.pk)

        return fingerprint(writer.bytes())

    def parse_public_numbers(self, parser):
        self.pk = parser.string()


# See https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
class OpensshCertificate(object):
    """Encapsulates a formatted OpenSSH certificate including signature and signing key"""
    def __init__(self, cert_info, signing_key, signature):

        self.cert_info = cert_info
        self.signing_key = signing_key
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
            signing_key = parser.string()
            signature = parser.string()
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid certificate data: %s" % e)

        if parser.remaining_bytes():
            raise ValueError(
                "%s bytes of additional data was not parsed while loading %s" % (parser.remaining_bytes(), path)
            )

        return cls(
            cert_info=cert_info,
            signing_key=signing_key,
            signature=signature,
        )

    def signing_key_fingerprint(self):
        return fingerprint(self.signing_key)

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

        return cert_info


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
