# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import binascii
import datetime
import sys

from ansible.module_utils._text import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import ModuleFailException

from ansible_collections.community.crypto.plugins.module_utils.acme.io import read_file

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import nopad_b64

from ansible_collections.community.crypto.plugins.module_utils.acme.backends import (
    CryptoBackend,
)

try:
    import cryptography
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.hashes
    import cryptography.hazmat.primitives.hmac
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.utils
    import cryptography.hazmat.primitives.serialization
    import cryptography.x509
    import cryptography.x509.oid
    from distutils.version import LooseVersion
    CRYPTOGRAPHY_VERSION = cryptography.__version__
    HAS_CURRENT_CRYPTOGRAPHY = (LooseVersion(CRYPTOGRAPHY_VERSION) >= LooseVersion('1.5'))
    if HAS_CURRENT_CRYPTOGRAPHY:
        _cryptography_backend = cryptography.hazmat.backends.default_backend()
except Exception as dummy:
    HAS_CURRENT_CRYPTOGRAPHY = False
    CRYPTOGRAPHY_VERSION = None


if sys.version_info[0] >= 3:
    # Python 3 (and newer)
    def _count_bytes(n):
        return (n.bit_length() + 7) // 8 if n > 0 else 0

    def _convert_int_to_bytes(count, no):
        return no.to_bytes(count, byteorder='big')

    def _pad_hex(n, digits):
        res = hex(n)[2:]
        if len(res) < digits:
            res = '0' * (digits - len(res)) + res
        return res
else:
    # Python 2
    def _count_bytes(n):
        if n <= 0:
            return 0
        h = '%x' % n
        return (len(h) + 1) // 2

    def _convert_int_to_bytes(count, n):
        h = '%x' % n
        if len(h) > 2 * count:
            raise Exception('Number {1} needs more than {0} bytes!'.format(count, n))
        return ('0' * (2 * count - len(h)) + h).decode('hex')

    def _pad_hex(n, digits):
        h = '%x' % n
        if len(h) < digits:
            h = '0' * (digits - len(h)) + h
        return h


class CryptographyBackend(CryptoBackend):
    def __init__(self, module):
        super(CryptographyBackend, self).__init__(module)

    def parse_key(self, key_file=None, key_content=None):
        '''
        Parses an RSA or Elliptic Curve key file in PEM format and returns a pair
        (error, key_data).
        '''
        # If key_content isn't given, read key_file
        if key_content is None:
            key_content = read_file(key_file)
        else:
            key_content = to_bytes(key_content)
        # Parse key
        try:
            key = cryptography.hazmat.primitives.serialization.load_pem_private_key(key_content, password=None, backend=_cryptography_backend)
        except Exception as e:
            return 'error while loading key: {0}'.format(e), None
        if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            pk = key.public_key().public_numbers()
            return None, {
                'key_obj': key,
                'type': 'rsa',
                'alg': 'RS256',
                'jwk': {
                    "kty": "RSA",
                    "e": nopad_b64(_convert_int_to_bytes(_count_bytes(pk.e), pk.e)),
                    "n": nopad_b64(_convert_int_to_bytes(_count_bytes(pk.n), pk.n)),
                },
                'hash': 'sha256',
            }
        elif isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            pk = key.public_key().public_numbers()
            if pk.curve.name == 'secp256r1':
                bits = 256
                alg = 'ES256'
                hashalg = 'sha256'
                point_size = 32
                curve = 'P-256'
            elif pk.curve.name == 'secp384r1':
                bits = 384
                alg = 'ES384'
                hashalg = 'sha384'
                point_size = 48
                curve = 'P-384'
            elif pk.curve.name == 'secp521r1':
                # Not yet supported on Let's Encrypt side, see
                # https://github.com/letsencrypt/boulder/issues/2217
                bits = 521
                alg = 'ES512'
                hashalg = 'sha512'
                point_size = 66
                curve = 'P-521'
            else:
                return 'unknown elliptic curve: {0}'.format(pk.curve.name), {}
            num_bytes = (bits + 7) // 8
            return None, {
                'key_obj': key,
                'type': 'ec',
                'alg': alg,
                'jwk': {
                    "kty": "EC",
                    "crv": curve,
                    "x": nopad_b64(_convert_int_to_bytes(num_bytes, pk.x)),
                    "y": nopad_b64(_convert_int_to_bytes(num_bytes, pk.y)),
                },
                'hash': hashalg,
                'point_size': point_size,
            }
        else:
            return 'unknown key type "{0}"'.format(type(key)), {}

    def sign(self, payload64, protected64, key_data):
        sign_payload = "{0}.{1}".format(protected64, payload64).encode('utf8')
        if 'mac_obj' in key_data:
            mac = key_data['mac_obj']()
            mac.update(sign_payload)
            signature = mac.finalize()
        elif isinstance(key_data['key_obj'], cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
            hashalg = cryptography.hazmat.primitives.hashes.SHA256
            signature = key_data['key_obj'].sign(sign_payload, padding, hashalg())
        elif isinstance(key_data['key_obj'], cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            if key_data['hash'] == 'sha256':
                hashalg = cryptography.hazmat.primitives.hashes.SHA256
            elif key_data['hash'] == 'sha384':
                hashalg = cryptography.hazmat.primitives.hashes.SHA384
            elif key_data['hash'] == 'sha512':
                hashalg = cryptography.hazmat.primitives.hashes.SHA512
            ecdsa = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(hashalg())
            r, s = cryptography.hazmat.primitives.asymmetric.utils.decode_dss_signature(key_data['key_obj'].sign(sign_payload, ecdsa))
            rr = _pad_hex(r, 2 * key_data['point_size'])
            ss = _pad_hex(s, 2 * key_data['point_size'])
            signature = binascii.unhexlify(rr) + binascii.unhexlify(ss)

        return {
            "protected": protected64,
            "payload": payload64,
            "signature": nopad_b64(signature),
        }

    def create_mac_key(self, alg, key):
        '''Create a MAC key.'''
        if alg == 'HS256':
            hashalg = cryptography.hazmat.primitives.hashes.SHA256
            hashbytes = 32
        elif alg == 'HS384':
            hashalg = cryptography.hazmat.primitives.hashes.SHA384
            hashbytes = 48
        elif alg == 'HS512':
            hashalg = cryptography.hazmat.primitives.hashes.SHA512
            hashbytes = 64
        else:
            raise ModuleFailException('Unsupported MAC key algorithm for cryptography backend: {0}'.format(alg))
        key_bytes = base64.urlsafe_b64decode(key)
        if len(key_bytes) < hashbytes:
            raise ModuleFailException(
                '{0} key must be at least {1} bytes long (after Base64 decoding)'.format(alg, hashbytes))
        return {
            'mac_obj': lambda: cryptography.hazmat.primitives.hmac.HMAC(
                key_bytes,
                hashalg(),
                _cryptography_backend),
            'type': 'hmac',
            'alg': alg,
            'jwk': {
                'kty': 'oct',
                'k': key,
            },
        }

    def get_csr_identifiers(self, csr_filename=None, csr_content=None):
        '''
        Return a set of requested identifiers (CN and SANs) for the CSR.
        Each identifier is a pair (type, identifier), where type is either
        'dns' or 'ip'.
        '''
        identifiers = set([])
        if csr_content is None:
            csr_content = read_file(csr_filename)
        else:
            csr_content = to_bytes(csr_content)
        csr = cryptography.x509.load_pem_x509_csr(csr_content, _cryptography_backend)
        for sub in csr.subject:
            if sub.oid == cryptography.x509.oid.NameOID.COMMON_NAME:
                identifiers.add(('dns', sub.value))
        for extension in csr.extensions:
            if extension.oid == cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for name in extension.value:
                    if isinstance(name, cryptography.x509.DNSName):
                        identifiers.add(('dns', name.value))
                    elif isinstance(name, cryptography.x509.IPAddress):
                        identifiers.add(('ip', name.value.compressed))
                    else:
                        raise ModuleFailException('Found unsupported SAN identifier {0}'.format(name))
        return identifiers

    def get_cert_days(self, cert_filename=None, cert_content=None, now=None):
        '''
        Return the days the certificate in cert_filename remains valid and -1
        if the file was not found. If cert_filename contains more than one
        certificate, only the first one will be considered.

        If now is not specified, datetime.datetime.now() is used.
        '''
        if cert_filename is not None:
            cert_content = read_file(cert_filename)
        else:
            cert_content = to_bytes(cert_content)

        if cert_content is None:
            return -1

        try:
            cert = cryptography.x509.load_pem_x509_certificate(cert_content, _cryptography_backend)
        except Exception as e:
            if cert_filename is None:
                raise ModuleFailException('Cannot parse certificate: {0}'.format(e))
            raise ModuleFailException('Cannot parse certificate {0}: {1}'.format(cert_filename, e))

        if now is None:
            now = datetime.datetime.now()
        return (cert.not_valid_after - now).days
