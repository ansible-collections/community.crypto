# -*- coding: utf-8 -*-
#
# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import traceback

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_privatekey,
    get_fingerprint_of_bytes,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.math import (
    binary_exp_mod,
    quick_is_not_prime,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.publickey_info import (
    _get_cryptography_public_key_info,
)


MINIMAL_CRYPTOGRAPHY_VERSION = '1.2.3'

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True

SIGNATURE_TEST_DATA = b'1234'


def _get_cryptography_private_key_info(key, need_private_key_data=False):
    key_type, key_public_data = _get_cryptography_public_key_info(key.public_key())
    key_private_data = dict()
    if need_private_key_data:
        if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            private_numbers = key.private_numbers()
            key_private_data['p'] = private_numbers.p
            key_private_data['q'] = private_numbers.q
            key_private_data['exponent'] = private_numbers.d
        elif isinstance(key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
            private_numbers = key.private_numbers()
            key_private_data['x'] = private_numbers.x
        elif isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            private_numbers = key.private_numbers()
            key_private_data['multiplier'] = private_numbers.private_value
    return key_type, key_public_data, key_private_data


def _check_dsa_consistency(key_public_data, key_private_data):
    # Get parameters
    p = key_public_data.get('p')
    q = key_public_data.get('q')
    g = key_public_data.get('g')
    y = key_public_data.get('y')
    x = key_private_data.get('x')
    for v in (p, q, g, y, x):
        if v is None:
            return None
    # Make sure that g is not 0, 1 or -1 in Z/pZ
    if g < 2 or g >= p - 1:
        return False
    # Make sure that x is in range
    if x < 1 or x >= q:
        return False
    # Check whether q divides p-1
    if (p - 1) % q != 0:
        return False
    # Check that g**q mod p == 1
    if binary_exp_mod(g, q, p) != 1:
        return False
    # Check whether g**x mod p == y
    if binary_exp_mod(g, x, p) != y:
        return False
    # Check (quickly) whether p or q are not primes
    if quick_is_not_prime(q) or quick_is_not_prime(p):
        return False
    return True


def _is_cryptography_key_consistent(key, key_public_data, key_private_data):
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
        return bool(key._backend._lib.RSA_check_key(key._rsa_cdata))
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
        result = _check_dsa_consistency(key_public_data, key_private_data)
        if result is not None:
            return result
        try:
            signature = key.sign(SIGNATURE_TEST_DATA, cryptography.hazmat.primitives.hashes.SHA256())
        except AttributeError:
            # sign() was added in cryptography 1.5, but we support older versions
            return None
        try:
            key.public_key().verify(
                signature,
                SIGNATURE_TEST_DATA,
                cryptography.hazmat.primitives.hashes.SHA256()
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
        try:
            signature = key.sign(
                SIGNATURE_TEST_DATA,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256())
            )
        except AttributeError:
            # sign() was added in cryptography 1.5, but we support older versions
            return None
        try:
            key.public_key().verify(
                signature,
                SIGNATURE_TEST_DATA,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(cryptography.hazmat.primitives.hashes.SHA256())
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    has_simple_sign_function = False
    if CRYPTOGRAPHY_HAS_ED25519 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
        has_simple_sign_function = True
    if CRYPTOGRAPHY_HAS_ED448 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey):
        has_simple_sign_function = True
    if has_simple_sign_function:
        signature = key.sign(SIGNATURE_TEST_DATA)
        try:
            key.public_key().verify(signature, SIGNATURE_TEST_DATA)
            return True
        except cryptography.exceptions.InvalidSignature:
            return False
    # For X25519 and X448, there's no test yet.
    return None


class PrivateKeyConsistencyError(OpenSSLObjectError):
    def __init__(self, msg, result):
        super(PrivateKeyConsistencyError, self).__init__(msg)
        self.error_message = msg
        self.result = result


class PrivateKeyParseError(OpenSSLObjectError):
    def __init__(self, msg, result):
        super(PrivateKeyParseError, self).__init__(msg)
        self.error_message = msg
        self.result = result


@six.add_metaclass(abc.ABCMeta)
class PrivateKeyInfoRetrieval(object):
    def __init__(self, module, backend, content, passphrase=None, return_private_key_data=False, check_consistency=False):
        # content must be a bytes string
        self.module = module
        self.backend = backend
        self.content = content
        self.passphrase = passphrase
        self.return_private_key_data = return_private_key_data
        self.check_consistency = check_consistency

    @abc.abstractmethod
    def _get_public_key(self, binary):
        pass

    @abc.abstractmethod
    def _get_key_info(self, need_private_key_data=False):
        pass

    @abc.abstractmethod
    def _is_key_consistent(self, key_public_data, key_private_data):
        pass

    def get_info(self, prefer_one_fingerprint=False):
        result = dict(
            can_parse_key=False,
            key_is_consistent=None,
        )
        priv_key_detail = self.content
        try:
            self.key = load_privatekey(
                path=None,
                content=priv_key_detail,
                passphrase=to_bytes(self.passphrase) if self.passphrase is not None else self.passphrase,
                backend=self.backend
            )
            result['can_parse_key'] = True
        except OpenSSLObjectError as exc:
            raise PrivateKeyParseError(to_native(exc), result)

        result['public_key'] = to_native(self._get_public_key(binary=False))
        pk = self._get_public_key(binary=True)
        result['public_key_fingerprints'] = get_fingerprint_of_bytes(
            pk, prefer_one=prefer_one_fingerprint) if pk is not None else dict()

        key_type, key_public_data, key_private_data = self._get_key_info(
            need_private_key_data=self.return_private_key_data or self.check_consistency)
        result['type'] = key_type
        result['public_data'] = key_public_data
        if self.return_private_key_data:
            result['private_data'] = key_private_data

        if self.check_consistency:
            result['key_is_consistent'] = self._is_key_consistent(key_public_data, key_private_data)
            if result['key_is_consistent'] is False:
                # Only fail when it is False, to avoid to fail on None (which means "we do not know")
                msg = (
                    "Private key is not consistent! (See "
                    "https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html)"
                )
                raise PrivateKeyConsistencyError(msg, result)
        return result


class PrivateKeyInfoRetrievalCryptography(PrivateKeyInfoRetrieval):
    """Validate the supplied private key, using the cryptography backend"""
    def __init__(self, module, content, **kwargs):
        super(PrivateKeyInfoRetrievalCryptography, self).__init__(module, 'cryptography', content, **kwargs)

    def _get_public_key(self, binary):
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER if binary else serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _get_key_info(self, need_private_key_data=False):
        return _get_cryptography_private_key_info(self.key, need_private_key_data=need_private_key_data)

    def _is_key_consistent(self, key_public_data, key_private_data):
        return _is_cryptography_key_consistent(self.key, key_public_data, key_private_data)


def get_privatekey_info(module, backend, content, passphrase=None, return_private_key_data=False, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = PrivateKeyInfoRetrievalCryptography(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content, passphrase=None, return_private_key_data=False, check_consistency=False):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Try cryptography
        if can_use_cryptography:
            backend = 'cryptography'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Cannot detect the required Python library "
                                  "cryptography (>= {0})").format(MINIMAL_CRYPTOGRAPHY_VERSION))

    if backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, PrivateKeyInfoRetrievalCryptography(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data, check_consistency=check_consistency)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
