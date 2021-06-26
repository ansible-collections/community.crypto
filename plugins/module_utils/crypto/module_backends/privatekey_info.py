# -*- coding: utf-8 -*-
#
# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import traceback

from distutils.version import LooseVersion

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_bytes

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
    _bigint_to_int,
    _get_pyopenssl_public_key_info,
)


MINIMAL_CRYPTOGRAPHY_VERSION = '1.2.3'
MINIMAL_PYOPENSSL_VERSION = '0.15'

PYOPENSSL_IMP_ERR = None
try:
    import OpenSSL
    from OpenSSL import crypto
    PYOPENSSL_VERSION = LooseVersion(OpenSSL.__version__)
except ImportError:
    PYOPENSSL_IMP_ERR = traceback.format_exc()
    PYOPENSSL_FOUND = False
else:
    PYOPENSSL_FOUND = True

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


def _get_cryptography_private_key_info(key):
    key_type, key_public_data = _get_cryptography_public_key_info(key.public_key())
    key_private_data = dict()
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
    def __init__(self, module, backend, content, passphrase=None, return_private_key_data=False):
        # content must be a bytes string
        self.module = module
        self.backend = backend
        self.content = content
        self.passphrase = passphrase
        self.return_private_key_data = return_private_key_data

    @abc.abstractmethod
    def _get_public_key(self, binary):
        pass

    @abc.abstractmethod
    def _get_key_info(self):
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

        result['public_key'] = self._get_public_key(binary=False)
        pk = self._get_public_key(binary=True)
        result['public_key_fingerprints'] = get_fingerprint_of_bytes(
            pk, prefer_one=prefer_one_fingerprint) if pk is not None else dict()

        key_type, key_public_data, key_private_data = self._get_key_info()
        result['type'] = key_type
        result['public_data'] = key_public_data
        if self.return_private_key_data:
            result['private_data'] = key_private_data

        result['key_is_consistent'] = self._is_key_consistent(key_public_data, key_private_data)
        if result['key_is_consistent'] is False:
            # Only fail when it is False, to avoid to fail on None (which means "we don't know")
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

    def _get_key_info(self):
        return _get_cryptography_private_key_info(self.key)

    def _is_key_consistent(self, key_public_data, key_private_data):
        return _is_cryptography_key_consistent(self.key, key_public_data, key_private_data)


class PrivateKeyInfoRetrievalPyOpenSSL(PrivateKeyInfoRetrieval):
    """validate the supplied private key."""

    def __init__(self, module, content, **kwargs):
        super(PrivateKeyInfoRetrievalPyOpenSSL, self).__init__(module, 'pyopenssl', content, **kwargs)

    def _get_public_key(self, binary):
        try:
            return crypto.dump_publickey(
                crypto.FILETYPE_ASN1 if binary else crypto.FILETYPE_PEM,
                self.key
            )
        except AttributeError:
            try:
                # pyOpenSSL < 16.0:
                bio = crypto._new_mem_buf()
                if binary:
                    rc = crypto._lib.i2d_PUBKEY_bio(bio, self.key._pkey)
                else:
                    rc = crypto._lib.PEM_write_bio_PUBKEY(bio, self.key._pkey)
                if rc != 1:
                    crypto._raise_current_error()
                return crypto._bio_to_string(bio)
            except AttributeError:
                self.module.warn('Your pyOpenSSL version does not support dumping public keys. '
                                 'Please upgrade to version 16.0 or newer, or use the cryptography backend.')

    def _get_key_info(self):
        key_type, key_public_data, try_fallback = _get_pyopenssl_public_key_info(self.key)
        key_private_data = dict()
        openssl_key_type = self.key.type()
        if crypto.TYPE_RSA == openssl_key_type:
            try:
                # Use OpenSSL directly to extract key data
                key = OpenSSL._util.lib.EVP_PKEY_get1_RSA(self.key._pkey)
                key = OpenSSL._util.ffi.gc(key, OpenSSL._util.lib.RSA_free)
                # OpenSSL 1.1 and newer have functions to extract the parameters
                # from the EVP PKEY data structures. Older versions didn't have
                # these getters, and it was common use to simply access the values
                # directly. Since there's no guarantee that these data structures
                # will still be accessible in the future, we use the getters for
                # 1.1 and later, and directly access the values for 1.0.x and
                # earlier.
                if OpenSSL.SSL.OPENSSL_VERSION_NUMBER >= 0x10100000:
                    # Get modulus and exponents
                    n = OpenSSL._util.ffi.new("BIGNUM **")
                    e = OpenSSL._util.ffi.new("BIGNUM **")
                    d = OpenSSL._util.ffi.new("BIGNUM **")
                    OpenSSL._util.lib.RSA_get0_key(key, n, e, d)
                    key_private_data['exponent'] = _bigint_to_int(d[0])
                    # Get factors
                    p = OpenSSL._util.ffi.new("BIGNUM **")
                    q = OpenSSL._util.ffi.new("BIGNUM **")
                    OpenSSL._util.lib.RSA_get0_factors(key, p, q)
                    key_private_data['p'] = _bigint_to_int(p[0])
                    key_private_data['q'] = _bigint_to_int(q[0])
                else:
                    # Get private exponent
                    key_private_data['exponent'] = _bigint_to_int(key.d)
                    # Get factors
                    key_private_data['p'] = _bigint_to_int(key.p)
                    key_private_data['q'] = _bigint_to_int(key.q)
            except AttributeError:
                try_fallback = True
        elif crypto.TYPE_DSA == openssl_key_type:
            try:
                # Use OpenSSL directly to extract key data
                key = OpenSSL._util.lib.EVP_PKEY_get1_DSA(self.key._pkey)
                key = OpenSSL._util.ffi.gc(key, OpenSSL._util.lib.DSA_free)
                # OpenSSL 1.1 and newer have functions to extract the parameters
                # from the EVP PKEY data structures. Older versions didn't have
                # these getters, and it was common use to simply access the values
                # directly. Since there's no guarantee that these data structures
                # will still be accessible in the future, we use the getters for
                # 1.1 and later, and directly access the values for 1.0.x and
                # earlier.
                if OpenSSL.SSL.OPENSSL_VERSION_NUMBER >= 0x10100000:
                    # Get private key exponents
                    y = OpenSSL._util.ffi.new("BIGNUM **")
                    x = OpenSSL._util.ffi.new("BIGNUM **")
                    OpenSSL._util.lib.DSA_get0_key(key, y, x)
                    key_private_data['x'] = _bigint_to_int(x[0])
                else:
                    # Get private key exponents
                    key_private_data['x'] = _bigint_to_int(key.priv_key)
            except AttributeError:
                try_fallback = True
        else:
            # Return 'unknown'
            key_type = 'unknown ({0})'.format(self.key.type())
        # If needed and if possible, fall back to cryptography
        if try_fallback and PYOPENSSL_VERSION >= LooseVersion('16.1.0') and CRYPTOGRAPHY_FOUND:
            return _get_cryptography_private_key_info(self.key.to_cryptography_key())
        return key_type, key_public_data, key_private_data

    def _is_key_consistent(self, key_public_data, key_private_data):
        openssl_key_type = self.key.type()
        if crypto.TYPE_RSA == openssl_key_type:
            try:
                return self.key.check()
            except crypto.Error:
                # OpenSSL error means that key is not consistent
                return False
        if crypto.TYPE_DSA == openssl_key_type:
            result = _check_dsa_consistency(key_public_data, key_private_data)
            if result is not None:
                return result
            signature = crypto.sign(self.key, SIGNATURE_TEST_DATA, 'sha256')
            # Verify wants a cert (where it can get the public key from)
            cert = crypto.X509()
            cert.set_pubkey(self.key)
            try:
                crypto.verify(cert, signature, SIGNATURE_TEST_DATA, 'sha256')
                return True
            except crypto.Error:
                return False
        # If needed and if possible, fall back to cryptography
        if PYOPENSSL_VERSION >= LooseVersion('16.1.0') and CRYPTOGRAPHY_FOUND:
            return _is_cryptography_key_consistent(self.key.to_cryptography_key(), key_public_data, key_private_data)
        return None


def get_privatekey_info(module, backend, content, passphrase=None, return_private_key_data=False, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = PrivateKeyInfoRetrievalCryptography(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data)
    elif backend == 'pyopenssl':
        info = PrivateKeyInfoRetrievalPyOpenSSL(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content, passphrase=None, return_private_key_data=False):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)
        can_use_pyopenssl = PYOPENSSL_FOUND and PYOPENSSL_VERSION >= LooseVersion(MINIMAL_PYOPENSSL_VERSION)

        # First try cryptography, then pyOpenSSL
        if can_use_cryptography:
            backend = 'cryptography'
        elif can_use_pyopenssl:
            backend = 'pyopenssl'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Can't detect any of the required Python libraries "
                                  "cryptography (>= {0}) or PyOpenSSL (>= {1})").format(
                                      MINIMAL_CRYPTOGRAPHY_VERSION,
                                      MINIMAL_PYOPENSSL_VERSION))

    if backend == 'pyopenssl':
        if not PYOPENSSL_FOUND:
            module.fail_json(msg=missing_required_lib('pyOpenSSL >= {0}'.format(MINIMAL_PYOPENSSL_VERSION)),
                             exception=PYOPENSSL_IMP_ERR)
        module.deprecate('The module is using the PyOpenSSL backend. This backend has been deprecated',
                         version='2.0.0', collection_name='community.crypto')
        return backend, PrivateKeyInfoRetrievalPyOpenSSL(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data)
    elif backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, PrivateKeyInfoRetrievalCryptography(
            module, content, passphrase=passphrase, return_private_key_data=return_private_key_data)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
