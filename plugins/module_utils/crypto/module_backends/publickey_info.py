# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import traceback

from distutils.version import LooseVersion

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X448,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    get_fingerprint_of_bytes,
    load_publickey,
)


MINIMAL_CRYPTOGRAPHY_VERSION = '1.2.3'
MINIMAL_PYOPENSSL_VERSION = '16.0.0'  # when working with public key objects, the minimal required version is 0.15

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


def _get_cryptography_public_key_info(key):
    key_public_data = dict()
    if isinstance(key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
        key_type = 'RSA'
        public_numbers = key.public_numbers()
        key_public_data['size'] = key.key_size
        key_public_data['modulus'] = public_numbers.n
        key_public_data['exponent'] = public_numbers.e
    elif isinstance(key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey):
        key_type = 'DSA'
        parameter_numbers = key.parameters().parameter_numbers()
        public_numbers = key.public_numbers()
        key_public_data['size'] = key.key_size
        key_public_data['p'] = parameter_numbers.p
        key_public_data['q'] = parameter_numbers.q
        key_public_data['g'] = parameter_numbers.g
        key_public_data['y'] = public_numbers.y
    elif CRYPTOGRAPHY_HAS_X25519 and isinstance(key, cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey):
        key_type = 'X25519'
    elif CRYPTOGRAPHY_HAS_X448 and isinstance(key, cryptography.hazmat.primitives.asymmetric.x448.X448PublicKey):
        key_type = 'X448'
    elif CRYPTOGRAPHY_HAS_ED25519 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey):
        key_type = 'Ed25519'
    elif CRYPTOGRAPHY_HAS_ED448 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey):
        key_type = 'Ed448'
    elif isinstance(key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
        key_type = 'ECC'
        public_numbers = key.public_numbers()
        key_public_data['curve'] = key.curve.name
        key_public_data['x'] = public_numbers.x
        key_public_data['y'] = public_numbers.y
        key_public_data['exponent_size'] = key.curve.key_size
    else:
        key_type = 'unknown ({0})'.format(type(key))
    return key_type, key_public_data


def _bigint_to_int(bn):
    '''Convert OpenSSL BIGINT to Python integer'''
    if bn == OpenSSL._util.ffi.NULL:
        return None
    hexstr = OpenSSL._util.lib.BN_bn2hex(bn)
    try:
        return int(OpenSSL._util.ffi.string(hexstr), 16)
    finally:
        OpenSSL._util.lib.OPENSSL_free(hexstr)


def _get_pyopenssl_public_key_info(key):
    key_public_data = dict()
    try_fallback = True
    openssl_key_type = key.type()
    if crypto.TYPE_RSA == openssl_key_type:
        key_type = 'RSA'
        key_public_data['size'] = key.bits()

        try:
            # Use OpenSSL directly to extract key data
            key = OpenSSL._util.lib.EVP_PKEY_get1_RSA(key._pkey)
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
                key_public_data['modulus'] = _bigint_to_int(n[0])
                key_public_data['exponent'] = _bigint_to_int(e[0])
            else:
                # Get modulus and exponents
                key_public_data['modulus'] = _bigint_to_int(key.n)
                key_public_data['exponent'] = _bigint_to_int(key.e)
            try_fallback = False
        except AttributeError:
            # Use fallback if available
            pass
    elif crypto.TYPE_DSA == openssl_key_type:
        key_type = 'DSA'
        key_public_data['size'] = key.bits()

        try:
            # Use OpenSSL directly to extract key data
            key = OpenSSL._util.lib.EVP_PKEY_get1_DSA(key._pkey)
            key = OpenSSL._util.ffi.gc(key, OpenSSL._util.lib.DSA_free)
            # OpenSSL 1.1 and newer have functions to extract the parameters
            # from the EVP PKEY data structures. Older versions didn't have
            # these getters, and it was common use to simply access the values
            # directly. Since there's no guarantee that these data structures
            # will still be accessible in the future, we use the getters for
            # 1.1 and later, and directly access the values for 1.0.x and
            # earlier.
            if OpenSSL.SSL.OPENSSL_VERSION_NUMBER >= 0x10100000:
                # Get public parameters (primes and group element)
                p = OpenSSL._util.ffi.new("BIGNUM **")
                q = OpenSSL._util.ffi.new("BIGNUM **")
                g = OpenSSL._util.ffi.new("BIGNUM **")
                OpenSSL._util.lib.DSA_get0_pqg(key, p, q, g)
                key_public_data['p'] = _bigint_to_int(p[0])
                key_public_data['q'] = _bigint_to_int(q[0])
                key_public_data['g'] = _bigint_to_int(g[0])
                # Get public key exponents
                y = OpenSSL._util.ffi.new("BIGNUM **")
                x = OpenSSL._util.ffi.new("BIGNUM **")
                OpenSSL._util.lib.DSA_get0_key(key, y, x)
                key_public_data['y'] = _bigint_to_int(y[0])
            else:
                # Get public parameters (primes and group element)
                key_public_data['p'] = _bigint_to_int(key.p)
                key_public_data['q'] = _bigint_to_int(key.q)
                key_public_data['g'] = _bigint_to_int(key.g)
                # Get public key exponents
                key_public_data['y'] = _bigint_to_int(key.pub_key)
            try_fallback = False
        except AttributeError:
            # Use fallback if available
            pass
    else:
        # Return 'unknown'
        key_type = 'unknown ({0})'.format(key.type())
    return key_type, key_public_data, try_fallback


class PublicKeyParseError(OpenSSLObjectError):
    def __init__(self, msg, result):
        super(PublicKeyParseError, self).__init__(msg)
        self.error_message = msg
        self.result = result


@six.add_metaclass(abc.ABCMeta)
class PublicKeyInfoRetrieval(object):
    def __init__(self, module, backend, content=None, key=None):
        # content must be a bytes string
        self.module = module
        self.backend = backend
        self.content = content
        self.key = key

    @abc.abstractmethod
    def _get_public_key(self, binary):
        pass

    @abc.abstractmethod
    def _get_key_info(self):
        pass

    def get_info(self, prefer_one_fingerprint=False):
        result = dict()
        if self.key is None:
            try:
                self.key = load_publickey(content=self.content, backend=self.backend)
            except OpenSSLObjectError as e:
                raise PublicKeyParseError(to_native(e))

        pk = self._get_public_key(binary=True)
        result['fingerprints'] = get_fingerprint_of_bytes(
            pk, prefer_one=prefer_one_fingerprint) if pk is not None else dict()

        key_type, key_public_data = self._get_key_info()
        result['type'] = key_type
        result['public_data'] = key_public_data
        return result


class PublicKeyInfoRetrievalCryptography(PublicKeyInfoRetrieval):
    """Validate the supplied public key, using the cryptography backend"""
    def __init__(self, module, content=None, key=None):
        super(PublicKeyInfoRetrievalCryptography, self).__init__(module, 'cryptography', content=content, key=key)

    def _get_public_key(self, binary):
        return self.key.public_bytes(
            serialization.Encoding.DER if binary else serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _get_key_info(self):
        return _get_cryptography_public_key_info(self.key)


class PublicKeyInfoRetrievalPyOpenSSL(PublicKeyInfoRetrieval):
    """validate the supplied public key."""

    def __init__(self, module, content=None, key=None):
        super(PublicKeyInfoRetrievalPyOpenSSL, self).__init__(module, 'pyopenssl', content=content, key=key)

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
        # If needed and if possible, fall back to cryptography
        if try_fallback and PYOPENSSL_VERSION >= LooseVersion('16.1.0') and CRYPTOGRAPHY_FOUND:
            return _get_cryptography_public_key_info(self.key.to_cryptography_key())
        return key_type, key_public_data


def get_publickey_info(module, backend, content=None, key=None, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = PublicKeyInfoRetrievalCryptography(module, content=content, key=key)
    elif backend == 'pyopenssl':
        info = PublicKeyInfoRetrievalPyOpenSSL(module, content=content, key=key)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content=None, key=None):
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
        return backend, PublicKeyInfoRetrievalPyOpenSSL(module, content=content, key=key)
    elif backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, PublicKeyInfoRetrievalCryptography(module, content=content, key=key)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
