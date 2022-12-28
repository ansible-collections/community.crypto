# -*- coding: utf-8 -*-
#
# Copyright (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import traceback

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

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
                raise PublicKeyParseError(to_native(e), {})

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


def get_publickey_info(module, backend, content=None, key=None, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = PublicKeyInfoRetrievalCryptography(module, content=content, key=key)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content=None, key=None):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Try cryptography
        if can_use_cryptography:
            backend = 'cryptography'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Cannot detect any of the required Python libraries "
                                  "cryptography (>= {0})").format(MINIMAL_CRYPTOGRAPHY_VERSION))

    if backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, PublicKeyInfoRetrievalCryptography(module, content=content, key=key)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
