# -*- coding: utf-8 -*-
#
# Copyright: (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import traceback

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.io import (
    load_file,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X448,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_compare_private_keys,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_private_key_format,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.common import ArgumentSpec


MINIMAL_CRYPTOGRAPHY_VERSION = '1.2.3'

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    import cryptography.exceptions
    import cryptography.hazmat.backends
    import cryptography.hazmat.primitives.serialization
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.dsa
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.utils
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


class PrivateKeyError(OpenSSLObjectError):
    pass


# From the object called `module`, only the following properties are used:
#
#  - module.params[]
#  - module.warn(msg: str)
#  - module.fail_json(msg: str, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class PrivateKeyConvertBackend:
    def __init__(self, module, backend):
        self.module = module
        self.src_path = module.params['src_path']
        self.src_content = module.params['src_content']
        self.src_passphrase = module.params['src_passphrase']
        self.format = module.params['format']
        self.dest_passphrase = module.params['dest_passphrase']
        self.backend = backend

        self.src_private_key = None
        if self.src_path is not None:
            self.src_private_key_bytes = load_file(self.src_path, module)
        else:
            self.src_private_key_bytes = self.src_content.encode('utf-8')

        self.dest_private_key = None
        self.dest_private_key_bytes = None

    @abc.abstractmethod
    def get_private_key_data(self):
        """Return bytes for self.src_private_key in output format."""
        pass

    def set_existing_destination(self, privatekey_bytes):
        """Set existing private key bytes. None indicates that the key does not exist."""
        self.dest_private_key_bytes = privatekey_bytes

    def has_existing_destination(self):
        """Query whether an existing private key is/has been there."""
        return self.dest_private_key_bytes is not None

    @abc.abstractmethod
    def _load_private_key(self, data, passphrase, current_hint=None):
        """Check whether data cna be loaded as a private key with the provided passphrase. Return tuple (type, private_key)."""
        pass

    def needs_conversion(self):
        """Check whether a conversion is necessary. Must only be called if needs_regeneration() returned False."""
        dummy, self.src_private_key = self._load_private_key(self.src_private_key_bytes, self.src_passphrase)

        if not self.has_existing_destination():
            return True

        try:
            format, self.dest_private_key = self._load_private_key(self.dest_private_key_bytes, self.dest_passphrase, current_hint=self.src_private_key)
        except Exception:
            return True

        return format != self.format or not cryptography_compare_private_keys(self.dest_private_key, self.src_private_key)

    def dump(self):
        """Serialize the object into a dictionary."""
        return {}


# Implementation with using cryptography
class PrivateKeyConvertCryptographyBackend(PrivateKeyConvertBackend):
    def __init__(self, module):
        super(PrivateKeyConvertCryptographyBackend, self).__init__(module=module, backend='cryptography')

        self.cryptography_backend = cryptography.hazmat.backends.default_backend()

    def get_private_key_data(self):
        """Return bytes for self.src_private_key in output format"""
        # Select export format and encoding
        try:
            export_encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM
            if self.format == 'pkcs1':
                # "TraditionalOpenSSL" format is PKCS1
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL
            elif self.format == 'pkcs8':
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8
            elif self.format == 'raw':
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.Raw
                export_encoding = cryptography.hazmat.primitives.serialization.Encoding.Raw
        except AttributeError:
            self.module.fail_json(msg='Cryptography backend does not support the selected output format "{0}"'.format(self.format))

        # Select key encryption
        encryption_algorithm = cryptography.hazmat.primitives.serialization.NoEncryption()
        if self.dest_passphrase:
            encryption_algorithm = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(to_bytes(self.dest_passphrase))

        # Serialize key
        try:
            return self.src_private_key.private_bytes(
                encoding=export_encoding,
                format=export_format,
                encryption_algorithm=encryption_algorithm
            )
        except ValueError as dummy:
            self.module.fail_json(
                msg='Cryptography backend cannot serialize the private key in the required format "{0}"'.format(self.format)
            )
        except Exception as dummy:
            self.module.fail_json(
                msg='Error while serializing the private key in the required format "{0}"'.format(self.format),
                exception=traceback.format_exc()
            )

    def _load_private_key(self, data, passphrase, current_hint=None):
        try:
            # Interpret bytes depending on format.
            format = identify_private_key_format(data)
            if format == 'raw':
                if passphrase is not None:
                    raise PrivateKeyError('Cannot load raw key with passphrase')
                if len(data) == 56 and CRYPTOGRAPHY_HAS_X448:
                    return format, cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.from_private_bytes(data)
                if len(data) == 57 and CRYPTOGRAPHY_HAS_ED448:
                    return format, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.from_private_bytes(data)
                if len(data) == 32:
                    if CRYPTOGRAPHY_HAS_X25519 and not CRYPTOGRAPHY_HAS_ED25519:
                        return format, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(data)
                    if CRYPTOGRAPHY_HAS_ED25519 and not CRYPTOGRAPHY_HAS_X25519:
                        return format, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(data)
                    if CRYPTOGRAPHY_HAS_X25519 and CRYPTOGRAPHY_HAS_ED25519:
                        if isinstance(current_hint, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey):
                            try:
                                return format, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(data)
                            except Exception:
                                return format, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(data)
                        else:
                            try:
                                return format, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(data)
                            except Exception:
                                return format, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(data)
                raise PrivateKeyError('Cannot load raw key')
            else:
                return format, cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    data,
                    None if passphrase is None else to_bytes(passphrase),
                    backend=self.cryptography_backend
                )
        except Exception as e:
            raise PrivateKeyError(e)


def select_backend(module):
    if not CRYPTOGRAPHY_FOUND:
        module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                         exception=CRYPTOGRAPHY_IMP_ERR)
    return PrivateKeyConvertCryptographyBackend(module)


def get_privatekey_argument_spec():
    return ArgumentSpec(
        argument_spec=dict(
            src_path=dict(type='path'),
            src_content=dict(type='str'),
            src_passphrase=dict(type='str', no_log=True),
            dest_passphrase=dict(type='str', no_log=True),
            format=dict(type='str', required=True, choices=['pkcs1', 'pkcs8', 'raw']),
        ),
        mutually_exclusive=[
            ['src_path', 'src_content'],
        ],
        required_one_of=[
            ['src_path', 'src_content'],
        ],
    )
