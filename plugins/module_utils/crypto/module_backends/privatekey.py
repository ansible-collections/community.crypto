# -*- coding: utf-8 -*-
#
# Copyright: (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import base64
import traceback

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X25519_FULL,
    CRYPTOGRAPHY_HAS_X448,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    get_fingerprint_of_privatekey,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_private_key_format,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey_info import (
    PrivateKeyConsistencyError,
    PrivateKeyParseError,
    get_privatekey_info,
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
class PrivateKeyBackend:
    def __init__(self, module, backend):
        self.module = module
        self.type = module.params['type']
        self.size = module.params['size']
        self.curve = module.params['curve']
        self.passphrase = module.params['passphrase']
        self.cipher = module.params['cipher']
        self.format = module.params['format']
        self.format_mismatch = module.params.get('format_mismatch', 'regenerate')
        self.regenerate = module.params.get('regenerate', 'full_idempotence')
        self.backend = backend

        self.private_key = None

        self.existing_private_key = None
        self.existing_private_key_bytes = None

        self.diff_before = self._get_info(None)
        self.diff_after = self._get_info(None)

    def _get_info(self, data):
        if data is None:
            return dict()
        result = dict(can_parse_key=False)
        try:
            result.update(get_privatekey_info(
                self.module, self.backend, data, passphrase=self.passphrase,
                return_private_key_data=False, prefer_one_fingerprint=True))
        except PrivateKeyConsistencyError as exc:
            result.update(exc.result)
        except PrivateKeyParseError as exc:
            result.update(exc.result)
        except Exception as exc:
            pass
        return result

    @abc.abstractmethod
    def generate_private_key(self):
        """(Re-)Generate private key."""
        pass

    def convert_private_key(self):
        """Convert existing private key (self.existing_private_key) to new private key (self.private_key).

        This is effectively a copy without active conversion. The conversion is done
        during load and store; get_private_key_data() uses the destination format to
        serialize the key.
        """
        self._ensure_existing_private_key_loaded()
        self.private_key = self.existing_private_key

    @abc.abstractmethod
    def get_private_key_data(self):
        """Return bytes for self.private_key."""
        pass

    def set_existing(self, privatekey_bytes):
        """Set existing private key bytes. None indicates that the key does not exist."""
        self.existing_private_key_bytes = privatekey_bytes
        self.diff_after = self.diff_before = self._get_info(self.existing_private_key_bytes)

    def has_existing(self):
        """Query whether an existing private key is/has been there."""
        return self.existing_private_key_bytes is not None

    @abc.abstractmethod
    def _check_passphrase(self):
        """Check whether provided passphrase matches, assuming self.existing_private_key_bytes has been populated."""
        pass

    @abc.abstractmethod
    def _ensure_existing_private_key_loaded(self):
        """Make sure that self.existing_private_key is populated from self.existing_private_key_bytes."""
        pass

    @abc.abstractmethod
    def _check_size_and_type(self):
        """Check whether provided size and type matches, assuming self.existing_private_key has been populated."""
        pass

    @abc.abstractmethod
    def _check_format(self):
        """Check whether the key file format, assuming self.existing_private_key and self.existing_private_key_bytes has been populated."""
        pass

    def needs_regeneration(self):
        """Check whether a regeneration is necessary."""
        if self.regenerate == 'always':
            return True
        if not self.has_existing():
            # key does not exist
            return True
        if not self._check_passphrase():
            if self.regenerate == 'full_idempotence':
                return True
            self.module.fail_json(msg='Unable to read the key. The key is protected with a another passphrase / no passphrase or broken.'
                                  ' Will not proceed. To force regeneration, call the module with `generate`'
                                  ' set to `full_idempotence` or `always`, or with `force=yes`.')
        self._ensure_existing_private_key_loaded()
        if self.regenerate != 'never':
            if not self._check_size_and_type():
                if self.regenerate in ('partial_idempotence', 'full_idempotence'):
                    return True
                self.module.fail_json(msg='Key has wrong type and/or size.'
                                      ' Will not proceed. To force regeneration, call the module with `generate`'
                                      ' set to `partial_idempotence`, `full_idempotence` or `always`, or with `force=yes`.')
        # During generation step, regenerate if format does not match and format_mismatch == 'regenerate'
        if self.format_mismatch == 'regenerate' and self.regenerate != 'never':
            if not self._check_format():
                if self.regenerate in ('partial_idempotence', 'full_idempotence'):
                    return True
                self.module.fail_json(msg='Key has wrong format.'
                                      ' Will not proceed. To force regeneration, call the module with `generate`'
                                      ' set to `partial_idempotence`, `full_idempotence` or `always`, or with `force=yes`.'
                                      ' To convert the key, set `format_mismatch` to `convert`.')
        return False

    def needs_conversion(self):
        """Check whether a conversion is necessary. Must only be called if needs_regeneration() returned False."""
        # During conversion step, convert if format does not match and format_mismatch == 'convert'
        self._ensure_existing_private_key_loaded()
        return self.has_existing() and self.format_mismatch == 'convert' and not self._check_format()

    def _get_fingerprint(self):
        if self.private_key:
            return get_fingerprint_of_privatekey(self.private_key, backend=self.backend)
        try:
            self._ensure_existing_private_key_loaded()
        except Exception as dummy:
            # Ignore errors
            pass
        if self.existing_private_key:
            return get_fingerprint_of_privatekey(self.existing_private_key, backend=self.backend)

    def dump(self, include_key):
        """Serialize the object into a dictionary."""

        if not self.private_key:
            try:
                self._ensure_existing_private_key_loaded()
            except Exception as dummy:
                # Ignore errors
                pass
        result = {
            'type': self.type,
            'size': self.size,
            'fingerprint': self._get_fingerprint(),
        }
        if self.type == 'ECC':
            result['curve'] = self.curve
        # Get hold of private key bytes
        pk_bytes = self.existing_private_key_bytes
        if self.private_key is not None:
            pk_bytes = self.get_private_key_data()
        self.diff_after = self._get_info(pk_bytes)
        if include_key:
            # Store result
            if pk_bytes:
                if identify_private_key_format(pk_bytes) == 'raw':
                    result['privatekey'] = base64.b64encode(pk_bytes)
                else:
                    result['privatekey'] = pk_bytes.decode('utf-8')
            else:
                result['privatekey'] = None

        result['diff'] = dict(
            before=self.diff_before,
            after=self.diff_after,
        )
        return result


# Implementation with using cryptography
class PrivateKeyCryptographyBackend(PrivateKeyBackend):

    def _get_ec_class(self, ectype):
        ecclass = cryptography.hazmat.primitives.asymmetric.ec.__dict__.get(ectype)
        if ecclass is None:
            self.module.fail_json(msg='Your cryptography version does not support {0}'.format(ectype))
        return ecclass

    def _add_curve(self, name, ectype, deprecated=False):
        def create(size):
            ecclass = self._get_ec_class(ectype)
            return ecclass()

        def verify(privatekey):
            ecclass = self._get_ec_class(ectype)
            return isinstance(privatekey.private_numbers().public_numbers.curve, ecclass)

        self.curves[name] = {
            'create': create,
            'verify': verify,
            'deprecated': deprecated,
        }

    def __init__(self, module):
        super(PrivateKeyCryptographyBackend, self).__init__(module=module, backend='cryptography')

        self.curves = dict()
        self._add_curve('secp224r1', 'SECP224R1')
        self._add_curve('secp256k1', 'SECP256K1')
        self._add_curve('secp256r1', 'SECP256R1')
        self._add_curve('secp384r1', 'SECP384R1')
        self._add_curve('secp521r1', 'SECP521R1')
        self._add_curve('secp192r1', 'SECP192R1', deprecated=True)
        self._add_curve('sect163k1', 'SECT163K1', deprecated=True)
        self._add_curve('sect163r2', 'SECT163R2', deprecated=True)
        self._add_curve('sect233k1', 'SECT233K1', deprecated=True)
        self._add_curve('sect233r1', 'SECT233R1', deprecated=True)
        self._add_curve('sect283k1', 'SECT283K1', deprecated=True)
        self._add_curve('sect283r1', 'SECT283R1', deprecated=True)
        self._add_curve('sect409k1', 'SECT409K1', deprecated=True)
        self._add_curve('sect409r1', 'SECT409R1', deprecated=True)
        self._add_curve('sect571k1', 'SECT571K1', deprecated=True)
        self._add_curve('sect571r1', 'SECT571R1', deprecated=True)
        self._add_curve('brainpoolP256r1', 'BrainpoolP256R1', deprecated=True)
        self._add_curve('brainpoolP384r1', 'BrainpoolP384R1', deprecated=True)
        self._add_curve('brainpoolP512r1', 'BrainpoolP512R1', deprecated=True)

        self.cryptography_backend = cryptography.hazmat.backends.default_backend()

        if not CRYPTOGRAPHY_HAS_X25519 and self.type == 'X25519':
            self.module.fail_json(msg='Your cryptography version does not support X25519')
        if not CRYPTOGRAPHY_HAS_X25519_FULL and self.type == 'X25519':
            self.module.fail_json(msg='Your cryptography version does not support X25519 serialization')
        if not CRYPTOGRAPHY_HAS_X448 and self.type == 'X448':
            self.module.fail_json(msg='Your cryptography version does not support X448')
        if not CRYPTOGRAPHY_HAS_ED25519 and self.type == 'Ed25519':
            self.module.fail_json(msg='Your cryptography version does not support Ed25519')
        if not CRYPTOGRAPHY_HAS_ED448 and self.type == 'Ed448':
            self.module.fail_json(msg='Your cryptography version does not support Ed448')

    def _get_wanted_format(self):
        if self.format not in ('auto', 'auto_ignore'):
            return self.format
        if self.type in ('X25519', 'X448', 'Ed25519', 'Ed448'):
            return 'pkcs8'
        else:
            return 'pkcs1'

    def generate_private_key(self):
        """(Re-)Generate private key."""
        try:
            if self.type == 'RSA':
                self.private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
                    public_exponent=65537,  # OpenSSL always uses this
                    key_size=self.size,
                    backend=self.cryptography_backend
                )
            if self.type == 'DSA':
                self.private_key = cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key(
                    key_size=self.size,
                    backend=self.cryptography_backend
                )
            if CRYPTOGRAPHY_HAS_X25519_FULL and self.type == 'X25519':
                self.private_key = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
            if CRYPTOGRAPHY_HAS_X448 and self.type == 'X448':
                self.private_key = cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.generate()
            if CRYPTOGRAPHY_HAS_ED25519 and self.type == 'Ed25519':
                self.private_key = cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate()
            if CRYPTOGRAPHY_HAS_ED448 and self.type == 'Ed448':
                self.private_key = cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate()
            if self.type == 'ECC' and self.curve in self.curves:
                if self.curves[self.curve]['deprecated']:
                    self.module.warn('Elliptic curves of type {0} should not be used for new keys!'.format(self.curve))
                self.private_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
                    curve=self.curves[self.curve]['create'](self.size),
                    backend=self.cryptography_backend
                )
        except cryptography.exceptions.UnsupportedAlgorithm as dummy:
            self.module.fail_json(msg='Cryptography backend does not support the algorithm required for {0}'.format(self.type))

    def get_private_key_data(self):
        """Return bytes for self.private_key"""
        # Select export format and encoding
        try:
            export_format = self._get_wanted_format()
            export_encoding = cryptography.hazmat.primitives.serialization.Encoding.PEM
            if export_format == 'pkcs1':
                # "TraditionalOpenSSL" format is PKCS1
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL
            elif export_format == 'pkcs8':
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8
            elif export_format == 'raw':
                export_format = cryptography.hazmat.primitives.serialization.PrivateFormat.Raw
                export_encoding = cryptography.hazmat.primitives.serialization.Encoding.Raw
        except AttributeError:
            self.module.fail_json(msg='Cryptography backend does not support the selected output format "{0}"'.format(self.format))

        # Select key encryption
        encryption_algorithm = cryptography.hazmat.primitives.serialization.NoEncryption()
        if self.cipher and self.passphrase:
            if self.cipher == 'auto':
                encryption_algorithm = cryptography.hazmat.primitives.serialization.BestAvailableEncryption(to_bytes(self.passphrase))
            else:
                self.module.fail_json(msg='Cryptography backend can only use "auto" for cipher option.')

        # Serialize key
        try:
            return self.private_key.private_bytes(
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

    def _load_privatekey(self):
        data = self.existing_private_key_bytes
        try:
            # Interpret bytes depending on format.
            format = identify_private_key_format(data)
            if format == 'raw':
                if len(data) == 56 and CRYPTOGRAPHY_HAS_X448:
                    return cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.from_private_bytes(data)
                if len(data) == 57 and CRYPTOGRAPHY_HAS_ED448:
                    return cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.from_private_bytes(data)
                if len(data) == 32:
                    if CRYPTOGRAPHY_HAS_X25519 and (self.type == 'X25519' or not CRYPTOGRAPHY_HAS_ED25519):
                        return cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(data)
                    if CRYPTOGRAPHY_HAS_ED25519 and (self.type == 'Ed25519' or not CRYPTOGRAPHY_HAS_X25519):
                        return cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(data)
                    if CRYPTOGRAPHY_HAS_X25519 and CRYPTOGRAPHY_HAS_ED25519:
                        try:
                            return cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(data)
                        except Exception:
                            return cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.from_private_bytes(data)
                raise PrivateKeyError('Cannot load raw key')
            else:
                return cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    data,
                    None if self.passphrase is None else to_bytes(self.passphrase),
                    backend=self.cryptography_backend
                )
        except Exception as e:
            raise PrivateKeyError(e)

    def _ensure_existing_private_key_loaded(self):
        if self.existing_private_key is None and self.has_existing():
            self.existing_private_key = self._load_privatekey()

    def _check_passphrase(self):
        try:
            format = identify_private_key_format(self.existing_private_key_bytes)
            if format == 'raw':
                # Raw keys cannot be encrypted. To avoid incompatibilities, we try to
                # actually load the key (and return False when this fails).
                self._load_privatekey()
                # Loading the key succeeded. Only return True when no passphrase was
                # provided.
                return self.passphrase is None
            else:
                return cryptography.hazmat.primitives.serialization.load_pem_private_key(
                    self.existing_private_key_bytes,
                    None if self.passphrase is None else to_bytes(self.passphrase),
                    backend=self.cryptography_backend
                )
        except Exception as dummy:
            return False

    def _check_size_and_type(self):
        if isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
            return self.type == 'RSA' and self.size == self.existing_private_key.key_size
        if isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
            return self.type == 'DSA' and self.size == self.existing_private_key.key_size
        if CRYPTOGRAPHY_HAS_X25519 and isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey):
            return self.type == 'X25519'
        if CRYPTOGRAPHY_HAS_X448 and isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey):
            return self.type == 'X448'
        if CRYPTOGRAPHY_HAS_ED25519 and isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
            return self.type == 'Ed25519'
        if CRYPTOGRAPHY_HAS_ED448 and isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey):
            return self.type == 'Ed448'
        if isinstance(self.existing_private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
            if self.type != 'ECC':
                return False
            if self.curve not in self.curves:
                return False
            return self.curves[self.curve]['verify'](self.existing_private_key)

        return False

    def _check_format(self):
        if self.format == 'auto_ignore':
            return True
        try:
            format = identify_private_key_format(self.existing_private_key_bytes)
            return format == self._get_wanted_format()
        except Exception as dummy:
            return False


def select_backend(module, backend):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Decision
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
        return backend, PrivateKeyCryptographyBackend(module)
    else:
        raise Exception('Unsupported value for backend: {0}'.format(backend))


def get_privatekey_argument_spec():
    return ArgumentSpec(
        argument_spec=dict(
            size=dict(type='int', default=4096),
            type=dict(type='str', default='RSA', choices=[
                'DSA', 'ECC', 'Ed25519', 'Ed448', 'RSA', 'X25519', 'X448'
            ]),
            curve=dict(type='str', choices=[
                'secp224r1', 'secp256k1', 'secp256r1', 'secp384r1', 'secp521r1',
                'secp192r1', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1',
                'sect163k1', 'sect163r2', 'sect233k1', 'sect233r1', 'sect283k1',
                'sect283r1', 'sect409k1', 'sect409r1', 'sect571k1', 'sect571r1',
            ]),
            passphrase=dict(type='str', no_log=True),
            cipher=dict(type='str'),
            format=dict(type='str', default='auto_ignore', choices=['pkcs1', 'pkcs8', 'raw', 'auto', 'auto_ignore']),
            format_mismatch=dict(type='str', default='regenerate', choices=['regenerate', 'convert']),
            select_crypto_backend=dict(type='str', choices=['auto', 'cryptography'], default='auto'),
            regenerate=dict(
                type='str',
                default='full_idempotence',
                choices=['never', 'fail', 'partial_idempotence', 'full_idempotence', 'always']
            ),
        ),
        required_together=[
            ['cipher', 'passphrase']
        ],
        required_if=[
            ['type', 'ECC', ['curve']],
        ],
    )
