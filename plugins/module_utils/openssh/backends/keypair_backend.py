# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
# Copyright: (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import abc
import os

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.openssh.cryptography import (
    HAS_OPENSSH_SUPPORT,
    HAS_OPENSSH_PRIVATE_FORMAT,
    InvalidCommentError,
    InvalidPassphraseError,
    InvalidPrivateKeyFileError,
    OpenSSHError,
    OpensshKeypair,
)
from ansible_collections.community.crypto.plugins.module_utils.openssh.backends.common import (
    KeygenCommand,
    OpensshModule,
    PrivateKey,
    PublicKey,
)
from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    any_in,
    file_mode,
    secure_write,
)


@six.add_metaclass(abc.ABCMeta)
class KeypairBackend(OpensshModule):

    def __init__(self, module):
        super(KeypairBackend, self).__init__(module)

        self.comment = self.module.params['comment']
        self.private_key_path = self.module.params['path']
        self.public_key_path = self.private_key_path + '.pub'
        self.regenerate = self.module.params['regenerate'] if not self.module.params['force'] else 'always'
        self.state = self.module.params['state']
        self.type = self.module.params['type']

        self.size = self._get_size(self.module.params['size'])
        self._validate_path()

        self.original_private_key = None
        self.original_public_key = None
        self.private_key = None
        self.public_key = None

    def _get_size(self, size):
        if self.type in ('rsa', 'rsa1'):
            result = 4096 if size is None else size
            if result < 1024:
                return self.module.fail_json(
                    msg="For RSA keys, the minimum size is 1024 bits and the default is 4096 bits. " +
                        "Attempting to use bit lengths under 1024 will cause the module to fail."
                )
        elif self.type == 'dsa':
            result = 1024 if size is None else size
            if result != 1024:
                return self.module.fail_json(msg="DSA keys must be exactly 1024 bits as specified by FIPS 186-2.")
        elif self.type == 'ecdsa':
            result = 256 if size is None else size
            if result not in (256, 384, 521):
                return self.module.fail_json(
                    msg="For ECDSA keys, size determines the key length by selecting from one of " +
                        "three elliptic curve sizes: 256, 384 or 521 bits. " +
                        "Attempting to use bit lengths other than these three values for ECDSA keys will " +
                        "cause this module to fail."
                )
        elif self.type == 'ed25519':
            # User input is ignored for `key size` when `key type` is ed25519
            result = 256
        else:
            return self.module.fail_json(msg="%s is not a valid value for key type" % self.type)

        return result

    def _validate_path(self):
        self._check_if_base_dir(self.private_key_path)

        if os.path.isdir(self.private_key_path):
            self.module.fail_json(msg='%s is a directory. Please specify a path to a file.' % self.private_key_path)

    def _execute(self):
        self.original_private_key = self._load_private_key()
        self.original_public_key = self._load_public_key()

        if self.state == 'present':
            self._validate_key_load()

            if self._should_generate():
                self._generate()
            elif not self._public_key_valid():
                self._restore_public_key()

            self.private_key = self._load_private_key()
            self.public_key = self._load_public_key()

            for path in (self.private_key_path, self.public_key_path):
                self._update_permissions(path)
        else:
            if self._should_remove():
                self._remove()

    def _load_private_key(self):
        result = None
        if self._private_key_exists():
            try:
                result = self._get_private_key()
            except Exception:
                pass

        return result

    def _private_key_exists(self):
        return os.path.exists(self.private_key_path)

    @abc.abstractmethod
    def _get_private_key(self):
        pass

    def _load_public_key(self):
        result = None
        if self._public_key_exists():
            try:
                result = PublicKey.load(self.public_key_path)
            except (IOError, OSError):
                pass
        return result

    def _public_key_exists(self):
        return os.path.exists(self.public_key_path)

    def _validate_key_load(self):
        if (self._private_key_exists()
                and self.regenerate in ('never', 'fail', 'partial_idempotence')
                and (self.original_private_key is None or not self._private_key_readable())):
            self.module.fail_json(
                msg="Unable to read the key. The key is protected with a passphrase or broken. " +
                    "Will not proceed. To force regeneration, call the module with `generate` " +
                    "set to `full_idempotence` or `always`, or with `force=yes`."
            )

    @abc.abstractmethod
    def _private_key_readable(self):
        pass

    def _should_generate(self):
        if self.regenerate == 'never':
            return self.original_private_key is None
        elif self.regenerate == 'fail':
            if not self._private_key_valid():
                self.module.fail_json(
                    msg="Key has wrong type and/or size. Will not proceed. " +
                        "To force regeneration, call the module with `generate` set to " +
                        "`partial_idempotence`, `full_idempotence` or `always`, or with `force=yes`."
                )
            return self.original_private_key is None
        elif self.regenerate in ('partial_idempotence', 'full_idempotence'):
            return not self._private_key_valid()
        else:
            return True

    def _private_key_valid(self):
        if self.original_private_key is None:
            return False

        return all([
            self.size == self.original_private_key.size,
            self.type == self.original_private_key.type,
        ])

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _generate(self):
        temp_private_key, temp_public_key = self._generate_temp_keypair()

        try:
            self._safe_secure_move([(temp_private_key, self.private_key_path), (temp_public_key, self.public_key_path)])
        except OSError as e:
            self.module.fail_json(msg=to_native(e))

    def _generate_temp_keypair(self):
        temp_private_key = os.path.join(self.module.tmpdir, os.path.basename(self.private_key_path))
        temp_public_key = temp_private_key + '.pub'

        try:
            self._generate_keypair(temp_private_key)
        except (IOError, OSError) as e:
            self.module.fail_json(msg=to_native(e))

        for f in (temp_private_key, temp_public_key):
            self.module.add_cleanup_file(f)

        return temp_private_key, temp_public_key

    @abc.abstractmethod
    def _generate_keypair(self, private_key_path):
        pass

    def _public_key_valid(self):
        if self.original_public_key is None:
            return False

        valid_public_key = self._get_public_key()
        valid_public_key.comment = self.comment

        return self.original_public_key == valid_public_key

    @abc.abstractmethod
    def _get_public_key(self):
        pass

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _restore_public_key(self):
        try:
            temp_public_key = self._create_temp_public_key(str(self._get_public_key()) + '\n')
            self._safe_secure_move([
                (temp_public_key, self.public_key_path)
            ])
        except (IOError, OSError):
            self.module.fail_json(
                msg="The public key is missing or does not match the private key. " +
                    "Unable to regenerate the public key."
            )

        if self.comment:
            self._update_comment()

    def _create_temp_public_key(self, content):
        temp_public_key = os.path.join(self.module.tmpdir, os.path.basename(self.public_key_path))

        default_permissions = 0o644
        existing_permissions = file_mode(self.public_key_path)

        try:
            secure_write(temp_public_key, existing_permissions or default_permissions, to_bytes(content))
        except (IOError, OSError) as e:
            self.module.fail_json(msg=to_native(e))
        self.module.add_cleanup_file(temp_public_key)

        return temp_public_key

    @abc.abstractmethod
    def _update_comment(self):
        pass

    def _should_remove(self):
        return self._private_key_exists() or self._public_key_exists()

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _remove(self):
        try:
            if self._private_key_exists():
                os.remove(self.private_key_path)
            if self._public_key_exists():
                os.remove(self.public_key_path)
        except (IOError, OSError) as e:
            self.module.fail_json(msg=to_native(e))

    @property
    def _result(self):
        private_key = self.private_key or self.original_private_key
        public_key = self.public_key or self.original_public_key

        return {
            'size': self.size,
            'type': self.type,
            'filename': self.private_key_path,
            'fingerprint': private_key.fingerprint if private_key else '',
            'public_key': str(public_key) if public_key else '',
            'comment': public_key.comment if public_key else '',
        }

    @property
    def diff(self):
        before = self.original_private_key.to_dict() if self.original_private_key else {}
        before.update(self.original_public_key.to_dict() if self.original_public_key else {})

        after = self.private_key.to_dict() if self.private_key else {}
        after.update(self.public_key.to_dict() if self.public_key else {})

        return {
            'before': before,
            'after': after,
        }


class KeypairBackendOpensshBin(KeypairBackend):
    def __init__(self, module):
        super(KeypairBackendOpensshBin, self).__init__(module)

        self.ssh_keygen = KeygenCommand(self.module)

    def _generate_keypair(self, private_key_path):
        self.ssh_keygen.generate_keypair(private_key_path, self.size, self.type, self.comment)

    def _get_private_key(self):
        private_key_content = self.ssh_keygen.get_private_key(self.private_key_path)[1]
        return PrivateKey.from_string(private_key_content)

    def _get_public_key(self):
        public_key_content = self.ssh_keygen.get_matching_public_key(self.private_key_path)[1]
        return PublicKey.from_string(public_key_content)

    def _private_key_readable(self):
        rc, stdout, stderr = self.ssh_keygen.get_matching_public_key(self.private_key_path)
        return not (rc == 255 or any_in(stderr, 'is not a public key file', 'incorrect passphrase', 'load failed'))

    def _update_comment(self):
        try:
            self.ssh_keygen.update_comment(self.private_key_path, self.comment)
        except (IOError, OSError) as e:
            self.module.fail_json(msg=to_native(e))


class KeypairBackendCryptography(KeypairBackend):
    def __init__(self, module):
        super(KeypairBackendCryptography, self).__init__(module)

        if self.type == 'rsa1':
            self.module.fail_json(msg="RSA1 keys are not supported by the cryptography backend")

        self.passphrase = to_bytes(module.params['passphrase']) if module.params['passphrase'] else None
        self.private_key_format = self._get_key_format(module.params['private_key_format'])

    def _get_key_format(self, key_format):
        result = 'SSH'

        if key_format == 'auto':
            # Default to OpenSSH 7.8 compatibility when OpenSSH is not installed
            ssh_version = self._get_ssh_version() or "7.8"

            if LooseVersion(ssh_version) < LooseVersion("7.8") and self.type != 'ed25519':
                # OpenSSH made SSH formatted private keys available in version 6.5,
                # but still defaulted to PKCS1 format with the exception of ed25519 keys
                result = 'PKCS1'

            if result == 'SSH' and not HAS_OPENSSH_PRIVATE_FORMAT:
                self.module.fail_json(
                    msg=missing_required_lib(
                        'cryptography >= 3.0',
                        reason="to load/dump private keys in the default OpenSSH format for OpenSSH >= 7.8 " +
                               "or for ed25519 keys"
                    )
                )

        return result

    def _generate_keypair(self, private_key_path):
        keypair = OpensshKeypair.generate(
            keytype=self.type,
            size=self.size,
            passphrase=self.passphrase,
            comment=self.comment or '',
        )

        encoded_private_key = OpensshKeypair.encode_openssh_privatekey(
            keypair.asymmetric_keypair, self.private_key_format
        )
        secure_write(private_key_path, 0o600, encoded_private_key)

        public_key_path = private_key_path + '.pub'
        secure_write(public_key_path, 0o644, keypair.public_key)

    def _get_private_key(self):
        keypair = OpensshKeypair.load(path=self.private_key_path, passphrase=self.passphrase, no_public_key=True)

        return PrivateKey(
            size=keypair.size,
            key_type=keypair.key_type,
            fingerprint=keypair.fingerprint,
        )

    def _get_public_key(self):
        try:
            keypair = OpensshKeypair.load(path=self.private_key_path, passphrase=self.passphrase, no_public_key=True)
        except OpenSSHError:
            # Simulates the null output of ssh-keygen
            return ""

        return PublicKey.from_string(to_text(keypair.public_key))

    def _private_key_readable(self):
        try:
            OpensshKeypair.load(path=self.private_key_path, passphrase=self.passphrase, no_public_key=True)
        except (InvalidPrivateKeyFileError, InvalidPassphraseError):
            return False

        # Cryptography >= 3.0 uses a SSH key loader which does not raise an exception when a passphrase is provided
        # when loading an unencrypted key
        if self.passphrase:
            try:
                OpensshKeypair.load(path=self.private_key_path, passphrase=None, no_public_key=True)
            except (InvalidPrivateKeyFileError, InvalidPassphraseError):
                return True
            else:
                return False

        return True

    def _update_comment(self):
        keypair = OpensshKeypair.load(path=self.private_key_path, passphrase=self.passphrase, no_public_key=True)
        try:
            keypair.comment = self.comment
        except InvalidCommentError as e:
            self.module.fail_json(msg=to_native(e))

        try:
            temp_public_key = self._create_temp_public_key(keypair.public_key + b'\n')
            self._safe_secure_move([(temp_public_key, self.public_key_path)])
        except (IOError, OSError) as e:
            self.module.fail_json(msg=to_native(e))


def select_backend(module, backend):
    can_use_cryptography = HAS_OPENSSH_SUPPORT
    can_use_opensshbin = bool(module.get_bin_path('ssh-keygen'))

    if backend == 'auto':
        if can_use_opensshbin and not module.params['passphrase']:
            backend = 'opensshbin'
        elif can_use_cryptography:
            backend = 'cryptography'
        else:
            module.fail_json(msg="Cannot find either the OpenSSH binary in the PATH " +
                                 "or cryptography >= 2.6 installed on this system")

    if backend == 'opensshbin':
        if not can_use_opensshbin:
            module.fail_json(msg="Cannot find the OpenSSH binary in the PATH")
        return backend, KeypairBackendOpensshBin(module)
    elif backend == 'cryptography':
        if not can_use_cryptography:
            module.fail_json(msg=missing_required_lib("cryptography >= 2.6"))
        return backend, KeypairBackendCryptography(module)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
