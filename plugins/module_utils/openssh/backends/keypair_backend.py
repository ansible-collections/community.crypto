# -*- coding: utf-8 -*-
#
# Copyright: (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
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

import abc
import errno
import os
import stat
from distutils.version import LooseVersion

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import parse_openssh_version
from ansible_collections.community.crypto.plugins.module_utils.openssh.cryptography import (
    HAS_OPENSSH_SUPPORT,
    HAS_OPENSSH_PRIVATE_FORMAT,
    InvalidCommentError,
    InvalidPassphraseError,
    InvalidPrivateKeyFileError,
    OpenSSHError,
    OpensshKeypair,
)


@six.add_metaclass(abc.ABCMeta)
class KeypairBackend(object):

    def __init__(self, module):
        self.module = module

        self.path = module.params['path']
        self.force = module.params['force']
        self.size = module.params['size']
        self.type = module.params['type']
        self.comment = module.params['comment']
        self.passphrase = module.params['passphrase']
        self.regenerate = module.params['regenerate']

        self.changed = False
        self.fingerprint = ''
        self.public_key = {}

        if self.regenerate == 'always':
            self.force = True

        if self.type in ('rsa', 'rsa1'):
            self.size = 4096 if self.size is None else self.size
            if self.size < 1024:
                module.fail_json(msg=('For RSA keys, the minimum size is 1024 bits and the default is 4096 bits. '
                                      'Attempting to use bit lengths under 1024 will cause the module to fail.'))
        elif self.type == 'dsa':
            self.size = 1024 if self.size is None else self.size
            if self.size != 1024:
                module.fail_json(msg=('DSA keys must be exactly 1024 bits as specified by FIPS 186-2.'))
        elif self.type == 'ecdsa':
            self.size = 256 if self.size is None else self.size
            if self.size not in (256, 384, 521):
                module.fail_json(msg=('For ECDSA keys, size determines the key length by selecting from '
                                      'one of three elliptic curve sizes: 256, 384 or 521 bits. '
                                      'Attempting to use bit lengths other than these three values for '
                                      'ECDSA keys will cause this module to fail. '))
        elif self.type == 'ed25519':
            # User input is ignored for `key size` when `key type` is ed25519
            self.size = 256
        else:
            module.fail_json(msg="%s is not a valid value for key type" % self.type)

    def generate(self):
        if self.force or not self.is_private_key_valid(perms_required=False):
            try:
                if self.exists() and not os.access(self.path, os.W_OK):
                    os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
                self._generate_keypair()
                self.changed = True
            except (IOError, OSError) as e:
                self.remove()
                self.module.fail_json(msg="%s" % to_native(e))

            self.fingerprint = self._get_current_key_properties()[2]
            self.public_key = self._get_public_key()
        elif not self.is_public_key_valid(perms_required=False):
            pubkey = self._get_public_key()
            try:
                with open(self.path + ".pub", "w") as pubkey_f:
                    pubkey_f.write(pubkey + '\n')
                os.chmod(self.path + ".pub", stat.S_IWUSR + stat.S_IRUSR + stat.S_IRGRP + stat.S_IROTH)
            except (IOError, OSError):
                self.module.fail_json(
                    msg='The public key is missing or does not match the private key. '
                        'Unable to regenerate the public key.')
            self.changed = True
            self.public_key = pubkey

            if self.comment:
                try:
                    if self.exists() and not os.access(self.path, os.W_OK):
                        os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
                except (IOError, OSError):
                    self.module.fail_json(msg='Unable to update the comment for the public key.')
                self._update_comment()

        private_key_perms_changed = self._permissions_changed()
        public_key_perms_changed = self._permissions_changed(public_key=True)
        if private_key_perms_changed or public_key_perms_changed:
            self.changed = True

    def is_private_key_valid(self, perms_required=True):
        if not self.exists():
            return False

        if self._check_pass_protected_or_broken_key():
            if self.regenerate in ('full_idempotence', 'always'):
                return False
            self.module.fail_json(msg='Unable to read the key. The key is protected with a passphrase or broken.'
                                      ' Will not proceed. To force regeneration, call the module with `generate`'
                                      ' set to `full_idempotence` or `always`, or with `force=yes`.')

        if not self._private_key_loadable():
            if os.path.isdir(self.path):
                self.module.fail_json(msg='%s is a directory. Please specify a path to a file.' % self.path)

            if self.regenerate in ('full_idempotence', 'always'):
                return False
            self.module.fail_json(msg='Unable to read the key. The key is protected with a passphrase or broken.'
                                      ' Will not proceed. To force regeneration, call the module with `generate`'
                                      ' set to `full_idempotence` or `always`, or with `force=yes`.')

        keysize, keytype, self.fingerprint = self._get_current_key_properties()

        if self.regenerate == 'never':
            return True

        if not (self.type == keytype and self.size == keysize):
            if self.regenerate in ('partial_idempotence', 'full_idempotence', 'always'):
                return False
            self.module.fail_json(
                msg='Key has wrong type and/or size.'
                    ' Will not proceed. To force regeneration, call the module with `generate`'
                    ' set to `partial_idempotence`, `full_idempotence` or `always`, or with `force=yes`.'
            )

        # Perms required short-circuits evaluation to prevent the side-effects of running _permissions_changed
        # when check_mode is not enabled
        return not (perms_required and self._permissions_changed())

    def is_public_key_valid(self, perms_required=True):

        def _get_pubkey_content():
            if self.exists(public_key=True):
                with open(self.path + ".pub", "r") as pubkey_f:
                    present_pubkey = pubkey_f.read().strip(' \n')
                return present_pubkey
            else:
                return ''

        def _parse_pubkey(pubkey_content):
            if pubkey_content:
                parts = pubkey_content.split(' ', 2)
                if len(parts) < 2:
                    return ()
                return parts[0], parts[1], '' if len(parts) <= 2 else parts[2]
            return ()

        def _pubkey_valid(pubkey):
            if pubkey_parts and _parse_pubkey(pubkey):
                return pubkey_parts[:2] == _parse_pubkey(pubkey)[:2]
            return False

        def _comment_valid():
            if pubkey_parts:
                return pubkey_parts[2] == self.comment
            return False

        pubkey_parts = _parse_pubkey(_get_pubkey_content())

        pubkey = self._get_public_key()
        if _pubkey_valid(pubkey):
            self.public_key = pubkey
        else:
            return False

        if self.comment and not _comment_valid():
            return False

        # Perms required short-circuits evaluation to prevent the side-effects of running _permissions_changes
        # when check_mode is not enabled
        return not (perms_required and self._permissions_changed(public_key=True))

    def _permissions_changed(self, public_key=False):
        file_args = self.module.load_file_common_arguments(self.module.params)
        if public_key:
            file_args['path'] = file_args['path'] + '.pub'
        if self.module.check_file_absent_if_check_mode(file_args['path']):
            return True
        return self.module.set_fs_attributes_if_different(file_args, False)

    @property
    def result(self):
        return {
            'changed': self.changed,
            'size': self.size,
            'type': self.type,
            'filename': self.path,
            'fingerprint': self.fingerprint if self.fingerprint else '',
            'public_key': self.public_key,
            'comment': self.comment if self.comment else '',
        }

    def remove(self):
        """Remove the resource from the filesystem."""

        try:
            os.remove(self.path)
            self.changed = True
        except (IOError, OSError) as exc:
            if exc.errno != errno.ENOENT:
                self.module.fail_json(msg=to_native(exc))
            else:
                pass

        if self.exists(public_key=True):
            try:
                os.remove(self.path + ".pub")
                self.changed = True
            except (IOError, OSError) as exc:
                if exc.errno != errno.ENOENT:
                    self.module.fail_json(msg=to_native(exc))
                else:
                    pass

    def exists(self, public_key=False):
        return os.path.exists(self.path if not public_key else self.path + ".pub")

    @abc.abstractmethod
    def _generate_keypair(self):
        pass

    @abc.abstractmethod
    def _get_current_key_properties(self):
        pass

    @abc.abstractmethod
    def _get_public_key(self):
        pass

    @abc.abstractmethod
    def _update_comment(self):
        pass

    @abc.abstractmethod
    def _private_key_loadable(self):
        pass

    @abc.abstractmethod
    def _check_pass_protected_or_broken_key(self):
        pass


class KeypairBackendOpensshBin(KeypairBackend):

    def __init__(self, module):
        super(KeypairBackendOpensshBin, self).__init__(module)

        self.openssh_bin = module.get_bin_path('ssh-keygen')

    def _load_privatekey(self):
        return self.module.run_command([self.openssh_bin, '-lf', self.path])

    def _get_publickey_from_privatekey(self):
        # -P '' is always included as an option to induce the expected standard output for
        # _check_pass_protected_or_broken_key, but introduces no side-effects when used to
        # output a matching public key
        return self.module.run_command([self.openssh_bin, '-P', '', '-yf', self.path])

    def _generate_keypair(self):
        args = [
            self.openssh_bin,
            '-q',
            '-N', '',
            '-b', str(self.size),
            '-t', self.type,
            '-f', self.path,
            '-C', self.comment if self.comment else ''
        ]

        # "y" must be entered in response to the "overwrite" prompt
        stdin_data = 'y' if self.exists() else None

        self.module.run_command(args, data=stdin_data)

    def _get_current_key_properties(self):
        rc, stdout, stderr = self._load_privatekey()
        properties = stdout.split()
        keysize = int(properties[0])
        fingerprint = properties[1]
        keytype = properties[-1][1:-1].lower()

        return keysize, keytype, fingerprint

    def _get_public_key(self):
        rc, stdout, stderr = self._get_publickey_from_privatekey()
        return stdout.strip('\n')

    def _update_comment(self):
        return self.module.run_command([self.openssh_bin, '-q', '-o', '-c', '-C', self.comment, '-f', self.path])

    def _private_key_loadable(self):
        rc, stdout, stderr = self._load_privatekey()
        return rc == 0

    def _check_pass_protected_or_broken_key(self):
        rc, stdout, stderr = self._get_publickey_from_privatekey()
        return rc == 255 or any_in(stderr, 'is not a public key file', 'incorrect passphrase', 'load failed')


class KeypairBackendCryptography(KeypairBackend):

    def __init__(self, module):
        super(KeypairBackendCryptography, self).__init__(module)

        if module.params['private_key_format'] == 'auto':
            ssh = module.get_bin_path('ssh')
            if ssh:
                proc = module.run_command([ssh, '-Vq'])
                ssh_version = parse_openssh_version(proc[2].strip())
            else:
                # Default to OpenSSH 7.8 compatibility when OpenSSH is not installed
                ssh_version = "7.8"

            self.private_key_format = 'SSH'

            if LooseVersion(ssh_version) < LooseVersion("7.8") and self.type != 'ed25519':
                # OpenSSH made SSH formatted private keys available in version 6.5,
                # but still defaulted to PKCS1 format with the exception of ed25519 keys
                self.private_key_format = 'PKCS1'

            if self.private_key_format == 'SSH' and not HAS_OPENSSH_PRIVATE_FORMAT:
                module.fail_json(
                    msg=missing_required_lib(
                        'cryptography >= 3.0',
                        reason="to load/dump private keys in the default OpenSSH format for OpenSSH >= 7.8 " +
                               "or for ed25519 keys"
                    )
                )

        if self.type == 'rsa1':
            module.fail_json(msg="RSA1 keys are not supported by the cryptography backend")

        self.passphrase = to_bytes(self.passphrase) if self.passphrase else None

    def _load_privatekey(self):
        return OpensshKeypair.load(path=self.path, passphrase=self.passphrase, no_public_key=True)

    def _generate_keypair(self):
        keypair = OpensshKeypair.generate(
            keytype=self.type,
            size=self.size,
            passphrase=self.passphrase,
            comment=self.comment if self.comment else "",
        )
        with open(self.path, 'w+b') as f:
            f.write(
                OpensshKeypair.encode_openssh_privatekey(
                    keypair.asymmetric_keypair,
                    self.private_key_format
                )
            )
        # ssh-keygen defaults private key permissions to 0600 octal
        os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
        with open(self.path + '.pub', 'w+b') as f:
            f.write(keypair.public_key)
        # ssh-keygen defaults public key permissions to 0644 octal
        os.chmod(self.path + ".pub", stat.S_IWUSR + stat.S_IRUSR + stat.S_IRGRP + stat.S_IROTH)

    def _get_current_key_properties(self):
        keypair = self._load_privatekey()

        return keypair.size, keypair.key_type, keypair.fingerprint

    def _get_public_key(self):
        try:
            keypair = self._load_privatekey()
        except OpenSSHError:
            # Simulates the null output of ssh-keygen
            return ""

        return to_text(keypair.public_key)

    def _update_comment(self):
        keypair = self._load_privatekey()
        try:
            keypair.comment = self.comment
            with open(self.path + ".pub", "w+b") as pubkey_file:
                pubkey_file.write(keypair.public_key + b'\n')
        except (InvalidCommentError, IOError, OSError) as e:
            # Return values while unused currently are made to simulate the output of run_command()
            return 1, "Comment could not be updated", to_native(e)
        return 0, "Comment updated successfully", ""

    def _private_key_loadable(self):
        try:
            self._load_privatekey()
        except OpenSSHError:
            return False
        return True

    def _check_pass_protected_or_broken_key(self):
        try:
            OpensshKeypair.load(
                path=self.path,
                passphrase=self.passphrase,
                no_public_key=True,
            )
        except (InvalidPrivateKeyFileError, InvalidPassphraseError):
            return True

        # Cryptography >= 3.0 uses a SSH key loader which does not raise an exception when a passphrase is provided
        # when loading an unencrypted key
        if self.passphrase:
            try:
                OpensshKeypair.load(
                    path=self.path,
                    passphrase=None,
                    no_public_key=True,
                )
            except (InvalidPrivateKeyFileError, InvalidPassphraseError):
                return False
            else:
                return True

        return False


def any_in(sequence, *elements):
    return any([e in sequence for e in elements])


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
