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


class KeypairError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class KeypairBackend:

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

        if self.type == 'dsa':
            self.size = 1024 if self.size is None else self.size
            if self.size != 1024:
                module.fail_json(msg=('DSA keys must be exactly 1024 bits as specified by FIPS 186-2.'))

        if self.type == 'ecdsa':
            self.size = 256 if self.size is None else self.size
            if self.size not in (256, 384, 521):
                module.fail_json(msg=('For ECDSA keys, size determines the key length by selecting from '
                                      'one of three elliptic curve sizes: 256, 384 or 521 bits. '
                                      'Attempting to use bit lengths other than these three values for '
                                      'ECDSA keys will cause this module to fail. '))
        if self.type == 'ed25519':
            self.size = 256

    def generate(self):
        if self.force or not self.is_private_key_valid(perms_required=False):
            try:
                if os.path.exists(self.path) and not os.access(self.path, os.W_OK):
                    os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
                self.changed = True

                self._generate_keypair()
                keysize, keytype, self.fingerprint = self._get_current_key_properties()
                self.public_key = self._get_public_key()
            except (IOError, OSError) as e:
                self.remove()
                self.module.fail_json(msg="%s" % to_native(e))
        elif not self.is_public_key_valid(perms_required=False):
            pubkey = self._get_public_key()
            try:
                self.changed = True
                with open(self.path + ".pub", "w") as pubkey_f:
                    pubkey_f.write(pubkey + '\n')
                os.chmod(self.path + ".pub", stat.S_IWUSR + stat.S_IRUSR + stat.S_IRGRP + stat.S_IROTH)
            except IOError:
                self.module.fail_json(
                    msg='The public key is missing or does not match the private key. '
                        'Unable to regenerate the public key.')
            self.public_key = pubkey

            if self.comment:
                try:
                    if os.path.exists(self.path) and not os.access(self.path, os.W_OK):
                        os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
                    self._update_comment()
                except IOError:
                    self.module.fail_json(
                        msg='Unable to update the comment for the public key.')

        if self._permissions_changed() or self._permissions_changed(public_key=True):
            self.changed = True

    def is_private_key_valid(self, perms_required=True):
        if not os.path.exists(self.path):
            return False

        if self._check_pass_protected_or_broken_key():
            if self.regenerate in ('full_idempotence', 'always'):
                return False
            self.module.fail_json(msg='Unable to read the key. The key is protected with a passphrase or broken.'
                                      ' Will not proceed. To force regeneration, call the module with `generate`'
                                      ' set to `full_idempotence` or `always`, or with `force=yes`.')

        if not self._private_key_loadable():
            if os.path.isdir(self.path):
                self.module.fail_json(msg='%s is a directory. Please specify a path to a file.' % (self.path))

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

        return not perms_required or not self._permissions_changed()

    def is_public_key_valid(self, perms_required=True):

        def _get_pubkey_content():
            if os.path.exists(self.path + ".pub"):
                with open(self.path + ".pub", "r") as pubkey_f:
                    present_pubkey = pubkey_f.read().strip(' \n')
                return present_pubkey
            else:
                return ''

        def _parse_pubkey(pubkey_content):
            if pubkey_content:
                parts = pubkey_content.split(' ', 2)
                if len(parts) < 2:
                    return False
                return parts[0], parts[1], '' if len(parts) <= 2 else parts[2]
            return False

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

        if self.comment:
            if not _comment_valid():
                return False

        if perms_required and self._permissions_changed(public_key=True):
            return False

        return True

    def _permissions_changed(self, public_key=False):
        file_args = self.module.load_file_common_arguments(self.module.params)
        if public_key:
            file_args['path'] = file_args['path'] + '.pub'
        return self.module.set_fs_attributes_if_different(file_args, False)

    def dump(self):
        return {
            'changed': self.changed,
            'size': self.size,
            'type': self.type,
            'filename': self.path,
            # On removal this has no value
            'fingerprint': self.fingerprint if self.fingerprint else '',
            'public_key': self.public_key,
            'comment': self.comment if self.comment else '',
        }

    def remove(self):
        """Remove the resource from the filesystem."""

        try:
            os.remove(self.path)
            self.changed = True
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise KeypairError(exc)
            else:
                pass

        if os.path.exists(self.path + ".pub"):
            try:
                os.remove(self.path + ".pub")
                self.changed = True
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise KeypairError(exc)
                else:
                    pass

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
        return self.module.run_command([self.openssh_bin, '-P', '', '-yf', self.path])

    def _generate_keypair(self):
        args = [
            self.openssh_bin,
            '-q',
            '-N', '',
            '-b', str(self.size),
            '-t', self.type,
            '-f', self.path,
        ]

        if self.comment:
            args.extend(['-C', self.comment])
        else:
            args.extend(['-C', ""])

        stdin_data = None
        if os.path.exists(self.path):
            stdin_data = 'y'
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
        if rc == 255 or 'is not a public key file' in stderr:
            return True
        if 'incorrect passphrase' in stderr or 'load failed' in stderr:
            return True
        return False


class KeypairBackendCryptography(KeypairBackend):

    def __init__(self, module):
        super(KeypairBackendCryptography, self).__init__(module)

        # The empty string is intentionally ignored so that dependency checks do not cause unnecessary failure
        if self.passphrase:
            if module.params['private_key_format'] == 'auto':
                ssh = module.get_bin_path('ssh', True)
                proc = module.run_command([ssh, '-Vq'])
                ssh_version = parse_openssh_version(proc[2].strip())

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
                module.fail_json(msg="Passphrases are not supported for RSA1 keys.")

            self.passphrase = to_bytes(self.passphrase)
        else:
            self.private_key_format = None

    def _load_privatekey(self):
        return OpensshKeypair.load(
            path=self.path,
            passphrase=self.passphrase,
            no_public_key=True,
        )

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
        os.chmod(self.path, stat.S_IWUSR + stat.S_IRUSR)
        with open(self.path + '.pub', 'w+b') as f:
            f.write(keypair.public_key)
        os.chmod(self.path + ".pub", stat.S_IWUSR + stat.S_IRUSR + stat.S_IRGRP + stat.S_IROTH)

    def _get_current_key_properties(self):
        keypair = self._load_privatekey()

        return str(keypair.size), keypair.type, keypair.fingerprint

    def _get_public_key(self):
        keypair = self._load_privatekey()

        return to_text(keypair.public_key)

    def _update_comment(self):
        keypair = self._load_privatekey()
        try:
            keypair.comment = self.comment
            with open(self.path + ".pub", "w+b") as pubkey_f:
                pubkey_f.write(keypair.public_key + b'\n')
        except (InvalidCommentError, IOError, OSError) as e:
            return 1, "Comment was not updated successfully", to_native(e)
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
            except InvalidPassphraseError:
                return False

            return True
        return False


def select_backend(module, backend):
    can_use_cryptography = HAS_OPENSSH_SUPPORT
    can_use_opensshbin = bool(module.get_bin_path('ssh-keygen'))

    if backend == 'auto':
        if module.params['passphrase']:
            if can_use_cryptography:
                backend = 'cryptography'
            else:
                module.fail_json(msg=missing_required_lib("cryptography >= 2.6"))
        else:
            if can_use_opensshbin:
                backend = 'opensshbin'
            elif can_use_cryptography:
                backend = 'cryptography'

        if backend == 'auto':
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
