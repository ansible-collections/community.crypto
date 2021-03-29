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

from base64 import b64encode, b64decode
from getpass import getuser
from socket import gethostname

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    HAS_CRYPTOGRAPHY,
    CRYPTOGRAPHY_HAS_ED25519,
)

if HAS_CRYPTOGRAPHY and CRYPTOGRAPHY_HAS_ED25519:
    HAS_OPENSSH_SUPPORT = True
else:
    HAS_OPENSSH_SUPPORT = False

try:
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, padding
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    pass

_TEXT_ENCODING = 'UTF-8'


class OpenSSHError(Exception):
    pass


class InvalidAlgorithmError(OpenSSHError):
    pass


class InvalidCommentError(OpenSSHError):
    pass


class InvalidDataError(OpenSSHError):
    pass


class InvalidKeyFileError(OpenSSHError):
    pass


class InvalidKeySizeError(OpenSSHError):
    pass


class InvalidKeyTypeError(OpenSSHError):
    pass


class InvalidPassphraseError(OpenSSHError):
    pass


class Asymmetric_Keypair(object):
    def __init__(self, path=None, keytype='rsa', size=None, passphrase=None):
        """Container for newly generated asymmetric keypairs or those loaded from existing files

           :path: A path to an existing private key to be loaded
           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret used to encrypt or decrypt a new or existing key respectively
        """

        self.__algorithm_parameters = {
            'rsa': {
                'default_size': 2048,
                'valid_sizes': range(1024, 16384),
            },
            'dsa': {
                'default_size': 1024,
                'valid_sizes': [1024],
            },
            'ed25519': {
                'default_size': 256,
                'valid_sizes': [256],
            },
            'ecdsa': {
                'default_size': 256,
                'valid_sizes': [256, 384, 521],
                'curves': {
                    256: ec.SECP256R1(),
                    384: ec.SECP384R1(),
                    521: ec.SECP521R1(),
                }
            }
        }

        self.__privatekey = None
        self.__publickey = None

        if passphrase:
            self.__validate_passphrase(passphrase)

            self.__encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode(encoding=_TEXT_ENCODING))
        else:
            self.__encryption_algorithm = serialization.NoEncryption()

        if path:
            self.__keytype = None
            self.__load(path, passphrase)
        else:
            if keytype not in self.__algorithm_parameters.keys():
                raise InvalidKeyTypeError("%s is not a valid keytype. Valid keytypes are %s" % (keytype, ", ".join(self.__algorithm_parameters.keys())))

            self.__keytype = keytype

            if size:
                self.__size = size
            else:
                self.__size = self.__algorithm_parameters[self.__keytype]['default_size']

            self.__generate()

    @property
    def private_key(self):
        """Returns the openssh formatted private key of this key pair
        """
        return self.__privatekey

    @property
    def public_key(self):
        """Returns the openssh formatted public key of this key pair
        """
        return self.__publickey

    @property
    def size(self):
        """Returns the size of the private key of this key pair
        """
        return self.__size

    @property
    def key_type(self):
        """Returns the key type of this key pair
        """
        return self.__keytype

    @property
    def encryption_algorithm(self):
        """Returns the key encryption algorithm of this key pair
        """
        return self.__encryption_algorithm

    def sign(self, data):
        """Returns bytes of data signed with the private key of this key pair

           :data: byteslike data to sign
        """
        signer_params = {
            'rsa': {
                'padding': padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                'algorithm': hashes.SHA256(),
            },
            'dsa': {
                'algorithm': hashes.SHA256(),
            },
            'ecdsa': {
                'signature_algorithm': ec.ECDSA(hashes.SHA256()),
            },
            'ed25519': {},
        }

        try:
            signed_data = self.__privatekey.sign(
                data,
                **signer_params[self.__keytype]
            )
        except TypeError as e:
            raise InvalidDataError(e)

        return signed_data

    def update_passphrase(self, passphrase):
        """Updates the encryption algorithm of this key pair

           :passphrase: Text secret used to encrypt this key pair
        """
        self.__validate_passphrase(passphrase)

        self.__encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode(encoding=_TEXT_ENCODING))

    def __generate(self):

        self.__privatekey = self.__generate_privatekey()
        self.__publickey = self.__generate_publickey()

    def __load(self, path, passphrase):

        self.__privatekey = self.__load_privatekey(path, passphrase)
        self.__publickey = self.__load_publickey(path)
        self.__size = self.__privatekey.key_size

    def __generate_privatekey(self):

        generators = {
            'rsa': self.__generate_rsa_key,
            'dsa': self.__generate_dsa_key,
            'ed25519': self.__generate_ed25519_key,
            'ecdsa': self.__generate_ecdsa_key,
        }

        size_validation_error = self.__validate_key_size()

        if size_validation_error:
            raise InvalidKeySizeError(size_validation_error)

        return generators[self.__keytype]()

    def __generate_publickey(self):

        return self.__privatekey.public_key()

    def __validate_key_size(self):

        if self.__size not in self.__algorithm_parameters[self.__keytype]['valid_sizes']:
            err = "%s is not a valid key size for %s keys" % (self.__size, self.__keytype)
        else:
            err = ""

        return err

    def __generate_rsa_key(self):
        return rsa.generate_private_key(
            # Public exponent should always be 65537 to prevent issues
            # if improper padding is used during signing
            public_exponent=65537,
            key_size=self.__size,
            backend=backend,
        )

    def __generate_dsa_key(self):
        return dsa.generate_private_key(
            key_size=self.__size,
            backend=backend,
        )

    def __generate_ed25519_key(self):
        return Ed25519PrivateKey.generate()

    def __generate_ecdsa_key(self):
        return ec.generate_private_key(
            self.__algorithm_parameters['ecdsa']['curves'][self.__size],
            backend=backend,
        )

    def __load_privatekey(self, path, passphrase):
        # OpenSSH formatted private keys are not available in Cryptography <3.0
        try:
            privatekey_loader = serialization.load_ssh_private_key
        except AttributeError:
            privatekey_loader = serialization.load_pem_private_key

        if passphrase:
            passphrase = passphrase.encode(encoding=_TEXT_ENCODING)

        try:
            with open(path, 'rb') as f:
                content = f.read()

                privatekey = privatekey_loader(
                    data=content,
                    password=passphrase,
                    backend=backend,
                )

                if isinstance(privatekey, rsa.RSAPrivateKey):
                    self.__keytype = 'rsa'
                elif isinstance(privatekey, dsa.DSAPrivateKey):
                    self.__keytype = 'dsa'
                elif isinstance(privatekey, ec.EllipticCurvePrivateKey):
                    self.__keytype = 'ecdsa'
                elif isinstance(privatekey, Ed25519PrivateKey):
                    self.__keytype = 'ed25519'
        except ValueError as e:
            raise InvalidKeyFileError(e)
        except TypeError as e:
            raise InvalidPassphraseError(e)
        except UnsupportedAlgorithm as e:
            raise InvalidAlgorithmError(e)

        return privatekey

    def __load_publickey(self, path):
        try:
            with open(path + '.pub', 'rb') as f:
                content = f.read()

                publickey = serialization.load_ssh_public_key(
                    data=content,
                    backend=backend,
                )

                pubkey_text = content.decode(encoding=_TEXT_ENCODING)

        except ValueError as e:
            raise InvalidKeyFileError(e)
        except UnsupportedAlgorithm as e:
            raise InvalidAlgorithmError(e)

        return publickey

    def __validate_passphrase(self, passphrase):
        if not hasattr(passphrase, 'encode'):
            raise InvalidPassphraseError("%s cannot be encoded to text" % passphrase)


class OpenSSH_Keypair(object):
    def __init__(self, path=None, keytype='rsa', size=None, passphrase=None, comment=None):
        """Container for OpenSSH encoded asymmetric keypairs

           :path: A path to an existing private key to be loaded
           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret used to encrypt or decrypt a new or existing key respectively
           :comment: Comment for a newly generated OpenSSH public key
        """

        self.__openssh_privatekey = None
        self.__openssh_publickey = None
        self.__fingerprint = None

        if path:
            self.__comment = self.__extract_comment(path)
        else:
            if not comment:
                self.__comment = "%s@%s" % (getuser(), gethostname())
            else:
                comment_validation_err = self.__validate_comment(comment)

                if comment_validation_err:
                    raise InvalidCommentError(comment_validation_err)

                self.__comment = comment

        self.__asym_keypair = Asymmetric_Keypair(path, keytype, size, passphrase)
        self.__openssh_privatekey, self.__openssh_publickey = self.__encode_openssh_keypair()
        self.__fingerprint = self.__calculate_fingerprint()

    def __eq__(self, other):
        return self.fingerprint == other.fingerprint and self.comment == other.comment

    @property
    def private_key(self):
        """Returns the OpenSSH formatted private key of this key pair
        """
        return self.__openssh_privatekey

    @property
    def public_key(self):
        """Returns the OpenSSH formatted public key of this key pair
        """
        return self.__openssh_publickey

    @property
    def size(self):
        """Returns the size of the private key of this key pair
        """
        return self.__asym_keypair.size

    @property
    def key_type(self):
        """Returns the key encryption algorithm of this key pair
        """
        return self.__asym_keypair.key_type

    @property
    def fingerprint(self):
        """Returns the fingerprint (SHA256 Hash) of the public key of this key pair
        """
        return self.__fingerprint

    @property
    def comment(self):
        """Returns the comment applied to the OpenSSH formatted public key of this key pair
        """
        return self.__comment

    @comment.setter
    def comment(self, comment):
        """Updates the comment applied to the OpenSSH formatted public key of this key pair

           :comment: Text to update the OpenSSH public key comment
        """
        comment_validation_err = self.__validate_comment(comment)

        if comment_validation_err:
            raise InvalidCommentError(comment_validation_err)

        self.__comment = comment
        encoded_comment = (" %s" % self.__comment).encode(encoding=_TEXT_ENCODING)
        self.__openssh_publickey = b' '.join(self.__openssh_publickey.split(b' ', 2)[:2]) + encoded_comment
        return self.__openssh_publickey

    def update_passphrase(self, passphrase):
        """Updates the passphrase used to encrypt the private key of this keypair

           :passphrase: Text secret used for encryption
        """
        self.__asym_keypair.update_passphrase(passphrase)
        self.__openssh_privatekey = self.__encode_openssh_privatekey()

    def __calculate_fingerprint(self):

        digest = hashes.Hash(hashes.SHA256(), backend=backend)

        decoded_pubkey = b64decode(self.__openssh_publickey.split(b' ')[1])

        digest.update(decoded_pubkey)

        return b64encode(digest.finalize()).decode(encoding=_TEXT_ENCODING).rstrip('=')

    def __encode_openssh_keypair(self):

        return self.__encode_openssh_privatekey(), self.__encode_openssh_publickey()

    def __encode_openssh_privatekey(self):
        # OpenSSH formatted private keys are not available in Cryptography <3.0
        try:
            privatekey_format = serialization.PrivateFormat.OpenSSH
        except AttributeError:
            privatekey_format = serialization.PrivateFormat.PKCS8

        encoded_privatekey = self.__asym_keypair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=privatekey_format,
            encryption_algorithm=self.__asym_keypair.encryption_algorithm
        )

        return encoded_privatekey

    def __encode_openssh_publickey(self):
        encoded_publickey = self.__asym_keypair.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        encoded_publickey += (" %s" % self.__comment).encode(encoding=_TEXT_ENCODING)

        return encoded_publickey

    def __extract_comment(self, path):
        try:
            with open(path + '.pub', 'rb') as f:
                fields = f.read().split(b' ', 2)
                if len(fields) == 3:
                    comment = fields[2].decode(_TEXT_ENCODING)
        except OSError as e:
            raise InvalidKeyFileError(e)

        return comment

    def __validate_comment(self, comment):
        err = ""

        if not hasattr(comment, 'encode'):
            err = "%s cannot be encoded to text" % comment

        return err
