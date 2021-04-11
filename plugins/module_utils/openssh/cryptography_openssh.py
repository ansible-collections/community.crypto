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
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
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


class InvalidPrivateKeyFileError(OpenSSHError):
    pass


class InvalidPublicKeyFileError(OpenSSHError):
    pass


class InvalidKeyFormatError(OpenSSHError):
    pass


class InvalidKeySizeError(OpenSSHError):
    pass


class InvalidKeyTypeError(OpenSSHError):
    pass


class InvalidPassphraseError(OpenSSHError):
    pass


class Asymmetric_Keypair(object):
    """Container for newly generated asymmetric keypairs or those loaded from existing files"""

    __algorithm_parameters = {
        'rsa': {
            'default_size': 2048,
            'valid_sizes': range(1024, 16384),
            'signer_params': {
                'padding': padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                'algorithm': hashes.SHA256(),
            },
        },
        'dsa': {
            'default_size': 1024,
            'valid_sizes': [1024],
            'signer_params': {
                'algorithm': hashes.SHA256(),
            },
        },
        'ed25519': {
            'default_size': 256,
            'valid_sizes': [256],
            'signer_params': {},
        },
        'ecdsa': {
            'default_size': 256,
            'valid_sizes': [256, 384, 521],
            'signer_params': {
                'signature_algorithm': ec.ECDSA(hashes.SHA256()),
            },
            'curves': {
                256: ec.SECP256R1(),
                384: ec.SECP384R1(),
                521: ec.SECP521R1(),
            }
        }
    }

    @classmethod
    def generate(cls, keytype='rsa', size=None, passphrase=None):
        """Returns an Asymmetric_Keypair object generated with the supplied parameters
           or defaults to an unencrypted RSA-2048 key

           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret used to encrypt the private key being generated
        """

        if keytype not in cls.__algorithm_parameters.keys():
            raise InvalidKeyTypeError(
                "%s is not a valid keytype. Valid keytypes are %s" % (
                    keytype, ", ".join(cls.__algorithm_parameters.keys())
                )
            )

        if not size:
            size = cls.__algorithm_parameters[keytype]['default_size']
        else:
            if size not in cls.__algorithm_parameters[keytype]['valid_sizes']:
                raise InvalidKeySizeError(
                    "%s is not a valid key size for %s keys" % (size, keytype)
                )

        if passphrase:
            validate_passphrase(passphrase)
            encryption_algorithm = serialization.BestAvailableEncryption(
                passphrase.encode(encoding=_TEXT_ENCODING)
            )
        else:
            encryption_algorithm = serialization.NoEncryption()

        if keytype == 'rsa':
            privatekey = rsa.generate_private_key(
                # Public exponent should always be 65537 to prevent issues
                # if improper padding is used during signing
                public_exponent=65537,
                key_size=size,
                backend=backend,
            )
        elif keytype == 'dsa':
            privatekey = dsa.generate_private_key(
                key_size=size,
                backend=backend,
            )
        elif keytype == 'ed25519':
            privatekey = Ed25519PrivateKey.generate()
        elif keytype == 'ecdsa':
            privatekey = ec.generate_private_key(
                cls.__algorithm_parameters['ecdsa']['curves'][size],
                backend=backend,
            )

        publickey = privatekey.public_key()

        return cls(
            keytype=keytype,
            size=size,
            privatekey=privatekey,
            publickey=publickey,
            encryption_algorithm=encryption_algorithm
        )

    @classmethod
    def load(cls, path, passphrase=None, key_format='PEM'):
        """Returns an Asymmetric_Keypair object loaded from the supplied file path

           :path: A path to an existing private key to be loaded
           :passphrase: Secret used to decrypt the private key being loaded
           :key_format: Format of key files to be loaded
        """

        if passphrase:
            validate_passphrase(passphrase)
            encryption_algorithm = serialization.BestAvailableEncryption(
                passphrase.encode(encoding=_TEXT_ENCODING)
            )
        else:
            encryption_algorithm = serialization.NoEncryption()

        privatekey = load_privatekey(path, passphrase, key_format)
        publickey = load_publickey(path, key_format)
        size = privatekey.key_size

        if isinstance(privatekey, rsa.RSAPrivateKey):
            keytype = 'rsa'
        elif isinstance(privatekey, dsa.DSAPrivateKey):
            keytype = 'dsa'
        elif isinstance(privatekey, ec.EllipticCurvePrivateKey):
            keytype = 'ecdsa'
        elif isinstance(privatekey, Ed25519PrivateKey):
            keytype = 'ed25519'

        return cls(
            keytype=keytype,
            size=size,
            privatekey=privatekey,
            publickey=publickey,
            encryption_algorithm=encryption_algorithm
        )

    def __init__(self, keytype, size, privatekey, publickey, encryption_algorithm):
        """
           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for the private key of this key pair
           :privatekey: Private key object of this key pair
           :publickey: Public key object of this key pair
           :encryption_algorithm: Hashed secret used to encrypt the private key of this key pair
        """

        self.__size = size
        self.__keytype = keytype
        self.__privatekey = privatekey
        self.__publickey = publickey
        self.__encryption_algorithm = encryption_algorithm

        if not self.verify(self.sign(b'message'), b'message'):
            raise InvalidPublicKeyFileError(
                "The private key and public key of this keypair do not match"
            )

    @property
    def private_key(self):
        """Returns the openssh formatted private key of this key pair"""

        return self.__privatekey

    @property
    def public_key(self):
        """Returns the openssh formatted public key of this key pair"""

        return self.__publickey

    @property
    def size(self):
        """Returns the size of the private key of this key pair"""

        return self.__size

    @property
    def key_type(self):
        """Returns the key type of this key pair"""

        return self.__keytype

    @property
    def encryption_algorithm(self):
        """Returns the key encryption algorithm of this key pair"""

        return self.__encryption_algorithm

    def sign(self, data):
        """Returns signature of data signed with the private key of this key pair

           :data: byteslike data to sign
        """

        try:
            signature = self.__privatekey.sign(
                data,
                **type(self).__algorithm_parameters[self.__keytype]['signer_params']
            )
        except TypeError as e:
            raise InvalidDataError(e)

        return signature

    def verify(self, signature, data):
        """Verifies that the signature associated with the provided data was signed
           by the private key of this key pair.

           :signature: signature to verify
           :data: byteslike data signed by the provided signature
        """

        try:
            self.__publickey.verify(
                signature,
                data,
                **type(self).__algorithm_parameters[self.__keytype]['signer_params']
            )
        except InvalidSignature:
            return False

        return True

    def update_passphrase(self, passphrase=None):
        """Updates the encryption algorithm of this key pair

           :passphrase: Text secret used to encrypt this key pair
        """

        if passphrase:
            validate_passphrase(passphrase)
            self.__encryption_algorithm = serialization.BestAvailableEncryption(passphrase.encode(encoding=_TEXT_ENCODING))
        else:
            self.__encryption_algorithm = serialization.NoEncryption()


class OpenSSH_Keypair(object):
    """Container for OpenSSH encoded asymmetric keypairs"""

    @classmethod
    def generate(cls, keytype='rsa', size=None, passphrase=None, comment=None):
        """Returns an Openssh_Keypair object generated using the supplied parameters or defaults to a RSA-2048 key

           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret used to encrypt the newly generated private key
           :comment: Comment for a newly generated OpenSSH public key
        """

        if not comment:
            comment = "%s@%s" % (getuser(), gethostname())

        asym_keypair = Asymmetric_Keypair.generate(keytype, size, passphrase)
        openssh_privatekey = cls.encode_openssh_privatekey(asym_keypair)
        openssh_publickey = cls.encode_openssh_publickey(asym_keypair, comment)
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment
        )

    @classmethod
    def load(cls, path, passphrase=None):
        """Returns an Openssh_Keypair object loaded from the supplied file path

           :path: A path to an existing private key to be loaded
           :passphrase: Secret used to decrypt the private key being loaded
        """

        comment = extract_comment(path)
        asym_keypair = Asymmetric_Keypair.load(path, passphrase, 'SSH')
        openssh_privatekey = cls.encode_openssh_privatekey(asym_keypair)
        openssh_publickey = cls.encode_openssh_publickey(asym_keypair, comment)
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment
        )

    @classmethod
    def encode_openssh_privatekey(cls, asym_keypair):
        """Returns an OpenSSH encoded private key for a given keypair

           :asym_keypair: Asymmetric_Keypair from the private key is extracted
        """

        # OpenSSH formatted private keys are not available in Cryptography <3.0
        try:
            privatekey_format = serialization.PrivateFormat.OpenSSH
        except AttributeError:
            privatekey_format = serialization.PrivateFormat.PKCS8

        encoded_privatekey = asym_keypair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=privatekey_format,
            encryption_algorithm=asym_keypair.encryption_algorithm
        )

        return encoded_privatekey

    @classmethod
    def encode_openssh_publickey(cls, asym_keypair, comment):
        """Returns an OpenSSH encoded public key for a given keypair

           :asym_keypair: Asymmetric_Keypair from the public key is extracted
           :comment: Comment to apply to the end of the returned OpenSSH encoded public key
        """
        encoded_publickey = asym_keypair.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        validate_comment(comment)

        encoded_publickey += (" %s" % comment).encode(encoding=_TEXT_ENCODING)

        return encoded_publickey

    def __init__(self, asym_keypair, openssh_privatekey, openssh_publickey, fingerprint, comment):
        """
           :asym_keypair: An Asymmetric_Keypair object from which the OpenSSH encoded keypair is derived
           :openssh_privatekey: An OpenSSH encoded private key
           :openssh_privatekey: An OpenSSH encoded public key
           :fingerprint: The fingerprint of the OpenSSH encoded public key of this keypair
           :comment: Comment applied to the OpenSSH public key of this keypair
        """

        self.__asym_keypair = asym_keypair
        self.__openssh_privatekey = openssh_privatekey
        self.__openssh_publickey = openssh_publickey
        self.__fingerprint = fingerprint
        self.__comment = comment

    def __eq__(self, other):
        return self.fingerprint == other.fingerprint and self.comment == other.comment

    @property
    def private_key(self):
        """Returns the OpenSSH formatted private key of this key pair"""

        return self.__openssh_privatekey

    @property
    def public_key(self):
        """Returns the OpenSSH formatted public key of this key pair"""

        return self.__openssh_publickey

    @property
    def size(self):
        """Returns the size of the private key of this key pair"""

        return self.__asym_keypair.size

    @property
    def key_type(self):
        """Returns the key encryption algorithm of this key pair"""

        return self.__asym_keypair.key_type

    @property
    def fingerprint(self):
        """Returns the fingerprint (SHA256 Hash) of the public key of this key pair"""

        return self.__fingerprint

    @property
    def comment(self):
        """Returns the comment applied to the OpenSSH formatted public key of this key pair"""

        return self.__comment

    @comment.setter
    def comment(self, comment):
        """Updates the comment applied to the OpenSSH formatted public key of this key pair

           :comment: Text to update the OpenSSH public key comment
        """

        validate_comment(comment)

        self.__comment = comment
        encoded_comment = (" %s" % self.__comment).encode(encoding=_TEXT_ENCODING)
        self.__openssh_publickey = b' '.join(self.__openssh_publickey.split(b' ', 2)[:2]) + encoded_comment
        return self.__openssh_publickey

    def update_passphrase(self, passphrase):
        """Updates the passphrase used to encrypt the private key of this keypair

           :passphrase: Text secret used for encryption
        """

        self.__asym_keypair.update_passphrase(passphrase)
        self.__openssh_privatekey = type(self).encode_openssh_privatekey(self.__asym_keypair)


def load_privatekey(path, passphrase, key_format):
    privatekey_loaders = {
        'PEM': serialization.load_pem_private_key,
        'DER': serialization.load_der_private_key,
    }

    # OpenSSH formatted private keys are not available in Cryptography <3.0
    if hasattr(serialization, 'load_ssh_private_key'):
        privatekey_loaders['SSH'] = serialization.load_ssh_private_key
    else:
        privatekey_loaders['SSH'] = serialization.load_pem_private_key

    try:
        privatekey_loader = privatekey_loaders[key_format]
    except KeyError:
        raise InvalidKeyFormatError(
            "%s is not a valid key format (%s)" % (
                key_format,
                ','.join(privatekey_loaders.keys())
            )
        )

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

    except ValueError as e:
        raise InvalidPrivateKeyFileError(e)
    except TypeError as e:
        raise InvalidPassphraseError(e)
    except UnsupportedAlgorithm as e:
        raise InvalidAlgorithmError(e)

    return privatekey


def load_publickey(path, key_format):
    publickey_loaders = {
        'PEM': serialization.load_pem_public_key,
        'DER': serialization.load_der_public_key,
        'SSH': serialization.load_ssh_public_key,
    }

    try:
        publickey_loader = publickey_loaders[key_format]
    except KeyError:
        raise InvalidKeyFormatError(
            "%s is not a valid key format (%s)" % (
                key_format,
                ','.join(publickey_loaders.keys())
            )
        )

    try:
        with open(path + '.pub', 'rb') as f:
            content = f.read()

            publickey = publickey_loader(
                data=content,
                backend=backend,
            )
    except ValueError as e:
        raise InvalidPublicKeyFileError(e)
    except UnsupportedAlgorithm as e:
        raise InvalidAlgorithmError(e)

    return publickey


def validate_passphrase(passphrase):
    if not hasattr(passphrase, 'encode'):
        raise InvalidPassphraseError("%s cannot be encoded to text" % passphrase)


def validate_comment(comment):
    if not hasattr(comment, 'encode'):
        raise InvalidCommentError("%s cannot be encoded to text" % comment)


def extract_comment(path):
    try:
        with open(path + '.pub', 'rb') as f:
            fields = f.read().split(b' ', 2)
            if len(fields) == 3:
                comment = fields[2].decode(_TEXT_ENCODING)
            else:
                comment = ""
    except OSError as e:
        raise InvalidPublicKeyFileError(e)

    return comment


def calculate_fingerprint(openssh_publickey):
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    decoded_pubkey = b64decode(openssh_publickey.split(b' ')[1])
    digest.update(decoded_pubkey)

    return b64encode(digest.finalize()).decode(encoding=_TEXT_ENCODING).rstrip('=')
