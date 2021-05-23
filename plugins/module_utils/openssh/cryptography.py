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

import os
from base64 import b64encode, b64decode
from distutils.version import LooseVersion
from getpass import getuser
from socket import gethostname

try:
    from cryptography import __version__ as CRYPTOGRAPHY_VERSION
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.backends.openssl import backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, padding
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    if LooseVersion(CRYPTOGRAPHY_VERSION) >= LooseVersion("3.0"):
        HAS_OPENSSH_PRIVATE_FORMAT = True
    else:
        HAS_OPENSSH_PRIVATE_FORMAT = False

    HAS_OPENSSH_SUPPORT = True

    _ALGORITHM_PARAMETERS = {
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
except ImportError:
    HAS_OPENSSH_PRIVATE_FORMAT = False
    HAS_OPENSSH_SUPPORT = False
    CRYPTOGRAPHY_VERSION = "0.0"
    _ALGORITHM_PARAMETERS = {}

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


class InvalidSignatureError(OpenSSHError):
    pass


class AsymmetricKeypair(object):
    """Container for newly generated asymmetric key pairs or those loaded from existing files"""

    @classmethod
    def generate(cls, keytype='rsa', size=None, passphrase=None):
        """Returns an Asymmetric_Keypair object generated with the supplied parameters
           or defaults to an unencrypted RSA-2048 key

           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret of type Bytes used to encrypt the private key being generated
        """

        if keytype not in _ALGORITHM_PARAMETERS.keys():
            raise InvalidKeyTypeError(
                "%s is not a valid keytype. Valid keytypes are %s" % (
                    keytype, ", ".join(_ALGORITHM_PARAMETERS.keys())
                )
            )

        if not size:
            size = _ALGORITHM_PARAMETERS[keytype]['default_size']
        else:
            if size not in _ALGORITHM_PARAMETERS[keytype]['valid_sizes']:
                raise InvalidKeySizeError(
                    "%s is not a valid key size for %s keys" % (size, keytype)
                )

        if passphrase:
            encryption_algorithm = get_encryption_algorithm(passphrase)
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
                _ALGORITHM_PARAMETERS['ecdsa']['curves'][size],
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
    def load(cls, path, passphrase=None, private_key_format='PEM', public_key_format='PEM', no_public_key=False):
        """Returns an Asymmetric_Keypair object loaded from the supplied file path

           :path: A path to an existing private key to be loaded
           :passphrase: Secret of type bytes used to decrypt the private key being loaded
           :private_key_format: Format of private key to be loaded
           :public_key_format: Format of public key to be loaded
           :no_public_key: Set 'True' to only load a private key and automatically populate the matching public key
        """

        if passphrase:
            encryption_algorithm = get_encryption_algorithm(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()

        privatekey = load_privatekey(path, passphrase, private_key_format)
        if no_public_key:
            publickey = privatekey.public_key()
        else:
            publickey = load_publickey(path + '.pub', public_key_format)

        # Ed25519 keys are always of size 256 and do not have a key_size attribute
        if isinstance(privatekey, Ed25519PrivateKey):
            size = _ALGORITHM_PARAMETERS['ed25519']['default_size']
        else:
            size = privatekey.key_size

        if isinstance(privatekey, rsa.RSAPrivateKey):
            keytype = 'rsa'
        elif isinstance(privatekey, dsa.DSAPrivateKey):
            keytype = 'dsa'
        elif isinstance(privatekey, ec.EllipticCurvePrivateKey):
            keytype = 'ecdsa'
        elif isinstance(privatekey, Ed25519PrivateKey):
            keytype = 'ed25519'
        else:
            raise InvalidKeyTypeError("Key type '%s' is not supported" % type(privatekey))

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

        try:
            self.verify(self.sign(b'message'), b'message')
        except InvalidSignatureError:
            raise InvalidPublicKeyFileError(
                "The private key and public key of this keypair do not match"
            )

    def __eq__(self, other):
        if not isinstance(other, AsymmetricKeypair):
            return NotImplemented

        return (compare_publickeys(self.public_key, other.public_key) and
                compare_encryption_algorithms(self.encryption_algorithm, other.encryption_algorithm))

    def __ne__(self, other):
        return not self == other

    @property
    def private_key(self):
        """Returns the private key of this key pair"""

        return self.__privatekey

    @property
    def public_key(self):
        """Returns the public key of this key pair"""

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
                **_ALGORITHM_PARAMETERS[self.__keytype]['signer_params']
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
            return self.__publickey.verify(
                signature,
                data,
                **_ALGORITHM_PARAMETERS[self.__keytype]['signer_params']
            )
        except InvalidSignature:
            raise InvalidSignatureError

    def update_passphrase(self, passphrase=None):
        """Updates the encryption algorithm of this key pair

           :passphrase: Byte secret used to encrypt this key pair
        """

        if passphrase:
            self.__encryption_algorithm = get_encryption_algorithm(passphrase)
        else:
            self.__encryption_algorithm = serialization.NoEncryption()


class OpensshKeypair(object):
    """Container for OpenSSH encoded asymmetric key pairs"""

    @classmethod
    def generate(cls, keytype='rsa', size=None, passphrase=None, comment=None):
        """Returns an Openssh_Keypair object generated using the supplied parameters or defaults to a RSA-2048 key

           :keytype: One of rsa, dsa, ecdsa, ed25519
           :size: The key length for newly generated keys
           :passphrase: Secret of type Bytes used to encrypt the newly generated private key
           :comment: Comment for a newly generated OpenSSH public key
        """

        if comment is None:
            comment = "%s@%s" % (getuser(), gethostname())

        asym_keypair = AsymmetricKeypair.generate(keytype, size, passphrase)
        openssh_privatekey = cls.encode_openssh_privatekey(asym_keypair, 'SSH')
        openssh_publickey = cls.encode_openssh_publickey(asym_keypair, comment)
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment,
        )

    @classmethod
    def load(cls, path, passphrase=None, no_public_key=False):
        """Returns an Openssh_Keypair object loaded from the supplied file path

           :path: A path to an existing private key to be loaded
           :passphrase: Secret used to decrypt the private key being loaded
           :no_public_key: Set 'True' to only load a private key and automatically populate the matching public key
        """

        if no_public_key:
            comment = ""
        else:
            comment = extract_comment(path + '.pub')

        asym_keypair = AsymmetricKeypair.load(path, passphrase, 'SSH', 'SSH', no_public_key)
        openssh_privatekey = cls.encode_openssh_privatekey(asym_keypair, 'SSH')
        openssh_publickey = cls.encode_openssh_publickey(asym_keypair, comment)
        fingerprint = calculate_fingerprint(openssh_publickey)

        return cls(
            asym_keypair=asym_keypair,
            openssh_privatekey=openssh_privatekey,
            openssh_publickey=openssh_publickey,
            fingerprint=fingerprint,
            comment=comment,
        )

    @staticmethod
    def encode_openssh_privatekey(asym_keypair, key_format):
        """Returns an OpenSSH encoded private key for a given keypair

           :asym_keypair: Asymmetric_Keypair from the private key is extracted
           :key_format: Format of the encoded private key.
        """

        if key_format == 'SSH':
            # Default to PEM format if SSH not available
            if not HAS_OPENSSH_PRIVATE_FORMAT:
                privatekey_format = serialization.PrivateFormat.PKCS8
            else:
                privatekey_format = serialization.PrivateFormat.OpenSSH
        elif key_format == 'PKCS8':
            privatekey_format = serialization.PrivateFormat.PKCS8
        elif key_format == 'PKCS1':
            if asym_keypair.key_type == 'ed25519':
                raise InvalidKeyFormatError("ed25519 keys cannot be represented in PKCS1 format")
            privatekey_format = serialization.PrivateFormat.TraditionalOpenSSL
        else:
            raise InvalidKeyFormatError("The accepted private key formats are SSH, PKCS8, and PKCS1")

        encoded_privatekey = asym_keypair.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=privatekey_format,
            encryption_algorithm=asym_keypair.encryption_algorithm
        )

        return encoded_privatekey

    @staticmethod
    def encode_openssh_publickey(asym_keypair, comment):
        """Returns an OpenSSH encoded public key for a given keypair

           :asym_keypair: Asymmetric_Keypair from the public key is extracted
           :comment: Comment to apply to the end of the returned OpenSSH encoded public key
        """
        encoded_publickey = asym_keypair.public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )

        validate_comment(comment)

        encoded_publickey += (" %s" % comment).encode(encoding=_TEXT_ENCODING) if comment else b''

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
        if not isinstance(other, OpensshKeypair):
            return NotImplemented

        return self.asymmetric_keypair == other.asymmetric_keypair and self.comment == other.comment

    @property
    def asymmetric_keypair(self):
        """Returns the underlying asymmetric key pair of this OpenSSH encoded key pair"""

        return self.__asym_keypair

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
        """Returns the key type of this key pair"""

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
        encoded_comment = (" %s" % self.__comment).encode(encoding=_TEXT_ENCODING) if self.__comment else b''
        self.__openssh_publickey = b' '.join(self.__openssh_publickey.split(b' ', 2)[:2]) + encoded_comment
        return self.__openssh_publickey

    def update_passphrase(self, passphrase):
        """Updates the passphrase used to encrypt the private key of this keypair

           :passphrase: Text secret used for encryption
        """

        self.__asym_keypair.update_passphrase(passphrase)
        self.__openssh_privatekey = OpensshKeypair.encode_openssh_privatekey(self.__asym_keypair, 'SSH')


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

    if not os.path.exists(path):
        raise InvalidPrivateKeyFileError("No file was found at %s" % path)

    try:
        with open(path, 'rb') as f:
            content = f.read()

            privatekey = privatekey_loader(
                data=content,
                password=passphrase,
                backend=backend,
            )

    except ValueError as e:
        # Revert to PEM if key could not be loaded in SSH format
        if key_format == 'SSH':
            try:
                privatekey = privatekey_loaders['PEM'](
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
        else:
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

    if not os.path.exists(path):
        raise InvalidPublicKeyFileError("No file was found at %s" % path)

    try:
        with open(path, 'rb') as f:
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


def compare_publickeys(pk1, pk2):
    a = isinstance(pk1, Ed25519PublicKey)
    b = isinstance(pk2, Ed25519PublicKey)
    if a or b:
        if not a or not b:
            return False
        a = pk1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        b = pk2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return a == b
    else:
        return pk1.public_numbers() == pk2.public_numbers()


def compare_encryption_algorithms(ea1, ea2):
    if isinstance(ea1, serialization.NoEncryption) and isinstance(ea2, serialization.NoEncryption):
        return True
    elif (isinstance(ea1, serialization.BestAvailableEncryption) and
          isinstance(ea2, serialization.BestAvailableEncryption)):
        return ea1.password == ea2.password
    else:
        return False


def get_encryption_algorithm(passphrase):
    try:
        return serialization.BestAvailableEncryption(passphrase)
    except ValueError as e:
        raise InvalidPassphraseError(e)


def validate_comment(comment):
    if not hasattr(comment, 'encode'):
        raise InvalidCommentError("%s cannot be encoded to text" % comment)


def extract_comment(path):

    if not os.path.exists(path):
        raise InvalidPublicKeyFileError("No file was found at %s" % path)

    try:
        with open(path, 'rb') as f:
            fields = f.read().split(b' ', 2)
            if len(fields) == 3:
                comment = fields[2].decode(_TEXT_ENCODING)
            else:
                comment = ""
    except (IOError, OSError) as e:
        raise InvalidPublicKeyFileError(e)

    return comment


def calculate_fingerprint(openssh_publickey):
    digest = hashes.Hash(hashes.SHA256(), backend=backend)
    decoded_pubkey = b64decode(openssh_publickey.split(b' ')[1])
    digest.update(decoded_pubkey)

    return 'SHA256:%s' % b64encode(digest.finalize()).decode(encoding=_TEXT_ENCODING).rstrip('=')
