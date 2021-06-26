# -*- coding: utf-8 -*-
#
# (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
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
import datetime
import errno
import hashlib
import os
import re

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native, to_bytes

try:
    from OpenSSL import crypto
    HAS_PYOPENSSL = True
except ImportError:
    # Error handled in the calling module.
    HAS_PYOPENSSL = False

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend as cryptography_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import serialization
except ImportError:
    # Error handled in the calling module.
    pass

from .basic import (
    OpenSSLObjectError,
    OpenSSLBadPassphraseError,
)


# This list of preferred fingerprints is used when prefer_one=True is supplied to the
# fingerprinting methods.
PREFERRED_FINGERPRINTS = (
    'sha256', 'sha3_256', 'sha512', 'sha3_512', 'sha384', 'sha3_384', 'sha1', 'md5'
)


def get_fingerprint_of_bytes(source, prefer_one=False):
    """Generate the fingerprint of the given bytes."""

    fingerprint = {}

    try:
        algorithms = hashlib.algorithms
    except AttributeError:
        try:
            algorithms = hashlib.algorithms_guaranteed
        except AttributeError:
            return None

    if prefer_one:
        # Sort algorithms to have the ones in PREFERRED_FINGERPRINTS at the beginning
        prefered_algorithms = [algorithm for algorithm in PREFERRED_FINGERPRINTS if algorithm in algorithms]
        prefered_algorithms += sorted([algorithm for algorithm in algorithms if algorithm not in PREFERRED_FINGERPRINTS])
        algorithms = prefered_algorithms

    for algo in algorithms:
        f = getattr(hashlib, algo)
        try:
            h = f(source)
        except ValueError:
            # This can happen for hash algorithms not supported in FIPS mode
            # (https://github.com/ansible/ansible/issues/67213)
            continue
        try:
            # Certain hash functions have a hexdigest() which expects a length parameter
            pubkey_digest = h.hexdigest()
        except TypeError:
            pubkey_digest = h.hexdigest(32)
        fingerprint[algo] = ':'.join(pubkey_digest[i:i + 2] for i in range(0, len(pubkey_digest), 2))
        if prefer_one:
            break

    return fingerprint


def get_fingerprint_of_privatekey(privatekey, backend='pyopenssl', prefer_one=False):
    """Generate the fingerprint of the public key. """

    if backend == 'pyopenssl':
        try:
            publickey = crypto.dump_publickey(crypto.FILETYPE_ASN1, privatekey)
        except AttributeError:
            # If PyOpenSSL < 16.0 crypto.dump_publickey() will fail.
            try:
                bio = crypto._new_mem_buf()
                rc = crypto._lib.i2d_PUBKEY_bio(bio, privatekey._pkey)
                if rc != 1:
                    crypto._raise_current_error()
                publickey = crypto._bio_to_string(bio)
            except AttributeError:
                # By doing this we prevent the code from raising an error
                # yet we return no value in the fingerprint hash.
                return None
    elif backend == 'cryptography':
        publickey = privatekey.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

    return get_fingerprint_of_bytes(publickey, prefer_one=prefer_one)


def get_fingerprint(path, passphrase=None, content=None, backend='pyopenssl', prefer_one=False):
    """Generate the fingerprint of the public key. """

    privatekey = load_privatekey(path, passphrase=passphrase, content=content, check_passphrase=False, backend=backend)

    return get_fingerprint_of_privatekey(privatekey, backend=backend, prefer_one=prefer_one)


def load_privatekey(path, passphrase=None, check_passphrase=True, content=None, backend='pyopenssl'):
    """Load the specified OpenSSL private key.

    The content can also be specified via content; in that case,
    this function will not load the key from disk.
    """

    try:
        if content is None:
            with open(path, 'rb') as b_priv_key_fh:
                priv_key_detail = b_priv_key_fh.read()
        else:
            priv_key_detail = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)

    if backend == 'pyopenssl':

        # First try: try to load with real passphrase (resp. empty string)
        # Will work if this is the correct passphrase, or the key is not
        # password-protected.
        try:
            result = crypto.load_privatekey(crypto.FILETYPE_PEM,
                                            priv_key_detail,
                                            to_bytes(passphrase or ''))
        except crypto.Error as e:
            if len(e.args) > 0 and len(e.args[0]) > 0:
                if e.args[0][0][2] in ('bad decrypt', 'bad password read'):
                    # This happens in case we have the wrong passphrase.
                    if passphrase is not None:
                        raise OpenSSLBadPassphraseError('Wrong passphrase provided for private key!')
                    else:
                        raise OpenSSLBadPassphraseError('No passphrase provided, but private key is password-protected!')
            raise OpenSSLObjectError('Error while deserializing key: {0}'.format(e))
        if check_passphrase:
            # Next we want to make sure that the key is actually protected by
            # a passphrase (in case we did try the empty string before, make
            # sure that the key is not protected by the empty string)
            try:
                crypto.load_privatekey(crypto.FILETYPE_PEM,
                                       priv_key_detail,
                                       to_bytes('y' if passphrase == 'x' else 'x'))
                if passphrase is not None:
                    # Since we can load the key without an exception, the
                    # key isn't password-protected
                    raise OpenSSLBadPassphraseError('Passphrase provided, but private key is not password-protected!')
            except crypto.Error as e:
                if passphrase is None and len(e.args) > 0 and len(e.args[0]) > 0:
                    if e.args[0][0][2] in ('bad decrypt', 'bad password read'):
                        # The key is obviously protected by the empty string.
                        # Don't do this at home (if it's possible at all)...
                        raise OpenSSLBadPassphraseError('No passphrase provided, but private key is password-protected!')
    elif backend == 'cryptography':
        try:
            result = load_pem_private_key(priv_key_detail,
                                          None if passphrase is None else to_bytes(passphrase),
                                          cryptography_backend())
        except TypeError:
            raise OpenSSLBadPassphraseError('Wrong or empty passphrase provided for private key')
        except ValueError:
            raise OpenSSLBadPassphraseError('Wrong passphrase provided for private key')

    return result


def load_publickey(path=None, content=None, backend=None):
    if content is None:
        if path is None:
            raise OpenSSLObjectError('Must provide either path or content')
        try:
            with open(path, 'rb') as b_priv_key_fh:
                content = b_priv_key_fh.read()
        except (IOError, OSError) as exc:
            raise OpenSSLObjectError(exc)

    if backend == 'cryptography':
        try:
            return serialization.load_pem_public_key(content, backend=cryptography_backend())
        except Exception as e:
            raise OpenSSLObjectError('Error while deserializing key: {0}'.format(e))
    else:
        try:
            return crypto.load_publickey(crypto.FILETYPE_PEM, content)
        except crypto.Error as e:
            raise OpenSSLObjectError('Error while deserializing key: {0}'.format(e))


def load_certificate(path, content=None, backend='pyopenssl'):
    """Load the specified certificate."""

    try:
        if content is None:
            with open(path, 'rb') as cert_fh:
                cert_content = cert_fh.read()
        else:
            cert_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)
    if backend == 'pyopenssl':
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_content)
    elif backend == 'cryptography':
        try:
            return x509.load_pem_x509_certificate(cert_content, cryptography_backend())
        except ValueError as exc:
            raise OpenSSLObjectError(exc)


def load_certificate_request(path, content=None, backend='pyopenssl'):
    """Load the specified certificate signing request."""
    try:
        if content is None:
            with open(path, 'rb') as csr_fh:
                csr_content = csr_fh.read()
        else:
            csr_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)
    if backend == 'pyopenssl':
        return crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_content)
    elif backend == 'cryptography':
        try:
            return x509.load_pem_x509_csr(csr_content, cryptography_backend())
        except ValueError as exc:
            raise OpenSSLObjectError(exc)


def parse_name_field(input_dict):
    """Take a dict with key: value or key: list_of_values mappings and return a list of tuples"""

    result = []
    for key in input_dict:
        if isinstance(input_dict[key], list):
            for entry in input_dict[key]:
                result.append((key, entry))
        else:
            result.append((key, input_dict[key]))
    return result


def convert_relative_to_datetime(relative_time_string):
    """Get a datetime.datetime or None from a string in the time format described in sshd_config(5)"""

    parsed_result = re.match(
        r"^(?P<prefix>[+-])((?P<weeks>\d+)[wW])?((?P<days>\d+)[dD])?((?P<hours>\d+)[hH])?((?P<minutes>\d+)[mM])?((?P<seconds>\d+)[sS]?)?$",
        relative_time_string)

    if parsed_result is None or len(relative_time_string) == 1:
        # not matched or only a single "+" or "-"
        return None

    offset = datetime.timedelta(0)
    if parsed_result.group("weeks") is not None:
        offset += datetime.timedelta(weeks=int(parsed_result.group("weeks")))
    if parsed_result.group("days") is not None:
        offset += datetime.timedelta(days=int(parsed_result.group("days")))
    if parsed_result.group("hours") is not None:
        offset += datetime.timedelta(hours=int(parsed_result.group("hours")))
    if parsed_result.group("minutes") is not None:
        offset += datetime.timedelta(
            minutes=int(parsed_result.group("minutes")))
    if parsed_result.group("seconds") is not None:
        offset += datetime.timedelta(
            seconds=int(parsed_result.group("seconds")))

    if parsed_result.group("prefix") == "+":
        return datetime.datetime.utcnow() + offset
    else:
        return datetime.datetime.utcnow() - offset


def get_relative_time_option(input_string, input_name, backend='cryptography'):
    """Return an absolute timespec if a relative timespec or an ASN1 formatted
       string is provided.

       The return value will be a datetime object for the cryptography backend,
       and a ASN1 formatted string for the pyopenssl backend."""
    result = to_native(input_string)
    if result is None:
        raise OpenSSLObjectError(
            'The timespec "%s" for %s is not valid' %
            input_string, input_name)
    # Relative time
    if result.startswith("+") or result.startswith("-"):
        result_datetime = convert_relative_to_datetime(result)
        if backend == 'pyopenssl':
            return result_datetime.strftime("%Y%m%d%H%M%SZ")
        elif backend == 'cryptography':
            return result_datetime
    # Absolute time
    if backend == 'pyopenssl':
        return input_string
    elif backend == 'cryptography':
        for date_fmt in ['%Y%m%d%H%M%SZ', '%Y%m%d%H%MZ', '%Y%m%d%H%M%S%z', '%Y%m%d%H%M%z']:
            try:
                return datetime.datetime.strptime(result, date_fmt)
            except ValueError:
                pass

        raise OpenSSLObjectError(
            'The time spec "%s" for %s is invalid' %
            (input_string, input_name)
        )


def select_message_digest(digest_string):
    digest = None
    if digest_string == 'sha256':
        digest = hashes.SHA256()
    elif digest_string == 'sha384':
        digest = hashes.SHA384()
    elif digest_string == 'sha512':
        digest = hashes.SHA512()
    elif digest_string == 'sha1':
        digest = hashes.SHA1()
    elif digest_string == 'md5':
        digest = hashes.MD5()
    return digest


@six.add_metaclass(abc.ABCMeta)
class OpenSSLObject(object):

    def __init__(self, path, state, force, check_mode):
        self.path = path
        self.state = state
        self.force = force
        self.name = os.path.basename(path)
        self.changed = False
        self.check_mode = check_mode

    def check(self, module, perms_required=True):
        """Ensure the resource is in its desired state."""

        def _check_state():
            return os.path.exists(self.path)

        def _check_perms(module):
            file_args = module.load_file_common_arguments(module.params)
            if module.check_file_absent_if_check_mode(file_args['path']):
                return False
            return not module.set_fs_attributes_if_different(file_args, False)

        if not perms_required:
            return _check_state()

        return _check_state() and _check_perms(module)

    @abc.abstractmethod
    def dump(self):
        """Serialize the object into a dictionary."""

        pass

    @abc.abstractmethod
    def generate(self):
        """Generate the resource."""

        pass

    def remove(self, module):
        """Remove the resource from the filesystem."""
        if self.check_mode:
            if os.path.exists(self.path):
                self.changed = True
            return

        try:
            os.remove(self.path)
            self.changed = True
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise OpenSSLObjectError(exc)
            else:
                pass
