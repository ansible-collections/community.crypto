# -*- coding: utf-8 -*-
#
# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import abc
import errno
import hashlib
import os

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_bytes
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_pem_format,
)

# These imports are for backwards compatibility:
from ansible_collections.community.crypto.plugins.module_utils.time import (  # noqa: F401, pylint: disable=unused-import
    convert_relative_to_datetime,
    ensure_utc_timezone,
    get_now_datetime,
    get_relative_time_option,
)


try:
    from OpenSSL import crypto

    HAS_PYOPENSSL = True
except (ImportError, AttributeError):
    # Error handled in the calling module.
    HAS_PYOPENSSL = False

try:
    from cryptography import x509
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.backends import default_backend as cryptography_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
except ImportError:
    # Error handled in the calling module.
    pass

from .basic import OpenSSLBadPassphraseError, OpenSSLObjectError


# This list of preferred fingerprints is used when prefer_one=True is supplied to the
# fingerprinting methods.
PREFERRED_FINGERPRINTS = (
    "sha256",
    "sha3_256",
    "sha512",
    "sha3_512",
    "sha384",
    "sha3_384",
    "sha1",
    "md5",
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
        prefered_algorithms = [
            algorithm for algorithm in PREFERRED_FINGERPRINTS if algorithm in algorithms
        ]
        prefered_algorithms += sorted(
            [
                algorithm
                for algorithm in algorithms
                if algorithm not in PREFERRED_FINGERPRINTS
            ]
        )
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
        fingerprint[algo] = ":".join(
            pubkey_digest[i : i + 2] for i in range(0, len(pubkey_digest), 2)
        )
        if prefer_one:
            break

    return fingerprint


def get_fingerprint_of_privatekey(privatekey, backend="cryptography", prefer_one=False):
    """Generate the fingerprint of the public key."""

    if backend == "cryptography":
        publickey = privatekey.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    return get_fingerprint_of_bytes(publickey, prefer_one=prefer_one)


def get_fingerprint(
    path, passphrase=None, content=None, backend="cryptography", prefer_one=False
):
    """Generate the fingerprint of the public key."""

    privatekey = load_privatekey(
        path,
        passphrase=passphrase,
        content=content,
        check_passphrase=False,
        backend=backend,
    )

    return get_fingerprint_of_privatekey(
        privatekey, backend=backend, prefer_one=prefer_one
    )


def load_privatekey(
    path, passphrase=None, check_passphrase=True, content=None, backend="cryptography"
):
    """Load the specified OpenSSL private key.

    The content can also be specified via content; in that case,
    this function will not load the key from disk.
    """

    try:
        if content is None:
            with open(path, "rb") as b_priv_key_fh:
                priv_key_detail = b_priv_key_fh.read()
        else:
            priv_key_detail = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)

    if backend == "pyopenssl":

        # First try: try to load with real passphrase (resp. empty string)
        # Will work if this is the correct passphrase, or the key is not
        # password-protected.
        try:
            result = crypto.load_privatekey(
                crypto.FILETYPE_PEM, priv_key_detail, to_bytes(passphrase or "")
            )
        except crypto.Error as e:
            if len(e.args) > 0 and len(e.args[0]) > 0:
                if e.args[0][0][2] in ("bad decrypt", "bad password read"):
                    # This happens in case we have the wrong passphrase.
                    if passphrase is not None:
                        raise OpenSSLBadPassphraseError(
                            "Wrong passphrase provided for private key!"
                        )
                    else:
                        raise OpenSSLBadPassphraseError(
                            "No passphrase provided, but private key is password-protected!"
                        )
            raise OpenSSLObjectError("Error while deserializing key: {0}".format(e))
        if check_passphrase:
            # Next we want to make sure that the key is actually protected by
            # a passphrase (in case we did try the empty string before, make
            # sure that the key is not protected by the empty string)
            try:
                crypto.load_privatekey(
                    crypto.FILETYPE_PEM,
                    priv_key_detail,
                    to_bytes("y" if passphrase == "x" else "x"),
                )
                if passphrase is not None:
                    # Since we can load the key without an exception, the
                    # key is not password-protected
                    raise OpenSSLBadPassphraseError(
                        "Passphrase provided, but private key is not password-protected!"
                    )
            except crypto.Error as e:
                if passphrase is None and len(e.args) > 0 and len(e.args[0]) > 0:
                    if e.args[0][0][2] in ("bad decrypt", "bad password read"):
                        # The key is obviously protected by the empty string.
                        # Do not do this at home (if it is possible at all)...
                        raise OpenSSLBadPassphraseError(
                            "No passphrase provided, but private key is password-protected!"
                        )
    elif backend == "cryptography":
        try:
            result = load_pem_private_key(
                priv_key_detail,
                None if passphrase is None else to_bytes(passphrase),
                cryptography_backend(),
            )
        except UnsupportedAlgorithm as exc:
            raise OpenSSLBadPassphraseError("Unsupported private key type: {exc}".format(exc=exc))
        except TypeError:
            raise OpenSSLBadPassphraseError(
                "Wrong or empty passphrase provided for private key"
            )
        except ValueError as exc:
            raise OpenSSLBadPassphraseError(
                "Wrong passphrase provided for private key, or private key cannot be parsed: {exc}".format(exc=exc)
            )

    return result


def load_publickey(path=None, content=None, backend=None):
    if content is None:
        if path is None:
            raise OpenSSLObjectError("Must provide either path or content")
        try:
            with open(path, "rb") as b_priv_key_fh:
                content = b_priv_key_fh.read()
        except (IOError, OSError) as exc:
            raise OpenSSLObjectError(exc)

    if backend == "cryptography":
        try:
            return serialization.load_pem_public_key(
                content, backend=cryptography_backend()
            )
        except Exception as e:
            raise OpenSSLObjectError("Error while deserializing key: {0}".format(e))


def load_certificate(
    path, content=None, backend="cryptography", der_support_enabled=False
):
    """Load the specified certificate."""

    try:
        if content is None:
            with open(path, "rb") as cert_fh:
                cert_content = cert_fh.read()
        else:
            cert_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)
    if backend == "pyopenssl":
        if der_support_enabled is False or identify_pem_format(cert_content):
            return crypto.load_certificate(crypto.FILETYPE_PEM, cert_content)
        elif der_support_enabled:
            raise OpenSSLObjectError(
                "Certificate in DER format is not supported by the pyopenssl backend."
            )
    elif backend == "cryptography":
        if der_support_enabled is False or identify_pem_format(cert_content):
            try:
                return x509.load_pem_x509_certificate(
                    cert_content, cryptography_backend()
                )
            except ValueError as exc:
                raise OpenSSLObjectError(exc)
        elif der_support_enabled:
            try:
                return x509.load_der_x509_certificate(
                    cert_content, cryptography_backend()
                )
            except ValueError as exc:
                raise OpenSSLObjectError(
                    "Cannot parse DER certificate: {0}".format(exc)
                )


def load_certificate_request(path, content=None, backend="cryptography"):
    """Load the specified certificate signing request."""
    try:
        if content is None:
            with open(path, "rb") as csr_fh:
                csr_content = csr_fh.read()
        else:
            csr_content = content
    except (IOError, OSError) as exc:
        raise OpenSSLObjectError(exc)
    if backend == "cryptography":
        try:
            return x509.load_pem_x509_csr(csr_content, cryptography_backend())
        except ValueError as exc:
            raise OpenSSLObjectError(exc)


def parse_name_field(input_dict, name_field_name=None):
    """Take a dict with key: value or key: list_of_values mappings and return a list of tuples"""
    error_str = "{key}" if name_field_name is None else "{key} in {name}"

    result = []
    for key, value in input_dict.items():
        if isinstance(value, list):
            for entry in value:
                if not isinstance(entry, six.string_types):
                    raise TypeError(
                        ("Values %s must be strings" % error_str).format(
                            key=key, name=name_field_name
                        )
                    )
                if not entry:
                    raise ValueError(
                        ("Values for %s must not be empty strings" % error_str).format(
                            key=key
                        )
                    )
                result.append((key, entry))
        elif isinstance(value, six.string_types):
            if not value:
                raise ValueError(
                    ("Value for %s must not be an empty string" % error_str).format(
                        key=key
                    )
                )
            result.append((key, value))
        else:
            raise TypeError(
                (
                    "Value for %s must be either a string or a list of strings"
                    % error_str
                ).format(key=key)
            )
    return result


def parse_ordered_name_field(input_list, name_field_name):
    """Take a dict with key: value or key: list_of_values mappings and return a list of tuples"""

    result = []
    for index, entry in enumerate(input_list):
        if len(entry) != 1:
            raise ValueError(
                "Entry #{index} in {name} must be a dictionary with exactly one key-value pair".format(
                    name=name_field_name, index=index + 1
                )
            )
        try:
            result.extend(parse_name_field(entry, name_field_name=name_field_name))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Error while processing entry #{index} in {name}: {error}".format(
                    name=name_field_name, index=index + 1, error=exc
                )
            )
    return result


def select_message_digest(digest_string):
    digest = None
    if digest_string == "sha256":
        digest = hashes.SHA256()
    elif digest_string == "sha384":
        digest = hashes.SHA384()
    elif digest_string == "sha512":
        digest = hashes.SHA512()
    elif digest_string == "sha1":
        digest = hashes.SHA1()
    elif digest_string == "md5":
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
            if module.check_file_absent_if_check_mode(file_args["path"]):
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
