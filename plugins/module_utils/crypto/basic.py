# -*- coding: utf-8 -*-
#
# (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# (c) 2020, Felix Fontein <felix@fontein.de>
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


import errno
import os
import tempfile

from distutils.version import LooseVersion

try:
    import OpenSSL  # noqa
    from OpenSSL import crypto  # noqa
    HAS_PYOPENSSL = True
except ImportError:
    # Error handled in the calling module.
    HAS_PYOPENSSL = False

try:
    import cryptography
    from cryptography import x509

    # Older versions of cryptography (< 2.1) do not have __hash__ functions for
    # general name objects (DNSName, IPAddress, ...), while providing overloaded
    # equality and string representation operations. This makes it impossible to
    # use them in hash-based data structures such as set or dict. Since we are
    # actually doing that in x509_certificate, and potentially in other code,
    # we need to monkey-patch __hash__ for these classes to make sure our code
    # works fine.
    if LooseVersion(cryptography.__version__) < LooseVersion('2.1'):
        # A very simply hash function which relies on the representation
        # of an object to be implemented. This is the case since at least
        # cryptography 1.0, see
        # https://github.com/pyca/cryptography/commit/7a9abce4bff36c05d26d8d2680303a6f64a0e84f
        def simple_hash(self):
            return hash(repr(self))

        # The hash functions for the following types were added for cryptography 2.1:
        # https://github.com/pyca/cryptography/commit/fbfc36da2a4769045f2373b004ddf0aff906cf38
        x509.DNSName.__hash__ = simple_hash
        x509.DirectoryName.__hash__ = simple_hash
        x509.GeneralName.__hash__ = simple_hash
        x509.IPAddress.__hash__ = simple_hash
        x509.OtherName.__hash__ = simple_hash
        x509.RegisteredID.__hash__ = simple_hash

        if LooseVersion(cryptography.__version__) < LooseVersion('1.2'):
            # The hash functions for the following types were added for cryptography 1.2:
            # https://github.com/pyca/cryptography/commit/b642deed88a8696e5f01ce6855ccf89985fc35d0
            # https://github.com/pyca/cryptography/commit/d1b5681f6db2bde7a14625538bd7907b08dfb486
            x509.RFC822Name.__hash__ = simple_hash
            x509.UniformResourceIdentifier.__hash__ = simple_hash

    # Test whether we have support for X25519, X448, Ed25519 and/or Ed448
    try:
        import cryptography.hazmat.primitives.asymmetric.x25519
        CRYPTOGRAPHY_HAS_X25519 = True
        try:
            cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.private_bytes
            CRYPTOGRAPHY_HAS_X25519_FULL = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_X25519_FULL = False
    except ImportError:
        CRYPTOGRAPHY_HAS_X25519 = False
        CRYPTOGRAPHY_HAS_X25519_FULL = False
    try:
        import cryptography.hazmat.primitives.asymmetric.x448
        CRYPTOGRAPHY_HAS_X448 = True
    except ImportError:
        CRYPTOGRAPHY_HAS_X448 = False
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519
        CRYPTOGRAPHY_HAS_ED25519 = True
    except ImportError:
        CRYPTOGRAPHY_HAS_ED25519 = False
    try:
        import cryptography.hazmat.primitives.asymmetric.ed448
        CRYPTOGRAPHY_HAS_ED448 = True
    except ImportError:
        CRYPTOGRAPHY_HAS_ED448 = False

    HAS_CRYPTOGRAPHY = True
except ImportError:
    # Error handled in the calling module.
    CRYPTOGRAPHY_HAS_X25519 = False
    CRYPTOGRAPHY_HAS_X25519_FULL = False
    CRYPTOGRAPHY_HAS_X448 = False
    CRYPTOGRAPHY_HAS_ED25519 = False
    CRYPTOGRAPHY_HAS_ED448 = False
    HAS_CRYPTOGRAPHY = False


class OpenSSLObjectError(Exception):
    pass


class OpenSSLBadPassphraseError(OpenSSLObjectError):
    pass


def load_file_if_exists(path, module=None, ignore_errors=False):
    try:
        with open(path, 'rb') as f:
            return f.read()
    except EnvironmentError as exc:
        if exc.errno == errno.ENOENT:
            return None
        if ignore_errors:
            return None
        if module is None:
            raise
        module.fail_json('Error while loading {0} - {1}'.format(path, str(exc)))
    except Exception as exc:
        if ignore_errors:
            return None
        if module is None:
            raise
        module.fail_json('Error while loading {0} - {1}'.format(path, str(exc)))


def write_file(module, content, default_mode=None, path=None):
    '''
    Writes content into destination file as securely as possible.
    Uses file arguments from module.
    '''
    # Find out parameters for file
    try:
        file_args = module.load_file_common_arguments(module.params, path=path)
    except TypeError:
        # The path argument is only supported in Ansible 2.10+. Fall back to
        # pre-2.10 behavior of module_utils/crypto.py for older Ansible versions.
        file_args = module.load_file_common_arguments(module.params)
        if path is not None:
            file_args['path'] = path
    if file_args['mode'] is None:
        file_args['mode'] = default_mode
    # Create tempfile name
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=b'.ansible_tmp')
    try:
        os.close(tmp_fd)
    except Exception:
        pass
    module.add_cleanup_file(tmp_name)  # if we fail, let Ansible try to remove the file
    try:
        try:
            # Create tempfile
            file = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(file, content)
            os.close(file)
        except Exception as e:
            try:
                os.remove(tmp_name)
            except Exception:
                pass
            module.fail_json(msg='Error while writing result into temporary file: {0}'.format(e))
        # Update destination to wanted permissions
        if os.path.exists(file_args['path']):
            module.set_fs_attributes_if_different(file_args, False)
        # Move tempfile to final destination
        module.atomic_move(tmp_name, file_args['path'])
        # Try to update permissions again
        module.set_fs_attributes_if_different(file_args, False)
    except Exception as e:
        try:
            os.remove(tmp_name)
        except Exception:
            pass
        module.fail_json(msg='Error while writing result: {0}'.format(e))
