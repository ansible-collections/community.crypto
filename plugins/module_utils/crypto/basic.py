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
