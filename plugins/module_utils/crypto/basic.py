# -*- coding: utf-8 -*-
#
# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

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

    # Test whether we have support for DSA, EC, Ed25519, Ed448, RSA, X25519 and/or X448
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/dsa/
        import cryptography.hazmat.primitives.asymmetric.dsa
        CRYPTOGRAPHY_HAS_DSA = True
        try:
            # added later in 1.5
            cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey.sign
            CRYPTOGRAPHY_HAS_DSA_SIGN = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_DSA_SIGN = False
    except ImportError:
        CRYPTOGRAPHY_HAS_DSA = False
        CRYPTOGRAPHY_HAS_DSA_SIGN = False
    try:
        # added in 2.6 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
        import cryptography.hazmat.primitives.asymmetric.ed25519
        CRYPTOGRAPHY_HAS_ED25519 = True
        try:
            # added with the primitive in 2.6
            cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.sign
            CRYPTOGRAPHY_HAS_ED25519_SIGN = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_ED25519_SIGN = False
    except ImportError:
        CRYPTOGRAPHY_HAS_ED25519 = False
        CRYPTOGRAPHY_HAS_ED25519_SIGN = False
    try:
        # added in 2.6 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed448/
        import cryptography.hazmat.primitives.asymmetric.ed448
        CRYPTOGRAPHY_HAS_ED448 = True
        try:
            # added with the primitive in 2.6
            cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.sign
            CRYPTOGRAPHY_HAS_ED448_SIGN = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_ED448_SIGN = False
    except ImportError:
        CRYPTOGRAPHY_HAS_ED448 = False
        CRYPTOGRAPHY_HAS_ED448_SIGN = False
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ec/
        import cryptography.hazmat.primitives.asymmetric.ec
        CRYPTOGRAPHY_HAS_EC = True
        try:
            # added later in 1.5
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey.sign
            CRYPTOGRAPHY_HAS_EC_SIGN = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_EC_SIGN = False
    except ImportError:
        CRYPTOGRAPHY_HAS_EC = False
        CRYPTOGRAPHY_HAS_EC_SIGN = False
    try:
        # added in 0.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
        import cryptography.hazmat.primitives.asymmetric.rsa
        CRYPTOGRAPHY_HAS_RSA = True
        try:
            # added later in 1.4
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey.sign
            CRYPTOGRAPHY_HAS_RSA_SIGN = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_RSA_SIGN = False
    except ImportError:
        CRYPTOGRAPHY_HAS_RSA = False
        CRYPTOGRAPHY_HAS_RSA_SIGN = False
    try:
        # added in 2.0 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
        import cryptography.hazmat.primitives.asymmetric.x25519
        CRYPTOGRAPHY_HAS_X25519 = True
        try:
            # added later in 2.5
            cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.private_bytes
            CRYPTOGRAPHY_HAS_X25519_FULL = True
        except AttributeError:
            CRYPTOGRAPHY_HAS_X25519_FULL = False
    except ImportError:
        CRYPTOGRAPHY_HAS_X25519 = False
        CRYPTOGRAPHY_HAS_X25519_FULL = False
    try:
        # added in 2.5 - https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x448/
        import cryptography.hazmat.primitives.asymmetric.x448
        CRYPTOGRAPHY_HAS_X448 = True
    except ImportError:
        CRYPTOGRAPHY_HAS_X448 = False

    HAS_CRYPTOGRAPHY = True
except ImportError:
    # Error handled in the calling module.
    CRYPTOGRAPHY_HAS_EC = False
    CRYPTOGRAPHY_HAS_EC_SIGN = False
    CRYPTOGRAPHY_HAS_ED25519 = False
    CRYPTOGRAPHY_HAS_ED25519_SIGN = False
    CRYPTOGRAPHY_HAS_ED448 = False
    CRYPTOGRAPHY_HAS_ED448_SIGN = False
    CRYPTOGRAPHY_HAS_DSA = False
    CRYPTOGRAPHY_HAS_DSA_SIGN = False
    CRYPTOGRAPHY_HAS_RSA = False
    CRYPTOGRAPHY_HAS_RSA_SIGN = False
    CRYPTOGRAPHY_HAS_X25519 = False
    CRYPTOGRAPHY_HAS_X25519_FULL = False
    CRYPTOGRAPHY_HAS_X448 = False
    HAS_CRYPTOGRAPHY = False


class OpenSSLObjectError(Exception):
    pass


class OpenSSLBadPassphraseError(OpenSSLObjectError):
    pass
