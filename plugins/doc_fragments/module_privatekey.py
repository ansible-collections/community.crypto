# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r'''
description:
    - One can generate L(RSA,https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29),
      L(DSA,https://en.wikipedia.org/wiki/Digital_Signature_Algorithm),
      L(ECC,https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) or
      L(EdDSA,https://en.wikipedia.org/wiki/EdDSA) private keys.
    - Keys are generated in PEM format.
    - "Please note that the module regenerates private keys if they do not match
      the module's options. In particular, if you provide another passphrase
      (or specify none), change the keysize, etc., the private key will be
      regenerated. If you are concerned that this could B(overwrite your private key),
      consider using the I(backup) option."
requirements:
    - cryptography >= 1.2.3 (older versions might work as well)
options:
    size:
        description:
            - Size (in bits) of the TLS/SSL key to generate.
        type: int
        default: 4096
    type:
        description:
            - The algorithm used to generate the TLS/SSL private key.
            - Note that C(ECC), C(X25519), C(X448), C(Ed25519) and C(Ed448) require the C(cryptography) backend.
              C(X25519) needs cryptography 2.5 or newer, while C(X448), C(Ed25519) and C(Ed448) require
              cryptography 2.6 or newer. For C(ECC), the minimal cryptography version required depends on the
              I(curve) option.
        type: str
        default: RSA
        choices: [ DSA, ECC, Ed25519, Ed448, RSA, X25519, X448 ]
    curve:
        description:
            - Note that not all curves are supported by all versions of C(cryptography).
            - For maximal interoperability, C(secp384r1) or C(secp256r1) should be used.
            - We use the curve names as defined in the
              L(IANA registry for TLS,https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
            - Please note that all curves except C(secp224r1), C(secp256k1), C(secp256r1), C(secp384r1) and C(secp521r1)
              are discouraged for new private keys.
        type: str
        choices:
            - secp224r1
            - secp256k1
            - secp256r1
            - secp384r1
            - secp521r1
            - secp192r1
            - brainpoolP256r1
            - brainpoolP384r1
            - brainpoolP512r1
            - sect163k1
            - sect163r2
            - sect233k1
            - sect233r1
            - sect283k1
            - sect283r1
            - sect409k1
            - sect409r1
            - sect571k1
            - sect571r1
    passphrase:
        description:
            - The passphrase for the private key.
        type: str
    cipher:
        description:
            - The cipher to encrypt the private key. Must be C(auto).
        type: str
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]
    format:
        description:
            - Determines which format the private key is written in. By default, PKCS1 (traditional OpenSSL format)
              is used for all keys which support it. Please note that not every key can be exported in any format.
            - The value C(auto) selects a format based on the key format. The value C(auto_ignore) does the same,
              but for existing private key files, it will not force a regenerate when its format is not the automatically
              selected one for generation.
            - Note that if the format for an existing private key mismatches, the key is B(regenerated) by default.
              To change this behavior, use the I(format_mismatch) option.
        type: str
        default: auto_ignore
        choices: [ pkcs1, pkcs8, raw, auto, auto_ignore ]
    format_mismatch:
        description:
            - Determines behavior of the module if the format of a private key does not match the expected format, but all
              other parameters are as expected.
            - If set to C(regenerate) (default), generates a new private key.
            - If set to C(convert), the key will be converted to the new format instead.
            - Only supported by the C(cryptography) backend.
        type: str
        default: regenerate
        choices: [ regenerate, convert ]
    regenerate:
        description:
            - Allows to configure in which situations the module is allowed to regenerate private keys.
              The module will always generate a new key if the destination file does not exist.
            - By default, the key will be regenerated when it does not match the module's options,
              except when the key cannot be read or the passphrase does not match. Please note that
              this B(changed) for Ansible 2.10. For Ansible 2.9, the behavior was as if C(full_idempotence)
              is specified.
            - If set to C(never), the module will fail if the key cannot be read or the passphrase
              is not matching, and will never regenerate an existing key.
            - If set to C(fail), the module will fail if the key does not correspond to the module's
              options.
            - If set to C(partial_idempotence), the key will be regenerated if it does not conform to
              the module's options. The key is B(not) regenerated if it cannot be read (broken file),
              the key is protected by an unknown passphrase, or when they key is not protected by a
              passphrase, but a passphrase is specified.
            - If set to C(full_idempotence), the key will be regenerated if it does not conform to the
              module's options. This is also the case if the key cannot be read (broken file), the key
              is protected by an unknown passphrase, or when they key is not protected by a passphrase,
              but a passphrase is specified. Make sure you have a B(backup) when using this option!
            - If set to C(always), the module will always regenerate the key. This is equivalent to
              setting I(force) to C(yes).
            - Note that if I(format_mismatch) is set to C(convert) and everything matches except the
              format, the key will always be converted, except if I(regenerate) is set to C(always).
        type: str
        choices:
            - never
            - fail
            - partial_idempotence
            - full_idempotence
            - always
        default: full_idempotence
seealso:
- module: community.crypto.x509_certificate
- module: community.crypto.x509_certificate_pipe
- module: community.crypto.openssl_csr
- module: community.crypto.openssl_csr_pipe
- module: community.crypto.openssl_dhparam
- module: community.crypto.openssl_pkcs12
- module: community.crypto.openssl_publickey
'''
