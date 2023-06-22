#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: crypto_info
author: "Felix Fontein (@felixfontein)"
short_description: Retrieve cryptographic capabilities
version_added: 2.1.0
description:
  - Retrieve information on cryptographic capabilities.
  - The current version retrieves information on the L(Python cryptography library, https://cryptography.io/) available to
    Ansible modules, and on the OpenSSL binary C(openssl) found in the path.
extends_documentation_fragment:
  - community.crypto.attributes
  - community.crypto.attributes.info_module
options: {}
'''

EXAMPLES = r'''
- name: Retrieve information
  community.crypto.crypto_info:
    account_key_src: /etc/pki/cert/private/account.key
  register: crypto_information

- name: Show retrieved information
  ansible.builtin.debug:
    var: crypto_information
'''

RETURN = r'''
python_cryptography_installed:
  description: Whether the L(Python cryptography library, https://cryptography.io/) is installed.
  returned: always
  type: bool
  sample: true

python_cryptography_import_error:
  description: Import error when trying to import the L(Python cryptography library, https://cryptography.io/).
  returned: when RV(python_cryptography_installed=false)
  type: str

python_cryptography_capabilities:
  description: Information on the installed L(Python cryptography library, https://cryptography.io/).
  returned: when RV(python_cryptography_installed=true)
  type: dict
  contains:
    version:
      description: The library version.
      type: str
    curves:
      description:
        - List of all supported elliptic curves.
        - Theoretically this should be non-empty for version 0.5 and higher, depending on the libssl version used.
      type: list
      elements: str
    has_ec:
      description:
        - Whether elliptic curves are supported.
        - Theoretically this should be the case for version 0.5 and higher, depending on the libssl version used.
      type: bool
    has_ec_sign:
      description:
        - Whether signing with elliptic curves is supported.
        - Theoretically this should be the case for version 1.5 and higher, depending on the libssl version used.
      type: bool
    has_ed25519:
      description:
        - Whether Ed25519 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed25519_sign:
      description:
        - Whether signing with Ed25519 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed448:
      description:
        - Whether Ed448 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_ed448_sign:
      description:
        - Whether signing with Ed448 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher, depending on the libssl version used.
      type: bool
    has_dsa:
      description:
        - Whether DSA keys are supported.
        - Theoretically this should be the case for version 0.5 and higher.
      type: bool
    has_dsa_sign:
      description:
        - Whether signing with DSA keys is supported.
        - Theoretically this should be the case for version 1.5 and higher.
      type: bool
    has_rsa:
      description:
        - Whether RSA keys are supported.
        - Theoretically this should be the case for version 0.5 and higher.
      type: bool
    has_rsa_sign:
      description:
        - Whether signing with RSA keys is supported.
        - Theoretically this should be the case for version 1.4 and higher.
      type: bool
    has_x25519:
      description:
        - Whether X25519 keys are supported.
        - Theoretically this should be the case for version 2.0 and higher, depending on the libssl version used.
      type: bool
    has_x25519_serialization:
      description:
        - Whether serialization of X25519 keys is supported.
        - Theoretically this should be the case for version 2.5 and higher, depending on the libssl version used.
      type: bool
    has_x448:
      description:
        - Whether X448 keys are supported.
        - Theoretically this should be the case for version 2.5 and higher, depending on the libssl version used.
      type: bool

openssl_present:
  description: Whether the OpenSSL binary C(openssl) is installed and can be found in the PATH.
  returned: always
  type: bool
  sample: true

openssl:
  description: Information on the installed OpenSSL binary.
  returned: when RV(openssl_present=true)
  type: dict
  contains:
    path:
      description: Path of the OpenSSL binary.
      type: str
      sample: /usr/bin/openssl
    version:
      description: The OpenSSL version.
      type: str
      sample: 1.1.1m
    version_output:
      description: The complete output of C(openssl version).
      type: str
      sample: 'OpenSSL 1.1.1m  14 Dec 2021\n'
'''

import traceback

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_EC,
    CRYPTOGRAPHY_HAS_EC_SIGN,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED25519_SIGN,
    CRYPTOGRAPHY_HAS_ED448,
    CRYPTOGRAPHY_HAS_ED448_SIGN,
    CRYPTOGRAPHY_HAS_DSA,
    CRYPTOGRAPHY_HAS_DSA_SIGN,
    CRYPTOGRAPHY_HAS_RSA,
    CRYPTOGRAPHY_HAS_RSA_SIGN,
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X25519_FULL,
    CRYPTOGRAPHY_HAS_X448,
    HAS_CRYPTOGRAPHY,
)

try:
    import cryptography
    from cryptography.exceptions import UnsupportedAlgorithm
except ImportError:
    UnsupportedAlgorithm = Exception
    CRYPTOGRAPHY_VERSION = None
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
else:
    CRYPTOGRAPHY_VERSION = cryptography.__version__
    CRYPTOGRAPHY_IMP_ERR = None


CURVES = (
    ('secp224r1', 'SECP224R1'),
    ('secp256k1', 'SECP256K1'),
    ('secp256r1', 'SECP256R1'),
    ('secp384r1', 'SECP384R1'),
    ('secp521r1', 'SECP521R1'),
    ('secp192r1', 'SECP192R1'),
    ('sect163k1', 'SECT163K1'),
    ('sect163r2', 'SECT163R2'),
    ('sect233k1', 'SECT233K1'),
    ('sect233r1', 'SECT233R1'),
    ('sect283k1', 'SECT283K1'),
    ('sect283r1', 'SECT283R1'),
    ('sect409k1', 'SECT409K1'),
    ('sect409r1', 'SECT409R1'),
    ('sect571k1', 'SECT571K1'),
    ('sect571r1', 'SECT571R1'),
    ('brainpoolP256r1', 'BrainpoolP256R1'),
    ('brainpoolP384r1', 'BrainpoolP384R1'),
    ('brainpoolP512r1', 'BrainpoolP512R1'),
)


def add_crypto_information(module):
    result = {}
    result['python_cryptography_installed'] = HAS_CRYPTOGRAPHY
    if not HAS_CRYPTOGRAPHY:
        result['python_cryptography_import_error'] = CRYPTOGRAPHY_IMP_ERR
        return result

    has_ed25519 = CRYPTOGRAPHY_HAS_ED25519
    if has_ed25519:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            Ed25519PrivateKey.from_private_bytes(b'')
        except ValueError:
            pass
        except UnsupportedAlgorithm:
            has_ed25519 = False

    has_ed448 = CRYPTOGRAPHY_HAS_ED448
    if has_ed448:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
            Ed448PrivateKey.from_private_bytes(b'')
        except ValueError:
            pass
        except UnsupportedAlgorithm:
            has_ed448 = False

    has_x25519 = CRYPTOGRAPHY_HAS_X25519
    if has_x25519:
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            if CRYPTOGRAPHY_HAS_X25519_FULL:
                X25519PrivateKey.from_private_bytes(b'')
            else:
                # Some versions do not support serialization and deserialization - use generate() instead
                X25519PrivateKey.generate()
        except ValueError:
            pass
        except UnsupportedAlgorithm:
            has_x25519 = False

    has_x448 = CRYPTOGRAPHY_HAS_X448
    if has_x448:
        try:
            from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
            X448PrivateKey.from_private_bytes(b'')
        except ValueError:
            pass
        except UnsupportedAlgorithm:
            has_x448 = False

    curves = []
    if CRYPTOGRAPHY_HAS_EC:
        import cryptography.hazmat.backends
        import cryptography.hazmat.primitives.asymmetric.ec

        backend = cryptography.hazmat.backends.default_backend()
        for curve_name, constructor_name in CURVES:
            ecclass = cryptography.hazmat.primitives.asymmetric.ec.__dict__.get(constructor_name)
            if ecclass:
                try:
                    cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(curve=ecclass(), backend=backend)
                    curves.append(curve_name)
                except UnsupportedAlgorithm:
                    pass

    info = {
        'version': CRYPTOGRAPHY_VERSION,
        'curves': curves,
        'has_ec': CRYPTOGRAPHY_HAS_EC,
        'has_ec_sign': CRYPTOGRAPHY_HAS_EC_SIGN,
        'has_ed25519': has_ed25519,
        'has_ed25519_sign': has_ed25519 and CRYPTOGRAPHY_HAS_ED25519_SIGN,
        'has_ed448': has_ed448,
        'has_ed448_sign': has_ed448 and CRYPTOGRAPHY_HAS_ED448_SIGN,
        'has_dsa': CRYPTOGRAPHY_HAS_DSA,
        'has_dsa_sign': CRYPTOGRAPHY_HAS_DSA_SIGN,
        'has_rsa': CRYPTOGRAPHY_HAS_RSA,
        'has_rsa_sign': CRYPTOGRAPHY_HAS_RSA_SIGN,
        'has_x25519': has_x25519,
        'has_x25519_serialization': has_x25519 and CRYPTOGRAPHY_HAS_X25519_FULL,
        'has_x448': has_x448,
    }
    result['python_cryptography_capabilities'] = info
    return result


def add_openssl_information(module):
    openssl_binary = module.get_bin_path('openssl')
    result = {
        'openssl_present': openssl_binary is not None,
    }
    if openssl_binary is None:
        return result

    openssl_result = {
        'path': openssl_binary,
    }
    result['openssl'] = openssl_result

    rc, out, err = module.run_command([openssl_binary, 'version'])
    if rc == 0:
        openssl_result['version_output'] = out
        parts = out.split(None, 2)
        if len(parts) > 1:
            openssl_result['version'] = parts[1]

    return result


INFO_FUNCTIONS = (
    add_crypto_information,
    add_openssl_information,
)


def main():
    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    result = {}
    for fn in INFO_FUNCTIONS:
        result.update(fn(module))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
