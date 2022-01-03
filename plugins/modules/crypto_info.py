#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: crypto_info
author: "Felix Fontein (@felixfontein)"
short_description: Retrieve cryptographic capabilities
version_added: 2.1.0
description:
   - "Retrieve information on cryptographic capabilities."
notes:
   - Supports C(check_mode).
options: {}
'''

EXAMPLES = '''
- name: Retrieve information
  community.crypto.crypto_info:
    account_key_src: /etc/pki/cert/private/account.key
  register: crypto_information

- name: Show retrieved information
  ansible.builtin.debug:
    var: crypto_information
'''

RETURN = '''
python_cryptography_installed:
  description: Whether the L(Python cryptography library, https://cryptography.io/) is installed.
  returned: always
  type: bool
  sample: true

python_cryptography_import_error:
  description: Import error when trying to import the L(Python cryptography library, https://cryptography.io/).
  returned: when I(python_cryptography_installed=false)
  type: str

python_cryptography_capabilities:
  description: Information on the installed L(Python cryptography library, https://cryptography.io/).
  returned: when I(python_cryptography_installed=true)
  type: dict
  contains:
    version:
      description: The library version.
      type: str
    has_ec:
      description:
        - Whether elliptic curves are supported.
        - Theoretically this should be the case for version 0.5 and higher.
      type: bool
    has_ec_sign:
      description:
        - Whether signing with elliptic curves is supported.
        - Theoretically this should be the case for version 1.5 and higher.
      type: bool
    has_ed25519:
      description:
        - Whether Ed25519 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher.
      type: bool
    has_ed25519_sign:
      description:
        - Whether signing with Ed25519 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher.
      type: bool
    has_ed448:
      description:
        - Whether Ed448 keys are supported.
        - Theoretically this should be the case for version 2.6 and higher.
      type: bool
    has_ed448_sign:
      description:
        - Whether signing with Ed448 keys is supported.
        - Theoretically this should be the case for version 2.6 and higher.
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
        - Theoretically this should be the case for version 2.0 and higher.
      type: bool
    has_x25519_serialization:
      description:
        - Whether serialization of X25519 keys is supported.
        - Theoretically this should be the case for version 2.5 and higher.
      type: bool
    has_x448:
      description:
        - Whether X448 keys are supported.
        - Theoretically this should be the case for version 2.5 and higher.
      type: bool
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

CRYPTOGRAPHY_IMP_ERR = None
CRYPTOGRAPHY_VERSION = None
try:
    import cryptography

    CRYPTOGRAPHY_VERSION = cryptography.__version__
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()


def add_crypto_information(module, result):
    result['python_cryptography_installed'] = HAS_CRYPTOGRAPHY
    if not HAS_CRYPTOGRAPHY:
        result['python_cryptography_import_error'] = CRYPTOGRAPHY_IMP_ERR
        return

    info = {
        'version': CRYPTOGRAPHY_VERSION,
        'has_ec': CRYPTOGRAPHY_HAS_EC,
        'has_ec_sign': CRYPTOGRAPHY_HAS_EC_SIGN,
        'has_ed25519': CRYPTOGRAPHY_HAS_ED25519,
        'has_ed25519_sign': CRYPTOGRAPHY_HAS_ED25519_SIGN,
        'has_ed448': CRYPTOGRAPHY_HAS_ED448,
        'has_ed448_sign': CRYPTOGRAPHY_HAS_ED448_SIGN,
        'has_dsa': CRYPTOGRAPHY_HAS_DSA,
        'has_dsa_sign': CRYPTOGRAPHY_HAS_DSA_SIGN,
        'has_rsa': CRYPTOGRAPHY_HAS_RSA,
        'has_rsa_sign': CRYPTOGRAPHY_HAS_RSA_SIGN,
        'has_x25519': CRYPTOGRAPHY_HAS_X25519,
        'has_x25519_serialization': CRYPTOGRAPHY_HAS_X25519_FULL,
        'has_x448': CRYPTOGRAPHY_HAS_X448,
    }
    result['python_cryptography_capabilities'] = info


def main():
    module = AnsibleModule(argument_spec={}, supports_check_mode=True)
    result = {}
    add_crypto_information(module, result)
    module.exit_json(**result)


if __name__ == '__main__':
    main()
