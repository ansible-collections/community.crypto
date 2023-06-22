# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
name: openssl_privatekey_info
short_description: Retrieve information from OpenSSL private keys
version_added: 2.10.0
author:
    - Felix Fontein (@felixfontein)
description:
    - Provided an OpenSSL private keys, retrieve information.
    - This is a filter version of the M(community.crypto.openssl_privatekey_info) module.
options:
    _input:
        description:
            - The content of the OpenSSL private key.
        type: string
        required: true
    passphrase:
        description:
            - The passphrase for the private key.
        type: str
    return_private_key_data:
        description:
            - Whether to return private key data.
            - Only set this to V(true) when you want private information about this key to
              be extracted.
            - "B(WARNING:) you have to make sure that private key data is not accidentally logged!"
        type: bool
        default: false
extends_documentation_fragment:
    - community.crypto.name_encoding
seealso:
    - module: community.crypto.openssl_privatekey_info
'''

EXAMPLES = '''
- name: Show the Subject Alt Names of the CSR
  ansible.builtin.debug:
    msg: >-
      {{
        (
          lookup('ansible.builtin.file', '/path/to/cert.csr')
          | community.crypto.openssl_privatekey_info
        ).subject_alt_name | join(', ')
      }}
'''

RETURN = '''
_value:
    description:
        - Information on the certificate.
    type: dict
    contains:
        public_key:
            description: Private key's public key in PEM format.
            returned: success
            type: str
            sample: "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A..."
        public_key_fingerprints:
            description:
                - Fingerprints of private key's public key.
                - For every hash algorithm available, the fingerprint is computed.
            returned: success
            type: dict
            sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
                      'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
        type:
            description:
                - The key's type.
                - One of V(RSA), V(DSA), V(ECC), V(Ed25519), V(X25519), V(Ed448), or V(X448).
                - Will start with V(unknown) if the key type cannot be determined.
            returned: success
            type: str
            sample: RSA
        public_data:
            description:
                - Public key data. Depends on key type.
            returned: success
            type: dict
            contains:
                size:
                    description:
                        - Bit size of modulus (RSA) or prime number (DSA).
                    type: int
                    returned: When RV(_value.type=RSA) or RV(_value.type=DSA)
                modulus:
                    description:
                        - The RSA key's modulus.
                    type: int
                    returned: When RV(_value.type=RSA)
                exponent:
                    description:
                        - The RSA key's public exponent.
                    type: int
                    returned: When RV(_value.type=RSA)
                p:
                    description:
                        - The C(p) value for DSA.
                        - This is the prime modulus upon which arithmetic takes place.
                    type: int
                    returned: When RV(_value.type=DSA)
                q:
                    description:
                        - The C(q) value for DSA.
                        - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the
                          multiplicative group of the prime field used.
                    type: int
                    returned: When RV(_value.type=DSA)
                g:
                    description:
                        - The C(g) value for DSA.
                        - This is the element spanning the subgroup of the multiplicative group of the prime field used.
                    type: int
                    returned: When RV(_value.type=DSA)
                curve:
                    description:
                        - The curve's name for ECC.
                    type: str
                    returned: When RV(_value.type=ECC)
                exponent_size:
                    description:
                        - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
                    type: int
                    returned: When RV(_value.type=ECC)
                x:
                    description:
                        - The C(x) coordinate for the public point on the elliptic curve.
                    type: int
                    returned: When RV(_value.type=ECC)
                y:
                    description:
                        - For RV(_value.type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
                        - For RV(_value.type=DSA), this is the publicly known group element whose discrete logarithm with
                          respect to C(g) is the private key.
                    type: int
                    returned: When RV(_value.type=DSA) or RV(_value.type=ECC)
        private_data:
            description:
                - Private key data. Depends on key type.
            returned: success and when O(return_private_key_data) is set to V(true)
            type: dict
'''

from ansible.errors import AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_bytes, to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey_info import (
    PrivateKeyParseError,
    get_privatekey_info,
)

from ansible_collections.community.crypto.plugins.plugin_utils.filter_module import FilterModuleMock


def openssl_privatekey_info_filter(data, passphrase=None, return_private_key_data=False):
    '''Extract information from X.509 PEM certificate.'''
    if not isinstance(data, string_types):
        raise AnsibleFilterError('The community.crypto.openssl_privatekey_info input must be a text type, not %s' % type(data))
    if passphrase is not None and not isinstance(passphrase, string_types):
        raise AnsibleFilterError('The passphrase option must be a text type, not %s' % type(passphrase))
    if not isinstance(return_private_key_data, bool):
        raise AnsibleFilterError('The return_private_key_data option must be a boolean, not %s' % type(return_private_key_data))

    module = FilterModuleMock({})
    try:
        result = get_privatekey_info(module, 'cryptography', content=to_bytes(data), passphrase=passphrase, return_private_key_data=return_private_key_data)
        result.pop('can_parse_key', None)
        result.pop('key_is_consistent', None)
        return result
    except PrivateKeyParseError as exc:
        raise AnsibleFilterError(exc.error_message)
    except OpenSSLObjectError as exc:
        raise AnsibleFilterError(to_native(exc))


class FilterModule(object):
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'openssl_privatekey_info': openssl_privatekey_info_filter,
        }
