# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
name: openssl_publickey_info
short_description: Retrieve information from OpenSSL public keys in PEM format
version_added: 2.10.0
author:
    - Felix Fontein (@felixfontein)
description:
    - Provided a public key in OpenSSL PEM format, retrieve information.
    - This is a filter version of the M(community.crypto.openssl_publickey_info) module.
options:
    _input:
        description:
            - The content of the OpenSSL PEM public key.
        type: string
        required: true
seealso:
    - module: community.crypto.openssl_publickey_info
'''

EXAMPLES = '''
- name: Show the type of a public key
  ansible.builtin.debug:
    msg: >-
      {{
        (
          lookup('ansible.builtin.file', '/path/to/public-key.pem')
          | community.crypto.openssl_publickey_info
        ).type
      }}
'''

RETURN = '''
_value:
    description:
        - Information on the public key.
    type: dict
    contains:
        fingerprints:
            description:
                - Fingerprints of public key.
                - For every hash algorithm available, the fingerprint is computed.
            returned: success
            type: dict
            sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
                      'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
        type:
            description:
                - The key's type.
                - One of C(RSA), C(DSA), C(ECC), C(Ed25519), C(X25519), C(Ed448), or C(X448).
                - Will start with C(unknown) if the key type cannot be determined.
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
                    returned: When C(type=RSA) or C(type=DSA)
                modulus:
                    description:
                        - The RSA key's modulus.
                    type: int
                    returned: When C(type=RSA)
                exponent:
                    description:
                        - The RSA key's public exponent.
                    type: int
                    returned: When C(type=RSA)
                p:
                    description:
                        - The C(p) value for DSA.
                        - This is the prime modulus upon which arithmetic takes place.
                    type: int
                    returned: When C(type=DSA)
                q:
                    description:
                        - The C(q) value for DSA.
                        - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the
                          multiplicative group of the prime field used.
                    type: int
                    returned: When C(type=DSA)
                g:
                    description:
                        - The C(g) value for DSA.
                        - This is the element spanning the subgroup of the multiplicative group of the prime field used.
                    type: int
                    returned: When C(type=DSA)
                curve:
                    description:
                        - The curve's name for ECC.
                    type: str
                    returned: When C(type=ECC)
                exponent_size:
                    description:
                        - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
                    type: int
                    returned: When C(type=ECC)
                x:
                    description:
                        - The C(x) coordinate for the public point on the elliptic curve.
                    type: int
                    returned: When C(type=ECC)
                y:
                    description:
                        - For C(type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
                        - For C(type=DSA), this is the publicly known group element whose discrete logarithm w.r.t. C(g) is the private key.
                    type: int
                    returned: When C(type=DSA) or C(type=ECC)
'''

from ansible.errors import AnsibleFilterError
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_bytes, to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.publickey_info import (
    PublicKeyParseError,
    get_publickey_info,
)

from ansible_collections.community.crypto.plugins.plugin_utils.filter_module import FilterModuleMock


def openssl_publickey_info_filter(data):
    '''Extract information from OpenSSL PEM public key.'''
    if not isinstance(data, string_types):
        raise AnsibleFilterError('The community.crypto.openssl_publickey_info input must be a text type, not %s' % type(data))

    module = FilterModuleMock({})
    try:
        return get_publickey_info(module, 'cryptography', content=to_bytes(data))
    except PublicKeyParseError as exc:
        raise AnsibleFilterError(exc.error_message)
    except OpenSSLObjectError as exc:
        raise AnsibleFilterError(to_native(exc))


class FilterModule(object):
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'openssl_publickey_info': openssl_publickey_info_filter,
        }
