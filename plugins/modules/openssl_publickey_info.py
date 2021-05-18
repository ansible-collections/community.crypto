#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_publickey_info
short_description: Provide information for OpenSSL public keys
description:
    - This module allows one to query information on OpenSSL public keys.
    - It uses the pyOpenSSL or cryptography python library to interact with OpenSSL. If both the
      cryptography and PyOpenSSL libraries are available (and meet the minimum version requirements)
      cryptography will be preferred as a backend over PyOpenSSL (unless the backend is forced with
      C(select_crypto_backend)). Please note that the PyOpenSSL backend was deprecated in Ansible 2.9
      and will be removed in community.crypto 2.0.0.
version_added: 1.7.0
requirements:
    - PyOpenSSL >= 0.15 or cryptography >= 1.2.3
author:
    - Felix Fontein (@felixfontein)
options:
    path:
        description:
            - Remote absolute path where the public key file is loaded from.
        type: path
    content:
        description:
            - Content of the public key file.
            - Either I(path) or I(content) must be specified, but not both.
        type: str

    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available, and falls back to C(pyopenssl).
            - If set to C(pyopenssl), will try to use the L(pyOpenSSL,https://pypi.org/project/pyOpenSSL/) library.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
            - Please note that the C(pyopenssl) backend has been deprecated in Ansible 2.9, and will be removed in community.crypto 2.0.0.
              From that point on, only the C(cryptography) backend will be available.
        type: str
        default: auto
        choices: [ auto, cryptography, pyopenssl ]

notes:
- Supports C(check_mode).

seealso:
- module: community.crypto.openssl_publickey
- module: community.crypto.openssl_privatekey_info
'''

EXAMPLES = r'''
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem

- name: Create public key from private key
  community.crypto.openssl_privatekey:
    privatekey_path: /etc/ssl/private/ansible.com.pem
    path: /etc/ssl/ansible.com.pub

- name: Get information on public key
  community.crypto.openssl_publickey_info:
    path: /etc/ssl/ansible.com.pub
  register: result

- name: Dump information
  ansible.builtin.debug:
    var: result
'''

RETURN = r'''
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


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.publickey_info import (
    PublicKeyParseError,
    select_backend,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str', no_log=True),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),
        ),
        required_one_of=(
            ['path', 'content'],
        ),
        mutually_exclusive=(
            ['path', 'content'],
        ),
        supports_check_mode=True,
    )

    result = dict(
        can_load_key=False,
        can_parse_key=False,
        key_is_consistent=None,
    )

    if module.params['content'] is not None:
        data = module.params['content'].encode('utf-8')
    else:
        try:
            with open(module.params['path'], 'rb') as f:
                data = f.read()
        except (IOError, OSError) as e:
            module.fail_json(msg='Error while reading public key file from disk: {0}'.format(e), **result)

    backend, module_backend = select_backend(
        module,
        module.params['select_crypto_backend'],
        data)

    try:
        result.update(module_backend.get_info())
        module.exit_json(**result)
    except PublicKeyParseError as exc:
        result.update(exc.result)
        module.fail_json(msg=exc.error_message, **result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
