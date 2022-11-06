#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_privatekey_info
short_description: Provide information for OpenSSL private keys
description:
    - This module allows one to query information on OpenSSL private keys.
    - In case the key consistency checks fail, the module will fail as this indicates a faked
      private key. In this case, all return variables are still returned. Note that key consistency
      checks are not available all key types; if none is available, C(none) is returned for
      C(key_is_consistent).
    - It uses the cryptography python library to interact with OpenSSL.
requirements:
    - cryptography >= 1.2.3
author:
    - Felix Fontein (@felixfontein)
    - Yanis Guenane (@Spredzy)
extends_documentation_fragment:
    - community.crypto.attributes
    - community.crypto.attributes.info_module
options:
    path:
        description:
            - Remote absolute path where the private key file is loaded from.
        type: path
    content:
        description:
            - Content of the private key file.
            - Either I(path) or I(content) must be specified, but not both.
        type: str
        version_added: '1.0.0'
    passphrase:
        description:
            - The passphrase for the private key.
        type: str
    return_private_key_data:
        description:
            - Whether to return private key data.
            - Only set this to C(true) when you want private information about this key to
              leave the remote machine.
            - "B(WARNING:) you have to make sure that private key data is not accidentally logged!"
        type: bool
        default: false
    check_consistency:
        description:
            - Whether to check consistency of the private key.
            - In community.crypto < 2.0.0, consistency was always checked.
            - Since community.crypto 2.0.0, the consistency check has been disabled by default to
              avoid private key material to be transported around and computed with, and only do
              so when requested explicitly. This can potentially prevent
              L(side-channel attacks,https://en.wikipedia.org/wiki/Side-channel_attack).
        type: bool
        default: false
        version_added: 2.0.0

    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]

seealso:
    - module: community.crypto.openssl_privatekey
    - module: community.crypto.openssl_privatekey_pipe
'''

EXAMPLES = r'''
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem

- name: Get information on generated key
  community.crypto.openssl_privatekey_info:
    path: /etc/ssl/private/ansible.com.pem
  register: result

- name: Dump information
  ansible.builtin.debug:
    var: result
'''

RETURN = r'''
can_load_key:
    description: Whether the module was able to load the private key from disk.
    returned: always
    type: bool
can_parse_key:
    description: Whether the module was able to parse the private key.
    returned: always
    type: bool
key_is_consistent:
    description:
        - Whether the key is consistent. Can also return C(none) next to C(true) and
          C(false), to indicate that consistency could not be checked.
        - In case the check returns C(false), the module will fail.
    returned: when I(check_consistency=true)
    type: bool
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
private_data:
    description:
        - Private key data. Depends on key type.
    returned: success and when I(return_private_key_data) is set to C(true)
    type: dict
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey_info import (
    PrivateKeyConsistencyError,
    PrivateKeyParseError,
    select_backend,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str', no_log=True),
            passphrase=dict(type='str', no_log=True),
            return_private_key_data=dict(type='bool', default=False),
            check_consistency=dict(type='bool', default=False),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography']),
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
            module.fail_json(msg='Error while reading private key file from disk: {0}'.format(e), **result)

    result['can_load_key'] = True

    backend, module_backend = select_backend(
        module,
        module.params['select_crypto_backend'],
        data,
        passphrase=module.params['passphrase'],
        return_private_key_data=module.params['return_private_key_data'],
        check_consistency=module.params['check_consistency'])

    try:
        result.update(module_backend.get_info())
        module.exit_json(**result)
    except PrivateKeyParseError as exc:
        result.update(exc.result)
        module.fail_json(msg=exc.error_message, **result)
    except PrivateKeyConsistencyError as exc:
        result.update(exc.result)
        module.fail_json(msg=exc.error_message, **result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
