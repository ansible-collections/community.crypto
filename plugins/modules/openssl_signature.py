#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_signature
version_added: 1.1.0
short_description: Sign data with openssl
description:
    - This module allows one to sign data using a private key.
    - The module uses the cryptography Python library.
requirements:
    - cryptography >= 1.4 (some key types require newer versions)
author:
    - Patrick Pichler (@aveexy)
    - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
    - community.crypto.attributes
attributes:
    check_mode:
        support: full
        details:
            - This action does not modify state.
    diff_mode:
        support: none
options:
    privatekey_path:
        description:
            - The path to the private key to use when signing.
            - Either I(privatekey_path) or I(privatekey_content) must be specified, but not both.
        type: path
    privatekey_content:
        description:
            - The content of the private key to use when signing the certificate signing request.
            - Either I(privatekey_path) or I(privatekey_content) must be specified, but not both.
        type: str
    privatekey_passphrase:
        description:
            - The passphrase for the private key.
            - This is required if the private key is password protected.
        type: str
    path:
        description:
            - The file to sign.
            - This file will only be read and not modified.
        type: path
        required: true
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]
notes:
    - |
      When using the C(cryptography) backend, the following key types require at least the following C(cryptography) version:
      RSA keys: C(cryptography) >= 1.4
      DSA and ECDSA keys: C(cryptography) >= 1.5
      ed448 and ed25519 keys: C(cryptography) >= 2.6
seealso:
    - module: community.crypto.openssl_signature_info
    - module: community.crypto.openssl_privatekey
'''

EXAMPLES = r'''
- name: Sign example file
  community.crypto.openssl_signature:
    privatekey_path: private.key
    path: /tmp/example_file
  register: sig

- name: Verify signature of example file
  community.crypto.openssl_signature_info:
    certificate_path: cert.pem
    path: /tmp/example_file
    signature: "{{ sig.signature }}"
  register: verify

- name: Make sure the signature is valid
  ansible.builtin.assert:
    that:
      - verify.valid
'''

RETURN = r'''
signature:
    description: Base64 encoded signature.
    returned: success
    type: str
'''

import os
import traceback
import base64

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

MINIMAL_CRYPTOGRAPHY_VERSION = '1.4'

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.hashes
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_DSA_SIGN,
    CRYPTOGRAPHY_HAS_EC_SIGN,
    CRYPTOGRAPHY_HAS_ED25519_SIGN,
    CRYPTOGRAPHY_HAS_ED448_SIGN,
    CRYPTOGRAPHY_HAS_RSA_SIGN,
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_privatekey,
)

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.basic import AnsibleModule, missing_required_lib


class SignatureBase(OpenSSLObject):

    def __init__(self, module, backend):
        super(SignatureBase, self).__init__(
            path=module.params['path'],
            state='present',
            force=False,
            check_mode=module.check_mode
        )

        self.backend = backend

        self.privatekey_path = module.params['privatekey_path']
        self.privatekey_content = module.params['privatekey_content']
        if self.privatekey_content is not None:
            self.privatekey_content = self.privatekey_content.encode('utf-8')
        self.privatekey_passphrase = module.params['privatekey_passphrase']

    def generate(self):
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self):
        # Empty method because OpenSSLObject wants this
        pass


# Implementation with using cryptography
class SignatureCryptography(SignatureBase):

    def __init__(self, module, backend):
        super(SignatureCryptography, self).__init__(module, backend)

    def run(self):
        _padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
        _hash = cryptography.hazmat.primitives.hashes.SHA256()

        result = dict()

        try:
            with open(self.path, "rb") as f:
                _in = f.read()

            private_key = load_privatekey(
                path=self.privatekey_path,
                content=self.privatekey_content,
                passphrase=self.privatekey_passphrase,
                backend=self.backend,
            )

            signature = None

            if CRYPTOGRAPHY_HAS_DSA_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey):
                    signature = private_key.sign(_in, _hash)

            if CRYPTOGRAPHY_HAS_EC_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
                    signature = private_key.sign(_in, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash))

            if CRYPTOGRAPHY_HAS_ED25519_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
                    signature = private_key.sign(_in)

            if CRYPTOGRAPHY_HAS_ED448_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey):
                    signature = private_key.sign(_in)

            if CRYPTOGRAPHY_HAS_RSA_SIGN:
                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
                    signature = private_key.sign(_in, _padding, _hash)

            if signature is None:
                self.module.fail_json(
                    msg="Unsupported key type. Your cryptography version is {0}".format(CRYPTOGRAPHY_VERSION)
                )

            result['signature'] = base64.b64encode(signature)
            return result

        except Exception as e:
            raise OpenSSLObjectError(e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str', no_log=True),
            privatekey_passphrase=dict(type='str', no_log=True),
            path=dict(type='path', required=True),
            select_crypto_backend=dict(type='str', choices=['auto', 'cryptography'], default='auto'),
        ),
        mutually_exclusive=(
            ['privatekey_path', 'privatekey_content'],
        ),
        required_one_of=(
            ['privatekey_path', 'privatekey_content'],
        ),
        supports_check_mode=True,
    )

    if not os.path.isfile(module.params['path']):
        module.fail_json(
            name=module.params['path'],
            msg='The file {0} does not exist'.format(module.params['path'])
        )

    backend = module.params['select_crypto_backend']
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Decision
        if can_use_cryptography:
            backend = 'cryptography'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Cannot detect the required Python library "
                                  "cryptography (>= {0})").format(MINIMAL_CRYPTOGRAPHY_VERSION))
    try:
        if backend == 'cryptography':
            if not CRYPTOGRAPHY_FOUND:
                module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                                 exception=CRYPTOGRAPHY_IMP_ERR)
            _sign = SignatureCryptography(module, backend)

        result = _sign.run()

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == '__main__':
    main()
