#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1'}

DOCUMENTATION = r'''
---
module: openssl_signature
short_description: Sign and verify data with openssl
description: This module allows one to sign and verify data via certificate and private key
requirements:
    - Either cryptography >= 1.2.3 (older versions might work as well)
    - Or pyOpenSSL
author:
    - Patrick Pichler (@aveexy)
options:
    action:
        description: Action to be executed
        type: str
        required: true
        choices: [ sign, verify ]

    private_key:
        description: Private key required for sign action
        type: path

    certificate:
        description: Certificate required for verify action
        type: path

    passphrase:
        description: Passphrase for private_key
        type: str

    path:
        description: file to sign/verify
        type: path
        required: true

    signature:
        description: base64 encoded signature required for verify action
        type: str

    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available, and falls back to C(pyopenssl).
            - If set to C(pyopenssl), will try to use the L(pyOpenSSL,https://pypi.org/project/pyOpenSSL/) library.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography, pyopenssl ]
'''

EXAMPLES = r'''
- name: Sign example file
  openssl_signature:
    action: sign
    private_key: private.key
    path: /tmp/example_file
  register: sig

- name: Verify signature of example file
  openssl_signature:
    action: verify
    certificate: cert.pem
    path: /tmp/example_file
    signature: sig.signature
'''

RETURN = r'''
signature:
    description: base64 encoded signature
    returned: changed or success
    type: str
'''

import os
import traceback
from distutils.version import LooseVersion
import base64

MINIMAL_PYOPENSSL_VERSION = '0.6'
MINIMAL_CRYPTOGRAPHY_VERSION = '1.2.3'

PYOPENSSL_IMP_ERR = None
try:
    import OpenSSL
    from OpenSSL import crypto

    PYOPENSSL_VERSION = LooseVersion(OpenSSL.__version__)
except ImportError:
    PYOPENSSL_IMP_ERR = traceback.format_exc()
    PYOPENSSL_FOUND = False
else:
    PYOPENSSL_FOUND = True

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    import cryptography.hazmat.primitives.asymmetric.rsa
    import cryptography.hazmat.primitives.asymmetric.dsa
    import cryptography.hazmat.primitives.asymmetric.ec
    import cryptography.hazmat.primitives.asymmetric.padding
    import cryptography.hazmat.primitives.hashes

    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True

from ansible.module_utils import crypto as crypto_utils
from ansible.module_utils._text import to_native, to_bytes
from ansible.module_utils.basic import AnsibleModule, missing_required_lib


class SignatureBase(crypto_utils.OpenSSLObject):

    def __init__(self, module, backend):
        super(SignatureBase, self).__init__(
            module.params['path'],
            'present',
            False,
            module.check_mode
        )

        self.backend = backend

        self.action = module.params['action']
        self.signature = module.params['signature']
        self.passphrase = module.params['passphrase']
        self.private_key = module.params['private_key']
        self.certificate = module.params['certificate']

    def generate(self):
        # Empty method because crypto_utils.OpenSSLObject wants this
        pass

    def dump(self):
        # Empty method because crypto_utils.OpenSSLObject wants this
        pass


# Implementation with using pyOpenSSL
class SignaturePyOpenSSL(SignatureBase):

    def __init__(self, module, backend):
        super(SignaturePyOpenSSL, self).__init__(module, backend)

    def run(self):
        try:
            result = dict()

            with open(self.path, "rb") as f:
                _in = f.read()

            if self.action == "verify":
                _signature = base64.b64decode(self.signature)
                certificate = crypto_utils.load_certificate(self.certificate, backend=self.backend)

                try:
                    OpenSSL.crypto.verify(certificate, _signature, _in, 'sha256')
                except Exception:
                    self.module.fail_json(
                        msg="Verification failed"
                    )

            elif self.action == "sign":
                private_key = crypto_utils.load_privatekey(
                    self.private_key,
                    None if self.passphrase is None else to_bytes(self.passphrase),
                    backend=self.backend
                )

                out = OpenSSL.crypto.sign(private_key, _in, "sha256")
                result['signature'] = base64.b64encode(out)

            return result
        except Exception as e:
            raise crypto_utils.OpenSSLObjectError(e)


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

            if self.action == "verify":
                _signature = base64.b64decode(self.signature)
                public_key = crypto_utils.load_certificate(self.certificate, backend=self.backend).public_key()

                try:
                    if isinstance(public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
                        public_key.verify(_signature, _in, _padding, _hash)

                    elif isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
                        public_key.verify(_signature, _in, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash))

                    elif (isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey) or
                          isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey)):
                        public_key.verify(_signature, _in)

                    else:
                        self.module.fail_json(
                            msg="Unsupported algorithm"
                        )

                except Exception:
                    self.module.fail_json(
                        msg="Verification failed"
                    )

            elif self.action == "sign":
                private_key = crypto_utils.load_privatekey(
                    self.private_key,
                    None if self.passphrase is None else to_bytes(self.passphrase),
                    backend=self.backend
                )

                if isinstance(private_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
                    out = private_key.sign(_in, _padding, _hash)

                elif isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey):
                    out = private_key.sign(_in, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash))

                elif (isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey) or
                      isinstance(private_key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey)):
                    out = private_key.sign(_in)

                else:
                    self.module.fail_json(
                        msg="Unsupported algorithm"
                    )

                result['signature'] = base64.b64encode(out)

            return result

        except Exception as e:
            raise crypto_utils.OpenSSLObjectError(e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(type='str', choices=[
                'sign', 'verify'
            ]),
            private_key=dict(type='path'),
            certificate=dict(type='path'),
            passphrase=dict(type='str', no_log=True),
            path=dict(type='path', required=True),
            signature=dict(type='path'),
            select_crypto_backend=dict(type='str', choices=['auto', 'pyopenssl', 'cryptography'], default='auto'),
        ),
        supports_check_mode=False,
    )

    if module.params['private_key'] is not None and module.params['certificate'] is not None:
        module.fail_json(
            msg="private_key and certificate are mutually exclusive"
        )

    if module.params['private_key'] is None and module.params['action'] == "sign":
        module.fail_json(
            msg="Private key missing"
        )

    if module.params['certificate'] is None and module.params['action'] == "verify":
        module.fail_json(
            msg="Certificate missing"
        )

    if module.params['action'] == "verify" and module.params['signature'] is None:
        module.fail_json(
            msg="Can't verify without a signature"
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
        can_use_pyopenssl = PYOPENSSL_FOUND and PYOPENSSL_VERSION >= LooseVersion(MINIMAL_PYOPENSSL_VERSION)

        # Decision
        if can_use_cryptography:
            backend = 'cryptography'
        elif can_use_pyopenssl:
            backend = 'pyopenssl'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Can't detect any of the required Python libraries "
                                  "cryptography (>= {0}) or PyOpenSSL (>= {1})").format(
                MINIMAL_CRYPTOGRAPHY_VERSION,
                MINIMAL_PYOPENSSL_VERSION))
    try:
        if backend == 'pyopenssl':
            if not PYOPENSSL_FOUND:
                module.fail_json(msg=missing_required_lib('pyOpenSSL >= {0}'.format(MINIMAL_PYOPENSSL_VERSION)),
                                 exception=PYOPENSSL_IMP_ERR)
            module.deprecate('The module is using the PyOpenSSL backend. This backend has been deprecated',
                             version='2.13')
            _sign = SignaturePyOpenSSL(module, backend)
        elif backend == 'cryptography':
            if not CRYPTOGRAPHY_FOUND:
                module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                                 exception=CRYPTOGRAPHY_IMP_ERR)
            _sign = SignatureCryptography(module, backend)

        result = _sign.run()

        module.exit_json(**result)
    except crypto_utils.OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == '__main__':
    main()
