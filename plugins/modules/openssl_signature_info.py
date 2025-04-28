#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: openssl_signature_info
version_added: 1.1.0
short_description: Verify signatures with openssl
description:
  - This module allows one to verify a signature for a file by a certificate.
  - The module uses the cryptography Python library.
requirements:
  - cryptography >= 1.4 (some key types require newer versions)
author:
  - Patrick Pichler (@aveexy)
  - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
  - community.crypto.attributes
  - community.crypto.attributes.info_module
  - community.crypto.attributes.idempotent_not_modify_state
options:
  path:
    description:
      - The signed file to verify.
      - This file will only be read and not modified.
    type: path
    required: true
  certificate_path:
    description:
      - The path to the certificate used to verify the signature.
      - Either O(certificate_path) or O(certificate_content) must be specified, but not both.
    type: path
  certificate_content:
    description:
      - The content of the certificate used to verify the signature.
      - Either O(certificate_path) or O(certificate_content) must be specified, but not both.
    type: str
  signature:
    description: Base64 encoded signature.
    type: str
    required: true
  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
    type: str
    default: auto
    choices: [auto, cryptography]
notes:
  - "When using the C(cryptography) backend, the following key types require at least the following C(cryptography) version:\n
    RSA keys: C(cryptography) >= 1.4\nDSA and ECDSA keys: C(cryptography) >= 1.5\ned448 and ed25519 keys: C(cryptography)
    >= 2.6."
seealso:
  - module: community.crypto.openssl_signature
  - module: community.crypto.x509_certificate
"""

EXAMPLES = r"""
---
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
"""

RETURN = r"""
valid:
  description: V(true) means the signature was valid for the given file, V(false) means it was not.
  returned: success
  type: bool
"""

import base64
import os
import traceback

from ansible_collections.community.crypto.plugins.module_utils.version import (
    LooseVersion,
)


MINIMAL_CRYPTOGRAPHY_VERSION = "1.4"

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

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    CRYPTOGRAPHY_HAS_DSA_SIGN,
    CRYPTOGRAPHY_HAS_EC_SIGN,
    CRYPTOGRAPHY_HAS_ED448_SIGN,
    CRYPTOGRAPHY_HAS_ED25519_SIGN,
    CRYPTOGRAPHY_HAS_RSA_SIGN,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_certificate,
)


class SignatureInfoBase(OpenSSLObject):

    def __init__(self, module, backend):
        super(SignatureInfoBase, self).__init__(
            path=module.params["path"],
            state="present",
            force=False,
            check_mode=module.check_mode,
        )

        self.backend = backend

        self.signature = module.params["signature"]
        self.certificate_path = module.params["certificate_path"]
        self.certificate_content = module.params["certificate_content"]
        if self.certificate_content is not None:
            self.certificate_content = self.certificate_content.encode("utf-8")

    def generate(self):
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self):
        # Empty method because OpenSSLObject wants this
        pass


# Implementation with using cryptography
class SignatureInfoCryptography(SignatureInfoBase):

    def __init__(self, module, backend):
        super(SignatureInfoCryptography, self).__init__(module, backend)

    def run(self):
        _padding = cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15()
        _hash = cryptography.hazmat.primitives.hashes.SHA256()

        result = dict()

        try:
            with open(self.path, "rb") as f:
                _in = f.read()

            _signature = base64.b64decode(self.signature)
            certificate = load_certificate(
                path=self.certificate_path,
                content=self.certificate_content,
                backend=self.backend,
            )
            public_key = certificate.public_key()
            verified = False
            valid = False

            if CRYPTOGRAPHY_HAS_DSA_SIGN:
                try:
                    if isinstance(
                        public_key,
                        cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey,
                    ):
                        public_key.verify(_signature, _in, _hash)
                        verified = True
                        valid = True
                except cryptography.exceptions.InvalidSignature:
                    verified = True
                    valid = False

            if CRYPTOGRAPHY_HAS_EC_SIGN:
                try:
                    if isinstance(
                        public_key,
                        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey,
                    ):
                        public_key.verify(
                            _signature,
                            _in,
                            cryptography.hazmat.primitives.asymmetric.ec.ECDSA(_hash),
                        )
                        verified = True
                        valid = True
                except cryptography.exceptions.InvalidSignature:
                    verified = True
                    valid = False

            if CRYPTOGRAPHY_HAS_ED25519_SIGN:
                try:
                    if isinstance(
                        public_key,
                        cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey,
                    ):
                        public_key.verify(_signature, _in)
                        verified = True
                        valid = True
                except cryptography.exceptions.InvalidSignature:
                    verified = True
                    valid = False

            if CRYPTOGRAPHY_HAS_ED448_SIGN:
                try:
                    if isinstance(
                        public_key,
                        cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey,
                    ):
                        public_key.verify(_signature, _in)
                        verified = True
                        valid = True
                except cryptography.exceptions.InvalidSignature:
                    verified = True
                    valid = False

            if CRYPTOGRAPHY_HAS_RSA_SIGN:
                try:
                    if isinstance(
                        public_key,
                        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
                    ):
                        public_key.verify(_signature, _in, _padding, _hash)
                        verified = True
                        valid = True
                except cryptography.exceptions.InvalidSignature:
                    verified = True
                    valid = False

            if not verified:
                self.module.fail_json(
                    msg="Unsupported key type. Your cryptography version is {0}".format(
                        CRYPTOGRAPHY_VERSION
                    )
                )
            result["valid"] = valid
            return result

        except Exception as e:
            raise OpenSSLObjectError(e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            certificate_path=dict(type="path"),
            certificate_content=dict(type="str"),
            path=dict(type="path", required=True),
            signature=dict(type="str", required=True),
            select_crypto_backend=dict(
                type="str", choices=["auto", "cryptography"], default="auto"
            ),
        ),
        mutually_exclusive=(["certificate_path", "certificate_content"],),
        required_one_of=(["certificate_path", "certificate_content"],),
        supports_check_mode=True,
    )

    if not os.path.isfile(module.params["path"]):
        module.fail_json(
            name=module.params["path"],
            msg="The file {0} does not exist".format(module.params["path"]),
        )

    backend = module.params["select_crypto_backend"]
    if backend == "auto":
        # Detection what is possible
        can_use_cryptography = (
            CRYPTOGRAPHY_FOUND
            and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)
        )

        # Decision
        if can_use_cryptography:
            backend = "cryptography"

        # Success?
        if backend == "auto":
            module.fail_json(
                msg=(
                    "Cannot detect any of the required Python libraries "
                    "cryptography (>= {0})"
                ).format(MINIMAL_CRYPTOGRAPHY_VERSION)
            )
    try:
        if backend == "cryptography":
            if not CRYPTOGRAPHY_FOUND:
                module.fail_json(
                    msg=missing_required_lib(
                        "cryptography >= {0}".format(MINIMAL_CRYPTOGRAPHY_VERSION)
                    ),
                    exception=CRYPTOGRAPHY_IMP_ERR,
                )
            _sign = SignatureInfoCryptography(module, backend)

        result = _sign.run()

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
