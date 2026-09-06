#!/usr/bin/python
# Copyright (c) 2026 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: openssl_pkcs12_info
author:
  - Felix Fontein (@felixfontein)
short_description: Return certificates and (optionally) private key of a PKCS#12 file
version_added: 3.4.0
description:
  - This module loads an PKCS#12 file and returns the contained certificates.
  - If O(return_private_key=true), the private key (if contained) is also returned.
extends_documentation_fragment:
  - community.crypto._attributes
  - community.crypto._attributes.info_module
  - community.crypto._attributes.idempotent_not_modify_state
  - community.crypto._cryptography_dep.minimum
options:
  passphrase:
    description:
      - The PKCS#12 password.
    type: str
  path:
    description:
      - Filename to read the PKCS#12 file from.
      - Either O(path) or O(content) must be specified, but not both.
    type: path
  content:
    description:
      - Base64 encoded contents of a PKCS#12 file.
      - Either O(path) or O(content) must be specified, but not both.
    type: str
  return_private_key:
    description:
      - Whether to return the private key as RV(privatekey).
      - Avoid returning this unless needed.
    type: bool
    default: false
seealso:
  - module: community.crypto.x509_certificate_info
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_pkcs12_extract
"""

EXAMPLES = r"""
---
- name: Obtain certificates from PKCS#12 file
  community.crypto.openssl_pkcs12_info:
    path: /opt/certs/ansible.p12
  register: result
"""

RETURN = r"""
friendly_name:
  description:
    - >-
      "Friendly name" of the certificate and private key pair.
    - If no private key is contained in the archive, this has value V(null).
  returned: success
  type: str
  sample: keypair
certificate:
  description:
    - Certificate associated to the private key in the PKCS#12 archive in PEM format.
    - If no private key is contained in the archive, this has value V(null).
  returned: success
  type: str
  sample: |-
    -----BEGIN CERTIFICATE-----
    MIIBljCCATugAw...
other_certificates:
  description:
    - Other certificates (not associated to the private key) in the PKCS#12 archive in PEM format.
  returned: success
  type: list
  elements: str
  sample:
    - |-
      -----BEGIN CERTIFICATE-----
      MIIBljCCATugAw...
privatekey:
  description:
    - The PKCS#12 archive's private key in PEM format, if present.
    - Only returned if O(return_private_key=true).
  returned: success if O(return_private_key=true)
  type: str
"""

import base64
import typing as t

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text

from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    parse_pkcs12,
)
from ansible_collections.community.crypto.plugins.module_utils._cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)

MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


class PkcsError(OpenSSLObjectError):
    pass


class PkcsInfo:
    def __init__(self, module: AnsibleModule) -> None:
        self.module = module
        self.passphrase: str | None = module.params["passphrase"]
        self.path: str | None = module.params["path"]
        self.return_private_key: bool = module.params["return_private_key"]

    def parse_bytes(self) -> tuple[
        bytes | None,
        bytes | None,
        list[bytes],
        bytes | None,
    ]:
        if self.path is not None:
            try:
                with open(self.path, "rb") as fh:
                    content = fh.read()
            except (IOError, OSError) as exc:
                raise PkcsError(f"Error while reading {self.path}: {exc}") from exc
        else:
            try:
                content = base64.b64decode(self.module.params["content"])
            except Exception as exc:
                raise PkcsError(
                    f"Error while decoding Base64 encoded content: {exc}"
                ) from exc

        try:
            private_key, certificate, additional_certificates, friendly_name = (
                parse_pkcs12(content, passphrase=self.passphrase)
            )

            pkey = None
            if private_key is not None:
                pkey = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )

            crt = None
            if certificate is not None:
                crt = certificate.public_bytes(serialization.Encoding.PEM)

            other_certs = []
            if additional_certificates is not None:
                other_certs = [
                    other_cert.public_bytes(serialization.Encoding.PEM)
                    for other_cert in additional_certificates
                ]

            return pkey, crt, other_certs, friendly_name
        except ValueError as exc:
            raise PkcsError(exc) from exc

    def run(self) -> dict[str, t.Any]:
        """Run the module."""
        pkey, cert, other_certs, friendly_name = self.parse_bytes()
        result: dict[str, t.Any] = {
            "certificate": to_text(cert) if cert else None,
            "other_certificates": [to_text(crt) for crt in other_certs],
            "friendly_name": to_text(friendly_name) if friendly_name is not None else None,
        }
        if self.return_private_key:
            result["privatekey"] = to_text(pkey) if pkey else None

        return result


def select_backend(module: AnsibleModule) -> PkcsInfo:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PkcsInfo(module)


def main() -> t.NoReturn:
    argument_spec = {
        "path": {"type": "path"},
        "content": {"type": "str", "no_log": True},
        "passphrase": {"type": "str", "no_log": True},
        "return_private_key": {"type": "bool", "default": False},
    }

    required_one_of = [
        ("path", "content"),
    ]

    mutually_exclusive = [
        ("path", "content"),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=required_one_of,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )

    pkcs12 = select_backend(module)

    try:
        result = pkcs12.run()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
