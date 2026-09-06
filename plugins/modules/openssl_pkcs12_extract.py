#!/usr/bin/python
# Copyright (c) 2017, Guillaume Delpierre <gde@llew.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
module: openssl_pkcs12_extract
author:
  - Felix Fontein (@felixfontein)
  - Guillaume Delpierre (@gdelpierre)
short_description: Extract certificate and private key from PKCS#12 archive
version_added: 3.4.0
description:
  - This module allows to extract certificates and private key from a PKCS#12 archive.
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto._attributes
  - community.crypto._attributes.files
  - community.crypto._cryptography_dep.minimum
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  safe_file_operations:
    support: full
  idempotent:
    support: full
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
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original output file back if you overwrote it with a
        new one by accident.
    type: bool
    default: false
  combined_path:
    description:
      - If specified, the concatenation of private key (if exists), certificate (if exists), and other certificates will be written to this path.
        All objects are written in PEM format.
      - If O(backup=true) and the file exists and is about to be overwritten,
        a backup will be created and its filename is returned as RV(combined_backup_file).
      - At least one of O(combined_path), O(cert_path), O(privatekey_path), O(other_certs_path), and O(all_certs_path) must be specified.
    type: path
  cert_path:
    description:
      - If specified, the certificate (if exists) associated to the private key will be written to this path in PEM format.
      - If O(backup=true) and the file exists and is about to be overwritten,
        a backup will be created and its filename is returned as RV(cert_backup_file).
      - At least one of O(combined_path), O(cert_path), O(privatekey_path), O(other_certs_path), and O(all_certs_path) must be specified.
    type: path
  privatekey_path:
    description:
      - If specified, the private key will be written to this path in PEM format.
      - If O(backup=true) and the file exists and is about to be overwritten,
        a backup will be created and its filename is returned as RV(privatekey_backup_file).
      - At least one of O(combined_path), O(cert_path), O(privatekey_path), O(other_certs_path), and O(all_certs_path) must be specified.
    type: path
  other_certs_path:
    description:
      - If specified, the concatenation of all other certificates (not associated to the private key) will be written to this path in PEM format.
      - If O(backup=true) and the file exists and is about to be overwritten,
        a backup will be created and its filename is returned as RV(other_certs_backup_file).
      - At least one of O(combined_path), O(cert_path), O(privatekey_path), O(other_certs_path), and O(all_certs_path) must be specified.
    type: path
  all_certs_path:
    description:
      - If specified, the concatenation of all certificates will be written to this path in PEM format.
      - If O(backup=true) and the file exists and is about to be overwritten,
        a backup will be created and its filename is returned as RV(all_certs_backup_file).
      - At least one of O(combined_path), O(cert_path), O(privatekey_path), O(other_certs_path), and O(all_certs_path) must be specified.
    type: path

seealso:
  - module: community.crypto.x509_certificate_info
  - module: community.crypto.openssl_pkcs12
  - module: community.crypto.openssl_pkcs12_info
  - module: community.crypto.openssl_privatekey_info
"""

EXAMPLES = r"""
---
- name: Parse PKCS#12 file and concatenate private key and certs into PEM file
  community.crypto.openssl_pkcs12_extract:
    path: /opt/certs/ansible.p12
    combined_path: /opt/certs/ansible-combined.pem
"""

RETURN = r"""
combined_backup_file:
  description:
    - Name of backup file created.
  returned: O(backup=true), O(combined_path) is specified, and the file contents have been changed
  type: str
  sample: /path/to/ansible.com-combined.pem.2019-03-09@11:22~
cert_backup_file:
  description:
    - Name of backup file created.
  returned: O(backup=true), O(cert_path) is specified, and the file contents have been changed
  type: str
  sample: /path/to/ansible.com.pem.2019-03-09@11:22~
privatekey_backup_file:
  description:
    - Name of backup file created.
  returned: O(backup=true), O(privatekey_path) is specified, and the file contents have been changed
  type: str
  sample: /path/to/ansible.com.key.2019-03-09@11:22~
other_certs_backup_file:
  description:
    - Name of backup file created.
  returned: O(backup=true), O(other_certs_path) is specified, and the file contents have been changed
  type: str
  sample: /path/to/ansible.com-chain.pem.2019-03-09@11:22~
all_certs_backup_file:
  description:
    - Name of backup file created.
  returned: O(backup=true), O(all_certs_path) is specified, and the file contents have been changed
  type: str
  sample: /path/to/ansible.com-all-certs.pem.2019-03-09@11:22~
"""

import base64
import os
import typing as t

from ansible.module_utils.basic import AnsibleModule

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
from ansible_collections.community.crypto.plugins.module_utils._io import (
    load_file_if_exists,
    write_file,
)

MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass


class PkcsError(OpenSSLObjectError):
    pass


class PkcsExtract:
    def __init__(self, module: AnsibleModule) -> None:
        self.module = module
        self.passphrase: str | None = module.params["passphrase"]
        self.path: str | None = module.params["path"]
        self.backup: bool = module.params["backup"]

        self.combined_path: str | None = module.params["combined_path"]
        self.cert_path: str | None = module.params["cert_path"]
        self.privatekey_path: str | None = module.params["privatekey_path"]
        self.other_certs_path: str | None = module.params["other_certs_path"]
        self.all_certs_path: str | None = module.params["all_certs_path"]

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

    def get_file_contents(
        self, pkey: bytes | None, cert: bytes | None, other_certs: list[bytes]
    ) -> dict[str, tuple[bytes, str, bool]]:
        result: dict[str, tuple[bytes, str, bool]] = {}

        if self.combined_path is not None:
            expected_content = b"".join(
                [pem for pem in [pkey, cert] + other_certs if pem is not None]
            )
            result[self.combined_path] = (
                expected_content,
                "combined_backup_file",
                True,
            )

        if self.cert_path is not None and cert is not None:
            result[self.cert_path] = (cert, "cert_backup_file", False)

        if self.privatekey_path is not None and pkey is not None:
            result[self.privatekey_path] = (pkey, "privatekey_backup_file", True)

        if self.other_certs_path is not None:
            result[self.other_certs_path] = (
                b"".join(other_certs),
                "other_certs_backup_file",
                False,
            )

        if self.all_certs_path is not None:
            expected_content = b"".join(
                [pem for pem in [cert] + other_certs if pem is not None]
            )
            result[self.all_certs_path] = (
                expected_content,
                "all_certs_backup_file",
                False,
            )

        return result

    def write_file_content(
        self,
        filename: str,
        content: bytes,
        *,
        result: dict[str, t.Any],
        contains_pkey: bool,
        backup_key: str,
    ) -> bool:
        base_dir = os.path.dirname(filename) or "."
        if not os.path.isdir(base_dir):
            raise PkcsError(
                f"The directory '{base_dir}' does not exist or the path is not a directory"
            )

        current_content = load_file_if_exists(path=filename, ignore_errors=True)
        if current_content == content:
            return False

        if not self.module.check_mode:
            if self.backup:
                result[backup_key] = self.module.backup_local(filename)
            write_file(
                module=self.module,
                path=filename,
                content=content,
                default_mode=0o600 if contains_pkey else None,
            )

        return True

    def write_file(
        self,
        filename: str,
        content: bytes,
        *,
        result: dict[str, t.Any],
        contains_pkey: bool,
        backup_key: str,
    ) -> bool:
        changed = self.write_file_content(
            filename,
            content,
            result=result,
            contains_pkey=contains_pkey,
            backup_key=backup_key,
        )

        if not self.module.check_file_absent_if_check_mode(filename):
            file_args = self.module.load_file_common_arguments(
                self.module.params, path=filename
            )
            changed = self.module.set_fs_attributes_if_different(file_args, changed)

        return changed

    def run(self) -> dict[str, t.Any]:
        """Run the module."""
        pkey, cert, other_certs, friendly_name = self.parse_bytes()
        files = self.get_file_contents(pkey, cert, other_certs)
        result: dict[str, t.Any] = {
            "friendly_name": friendly_name,
        }
        changed = False
        for file, (content, backup_key, contains_pkey) in files.items():
            if self.write_file(
                file,
                content,
                result=result,
                contains_pkey=contains_pkey,
                backup_key=backup_key,
            ):
                changed = True
        result["changed"] = changed
        return result


def select_backend(module: AnsibleModule) -> PkcsExtract:
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PkcsExtract(module)


def main() -> t.NoReturn:
    argument_spec = {
        "path": {"type": "path"},
        "content": {"type": "str", "no_log": True},
        "passphrase": {"type": "str", "no_log": True},
        "backup": {"type": "bool", "default": False},
        "combined_path": {"type": "path"},
        "cert_path": {"type": "path"},
        "privatekey_path": {"type": "path"},
        "other_certs_path": {"type": "path"},
        "all_certs_path": {"type": "path"},
    }

    required_one_of = [
        ("path", "content"),
        (
            "combined_path",
            "cert_path",
            "privatekey_path",
            "other_certs_path",
            "all_certs_path",
        ),
    ]

    mutually_exclusive = [
        ("path", "content"),
    ]

    module = AnsibleModule(
        add_file_common_args=True,
        argument_spec=argument_spec,
        required_one_of=required_one_of,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )

    pkcs12 = select_backend(module)

    base_dir = os.path.dirname(module.params["path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg=f"The directory '{base_dir}' does not exist or the path is not a directory",
        )

    try:
        result = pkcs12.run()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
