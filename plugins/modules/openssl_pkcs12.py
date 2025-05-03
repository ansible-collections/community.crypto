#!/usr/bin/python
# Copyright (c) 2017, Guillaume Delpierre <gde@llew.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations


DOCUMENTATION = r"""
module: openssl_pkcs12
author:
  - Guillaume Delpierre (@gdelpierre)
short_description: Generate OpenSSL PKCS#12 archive
description:
  - This module allows one to (re-)generate PKCS#12.
  - The module uses the cryptography Python library.
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto.attributes
  - community.crypto.attributes.files
  - community.crypto.cryptography_dep.minimum
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  safe_file_operations:
    support: full
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(force=true).
options:
  action:
    description:
      - V(export) or V(parse) a PKCS#12.
    type: str
    default: export
    choices: [export, parse]
  other_certificates:
    description:
      - List of other certificates to include. Pre Ansible 2.8 this parameter was called O(ca_certificates).
      - Assumes there is one PEM-encoded certificate per file. If a file contains multiple PEM certificates, set O(other_certificates_parse_all)
        to V(true).
      - Mutually exclusive with O(other_certificates_content).
    type: list
    elements: path
    aliases: [ca_certificates]
  other_certificates_content:
    description:
      - List of other certificates to include.
      - Assumes there is one PEM-encoded certificate per item. If an item contains multiple PEM certificates, set O(other_certificates_parse_all)
      - Mutually exclusive with O(other_certificates).
    type: list
    elements: str
    version_added: "2.26.0"
  other_certificates_parse_all:
    description:
      - If set to V(true), assumes that the files mentioned in O(other_certificates)/O(other_certificates_content) can contain more than one
        certificate per file/item (or even none per file/item).
    type: bool
    default: false
    version_added: 1.4.0
  certificate_path:
    description:
      - The path to read certificates and private keys from.
      - Must be in PEM format.
      - Mutually exclusive with O(certificate_content).
    type: path
  certificate_content:
    description:
      - Content of the certificate file in PEM format.
      - Mutually exclusive with O(certificate_path).
    type: str
    version_added: "2.26.0"
  force:
    description:
      - Should the file be regenerated even if it already exists.
    type: bool
    default: false
  friendly_name:
    description:
      - Specifies the friendly name for the certificate and private key.
    type: str
    aliases: [name]
  iter_size:
    description:
      - Number of times to repeat the encryption step.
      - This is B(not considered during idempotency checks).
      - This is only used when O(encryption_level=compatibility2022).
      - When using it, the default is V(50000).
    type: int
  maciter_size:
    description:
      - Number of times to repeat the MAC step.
      - This is B(not considered during idempotency checks).
      - This value is B(not used).
    type: int
    # TODO: deprecate!
  encryption_level:
    description:
      - Determines the encryption level used.
      - V(auto) uses the default of the selected backend. For C(cryptography), this is what the cryptography library's specific
        version considers the best available encryption.
      - V(compatibility2022) uses compatibility settings for older software in 2022. This is only supported by the C(cryptography)
        backend if cryptography >= 38.0.0 is available.
      - B(Note) that this option is B(not used for idempotency).
    choices:
      - auto
      - compatibility2022
    default: auto
    type: str
    version_added: 2.8.0
  passphrase:
    description:
      - The PKCS#12 password.
      - B(Note:) PKCS12 encryption is typically not secure and should not be used as a security mechanism. If you need to
        store or send a PKCS12 file safely, you should additionally encrypt it with something else. (L(Source,
        https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#cryptography.hazmat.primitives.serialization.pkcs12.serialize_key_and_certificates)).
    type: str
  path:
    description:
      - Filename to write the PKCS#12 file to.
    type: path
    required: true
  privatekey_passphrase:
    description:
      - Passphrase source to decrypt any input private keys with.
    type: str
  privatekey_path:
    description:
      - File to read private key from.
      - Mutually exclusive with O(privatekey_content).
    type: path
  privatekey_content:
    description:
      - Content of the private key file.
      - Mutually exclusive with O(privatekey_path).
    type: str
    version_added: "2.3.0"
  state:
    description:
      - Whether the file should exist or not. All parameters except O(path) are ignored when state is V(absent).
    choices: [absent, present]
    default: present
    type: str
  src:
    description:
      - PKCS#12 file path to parse.
    type: path
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original output file back if you overwrote it with a
        new one by accident.
    type: bool
    default: false
  return_content:
    description:
      - If set to V(true), will return the (current or generated) PKCS#12's content as RV(pkcs12).
    type: bool
    default: false
    version_added: "1.0.0"
  select_crypto_backend:
    description:
      - Determines which crypto backend to use.
      - The default choice is V(auto), which tries to use C(cryptography) if available.
      - If set to V(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
      - The value V(pyopenssl) has been removed for community.crypto 3.0.0.
      - Note that with community.crypto 3.0.0, all remaining values behave the same.
        This option will be deprecated in a later version.
        We recommend to not set it explicitly.
    type: str
    default: auto
    choices: [auto, cryptography]
    version_added: 1.7.0
seealso:
  - module: community.crypto.x509_certificate
  - module: community.crypto.openssl_csr
  - module: community.crypto.openssl_dhparam
  - module: community.crypto.openssl_privatekey
  - module: community.crypto.openssl_publickey
"""

EXAMPLES = r"""
---
- name: Generate PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
  # Note that if /opt/certs/ca.pem contains multiple certificates,
  # only the first one will be used. See the other_certificates_parse_all
  # option for changing this behavior.
    state: present

- name: Generate PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_content: '{{ private_key_contents }}'
    certificate_path: /opt/certs/cert.pem
    other_certificates_parse_all: true
    other_certificates:
      - /opt/certs/ca_bundle.pem
      # Since we set other_certificates_parse_all to true, all
      # certificates in the CA bundle are included and not just
      # the first one.
      - /opt/certs/intermediate.pem
      # In case this file has multiple certificates in it,
      # all will be included as well.
    state: present

- name: Change PKCS#12 file permission
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
    state: present
    mode: '0600'

- name: Regen PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    src: /opt/certs/ansible.p12
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
    state: present
    mode: '0600'
    force: true

- name: Dump/Parse PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: parse
    src: /opt/certs/ansible.p12
    path: /opt/certs/ansible.pem
    state: present

- name: Remove PKCS#12 file
  community.crypto.openssl_pkcs12:
    path: /opt/certs/ansible.p12
    state: absent
"""

RETURN = r"""
filename:
  description: Path to the generate PKCS#12 file.
  returned: changed or success
  type: str
  sample: /opt/certs/ansible.p12
privatekey:
  description: Path to the TLS/SSL private key the public key was generated from.
  returned: changed or success
  type: str
  sample: /etc/ssl/private/ansible.com.pem
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/ansible.com.pem.2019-03-09@11:22~
pkcs12:
  description: The (current or generated) PKCS#12's content Base64 encoded.
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
  version_added: "1.0.0"
"""

import abc
import base64
import itertools
import os
import stat
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    parse_pkcs12,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    split_pem_list,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_certificate,
    load_privatekey,
)
from ansible_collections.community.crypto.plugins.module_utils.cryptography_dep import (
    COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
    assert_required_cryptography_version,
)
from ansible_collections.community.crypto.plugins.module_utils.io import (
    load_file_if_exists,
    write_file,
)


MINIMAL_CRYPTOGRAPHY_VERSION = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        serialize_key_and_certificates,
    )
except ImportError:
    pass

CRYPTOGRAPHY_COMPATIBILITY2022_ERR = None
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization.pkcs12 import PBES

    # Try to build encryption builder for compatibility2022
    serialization.PrivateFormat.PKCS12.encryption_builder().key_cert_algorithm(
        PBES.PBESv1SHA1And3KeyTripleDESCBC
    ).hmac_hash(hashes.SHA1())
except Exception:
    CRYPTOGRAPHY_COMPATIBILITY2022_ERR = traceback.format_exc()
    CRYPTOGRAPHY_HAS_COMPATIBILITY2022 = False
else:
    CRYPTOGRAPHY_HAS_COMPATIBILITY2022 = True


def load_certificate_set(filename):
    """
    Load list of concatenated PEM files, and return a list of parsed certificates.
    """
    with open(filename, "rb") as f:
        data = f.read().decode("utf-8")
    return [
        load_certificate(None, content=cert.encode("utf-8"))
        for cert in split_pem_list(data)
    ]


class PkcsError(OpenSSLObjectError):
    pass


class Pkcs(OpenSSLObject):
    def __init__(self, module, iter_size_default=2048):
        super(Pkcs, self).__init__(
            module.params["path"],
            module.params["state"],
            module.params["force"],
            module.check_mode,
        )
        self.action = module.params["action"]
        self.other_certificates = module.params["other_certificates"]
        self.other_certificates_parse_all = module.params[
            "other_certificates_parse_all"
        ]
        self.other_certificates_content = module.params["other_certificates_content"]
        self.certificate_path = module.params["certificate_path"]
        self.certificate_content = module.params["certificate_content"]
        self.friendly_name = module.params["friendly_name"]
        self.iter_size = module.params["iter_size"] or iter_size_default
        self.maciter_size = module.params["maciter_size"] or 1
        self.encryption_level = module.params["encryption_level"]
        self.passphrase = module.params["passphrase"]
        self.pkcs12 = None
        self.privatekey_passphrase = module.params["privatekey_passphrase"]
        self.privatekey_path = module.params["privatekey_path"]
        self.privatekey_content = module.params["privatekey_content"]
        self.pkcs12_bytes = None
        self.return_content = module.params["return_content"]
        self.src = module.params["src"]

        if module.params["mode"] is None:
            module.params["mode"] = "0400"

        self.backup = module.params["backup"]
        self.backup_file = None

        if self.certificate_path is not None:
            try:
                with open(self.certificate_path, "rb") as fh:
                    self.certificate_content = fh.read()
            except (IOError, OSError) as exc:
                raise PkcsError(exc)
        elif self.certificate_content is not None:
            self.certificate_content = to_bytes(self.certificate_content)

        if self.privatekey_path is not None:
            try:
                with open(self.privatekey_path, "rb") as fh:
                    self.privatekey_content = fh.read()
            except (IOError, OSError) as exc:
                raise PkcsError(exc)
        elif self.privatekey_content is not None:
            self.privatekey_content = to_bytes(self.privatekey_content)

        if self.other_certificates:
            if self.other_certificates_parse_all:
                filenames = list(self.other_certificates)
                self.other_certificates = []
                for other_cert_bundle in filenames:
                    self.other_certificates.extend(
                        load_certificate_set(other_cert_bundle)
                    )
            else:
                self.other_certificates = [
                    load_certificate(other_cert)
                    for other_cert in self.other_certificates
                ]
        elif self.other_certificates_content:
            certs = self.other_certificates_content
            if self.other_certificates_parse_all:
                certs = list(
                    itertools.chain.from_iterable(
                        split_pem_list(content) for content in certs
                    )
                )
            self.other_certificates = [
                load_certificate(None, content=to_bytes(other_cert))
                for other_cert in certs
            ]

    @abc.abstractmethod
    def generate_bytes(self, module):
        """Generate PKCS#12 file archive."""
        pass

    @abc.abstractmethod
    def parse_bytes(self, pkcs12_content):
        pass

    @abc.abstractmethod
    def _dump_privatekey(self, pkcs12):
        pass

    @abc.abstractmethod
    def _dump_certificate(self, pkcs12):
        pass

    @abc.abstractmethod
    def _dump_other_certificates(self, pkcs12):
        pass

    @abc.abstractmethod
    def _get_friendly_name(self, pkcs12):
        pass

    def check(self, module, perms_required=True):
        """Ensure the resource is in its desired state."""

        state_and_perms = super(Pkcs, self).check(module, perms_required)

        def _check_pkey_passphrase():
            if self.privatekey_passphrase:
                try:
                    load_privatekey(
                        None,
                        content=self.privatekey_content,
                        passphrase=self.privatekey_passphrase,
                    )
                except OpenSSLObjectError:
                    return False
            return True

        if not state_and_perms:
            return state_and_perms

        if os.path.exists(self.path) and module.params["action"] == "export":
            self.generate_bytes(module)  # ignore result
            self.src = self.path
            try:
                (
                    pkcs12_privatekey,
                    pkcs12_certificate,
                    pkcs12_other_certificates,
                    pkcs12_friendly_name,
                ) = self.parse()
            except OpenSSLObjectError:
                return False
            if (pkcs12_privatekey is not None) and (
                self.privatekey_content is not None
            ):
                expected_pkey = self._dump_privatekey(self.pkcs12)
                if pkcs12_privatekey != expected_pkey:
                    return False
            elif bool(pkcs12_privatekey) != bool(self.privatekey_content):
                return False

            if (pkcs12_certificate is not None) and (
                self.certificate_content is not None
            ):
                expected_cert = self._dump_certificate(self.pkcs12)
                if pkcs12_certificate != expected_cert:
                    return False
            elif bool(pkcs12_certificate) != bool(self.certificate_content):
                return False

            if (pkcs12_other_certificates is not None) and (
                self.other_certificates is not None
            ):
                expected_other_certs = self._dump_other_certificates(self.pkcs12)
                if set(pkcs12_other_certificates) != set(expected_other_certs):
                    return False
            elif bool(pkcs12_other_certificates) != bool(self.other_certificates):
                return False

            if pkcs12_privatekey:
                # This check is required because pyOpenSSL will not return a friendly name
                # if the private key is not set in the file
                friendly_name = self._get_friendly_name(self.pkcs12)
                if (friendly_name is not None) and (pkcs12_friendly_name is not None):
                    if friendly_name != pkcs12_friendly_name:
                        return False
                elif bool(friendly_name) != bool(pkcs12_friendly_name):
                    return False
        elif (
            module.params["action"] == "parse"
            and os.path.exists(self.src)
            and os.path.exists(self.path)
        ):
            try:
                pkey, cert, other_certs, friendly_name = self.parse()
            except OpenSSLObjectError:
                return False
            expected_content = to_bytes(
                "".join(
                    [
                        to_native(pem)
                        for pem in [pkey, cert] + other_certs
                        if pem is not None
                    ]
                )
            )
            dumped_content = load_file_if_exists(self.path, ignore_errors=True)
            if expected_content != dumped_content:
                return False
        else:
            return False

        return _check_pkey_passphrase()

    def dump(self):
        """Serialize the object into a dictionary."""

        result = {
            "filename": self.path,
        }
        if self.privatekey_path:
            result["privatekey_path"] = self.privatekey_path
        if self.backup_file:
            result["backup_file"] = self.backup_file
        if self.return_content:
            if self.pkcs12_bytes is None:
                self.pkcs12_bytes = load_file_if_exists(self.path, ignore_errors=True)
            result["pkcs12"] = (
                base64.b64encode(self.pkcs12_bytes) if self.pkcs12_bytes else None
            )

        return result

    def remove(self, module):
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        super(Pkcs, self).remove(module)

    def parse(self):
        """Read PKCS#12 file."""

        try:
            with open(self.src, "rb") as pkcs12_fh:
                pkcs12_content = pkcs12_fh.read()
            return self.parse_bytes(pkcs12_content)
        except IOError as exc:
            raise PkcsError(exc)

    def generate(self):
        pass

    def write(self, module, content, mode=None):
        """Write the PKCS#12 file."""
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        write_file(module, content, mode)
        if self.return_content:
            self.pkcs12_bytes = content


class PkcsCryptography(Pkcs):
    def __init__(self, module):
        super(PkcsCryptography, self).__init__(module, iter_size_default=50000)
        if (
            self.encryption_level == "compatibility2022"
            and not CRYPTOGRAPHY_HAS_COMPATIBILITY2022
        ):
            module.fail_json(
                msg="The installed cryptography version does not support encryption_level = compatibility2022."
                " You need cryptography >= 38.0.0 and support for SHA1",
                exception=CRYPTOGRAPHY_COMPATIBILITY2022_ERR,
            )

    def generate_bytes(self, module):
        """Generate PKCS#12 file archive."""
        pkey = None
        if self.privatekey_content:
            try:
                pkey = load_privatekey(
                    None,
                    content=self.privatekey_content,
                    passphrase=self.privatekey_passphrase,
                )
            except OpenSSLBadPassphraseError as exc:
                raise PkcsError(exc)

        cert = None
        if self.certificate_content:
            cert = load_certificate(None, content=self.certificate_content)

        friendly_name = (
            to_bytes(self.friendly_name) if self.friendly_name is not None else None
        )

        # Store fake object which can be used to retrieve the components back
        self.pkcs12 = (pkey, cert, self.other_certificates, friendly_name)

        if not self.passphrase:
            encryption = serialization.NoEncryption()
        elif self.encryption_level == "compatibility2022":
            encryption = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .kdf_rounds(self.iter_size)
                .key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .hmac_hash(hashes.SHA1())
                .build(to_bytes(self.passphrase))
            )
        else:
            encryption = serialization.BestAvailableEncryption(
                to_bytes(self.passphrase)
            )

        return serialize_key_and_certificates(
            friendly_name,
            pkey,
            cert,
            self.other_certificates,
            encryption,
        )

    def parse_bytes(self, pkcs12_content):
        try:
            private_key, certificate, additional_certificates, friendly_name = (
                parse_pkcs12(pkcs12_content, self.passphrase)
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

            return (pkey, crt, other_certs, friendly_name)
        except ValueError as exc:
            raise PkcsError(exc)

    # The following methods will get self.pkcs12 passed, which is computed as:
    #
    #     self.pkcs12 = (pkey, cert, self.other_certificates, self.friendly_name)

    def _dump_privatekey(self, pkcs12):
        return (
            pkcs12[0].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            if pkcs12[0]
            else None
        )

    def _dump_certificate(self, pkcs12):
        return pkcs12[1].public_bytes(serialization.Encoding.PEM) if pkcs12[1] else None

    def _dump_other_certificates(self, pkcs12):
        return [
            other_cert.public_bytes(serialization.Encoding.PEM)
            for other_cert in pkcs12[2]
        ]

    def _get_friendly_name(self, pkcs12):
        return pkcs12[3]


def select_backend(module):
    assert_required_cryptography_version(
        module, minimum_cryptography_version=MINIMAL_CRYPTOGRAPHY_VERSION
    )
    return PkcsCryptography(module)


def main():
    argument_spec = dict(
        action=dict(type="str", default="export", choices=["export", "parse"]),
        other_certificates=dict(
            type="list", elements="path", aliases=["ca_certificates"]
        ),
        other_certificates_parse_all=dict(type="bool", default=False),
        other_certificates_content=dict(type="list", elements="str"),
        certificate_path=dict(type="path"),
        certificate_content=dict(type="str"),
        force=dict(type="bool", default=False),
        friendly_name=dict(type="str", aliases=["name"]),
        encryption_level=dict(
            type="str", choices=["auto", "compatibility2022"], default="auto"
        ),
        iter_size=dict(type="int"),
        maciter_size=dict(type="int"),
        passphrase=dict(type="str", no_log=True),
        path=dict(type="path", required=True),
        privatekey_passphrase=dict(type="str", no_log=True),
        privatekey_path=dict(type="path"),
        privatekey_content=dict(type="str", no_log=True),
        state=dict(type="str", default="present", choices=["absent", "present"]),
        src=dict(type="path"),
        backup=dict(type="bool", default=False),
        return_content=dict(type="bool", default=False),
        select_crypto_backend=dict(
            type="str", default="auto", choices=["auto", "cryptography"]
        ),
    )

    required_if = [
        ["action", "parse", ["src"]],
    ]

    mutually_exclusive = [
        ["privatekey_path", "privatekey_content"],
        ["certificate_path", "certificate_content"],
        ["other_certificates", "other_certificates_content"],
    ]

    module = AnsibleModule(
        add_file_common_args=True,
        argument_spec=argument_spec,
        required_if=required_if,
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
        changed = False

        if module.params["state"] == "present":
            if module.check_mode:
                result = pkcs12.dump()
                result["changed"] = module.params["force"] or not pkcs12.check(module)
                module.exit_json(**result)

            if not pkcs12.check(module, perms_required=False) or module.params["force"]:
                if module.params["action"] == "export":
                    if not module.params["friendly_name"]:
                        module.fail_json(msg="Friendly_name is required")
                    pkcs12_content = pkcs12.generate_bytes(module)
                    pkcs12.write(module, pkcs12_content, 0o600)
                    changed = True
                else:
                    pkey, cert, other_certs, friendly_name = pkcs12.parse()
                    dump_content = "".join(
                        [
                            to_native(pem)
                            for pem in [pkey, cert] + other_certs
                            if pem is not None
                        ]
                    )
                    pkcs12.write(module, to_bytes(dump_content))
                    changed = True

            file_args = module.load_file_common_arguments(module.params)
            if module.check_file_absent_if_check_mode(file_args["path"]):
                changed = True
            elif module.set_fs_attributes_if_different(file_args, changed):
                changed = True
        else:
            if module.check_mode:
                result = pkcs12.dump()
                result["changed"] = os.path.exists(module.params["path"])
                module.exit_json(**result)

            if os.path.exists(module.params["path"]):
                pkcs12.remove(module)
                changed = True

        result = pkcs12.dump()
        result["changed"] = changed
        if os.path.exists(module.params["path"]):
            file_mode = f"{stat.S_IMODE(os.stat(module.params['path']).st_mode):04o}"
            result["mode"] = file_mode

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=str(exc))


if __name__ == "__main__":
    main()
