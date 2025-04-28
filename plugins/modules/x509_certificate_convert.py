#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: x509_certificate_convert
short_description: Convert X.509 certificates
version_added: 2.19.0
description:
  - This module allows to convert X.509 certificates between different formats.
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto.attributes
  - community.crypto.attributes.files
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
  src_path:
    description:
      - Name of the file containing the X.509 certificate to convert.
      - Exactly one of O(src_path) or O(src_content) must be specified.
    type: path
  src_content:
    description:
      - The content of the file containing the X.509 certificate to convert.
      - This must be text. If you are not sure that the input file is PEM, you must Base64 encode the value and set O(src_content_base64=true).
        You can use the P(ansible.builtin.b64encode#filter) filter plugin for this.
      - Exactly one of O(src_path) or O(src_content) must be specified.
    type: str
  src_content_base64:
    description:
      - If set to V(true) when O(src_content) is provided, the module assumes that the value of O(src_content) is Base64 encoded.
    type: bool
    default: false
  format:
    description:
      - Determines which format the destination X.509 certificate should be written in.
      - Please note that not every key can be exported in any format, and that not every format supports encryption.
    type: str
    choices:
      - pem
      - der
    required: true
  strict:
    description:
      - If the input is a PEM file, ensure that it contains a single PEM object, that the header and footer match, and are
        of type C(CERTIFICATE) or C(X509 CERTIFICATE).
      - See also the O(verify_cert_parsable) option, which checks whether the certificate is parsable.
    type: bool
    default: false
  dest_path:
    description:
      - Name of the file in which the generated TLS/SSL X.509 certificate will be written.
    type: path
    required: true
  backup:
    description:
      - Create a backup file including a timestamp so you can get the original X.509 certificate back if you overwrote it
        with a new one by accident.
    type: bool
    default: false
  verify_cert_parsable:
    description:
      - If set to V(true), ensures that the certificate can be parsed.
      - To ensure that a PEM file does not contain multiple certificates, use the O(strict) option.
    type: bool
    default: false
    version_added: 2.23.0
seealso:
  - plugin: ansible.builtin.b64encode
    plugin_type: filter
  - module: community.crypto.x509_certificate
  - module: community.crypto.x509_certificate_pipe
  - module: community.crypto.x509_certificate_info
requirements:
  - cryptography >= 1.6 if O(verify_cert_parsable=true)
"""

EXAMPLES = r"""
---
- name: Convert PEM X.509 certificate to DER format
  community.crypto.x509_certificate_convert:
    src_path: /etc/ssl/cert/ansible.com.pem
    dest_path: /etc/ssl/cert/ansible.com.der
    format: der
"""

RETURN = r"""
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/cert.pem.2019-03-09@11:22~
"""

import base64
import os
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    PEM_END,
    PEM_END_START,
    PEM_START,
    extract_pem,
    identify_pem_format,
    split_pem_list,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
)
from ansible_collections.community.crypto.plugins.module_utils.io import (
    load_file_if_exists,
    write_file,
)


MINIMAL_CRYPTOGRAPHY_VERSION = "1.6"

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography  # noqa: F401, pylint: disable=unused-import
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_der_x509_certificate
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


def parse_certificate(input, strict=False):
    input_format = "pem" if identify_pem_format(input) else "der"
    if input_format == "pem":
        pems = split_pem_list(to_text(input))
        if len(pems) > 1 and strict:
            raise ValueError(
                "The input contains {count} PEM objects, expecting only one since strict=true".format(
                    count=len(pems)
                )
            )
        pem_header_type, content = extract_pem(pems[0], strict=strict)
        if strict and pem_header_type not in ("CERTIFICATE", "X509 CERTIFICATE"):
            raise ValueError(
                "type is {type!r}, expecting CERTIFICATE or X509 CERTIFICATE".format(
                    type=pem_header_type
                )
            )
        input = base64.b64decode(content)
    else:
        pem_header_type = None
    return input, input_format, pem_header_type


class X509CertificateConvertModule(OpenSSLObject):
    def __init__(self, module):
        super(X509CertificateConvertModule, self).__init__(
            module.params["dest_path"],
            "present",
            False,
            module.check_mode,
        )

        self.src_path = module.params["src_path"]
        self.src_content = module.params["src_content"]
        self.src_content_base64 = module.params["src_content_base64"]
        if self.src_content is not None:
            self.input = to_bytes(self.src_content)
            if self.src_content_base64:
                try:
                    self.input = base64.b64decode(self.input)
                except Exception as exc:
                    module.fail_json(
                        msg="Cannot Base64 decode src_content: {exc}".format(exc=exc)
                    )
        else:
            try:
                with open(self.src_path, "rb") as f:
                    self.input = f.read()
            except Exception as exc:
                module.fail_json(
                    msg="Failure while reading file {fn}: {exc}".format(
                        fn=self.src_path, exc=exc
                    )
                )

        self.format = module.params["format"]
        self.strict = module.params["strict"]
        self.wanted_pem_type = "CERTIFICATE"

        try:
            self.input, self.input_format, dummy = parse_certificate(
                self.input, strict=self.strict
            )
        except Exception as exc:
            module.fail_json(msg="Error while parsing PEM: {exc}".format(exc=exc))

        if module.params["verify_cert_parsable"]:
            self.verify_cert_parsable(module)

        self.backup = module.params["backup"]
        self.backup_file = None

        module.params["path"] = self.path

        self.dest_content = load_file_if_exists(self.path, module)
        self.dest_content_format = None
        self.dest_content_pem_type = None
        if self.dest_content is not None:
            try:
                (
                    self.dest_content,
                    self.dest_content_format,
                    self.dest_content_pem_type,
                ) = parse_certificate(self.dest_content, strict=True)
            except Exception:
                pass

    def verify_cert_parsable(self, module):
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(
                msg=missing_required_lib(
                    "cryptography >= {0}".format(MINIMAL_CRYPTOGRAPHY_VERSION)
                ),
                exception=CRYPTOGRAPHY_IMP_ERR,
            )
        try:
            load_der_x509_certificate(self.input, default_backend())
        except Exception as exc:
            module.fail_json(
                msg="Error while parsing certificate: {exc}".format(exc=exc)
            )

    def needs_conversion(self):
        if self.dest_content is None or self.dest_content_format is None:
            return True
        if self.dest_content_format != self.format:
            return True
        if self.input != self.dest_content:
            return True
        if self.format == "pem" and self.dest_content_pem_type != self.wanted_pem_type:
            return True
        return False

    def get_dest_certificate(self):
        if self.format == "der":
            return self.input
        data = to_bytes(base64.b64encode(self.input))
        lines = [to_bytes("{0}{1}{2}".format(PEM_START, self.wanted_pem_type, PEM_END))]
        lines += [data[i : i + 64] for i in range(0, len(data), 64)]
        lines.append(
            to_bytes("{0}{1}{2}\n".format(PEM_END_START, self.wanted_pem_type, PEM_END))
        )
        return b"\n".join(lines)

    def generate(self, module):
        """Do conversion."""
        if self.needs_conversion():
            # Convert
            cert_data = self.get_dest_certificate()
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module, cert_data)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args["path"]):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(
                file_args, self.changed
            )

    def dump(self):
        """Serialize the object into a dictionary."""
        result = dict(
            changed=self.changed,
        )
        if self.backup_file:
            result["backup_file"] = self.backup_file

        return result


def main():
    argument_spec = dict(
        src_path=dict(type="path"),
        src_content=dict(type="str"),
        src_content_base64=dict(type="bool", default=False),
        format=dict(type="str", required=True, choices=["pem", "der"]),
        strict=dict(type="bool", default=False),
        dest_path=dict(type="path", required=True),
        backup=dict(type="bool", default=False),
        verify_cert_parsable=dict(type="bool", default=False),
    )
    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        add_file_common_args=True,
        required_one_of=[("src_path", "src_content")],
        mutually_exclusive=[("src_path", "src_content")],
    )

    base_dir = os.path.dirname(module.params["dest_path"]) or "."
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg="The directory %s does not exist or the file is not a directory"
            % base_dir,
        )

    try:
        cert = X509CertificateConvertModule(module)
        cert.generate(module)
        result = cert.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
