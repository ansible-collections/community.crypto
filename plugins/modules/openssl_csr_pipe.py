#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: openssl_csr_pipe
short_description: Generate OpenSSL Certificate Signing Request (CSR)
version_added: 1.3.0
description:
  - Please note that the module regenerates an existing CSR if it does not match the module's options, or if it seems to be
    corrupt.
author:
  - Yanis Guenane (@Spredzy)
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - community.crypto.attributes
  - community.crypto.module_csr
attributes:
  check_mode:
    support: full
    details:
      - Currently in check mode, private keys will not be (re-)generated, only the changed status is set. This will change
        in community.crypto 3.0.0.
      - From community.crypto 3.0.0 on, the module will ignore check mode and always behave as if check mode is not active.
        If you think this breaks your use-case of this module, please create an issue in the community.crypto repository.
options:
  content:
    description:
      - The existing CSR.
    type: str
  privatekey_path:
    description:
      - The path to the private key to use when signing the certificate signing request.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
  privatekey_content:
    description:
      - The content of the private key to use when signing the certificate signing request.
      - Either O(privatekey_path) or O(privatekey_content) must be specified, but not both.
seealso:
  - module: community.crypto.openssl_csr
"""

EXAMPLES = r"""
---
- name: Generate an OpenSSL Certificate Signing Request
  community.crypto.openssl_csr_pipe:
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com
  register: result
- name: Print CSR
  ansible.builtin.debug:
    var: result.csr

- name: Generate an OpenSSL Certificate Signing Request with an inline CSR
  community.crypto.openssl_csr:
    content: "{{ lookup('ansible.builtin.file', '/etc/ssl/csr/www.ansible.com.csr') }}"
    privatekey_content: "{{ private_key_content }}"
    common_name: www.ansible.com
  register: result
- name: Store CSR
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com.csr
    content: "{{ result.csr }}"
  when: result is changed
"""

RETURN = r"""
privatekey:
  description:
    - Path to the TLS/SSL private key the CSR was generated for.
    - Will be V(none) if the private key has been provided in O(privatekey_content).
  returned: changed or success
  type: str
  sample: /etc/ssl/private/ansible.com.pem
subject:
  description: A list of the subject tuples attached to the CSR.
  returned: changed or success
  type: list
  elements: list
  sample: [['CN', 'www.ansible.com'], ['O', 'Ansible']]
subjectAltName:
  description: The alternative names this CSR is valid for.
  returned: changed or success
  type: list
  elements: str
  sample: ['DNS:www.ansible.com', 'DNS:m.ansible.com']
keyUsage:
  description: Purpose for which the public key may be used.
  returned: changed or success
  type: list
  elements: str
  sample: ['digitalSignature', 'keyAgreement']
extendedKeyUsage:
  description: Additional restriction on the public key purposes.
  returned: changed or success
  type: list
  elements: str
  sample: ['clientAuth']
basicConstraints:
  description: Indicates if the certificate belongs to a CA.
  returned: changed or success
  type: list
  elements: str
  sample: ['CA:TRUE', 'pathLenConstraint:0']
ocsp_must_staple:
  description: Indicates whether the certificate has the OCSP Must Staple feature enabled.
  returned: changed or success
  type: bool
  sample: false
name_constraints_permitted:
  description: List of permitted subtrees to sign certificates for.
  returned: changed or success
  type: list
  elements: str
  sample: ['email:.somedomain.com']
name_constraints_excluded:
  description: List of excluded subtrees the CA cannot sign certificates for.
  returned: changed or success
  type: list
  elements: str
  sample: ['email:.com']
csr:
  description: The (current or generated) CSR's content.
  returned: changed or success
  type: str
"""

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.csr import (
    get_csr_argument_spec,
    select_backend,
)


class CertificateSigningRequestModule(object):
    def __init__(self, module, module_backend):
        self.check_mode = module.check_mode
        self.module = module
        self.module_backend = module_backend
        self.changed = False
        if module.params["content"] is not None:
            self.module_backend.set_existing(module.params["content"].encode("utf-8"))

    def generate(self, module):
        """Generate the certificate signing request."""
        if self.module_backend.needs_regeneration():
            if not self.check_mode:
                self.module_backend.generate_csr()
            else:
                self.module.deprecate(
                    "Check mode support for openssl_csr_pipe will change in community.crypto 3.0.0"
                    " to behave the same as without check mode. You can get that behavior right now"
                    " by adding `check_mode: false` to the openssl_csr_pipe task. If you think this"
                    " breaks your use-case of this module, please create an issue in the"
                    " community.crypto repository",
                    version="3.0.0",
                    collection_name="community.crypto",
                )
            self.changed = True

    def dump(self):
        """Serialize the object into a dictionary."""
        result = self.module_backend.dump(include_csr=True)
        result.update(
            {
                "changed": self.changed,
            }
        )
        return result


def main():
    argument_spec = get_csr_argument_spec()
    argument_spec.argument_spec.update(
        dict(
            content=dict(type="str"),
        )
    )
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
    )

    try:
        backend = module.params["select_crypto_backend"]
        backend, module_backend = select_backend(module, backend)

        csr = CertificateSigningRequestModule(module, module_backend)
        csr.generate(module)
        result = csr.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
