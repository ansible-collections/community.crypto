#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright: (2) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: x509_certificate_pipe
short_description: Generate and/or check OpenSSL certificates
version_added: 1.3.0
description:
    - It implements a notion of provider (ie. C(selfsigned), C(ownca), C(entrust))
      for your certificate.
    - "Please note that the module regenerates an existing certificate if it does not match the module's
      options, or if it seems to be corrupt. If you are concerned that this could overwrite
      your existing certificate, consider using the I(backup) option."
author:
  - Yanis Guenane (@Spredzy)
  - Markus Teufelberger (@MarkusTeufelberger)
  - Felix Fontein (@felixfontein)
options:
    provider:
        description:
            - Name of the provider to use to generate/retrieve the OpenSSL certificate.
            - "The C(entrust) provider requires credentials for the
               L(Entrust Certificate Services,https://www.entrustdatacard.com/products/categories/ssl-certificates) (ECS) API."
        type: str
        choices: [ entrust, ownca, selfsigned ]
        required: true

    content:
        description:
            - The existing certificate.
        type: str

seealso:
- module: community.crypto.x509_certificate

notes:
- Supports C(check_mode).

extends_documentation_fragment:
    - community.crypto.module_certificate
    - community.crypto.module_certificate.backend_entrust_documentation
    - community.crypto.module_certificate.backend_ownca_documentation
    - community.crypto.module_certificate.backend_selfsigned_documentation
'''

EXAMPLES = r'''
- name: Generate a Self Signed OpenSSL certificate
  community.crypto.x509_certificate_pipe:
    provider: selfsigned
    privatekey_path: /etc/ssl/private/ansible.com.pem
    csr_path: /etc/ssl/csr/ansible.com.csr
  register: result
- name: Print the certificate
  ansible.builtin.debug:
    var: result.certificate

# In the following example, both CSR and certificate file are stored on the
# machine where ansible-playbook is executed, while the OwnCA data (certificate,
# private key) are stored on the remote machine.

- name: (1/2) Generate an OpenSSL Certificate with the CSR provided inline
  community.crypto.x509_certificate_pipe:
    provider: ownca
    content: "{{ lookup('file', '/etc/ssl/csr/www.ansible.com.crt') }}"
    csr_content: "{{ lookup('file', '/etc/ssl/csr/www.ansible.com.csr') }}"
    ownca_cert: /path/to/ca_cert.crt
    ownca_privatekey: /path/to/ca_cert.key
    ownca_privatekey_passphrase: hunter2
  register: result

- name: (2/2) Store certificate
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com.crt
    content: "{{ result.certificate }}"
  delegate_to: localhost
  when: result is changed

# In the following example, the certificate from another machine is signed by
# our OwnCA whose private key and certificate are only available on this
# machine (where ansible-playbook is executed), without having to write
# the certificate file to disk on localhost. The CSR could have been
# provided by community.crypto.openssl_csr_pipe earlier, or also have been
# read from the remote machine.

- name: (1/3) Read certificate's contents from remote machine
  ansible.builtin.slurp:
    src: /etc/ssl/csr/www.ansible.com.crt
  register: certificate_content

- name: (2/3) Generate an OpenSSL Certificate with the CSR provided inline
  community.crypto.x509_certificate_pipe:
    provider: ownca
    content: "{{ certificate_content.content | b64decode }}"
    csr_content: "{{ the_csr }}"
    ownca_cert: /path/to/ca_cert.crt
    ownca_privatekey: /path/to/ca_cert.key
    ownca_privatekey_passphrase: hunter2
  delegate_to: localhost
  register: result

- name: (3/3) Store certificate
  ansible.builtin.copy:
    dest: /etc/ssl/csr/www.ansible.com.crt
    content: "{{ result.certificate }}"
  when: result is changed
'''

RETURN = r'''
certificate:
    description: The (current or generated) certificate's content.
    returned: changed or success
    type: str
'''


import os

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    select_backend,
    get_certificate_argument_spec,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate_entrust import (
    EntrustCertificateProvider,
    add_entrust_provider_to_argument_spec,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate_ownca import (
    OwnCACertificateProvider,
    add_ownca_provider_to_argument_spec,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate_selfsigned import (
    SelfSignedCertificateProvider,
    add_selfsigned_provider_to_argument_spec,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)


class GenericCertificate(object):
    """Retrieve a certificate using the given module backend."""
    def __init__(self, module, module_backend):
        self.check_mode = module.check_mode
        self.module_backend = module_backend
        self.changed = False
        if module.params['content'] is not None:
            self.module_backend.set_existing(module.params['content'].encode('utf-8'))

    def generate(self, module):
        if self.module_backend.needs_regeneration():
            if not self.check_mode:
                self.module_backend.generate_certificate()
            self.changed = True

    def dump(self, check_mode=False):
        result = self.module_backend.dump(include_certificate=True)
        result.update({
            'changed': self.changed,
        })
        return result


def main():
    argument_spec = get_certificate_argument_spec()
    argument_spec.argument_spec['provider']['required'] = True
    add_entrust_provider_to_argument_spec(argument_spec)
    add_ownca_provider_to_argument_spec(argument_spec)
    add_selfsigned_provider_to_argument_spec(argument_spec)
    argument_spec.argument_spec.update(dict(
        content=dict(type='str'),
    ))
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
    )

    try:
        provider = module.params['provider']
        provider_map = {
            'entrust': EntrustCertificateProvider,
            'ownca': OwnCACertificateProvider,
            'selfsigned': SelfSignedCertificateProvider,
        }

        backend = module.params['select_crypto_backend']
        module_backend = select_backend(module, backend, provider_map[provider]())
        certificate = GenericCertificate(module, module_backend)
        certificate.generate(module)
        result = certificate.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
