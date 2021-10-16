#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: x509_certificate
short_description: Generate and/or check OpenSSL certificates
description:
    - It implements a notion of provider (one of C(selfsigned), C(ownca), C(acme), and C(entrust))
      for your certificate.
    - "Please note that the module regenerates existing certificate if it does not match the module's
      options, or if it seems to be corrupt. If you are concerned that this could overwrite
      your existing certificate, consider using the I(backup) option."
    - Note that this module was called C(openssl_certificate) when included directly in Ansible up to version 2.9.
      When moved to the collection C(community.crypto), it was renamed to
      M(community.crypto.x509_certificate). From Ansible 2.10 on, it can still be used by the
      old short name (or by C(ansible.builtin.openssl_certificate)), which redirects to
      C(community.crypto.x509_certificate). When using FQCNs or when using the
      L(collections,https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#using-collections-in-a-playbook)
      keyword, the new name M(community.crypto.x509_certificate) should be used to avoid
      a deprecation warning.
author:
  - Yanis Guenane (@Spredzy)
  - Markus Teufelberger (@MarkusTeufelberger)
options:
    state:
        description:
            - Whether the certificate should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ absent, present ]

    path:
        description:
            - Remote absolute path where the generated certificate file should be created or is already located.
        type: path
        required: true

    provider:
        description:
            - Name of the provider to use to generate/retrieve the OpenSSL certificate.
              Please see the examples on how to emulate it with
              M(community.crypto.x509_certificate_info), M(community.crypto.openssl_csr_info),
              M(community.crypto.openssl_privatekey_info) and M(ansible.builtin.assert).
            - "The C(entrust) provider was added for Ansible 2.9 and requires credentials for the
               L(Entrust Certificate Services,https://www.entrustdatacard.com/products/categories/ssl-certificates) (ECS) API."
            - Required if I(state) is C(present).
        type: str
        choices: [ acme, entrust, ownca, selfsigned ]

    return_content:
        description:
            - If set to C(yes), will return the (current or generated) certificate's content as I(certificate).
        type: bool
        default: no
        version_added: '1.0.0'

    backup:
        description:
            - Create a backup file including a timestamp so you can get the original
              certificate back if you overwrote it with a new one by accident.
        type: bool
        default: no

    csr_content:
        version_added: '1.0.0'
    privatekey_content:
        version_added: '1.0.0'
    acme_directory:
        version_added: '1.0.0'
    ownca_content:
        version_added: '1.0.0'
    ownca_privatekey_content:
        version_added: '1.0.0'

notes:
- Supports C(check_mode).

seealso:
- module: community.crypto.x509_certificate_pipe

extends_documentation_fragment:
    - ansible.builtin.files
    - community.crypto.module_certificate
    - community.crypto.module_certificate.backend_acme_documentation
    - community.crypto.module_certificate.backend_entrust_documentation
    - community.crypto.module_certificate.backend_ownca_documentation
    - community.crypto.module_certificate.backend_selfsigned_documentation
'''

EXAMPLES = r'''
- name: Generate a Self Signed OpenSSL certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    privatekey_path: /etc/ssl/private/ansible.com.pem
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: selfsigned

- name: Generate an OpenSSL certificate signed with your own CA certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    ownca_path: /etc/ssl/crt/ansible_CA.crt
    ownca_privatekey_path: /etc/ssl/private/ansible_CA.pem
    provider: ownca

- name: Generate a Let's Encrypt Certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: acme
    acme_accountkey_path: /etc/ssl/private/ansible.com.pem
    acme_challenge_path: /etc/ssl/challenges/ansible.com/

- name: Force (re-)generate a new Let's Encrypt Certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: acme
    acme_accountkey_path: /etc/ssl/private/ansible.com.pem
    acme_challenge_path: /etc/ssl/challenges/ansible.com/
    force: yes

- name: Generate an Entrust certificate via the Entrust Certificate Services (ECS) API
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: entrust
    entrust_requester_name: Jo Doe
    entrust_requester_email: jdoe@ansible.com
    entrust_requester_phone: 555-555-5555
    entrust_cert_type: STANDARD_SSL
    entrust_api_user: apiusername
    entrust_api_key: a^lv*32!cd9LnT
    entrust_api_client_cert_path: /etc/ssl/entrust/ecs-client.crt
    entrust_api_client_cert_key_path: /etc/ssl/entrust/ecs-key.crt
    entrust_api_specification_path: /etc/ssl/entrust/api-docs/cms-api-2.1.0.yaml

# The following example shows how to emulate the behavior of the removed
# "assertonly" provider with the x509_certificate_info, openssl_csr_info,
# openssl_privatekey_info and assert modules:

- name: Get certificate information
  community.crypto.x509_certificate_info:
    path: /etc/ssl/crt/ansible.com.crt
    # for valid_at, invalid_at and valid_in
    valid_at:
      one_day_ten_hours: "+1d10h"
      fixed_timestamp: 20200331202428Z
      ten_seconds: "+10"
  register: result

- name: Get CSR information
  community.crypto.openssl_csr_info:
    # Verifies that the CSR signature is valid; module will fail if not
    path: /etc/ssl/csr/ansible.com.csr
  register: result_csr

- name: Get private key information
  community.crypto.openssl_privatekey_info:
    path: /etc/ssl/csr/ansible.com.key
  register: result_privatekey

- assert:
    that:
      # When private key was specified for assertonly, this was checked:
      - result.public_key == result_privatekey.public_key
      # When CSR was specified for assertonly, this was checked:
      - result.public_key == result_csr.public_key
      - result.subject_ordered == result_csr.subject_ordered
      - result.extensions_by_oid == result_csr.extensions_by_oid
      # signature_algorithms check
      - "result.signature_algorithm == 'sha256WithRSAEncryption' or result.signature_algorithm == 'sha512WithRSAEncryption'"
      # subject and subject_strict
      - "result.subject.commonName == 'ansible.com'"
      - "result.subject | length == 1"  # the number must be the number of entries you check for
      # issuer and issuer_strict
      - "result.issuer.commonName == 'ansible.com'"
      - "result.issuer | length == 1"  # the number must be the number of entries you check for
      # has_expired
      - not result.expired
      # version
      - result.version == 3
      # key_usage and key_usage_strict
      - "'Data Encipherment' in result.key_usage"
      - "result.key_usage | length == 1"  # the number must be the number of entries you check for
      # extended_key_usage and extended_key_usage_strict
      - "'DVCS' in result.extended_key_usage"
      - "result.extended_key_usage | length == 1"  # the number must be the number of entries you check for
      # subject_alt_name and subject_alt_name_strict
      - "'dns:ansible.com' in result.subject_alt_name"
      - "result.subject_alt_name | length == 1"  # the number must be the number of entries you check for
      # not_before and not_after
      - "result.not_before == '20190331202428Z'"
      - "result.not_after == '20190413202428Z'"
      # valid_at, invalid_at and valid_in
      - "result.valid_at.one_day_ten_hours"  # for valid_at
      - "not result.valid_at.fixed_timestamp"  # for invalid_at
      - "result.valid_at.ten_seconds"  # for valid_in
'''

RETURN = r'''
filename:
    description: Path to the generated certificate.
    returned: changed or success
    type: str
    sample: /etc/ssl/crt/www.ansible.com.crt
backup_file:
    description: Name of backup file created.
    returned: changed and if I(backup) is C(yes)
    type: str
    sample: /path/to/www.ansible.com.crt.2019-03-09@11:22~
certificate:
    description: The (current or generated) certificate's content.
    returned: if I(state) is C(present) and I(return_content) is C(yes)
    type: str
    version_added: '1.0.0'
'''


import os

from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    select_backend,
    get_certificate_argument_spec,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate_acme import (
    AcmeCertificateProvider,
    add_acme_provider_to_argument_spec,
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

from ansible_collections.community.crypto.plugins.module_utils.io import (
    load_file_if_exists,
    write_file,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
)


class CertificateAbsent(OpenSSLObject):
    def __init__(self, module):
        super(CertificateAbsent, self).__init__(
            module.params['path'],
            module.params['state'],
            module.params['force'],
            module.check_mode
        )
        self.module = module
        self.return_content = module.params['return_content']
        self.backup = module.params['backup']
        self.backup_file = None

    def generate(self, module):
        pass

    def remove(self, module):
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        super(CertificateAbsent, self).remove(module)

    def dump(self, check_mode=False):
        result = {
            'changed': self.changed,
            'filename': self.path,
            'privatekey': self.module.params['privatekey_path'],
            'csr': self.module.params['csr_path']
        }
        if self.backup_file:
            result['backup_file'] = self.backup_file
        if self.return_content:
            result['certificate'] = None

        return result


class GenericCertificate(OpenSSLObject):
    """Retrieve a certificate using the given module backend."""
    def __init__(self, module, module_backend):
        super(GenericCertificate, self).__init__(
            module.params['path'],
            module.params['state'],
            module.params['force'],
            module.check_mode
        )
        self.module = module
        self.return_content = module.params['return_content']
        self.backup = module.params['backup']
        self.backup_file = None

        self.module_backend = module_backend
        self.module_backend.set_existing(load_file_if_exists(self.path, module))

    def generate(self, module):
        if self.module_backend.needs_regeneration():
            if not self.check_mode:
                self.module_backend.generate_certificate()
                result = self.module_backend.get_certificate_data()
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module, result)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args['path']):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(file_args, self.changed)

    def check(self, module, perms_required=True):
        """Ensure the resource is in its desired state."""
        return super(GenericCertificate, self).check(module, perms_required) and not self.module_backend.needs_regeneration()

    def dump(self, check_mode=False):
        result = self.module_backend.dump(include_certificate=self.return_content)
        result.update({
            'changed': self.changed,
            'filename': self.path,
        })
        if self.backup_file:
            result['backup_file'] = self.backup_file
        return result


def main():
    argument_spec = get_certificate_argument_spec()
    add_acme_provider_to_argument_spec(argument_spec)
    add_entrust_provider_to_argument_spec(argument_spec)
    add_ownca_provider_to_argument_spec(argument_spec)
    add_selfsigned_provider_to_argument_spec(argument_spec)
    argument_spec.argument_spec.update(dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        path=dict(type='path', required=True),
        backup=dict(type='bool', default=False),
        return_content=dict(type='bool', default=False),
    ))
    argument_spec.required_if.append(['state', 'present', ['provider']])
    module = argument_spec.create_ansible_module(
        add_file_common_args=True,
        supports_check_mode=True,
    )

    try:
        if module.params['state'] == 'absent':
            certificate = CertificateAbsent(module)

            if module.check_mode:
                result = certificate.dump(check_mode=True)
                result['changed'] = os.path.exists(module.params['path'])
                module.exit_json(**result)

            certificate.remove(module)

        else:
            base_dir = os.path.dirname(module.params['path']) or '.'
            if not os.path.isdir(base_dir):
                module.fail_json(
                    name=base_dir,
                    msg='The directory %s does not exist or the file is not a directory' % base_dir
                )

            provider = module.params['provider']
            provider_map = {
                'acme': AcmeCertificateProvider,
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
