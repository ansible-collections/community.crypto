#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_csr
short_description: Generate OpenSSL Certificate Signing Request (CSR)
description:
    - "Please note that the module regenerates an existing CSR if it doesn't match the module's
      options, or if it seems to be corrupt. If you are concerned that this could overwrite
      your existing CSR, consider using the I(backup) option."
author:
- Yanis Guenane (@Spredzy)
- Felix Fontein (@felixfontein)
options:
    state:
        description:
            - Whether the certificate signing request should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ absent, present ]
    force:
        description:
            - Should the certificate signing request be forced regenerated by this ansible module.
        type: bool
        default: no
    path:
        description:
            - The name of the file into which the generated OpenSSL certificate signing request will be written.
        type: path
        required: true
    backup:
        description:
            - Create a backup file including a timestamp so you can get the original
              CSR back if you overwrote it with a new one by accident.
        type: bool
        default: no
    return_content:
        description:
            - If set to C(yes), will return the (current or generated) CSR's content as I(csr).
        type: bool
        default: no
        version_added: "1.0.0"
    privatekey_content:
        version_added: "1.0.0"
    name_constraints_permitted:
        version_added: 1.1.0
    name_constraints_excluded:
        version_added: 1.1.0
    name_constraints_critical:
        version_added: 1.1.0
extends_documentation_fragment:
- ansible.builtin.files
- community.crypto.module_csr
seealso:
- module: community.crypto.openssl_csr_pipe
'''

EXAMPLES = r'''
- name: Generate an OpenSSL Certificate Signing Request
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com

- name: Generate an OpenSSL Certificate Signing Request with an inline key
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_content: "{{ private_key_content }}"
    common_name: www.ansible.com

- name: Generate an OpenSSL Certificate Signing Request with a passphrase protected private key
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    privatekey_passphrase: ansible
    common_name: www.ansible.com

- name: Generate an OpenSSL Certificate Signing Request with Subject information
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    country_name: FR
    organization_name: Ansible
    email_address: jdoe@ansible.com
    common_name: www.ansible.com

- name: Generate an OpenSSL Certificate Signing Request with subjectAltName extension
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    subject_alt_name: 'DNS:www.ansible.com,DNS:m.ansible.com'

- name: Generate an OpenSSL CSR with subjectAltName extension with dynamic list
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    subject_alt_name: "{{ item.value | map('regex_replace', '^', 'DNS:') | list }}"
  with_dict:
    dns_server:
    - www.ansible.com
    - m.ansible.com

- name: Force regenerate an OpenSSL Certificate Signing Request
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    force: yes
    common_name: www.ansible.com

- name: Generate an OpenSSL Certificate Signing Request with special key usages
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com
    key_usage:
      - digitalSignature
      - keyAgreement
    extended_key_usage:
      - clientAuth

- name: Generate an OpenSSL Certificate Signing Request with OCSP Must Staple
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com
    ocsp_must_staple: yes

- name: Generate an OpenSSL Certificate Signing Request for WinRM Certificate authentication
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/winrm.auth.csr
    privatekey_path: /etc/ssl/private/winrm.auth.pem
    common_name: username
    extended_key_usage:
    - clientAuth
    subject_alt_name: otherName:1.3.6.1.4.1.311.20.2.3;UTF8:username@localhost
'''

RETURN = r'''
privatekey:
    description:
    - Path to the TLS/SSL private key the CSR was generated for
    - Will be C(none) if the private key has been provided in I(privatekey_content).
    returned: changed or success
    type: str
    sample: /etc/ssl/private/ansible.com.pem
filename:
    description: Path to the generated Certificate Signing Request
    returned: changed or success
    type: str
    sample: /etc/ssl/csr/www.ansible.com.csr
subject:
    description: A list of the subject tuples attached to the CSR
    returned: changed or success
    type: list
    elements: list
    sample: "[('CN', 'www.ansible.com'), ('O', 'Ansible')]"
subjectAltName:
    description: The alternative names this CSR is valid for
    returned: changed or success
    type: list
    elements: str
    sample: [ 'DNS:www.ansible.com', 'DNS:m.ansible.com' ]
keyUsage:
    description: Purpose for which the public key may be used
    returned: changed or success
    type: list
    elements: str
    sample: [ 'digitalSignature', 'keyAgreement' ]
extendedKeyUsage:
    description: Additional restriction on the public key purposes
    returned: changed or success
    type: list
    elements: str
    sample: [ 'clientAuth' ]
basicConstraints:
    description: Indicates if the certificate belongs to a CA
    returned: changed or success
    type: list
    elements: str
    sample: ['CA:TRUE', 'pathLenConstraint:0']
ocsp_must_staple:
    description: Indicates whether the certificate has the OCSP
                 Must Staple feature enabled
    returned: changed or success
    type: bool
    sample: false
name_constraints_permitted:
    description: List of permitted subtrees to sign certificates for.
    returned: changed or success
    type: list
    elements: str
    sample: ['email:.somedomain.com']
    version_added: 1.1.0
name_constraints_excluded:
    description: List of excluded subtrees the CA cannot sign certificates for.
    returned: changed or success
    type: list
    elements: str
    sample: ['email:.com']
    version_added: 1.1.0
backup_file:
    description: Name of backup file created.
    returned: changed and if I(backup) is C(yes)
    type: str
    sample: /path/to/www.ansible.com.csr.2019-03-09@11:22~
csr:
    description: The (current or generated) CSR's content.
    returned: if I(state) is C(present) and I(return_content) is C(yes)
    type: str
    version_added: "1.0.0"
'''

import os

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.csr import (
    select_backend,
    get_csr_argument_spec,
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


class CertificateSigningRequestModule(OpenSSLObject):

    def __init__(self, module, module_backend):
        super(CertificateSigningRequestModule, self).__init__(
            module.params['path'],
            module.params['state'],
            module.params['force'],
            module.check_mode
        )
        self.module_backend = module_backend
        self.return_content = module.params['return_content']

        self.backup = module.params['backup']
        self.backup_file = None

        self.module_backend.set_existing(load_file_if_exists(self.path, module))

    def generate(self, module):
        '''Generate the certificate signing request.'''
        if self.force or self.module_backend.needs_regeneration():
            if not self.check_mode:
                self.module_backend.generate_csr()
                result = self.module_backend.get_csr_data()
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                write_file(module, result)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        self.changed = module.set_fs_attributes_if_different(file_args, self.changed)

    def remove(self, module):
        self.module_backend.set_existing(None)
        if self.backup and not self.check_mode:
            self.backup_file = module.backup_local(self.path)
        super(CertificateSigningRequestModule, self).remove(module)

    def dump(self):
        '''Serialize the object into a dictionary.'''
        result = self.module_backend.dump(include_csr=self.return_content)
        result.update({
            'filename': self.path,
            'changed': self.changed,
        })
        if self.backup_file:
            result['backup_file'] = self.backup_file
        return result


def main():
    argument_spec, required_together, required_if, mutually_exclusive, required_one_of = get_csr_argument_spec()
    argument_spec.update(dict(
        state=dict(type='str', default='present', choices=['absent', 'present']),
        force=dict(type='bool', default=False),
        path=dict(type='path', required=True),
        backup=dict(type='bool', default=False),
        return_content=dict(type='bool', default=False),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_together=[] + required_together,
        required_if=[('state', 'present', rof, True) for rof in required_one_of] + required_if,
        mutually_exclusive=[] + mutually_exclusive,
        add_file_common_args=True,
        supports_check_mode=True,
    )

    base_dir = os.path.dirname(module.params['path']) or '.'
    if not os.path.isdir(base_dir):
        module.fail_json(name=base_dir, msg='The directory %s does not exist or the file is not a directory' % base_dir)

    backend = module.params['select_crypto_backend']
    backend, module_backend = select_backend(module, backend)
    try:
        csr = CertificateSigningRequestModule(module, module_backend)
        if module.params['state'] == 'present':
            csr.generate(module)
        else:
            csr.remove(module)

        result = csr.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
