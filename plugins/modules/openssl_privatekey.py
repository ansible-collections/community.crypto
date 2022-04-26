#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_privatekey
short_description: Generate OpenSSL private keys
description:
    - This module allows one to (re)generate OpenSSL private keys.
    - The default mode for the private key file will be C(0600) if I(mode) is not explicitly set.
author:
    - Yanis Guenane (@Spredzy)
    - Felix Fontein (@felixfontein)
options:
    state:
        description:
            - Whether the private key should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ absent, present ]
    force:
        description:
            - Should the key be regenerated even if it already exists.
        type: bool
        default: no
    path:
        description:
            - Name of the file in which the generated TLS/SSL private key will be written. It will have C(0600) mode
              if I(mode) is not explicitly set.
        type: path
        required: true
    format:
        version_added: '1.0.0'
    format_mismatch:
        version_added: '1.0.0'
    backup:
        description:
            - Create a backup file including a timestamp so you can get
              the original private key back if you overwrote it with a new one by accident.
        type: bool
        default: no
    return_content:
        description:
            - If set to C(yes), will return the (current or generated) private key's content as I(privatekey).
            - Note that especially if the private key is not encrypted, you have to make sure that the returned
              value is treated appropriately and not accidentally written to logs etc.! Use with care!
            - Use Ansible's I(no_log) task option to avoid the output being shown. See also
              U(https://docs.ansible.com/ansible/latest/reference_appendices/faq.html#how-do-i-keep-secret-data-in-my-playbook).
        type: bool
        default: no
        version_added: '1.0.0'
    regenerate:
        version_added: '1.0.0'
extends_documentation_fragment:
- ansible.builtin.files
- community.crypto.module_privatekey
seealso:
- module: community.crypto.openssl_privatekey_pipe
- module: community.crypto.openssl_privatekey_info
'''

EXAMPLES = r'''
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem

- name: Generate an OpenSSL private key with the default values (4096 bits, RSA) and a passphrase
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    passphrase: ansible
    cipher: aes256

- name: Generate an OpenSSL private key with a different size (2048 bits)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    size: 2048

- name: Force regenerate an OpenSSL private key if it already exists
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    force: yes

- name: Generate an OpenSSL private key with a different algorithm (DSA)
  community.crypto.openssl_privatekey:
    path: /etc/ssl/private/ansible.com.pem
    type: DSA
'''

RETURN = r'''
size:
    description: Size (in bits) of the TLS/SSL private key.
    returned: changed or success
    type: int
    sample: 4096
type:
    description: Algorithm used to generate the TLS/SSL private key.
    returned: changed or success
    type: str
    sample: RSA
curve:
    description: Elliptic curve used to generate the TLS/SSL private key.
    returned: changed or success, and I(type) is C(ECC)
    type: str
    sample: secp256r1
filename:
    description: Path to the generated TLS/SSL private key file.
    returned: changed or success
    type: str
    sample: /etc/ssl/private/ansible.com.pem
fingerprint:
    description:
    - The fingerprint of the public key. Fingerprint will be generated for each C(hashlib.algorithms) available.
    returned: changed or success
    type: dict
    sample:
      md5: "84:75:71:72:8d:04:b5:6c:4d:37:6d:66:83:f5:4c:29"
      sha1: "51:cc:7c:68:5d:eb:41:43:88:7e:1a:ae:c7:f8:24:72:ee:71:f6:10"
      sha224: "b1:19:a6:6c:14:ac:33:1d:ed:18:50:d3:06:5c:b2:32:91:f1:f1:52:8c:cb:d5:75:e9:f5:9b:46"
      sha256: "41:ab:c7:cb:d5:5f:30:60:46:99:ac:d4:00:70:cf:a1:76:4f:24:5d:10:24:57:5d:51:6e:09:97:df:2f:de:c7"
      sha384: "85:39:50:4e:de:d9:19:33:40:70:ae:10:ab:59:24:19:51:c3:a2:e4:0b:1c:b1:6e:dd:b3:0c:d9:9e:6a:46:af:da:18:f8:ef:ae:2e:c0:9a:75:2c:9b:b3:0f:3a:5f:3d"
      sha512: "fd:ed:5e:39:48:5f:9f:fe:7f:25:06:3f:79:08:cd:ee:a5:e7:b3:3d:13:82:87:1f:84:e1:f5:c7:28:77:53:94:86:56:38:69:f0:d9:35:22:01:1e:a6:60:...:0f:9b"
backup_file:
    description: Name of backup file created.
    returned: changed and if I(backup) is C(yes)
    type: str
    sample: /path/to/privatekey.pem.2019-03-09@11:22~
privatekey:
    description:
        - The (current or generated) private key's content.
        - Will be Base64-encoded if the key is in raw format.
    returned: if I(state) is C(present) and I(return_content) is C(yes)
    type: str
    version_added: '1.0.0'
'''

import os

from ansible.module_utils.common.text.converters import to_native

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

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey import (
    select_backend,
    get_privatekey_argument_spec,
)


class PrivateKeyModule(OpenSSLObject):

    def __init__(self, module, module_backend):
        super(PrivateKeyModule, self).__init__(
            module.params['path'],
            module.params['state'],
            module.params['force'],
            module.check_mode,
        )
        self.module_backend = module_backend
        self.return_content = module.params['return_content']
        if self.force:
            module_backend.regenerate = 'always'

        self.backup = module.params['backup']
        self.backup_file = None

        if module.params['mode'] is None:
            module.params['mode'] = '0600'

        module_backend.set_existing(load_file_if_exists(self.path, module))

    def generate(self, module):
        """Generate a keypair."""

        if self.module_backend.needs_regeneration():
            # Regenerate
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                self.module_backend.generate_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                if self.return_content:
                    self.privatekey_bytes = privatekey_data
                write_file(module, privatekey_data, 0o600)
            self.changed = True
        elif self.module_backend.needs_conversion():
            # Convert
            if not self.check_mode:
                if self.backup:
                    self.backup_file = module.backup_local(self.path)
                self.module_backend.convert_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                if self.return_content:
                    self.privatekey_bytes = privatekey_data
                write_file(module, privatekey_data, 0o600)
            self.changed = True

        file_args = module.load_file_common_arguments(module.params)
        if module.check_file_absent_if_check_mode(file_args['path']):
            self.changed = True
        else:
            self.changed = module.set_fs_attributes_if_different(file_args, self.changed)

    def remove(self, module):
        self.module_backend.set_existing(None)
        if self.backup and not self.check_mode:
            self.backup_file = module.backup_local(self.path)
        super(PrivateKeyModule, self).remove(module)

    def dump(self):
        """Serialize the object into a dictionary."""

        result = self.module_backend.dump(include_key=self.return_content)
        result['filename'] = self.path
        result['changed'] = self.changed
        if self.backup_file:
            result['backup_file'] = self.backup_file

        return result


def main():

    argument_spec = get_privatekey_argument_spec()
    argument_spec.argument_spec.update(dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        force=dict(type='bool', default=False),
        path=dict(type='path', required=True),
        backup=dict(type='bool', default=False),
        return_content=dict(type='bool', default=False),
    ))
    module = argument_spec.create_ansible_module(
        supports_check_mode=True,
        add_file_common_args=True,
    )

    base_dir = os.path.dirname(module.params['path']) or '.'
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg='The directory %s does not exist or the file is not a directory' % base_dir
        )

    backend, module_backend = select_backend(
        module=module,
        backend=module.params['select_crypto_backend'],
    )

    try:
        private_key = PrivateKeyModule(module, module_backend)

        if private_key.state == 'present':
            private_key.generate(module)
        else:
            private_key.remove(module)

        result = private_key.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == '__main__':
    main()
