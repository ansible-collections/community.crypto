#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_privatekey_pipe
short_description: Generate OpenSSL private keys without disk access
version_added: 1.2.0
description:
    - This module allows one to (re)generate OpenSSL private keys without disk access.
    - This allows to read and write keys to vaults without having to write intermediate versions to disk.
    - Make sure to not write the result of this module into logs or to the console, as it contains private key data!
author:
    - Yanis Guenane (@Spredzy)
    - Felix Fontein (@felixfontein)
options:
    content:
        description:
            - The current private key data.
            - Needed for idempotency. If not provided, the module will always return a change, and all idempotence-related
              options are ignored.
        type: str
    content_base64:
        description:
            - Set to C(true) if the content is base64 encoded.
        type: bool
        default: false
extends_documentation_fragment:
- ansible.builtin.files
- community.crypto.module_privatekey
seealso:
- module: community.crypto.openssl_privatekey
- module: community.crypto.openssl_privatekey_info
'''

EXAMPLES = r'''
- name: Generate an OpenSSL private key with the default values (4096 bits, RSA)
  community.crypto.openssl_privatekey_pipe:
    path: /etc/ssl/private/ansible.com.pem
  register: output
- name: Show generated key
  debug:
    msg: "{{ output.privatekey }}"
  # DO NOT OUTPUT KEY MATERIAL TO CONSOLE OR LOGS IN PRODUCTION!

- name: Update sops-encrypted key with the community.sops collection
  community.crypto.openssl_privatekey_pipe:
    content: "{{ lookup('community.sops.sops', 'private_key.pem.sops') }}"
    size: 2048
  register: output
- name: Update encrypted key when openssl_privatekey_pipe reported a change
  community.sops.encrypt_sops:
    path: private_key.pem.sops
    content_text: output.privatekey
  when: output is changed
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
fingerprint:
    description:
    - The fingerprint of the public key. Fingerprint will be generated for each C(hashlib.algorithms) available.
    - The PyOpenSSL backend requires PyOpenSSL >= 16.0 for meaningful output.
    returned: changed or success
    type: dict
    sample:
      md5: "84:75:71:72:8d:04:b5:6c:4d:37:6d:66:83:f5:4c:29"
      sha1: "51:cc:7c:68:5d:eb:41:43:88:7e:1a:ae:c7:f8:24:72:ee:71:f6:10"
      sha224: "b1:19:a6:6c:14:ac:33:1d:ed:18:50:d3:06:5c:b2:32:91:f1:f1:52:8c:cb:d5:75:e9:f5:9b:46"
      sha256: "41:ab:c7:cb:d5:5f:30:60:46:99:ac:d4:00:70:cf:a1:76:4f:24:5d:10:24:57:5d:51:6e:09:97:df:2f:de:c7"
      sha384: "85:39:50:4e:de:d9:19:33:40:70:ae:10:ab:59:24:19:51:c3:a2:e4:0b:1c:b1:6e:dd:b3:0c:d9:9e:6a:46:af:da:18:f8:ef:ae:2e:c0:9a:75:2c:9b:b3:0f:3a:5f:3d"
      sha512: "fd:ed:5e:39:48:5f:9f:fe:7f:25:06:3f:79:08:cd:ee:a5:e7:b3:3d:13:82:87:1f:84:e1:f5:c7:28:77:53:94:86:56:38:69:f0:d9:35:22:01:1e:a6:60:...:0f:9b"
privatekey:
    description:
        - The (current or generated) private key's content.
        - Will be Base64-encoded if the key is in raw format.
    returned: always
    type: str
'''

import base64

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.privatekey import (
    select_backend,
    get_privatekey_argument_spec,
)


class PrivateKeyModule(object):
    def __init__(self, module, module_backend):
        self.module = module
        self.module_backend = module_backend
        self.check_mode = module.check_mode
        self.changed = False

        if module.params['content'] is not None:
            if module.params['content_base64']:
                try:
                    data = base64.b64decode(module.params['content'])
                except Exception as e:
                    module.fail_json(msg='Cannot decode Base64 encoded data: {0}'.format(e))
            else:
                data = to_bytes(module.params['content'])
            module_backend.set_existing(data)

    def generate(self, module):
        """Generate a keypair."""

        if self.module_backend.needs_regeneration():
            # Regenerate
            if not self.check_mode:
                self.module_backend.generate_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                self.privatekey_bytes = privatekey_data
            self.changed = True
        elif self.module_backend.needs_conversion():
            # Convert
            if not self.check_mode:
                self.module_backend.convert_private_key()
                privatekey_data = self.module_backend.get_private_key_data()
                self.privatekey_bytes = privatekey_data
            self.changed = True

    def dump(self):
        """Serialize the object into a dictionary."""
        result = self.module_backend.dump(include_key=True)
        result['changed'] = self.changed
        return result


def main():

    argument_spec, required_together, required_if = get_privatekey_argument_spec()
    argument_spec.update(dict(
        content=dict(type='str', no_log=True),
        content_base64=dict(type='bool', default=False),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        add_file_common_args=True,
        required_together=required_together + [],
        required_if=required_if + [],
    )
    # This could also be passed to the AnsibleModule() construction, but will be
    # overwritten when the module's options are processed (Ansible always passes
    # _ansible_no_log which overwrites it). We later have to remove the value of
    # content from the `module.no_log_values` set, and we want to avoid accidental
    # logging later on.
    module.no_log = True

    backend, module_backend = select_backend(
        module=module,
        backend=module.params['select_crypto_backend'],
    )

    try:
        private_key = PrivateKeyModule(module, module_backend)
        private_key.generate(module)
        result = private_key.dump()
        # In case changed=False, the module's input (`content`) is returned as `privatekey`.
        # Since `content` is no_log=True, `privatekey`'s value will get replaced by
        # ANSIBLE_NO_LOG_VALUE. To avoid this, we remove the value of `content` from
        # module.no_log_values. Since we explicitly set `module.no_log = True` above, this
        # should be safe.
        try:
            module.no_log_values.remove(module.params['content'])
        except KeyError:
            pass
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == '__main__':
    main()
