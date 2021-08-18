#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: openssh_keypair
author: "David Kainz (@lolcube)"
short_description: Generate OpenSSH private and public keys
description:
    - "This module allows one to (re)generate OpenSSH private and public keys. It uses
      ssh-keygen to generate keys. One can generate C(rsa), C(dsa), C(rsa1), C(ed25519)
      or C(ecdsa) private keys."
requirements:
    - ssh-keygen (if I(backend=openssh))
    - cryptography >= 2.6 (if I(backend=cryptography) and OpenSSH < 7.8 is installed)
    - cryptography >= 3.0 (if I(backend=cryptography) and OpenSSH >= 7.8 is installed)
options:
    state:
        description:
            - Whether the private and public keys should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ present, absent ]
    size:
        description:
            - "Specifies the number of bits in the private key to create. For RSA keys, the minimum size is 1024 bits and the default is 4096 bits.
              Generally, 2048 bits is considered sufficient.  DSA keys must be exactly 1024 bits as specified by FIPS 186-2.
              For ECDSA keys, size determines the key length by selecting from one of three elliptic curve sizes: 256, 384 or 521 bits.
              Attempting to use bit lengths other than these three values for ECDSA keys will cause this module to fail.
              Ed25519 keys have a fixed length and the size will be ignored."
        type: int
    type:
        description:
            - "The algorithm used to generate the SSH private key. C(rsa1) is for protocol version 1.
              C(rsa1) is deprecated and may not be supported by every version of ssh-keygen."
        type: str
        default: rsa
        choices: ['rsa', 'dsa', 'rsa1', 'ecdsa', 'ed25519']
    force:
        description:
            - Should the key be regenerated even if it already exists
        type: bool
        default: false
    path:
        description:
            - Name of the files containing the public and private key. The file containing the public key will have the extension C(.pub).
        type: path
        required: true
    comment:
        description:
            - Provides a new comment to the public key.
        type: str
    passphrase:
        description:
            - Passphrase used to decrypt an existing private key or encrypt a newly generated private key.
            - Passphrases are not supported for I(type=rsa1).
            - Can only be used when I(backend=cryptography), or when I(backend=auto) and a required C(cryptography) version is installed.
        type: str
        version_added: 1.7.0
    private_key_format:
        description:
            - Used when a I(backend=cryptography) to select a format for the private key at the provided I(path).
            - The only valid option currently is C(auto) which will match the key format of the installed OpenSSH version.
            - For OpenSSH < 7.8 private keys will be in PKCS1 format except ed25519 keys which will be in OpenSSH format.
            - For OpenSSH >= 7.8 all private key types will be in the OpenSSH format.
        type: str
        default: auto
        choices:
            - auto
        version_added: 1.7.0
    backend:
        description:
            - Selects between the C(cryptography) library or the OpenSSH binary C(opensshbin).
            - C(auto) will default to C(opensshbin) unless the OpenSSH binary is not installed or when using I(passphrase).
        type: str
        default: auto
        choices:
            - auto
            - cryptography
            - opensshbin
        version_added: 1.7.0
    regenerate:
        description:
            - Allows to configure in which situations the module is allowed to regenerate private keys.
              The module will always generate a new key if the destination file does not exist.
            - By default, the key will be regenerated when it does not match the module's options,
              except when the key cannot be read or the passphrase does not match. Please note that
              this B(changed) for Ansible 2.10. For Ansible 2.9, the behavior was as if C(full_idempotence)
              is specified.
            - If set to C(never), the module will fail if the key cannot be read or the passphrase
              isn't matching, and will never regenerate an existing key.
            - If set to C(fail), the module will fail if the key does not correspond to the module's
              options.
            - If set to C(partial_idempotence), the key will be regenerated if it does not conform to
              the module's options. The key is B(not) regenerated if it cannot be read (broken file),
              the key is protected by an unknown passphrase, or when they key is not protected by a
              passphrase, but a passphrase is specified.
            - If set to C(full_idempotence), the key will be regenerated if it does not conform to the
              module's options. This is also the case if the key cannot be read (broken file), the key
              is protected by an unknown passphrase, or when they key is not protected by a passphrase,
              but a passphrase is specified. Make sure you have a B(backup) when using this option!
            - If set to C(always), the module will always regenerate the key. This is equivalent to
              setting I(force) to C(yes).
            - Note that adjusting the comment and the permissions can be changed without regeneration.
              Therefore, even for C(never), the task can result in changed.
        type: str
        choices:
            - never
            - fail
            - partial_idempotence
            - full_idempotence
            - always
        default: partial_idempotence
        version_added: '1.0.0'
notes:
    - In case the ssh key is broken or password protected, the module will fail.
      Set the I(force) option to C(yes) if you want to regenerate the keypair.
    - Supports C(check_mode).
    - In the case a custom C(mode), C(group), C(owner), or other file attribute is provided it will be applied to both key files.

extends_documentation_fragment: files
'''

EXAMPLES = '''
- name: Generate an OpenSSH keypair with the default values (4096 bits, rsa)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa

- name: Generate an OpenSSH keypair with the default values (4096 bits, rsa) and encrypted private key
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    passphrase: super_secret_password

- name: Generate an OpenSSH rsa keypair with a different size (2048 bits)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    size: 2048

- name: Force regenerate an OpenSSH keypair if it already exists
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_rsa
    force: True

- name: Generate an OpenSSH keypair with a different algorithm (dsa)
  community.crypto.openssh_keypair:
    path: /tmp/id_ssh_dsa
    type: dsa
'''

RETURN = '''
size:
    description: Size (in bits) of the SSH private key.
    returned: changed or success
    type: int
    sample: 4096
type:
    description: Algorithm used to generate the SSH private key.
    returned: changed or success
    type: str
    sample: rsa
filename:
    description: Path to the generated SSH private key file.
    returned: changed or success
    type: str
    sample: /tmp/id_ssh_rsa
fingerprint:
    description: The fingerprint of the key.
    returned: changed or success
    type: str
    sample: SHA256:r4YCZxihVjedH2OlfjVGI6Y5xAYtdCwk8VxKyzVyYfM
public_key:
    description: The public key of the generated SSH private key.
    returned: changed or success
    type: str
    sample: ssh-rsa AAAAB3Nza(...omitted...)veL4E3Xcw== test_key
comment:
    description: The comment of the generated key.
    returned: changed or success
    type: str
    sample: test@comment
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils.openssh.backends.keypair_backend import (
    select_backend
)


def main():

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            size=dict(type='int'),
            type=dict(type='str', default='rsa', choices=['rsa', 'dsa', 'rsa1', 'ecdsa', 'ed25519']),
            force=dict(type='bool', default=False),
            path=dict(type='path', required=True),
            comment=dict(type='str'),
            regenerate=dict(
                type='str',
                default='partial_idempotence',
                choices=['never', 'fail', 'partial_idempotence', 'full_idempotence', 'always']
            ),
            passphrase=dict(type='str', no_log=True),
            private_key_format=dict(type='str', default='auto', no_log=False, choices=['auto']),
            backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'opensshbin'])
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )

    keypair = select_backend(module, module.params['backend'])[1]

    keypair.execute()


if __name__ == '__main__':
    main()
