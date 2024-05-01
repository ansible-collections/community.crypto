#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024, Austin Lucas Lake <53884490+austinlucaslake@users.noreply.github.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: gpg_keypair
author: "Austin Lucas Lake (@austinlucaslake)"
short_description: Generate or delete GPG private and public keys
description:
    - "This module allows one to generate or delete OpenSSH private and public keys using GnuPG (gpg)."
requirements:
    - gpg >= 2.1
extends_documentation_fragment:
    - ansible.builtin.files
    - community.crypto.attributes
    - community.crypto.attributes.files
attributes:
    check_mode:
        support: full
options:
    state:
        description:
            - Whether the private and public keys should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ present, absent ]
    key_type:
        description:
            - "Specifies the type of key to create. By default this is V(EDDSSA) which must be used with Curve25519.
              Supported key types are V(RSA), V(DSA), V(ECDSA), V(EDDSA), and V(ECDH)."
        type: str
        default: EDDSA
        choices: ['RSA', 'DSA', 'ECDSA', 'EDDSA', 'ECDH']        
    key_length:
        description:
            - For non-ECC keys, this specifies the number of bits in the key to create.
            - For RSA keys, the minimum is V(1024), the maximum is V(4096), and the default is V(3072).
            - For DSA keys, the minimum is V(768), the maximum is V(3072), and the default is V(2048).
            - Invalid values will automatically be saturated in the afforemented ranges for each respective key.
            - For ECC keys, this parameter will be ignored.
        type: int
    key_curve:
        description:
            - For ECC keys, this specifies the curve used to generate the keys.
            - Supported key curves are V(cv25519), V(nistp256), V(nistp384), V(nistp521), V(brainpoolP256r1), V(brainpoolP384r1), V(brainpoolP512r1), and V(secp256k1).
            - EDDSA keys can only be used with V(cv25519).
            - Only EDDSA and ECDH keys support V(cv25519), and for both, V(cv25519) is the default.
            - For ECDSA and ECDH, the default is V(brainpoolP512r1).
            - For non-ECC keys, this parameter with be ignored.
        type: str
        choices: ['cv25519', 'nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']
    key_usage:
        description:
            - Specifies usage(s) for key.
            - Support usages are V(encrypt), V(sign), V(auth), V(cert).
            - V(cert) is given to all primary keys regardess, however can be used to only give V(vert) usage to a key.
            - If not usage is specified, the valid usages for the given key type with be assigned.
            - If O(state) is V(absent), this parameter is ignored. 
        type: list[str]
        choices: ['encrypt', 'sign', 'auth', 'cert']
    subkey_type:
        description:
            - Similar to O(key_type), but also supports V(ELG).
        type: str
        default: EDDSA
        choices: ['RSA', 'DSA', 'ECDSA', 'EDDSA', 'ECDH', 'ELG']
    subkey_length:
        description:
            - Similar to O(key_length).
            - For ELG keys, the minimum is V(1024), the maximum is V(4096), and the default is V(3072)."
        type: int
    subkey_curve:
        description:
            - "Similar to O(key_curve)"
        type: str
        choices: ['cv25519', 'nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']
    key_usage:
        description:
            - Similar to O(key_usage), but does not support V(cert).
        type: list[str]
        choices: ['encrypt', 'sign', 'auth', 'cert']
    name:
        description:
            - Specifies a name for the key.
        type: str
    comment:
        description:
            - Specifies a comment for the key.
        type: str
    email:
        description:
            - Specifies an email for the key.
        type: str
    passphrase:
        description:
            - Passphrase used to decrypt an existing private key or encrypt a newly generated private key.
            - If O(state) is V(absent), this parameter is ignored. 
        type: str
    fingerprints:
        description:
            - Specifies keys to match against.
            - Provided fingerprints will take priority over user-id "V(name) (V(comment)) <V(email)>".
            - If O(state) is V(absent), keys with the provided fingerprints will be deleted if found 
        type: list[str]
    keyserver:
        description:
            - Specifies keyserver to upload key to.
            - If O(state) is V(absent), this parameter will be ignored.
        type: str
    transient_key:
        description:
            - Allows key generation to use a faster, but less secure random number generator.
        type: bool
        default: False
    return_fingerprints:
        description:
            - Allows for the return of fingerprint(s) for newly created or deleted keys(s)
        type: bool
        default: False
'''

EXAMPLES = '''
- name: Generate the default GPG keypair (Ed25519)
  community.crypto.gpg_keypair:

- name: Generate the default GPG keypair with a passphrase
  community.crypto.gpg_keypair:
    passphrase: super_secret_password

- name: Generate a RSA GPG keypair with the default RSA size (2048 bits)
  community.crypto.gpg_keypair:
    key_type: RSA

- name: Generate a RSA GPG keypair with custom size (4096 bits)
  community.crypto.gpg_keypair:
    key_type: RSA
    key_length: 4096

- name: Generate an ECC GPG keypair 
  community.crypto.gpg_keypair:
    key_type: EDDSA
    key_curve: cv25519

- name: Generate a GPG keypair and with a subkey:
  community.crypto.gpg_keypair:
    subkey_type: ECDH
    subkey_curve: cv25519

- name: Generate a GPG keypair with custom user-id:
  community.crypto.gpg_keypair:
    name: Your Name
    comment: Interesting comment.
    email: example@email.com

- name: Generate a GPG keypair and return fingerprint of new key
  community.crypto.gpg_keypair:
    return_fingerprints: true
  register: gpg_keys

- name: Delete GPG keypair(s) matching a specified user-id:
  community.crypto.gpg_keypair:
    state: abscent
    name: Your Name
    comment: Interesting comment.
    email: example@email.com

- name: Delete GPG keypair(s) matching a specified fingerprint:
  community.crypto.gpg_keypair:
    state: abscent
    fingerprints:
      - ABC123...

'''

RETURN = '''
size:
    description: Size (in bits) of the SSH private key.
    returned: changed or success
    type: int
    sample: 4096
fingerprints:
    description: Fingerprint(s) of newly created or deleted key(s)
    return: changed and `return_fingerprints`==True
    type: list[str]
    sample: [ ABC123... ]
'''

from typing import Dict, Union

import itertools
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.crypto.plugins.module_utils.gnupg.cli import GPGError
from ansible_collections.community.crypto.plugins.plugin_utils.gnupg import GPGError

def validate_params(params: Dict[str, Union[str, int]]) -> None:

    if params['override'] and params['present'] and not (params['fingerprint'] or params['name'] or params['comment'] or params['email']):
            raise GPGError, 'To override existing keys, please provide any combination of the `fingerprint`, `name`, `comment`, and `email` parameters.'
    keys = ['key']
    if params['subkey_type']:
        keys.append('subkey')
    for key in keys:
        if params[f'{key}_type'] == 'EDDSA':
            if not params[f'{key}_usage']: params[f'{key}_usage'] = ['sign', 'auth']
            elif params[f'{key}_usage'] not in list(itertools.combinations(['sign', 'auth'])):
                raise GPGError, f'Invalid {key}_usage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_curve'] or params[f'{key}_curve'] == 'cv25519':
                params[f'{key}_curve'] = 'ed25519'
            elif params[f'{key}_curve'] != 'cv25519':
                raise GPGError, f'Invalid {key}_curve for {params[f"{key}_type"]} {key}.'  
        elif params[f'{key}_type'] == 'ECDH':
            if not params[f'{key}_usage']: params[f'{key}_usage'] = ['encrypt']
            elif params[f'{key}_usage'] != ['encrypt']:
                raise GPGError, f'Invalid {key}_usage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_curve']: params[f'{key}_curve'] = 'cv25519'
            elif params[f'{key}_curve'] != 'cv25519':
                raise GPGError, f'Invalid {key}_curve for {params[f"{key}_type"]} {key}.'  
        elif params[f'{key}_type'] == 'ECDSA':
            if not params[f'{key}_usage']: params[f'{key}_usage'] = ['sign', 'auth']
            elif params[f'{key}_usage'] not in list(itertools.combinations(['sign', 'auth'])):
                raise GPGError, f'Invalid {key}_usage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_curve']: params[f'{key}_curve'] = 'brainpoolp521r1'
            elif params[f'{key}_curve'] not in ['nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']:
                raise GPGError, f'Invalid {key}_curve for {params[f"{key}_type"]} {key}.'  
        elif params[f'{key}_type'] == 'RSA':
            if not params[f'{key}_usage']: params = ['ecrypt', 'sign', 'auth']
            elif not params[f'{key}_usage'] not in list(itertools.combinatios(['ecrypt', 'sign', 'auth'])):
                raise GPGError, f'Invalid {key}_usage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_length']: params[f'{key}_length'] = 3072
            elif not 1024 <= params[f'{key}_length'] < 4096:
                params[f'{key}_length'] = min(max(params[f'{key}_length'], 1024), 4096)
        elif params[f'{key}_type'] == 'DSA':
            if not params[f'{key}_usage']: params[f'{key}_usage'] = ['sign', 'auth']
            elif params[f'{key}_usage'] not in list(itertools.combinations(['sign', 'auth'])):
                raise GPGError, f'Invalid {key}_usage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_length']: params[f'{key}_length'] = 2048
            elif not 768 <= params[f'{key}_length'] < 3072:    
                params[f'{key}_length'] = min(max(params[f'{key}_length'], 768), 3072)
        elif params[f'{key}_type'] == 'ELG':
            if params[f'{key}_type'] == params['key_type']:
                raise GPGError, f'Invalid algorithm for {key}_type parameter.'
            if not params[f'{key}_usage']: params[f'{key}_usage'] = ['encrypt']
            elif params[f'{key}_usage'] != ['encrypt']:
                raise GPGError, f'Invalid {key}_iusage for {params[f"{key}_type"]} {key}.'
            if not params[f'{key}_length']: params[f'{key}_length'] = 3072
            elif not 1024 <= params[f'{key}_length'] < 4096:
                params[f'{key}_length'] = min(max(params[f'{key}_length'], 1024), 4096)

def list_matching_keys(name, comment, email, fingerprint):
    user_id = ""
    if params['name']:
        user_id += f'{params["name"]} '
    if params['comment']:
        user_id += f'({params["comment"]}) '
    if params['email']:
        user_id += f'<{params["email"]}>'
    if user_id:
        user_id = f'"{user_id.strip()}"'

    if user_id or fingerprints:
        _, stdout, _ = gpg_runner.run_command(['gpg', '--batch', '--list-secret-keys', f'{*fingerprints if fingerprints else user_id}'])
        lines = stdout.split('\n')
        matching_keys = [line.strip() for line in lines if line.strip().isalnum()]
        return matching_keys
    return []

def delete_keypair(
    gpg_runner: PluginGPGRunner,
    matching_keys: List[str],
    check_mode: bool = False
) -> Dict[str, Union[str, int]]:
    if matching_keys:
        gpg_runner.run_command([
            f'{"dry-run" if check_mode else ""}',
            '--batch',
            '--yes',
            '--delete-secret-and-public-key',
            *matching_key
        ], check_rc=True)
        if params['return_fingerprints']:
            return dict(changed=True, fingerprints=matching_keys)
        return dict(changed=True, fingerprints=[])
    return dict(changed=False, fingerprints=[])

def generate_keypair(
    gpg_runner: PluginGPGRunner,
    params: Dict[str, Union[str, int, bool, List[str]]],
    matching_keys,
    check_mode: bool = False
) -> Dict[str, Union[bool, str]]:
    if matching_keys:
        if params['return_fingerprints']:
            return dict(changed=False, fingerprints=matching_keys)
        return dict(change=False, fingerprints=[])

    parameters = f"""<<EOF
        Key-Type: {params['key_type']}
        Key-Length: {params['key_type']}
        Key-Curve: {params['key_curve']}
        {f'''
        Subkey-Type: {params["subkey_type"]}
        Subkey-Length: {params["subkey_type"]}
        Subkey-Curve: {params["subkey_curve"]}
        ''' if params['subkey_type'] else ''}
        Expire-Date: {params['expire_date']}
        {f'Name-Real: {params["name"]}' if params['name'] else ''}
        {f'Name-Comment: {params["comment"]}' if params['comment'] else ''}
        {f'Name-Email: {params["email"]}' if params['email'] else ''}
        {f'Passphrase: {params["passphrase"]}' if params['passphrase'] else '%no-protection'}
        {f'Keyserver: {params["keyserver"]}' if params['keyserver'] else ''}
        {'%transient-key' if params['transient_key'] else ''}
        {'%dry-run' if check_mode or not params['force'] else ''}
        %commit
        EOF
        """

    _, stdout, _ = gpg_runner.run_command([
        f'{"dry-run" if check_mode else ""}',
        '--batch',
        '--log-file',
        '/dev/stdout',
        '--gen-key',
        f'{parameters}'
    ])

    if params['return_fingerprints']:
        fingerprints = []
        fingerprint = re.search(r"([a-zA-Z0-9]*)\.rev", stdout)
        if fingerprint:
            fingerprints.append(fingerprint)
        return dict(changed=True, fingerprints=fingerprints)
    return dict(changed=True, fingerprints=[])

def run_module(params: Dict[str, Union[str, int, bool, List[str]]], check_mode: bool = False):
    validate_params(params)
    gpg_runner = PluginGPGRunner()
    matching_keys = list_matching_keys(
        params["name"],
        params["comment"],
        params["email"],
        params["fingerprints"]
    )
    result = generate_keypair(gpg_runner, params, matching_keys, check_mode) if params['state'] == 'present' else delete_keypair(gpg_runner, matching_keys, check_mode)
    return result

def main():
    key_types = ['RSA', 'DSA', 'ECDH', 'ECDSA', 'EDDSA', 'ELG']
    key_curves = ['cv25519', 'nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']
    key_usages = ['encrypt', 'sign', 'auth', 'cert']

    module = AnsibleModule(
        argument_spec=
            state=dict(type='str', default='present', choices=['present', 'absent']),
            key_type=dict(type='str', default='EDDSA', choices=key_types[:-1]),
            key_curve=dict(type='str', choices=key_curves),
            key_usage=dict(type='str', choices=key_usages),
            subkey_type=dict(type='str', choices=key_types),
            subkey_curve=dict(type='str', choices=key_curves),
            subkey_usage=dict(type='str', choices=key_usages[:-1]),
            name=dict(type='str', default=None),
            comment=dict(type='str', default=None),
            email=dict(type='str', default=None),
            passphrase=dict(type='str', default=None),
            fingerprints=dict(type='str', default=None, no_log=True),
            keyserver=dict(type='str', default=None)
            transient_key=dict(type='bool', default=False),
            return_fingerprints=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )

    try:
        result = run_module(module.params, check_mode)
        module.exit_json(**results)
    except GPGError as e:
        module.fail_json(e)
    except Exception as e:
        module.fail_json(e)

if __name__ == '__main__':
    main()
