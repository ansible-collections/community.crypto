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
version_added: 2.20.0
description:
    - "This module allows one to generate or delete GPG private and public keys using GnuPG (gpg)."
requirements:
    - gpg >= 2.1
extends_documentation_fragment:
    - ansible.builtin.files
    - community.crypto.attributes
    - community.crypto.attributes.files
attributes:
    check_mode:
        support: full
    diff_mode:
        support: none
options:
    state:
        description:
            - Whether the private and public keys should exist or not, taking action if the state is different from what is stated.
        type: str
        default: present
        choices: [ present, absent ]
    key_type:
        description:
            - Specifies the type of key to create.
        type: str
        choices: ['RSA', 'DSA', 'ECDSA', 'EDDSA']
    key_length:
        description:
            - For non-ECC keys, this specifies the number of bits in the key to create.
            - For RSA keys, the minimum is V(1024), the maximum is V(4096), and the default is V(3072).
            - For DSA keys, the minimum is V(768), the maximum is V(3072), and the default is V(2048).
            - As per gpg's behavior, values below the allowed ranges will be set to the respective defaults, and those above the allowed ranges will saturate at the maximum.
            - For ECC keys, this parameter will be ignored.
        type: int
    key_curve:
        description:
            - For ECC keys, this specifies the curve used to generate the keys.
            - EDDSA keys only support the V(ed25519) curve and they can only be generate using said curve.
            - For ECDSA keys, the default is V(brainpoolP512r1).
            - For non-ECC keys, this parameter with be ignored.
        type: str
        choices: ['nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1', 'ed25519']
    key_usage:
        description:
            - Specifies usage(s) for key.
            - V(cert) is given to all primary keys regardess, however can be used to only give V(vert) usage to a key.
            - If not usage is specified, the valid usages for the given key type with be assigned.
            - If O(state) is V(absent), this parameter is ignored. 
        type: list
        elements: str
        choices: ['encrypt', 'sign', 'auth', 'cert']
    subkeys:
        description:
            - List of subkeys with their own respective key types, lengths, curves, and usages.
            - Similar to O(key_type), O(key_length), O(key_curve), and (key_usage).
            - Supports ECDH and ELG keys.
            - For both ECDH and ELG keys, the only supported usage is V(encrypt).
            - For ECDH keys, the default curve is V(brainpoolP512r1).
            - ECDH keys also support the V(cv25519) curve.
            - For ELG keys, the minimum length is V(1024) bits, the maximum length is V(4096) bits, and the default length is V(3072) bits.

        type: list
        elements: dict
        options:
            subkey_type:
                type: str 
            subkey_length:
                type: int
            subkey_curve:
                type: str
            subkey_usage:
                type: list
                elements: str
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
            - If O(state=absent), this parameter is ignored. 
        type: str
    fingerprints:
        description:
            - Specifies keys to match against.
            - Provided fingerprints will take priority over user-id "O(name) (O(comment)) <O(email)>".
            - If O(state=absent), keys with the provided fingerprints will be deleted if found.
        type: list
        elements: str
    keyserver:
        description:
            - Specifies keyserver to upload key to.
            - If O(state=absent), this parameter will be ignored.
        type: str
    transient_key:
        description:
            - Allows key generation to use a faster, but less secure random number generator.
        type: bool
        default: False
'''

EXAMPLES = '''
- name: Generate the default GPG keypair
  community.crypto.gpg_keypair:

- name: Generate the default GPG keypair with a passphrase
  community.crypto.gpg_keypair:
    passphrase: {{ passphrase }} 

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
    key_curve: ed25519

- name: Generate a GPG keypair and with a subkey:
  community.crypto.gpg_keypair:
    subkeys:
        - { subkey_type: ECDH, subkey_curve: cv25519 }

- name: Generate a GPG keypair with custom user-id:
  community.crypto.gpg_keypair:
    name: name
    comment: comment
    email: name@email.com

- name: Delete GPG keypair(s) matching a specified user-id:
  community.crypto.gpg_keypair:
    state: absent
    name: name
    comment: comment
    email: name@email.com

- name: Delete a GPG keypair matching a specified fingerprint:
  community.crypto.gpg_keypair:
    state: abscent
    fingerprints:
      - ABC123...
'''

RETURN = '''
changed:
    description: Indicates if changes were made to GPG keyring.
    type: bool
    sample: True
fingerprints:
    description: Fingerprint(s) of newly created or matched key(s).
    type: list
    elements: str
    sample: [ ABC123... ]
'''

from typing import Dict, Union

import itertools
import re

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.crypto.plugins.module_utils.gnupg.cli import GPGError
from ansible_collections.community.crypto.plugins.plugin_utils.gnupg import GPGError


def validate_key(key_type, key_length, key_curve, key_usage, key_name = 'primary key'):
    if key_type == 'EDDSA':
        if key_curve and key_curve != 'ed25519':
            raise GPGError('Invalid curve for {} {}.'.format(key_type, key_name))
        elif:
            raise GPGError('No curve provided for {} {}.'.format(key_type, key_name))
        elif key_usage and key_usage not in list(itertools.combinations(['sign', 'auth'])):
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))
    elif key_type == 'ECDH':
        if key_name = 'primary key':
            raise GPGError('Invalid type for {}.'.format(key_name))
        elif key_usage and key_usage != ['encrypt']:
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))
        elif not key_curve:
            raise GPGError('No curve provided for {} {}.'.format(key_type, key_name))
    elif key_type == 'ECDSA':
        if key_curve and key_curve not in ['nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1']:
            raise GPGError('Invalid curve for {} {}.'.format(key_type, key_name))
        elif not key_curve:
            raise GPGError('No curve provided for {} {}.'.format(key_type, key_name))
        elif key_usage and key_usage not in list(itertools.combinations(['sign', 'auth'])):
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))
    elif key_type == 'RSA':
        if key_usage and key_usage not in list(itertools.combinatios(['ecrypt', 'sign', 'auth'])):
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))
    elif key_type == 'DSA':
        if key_usage and key_usage not in list(itertools.combinations(['sign', 'auth'])):
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))
    elif key_type == 'ELG':
        if key_name == 'primary key':
            raise GPGError('Invalid type for {}.'.format(key_name))
        elif key_usage != ['encrypt']:
            raise GPGError('Invalid usage for {} {}.'.format(key_type, key_name))


def validate_params(params):
    validate_key(params['key_type'], params['key_length'], params['key_curve'], params['key_usage'])
    for index, subkey in enumerate(params['subkeys']):
        validate_key(subkey['subkey_type'], subkey['subkey_length'], subkey['subkey_curve'], subkey['subkey_usage'], ('subkey #{}').format(index+1))


def list_matching_keys(name, comment, email, fingerprint):
    user_id = ''
    if params['name']:
        user_id += '{} '.format(params["name"])
    if params['comment']:
        user_id += '({}) '.format(params["comment"])
    if params['email']:
        user_id += '<{}>'.format(params["email"])
    if user_id:
        user_id = '"{}"'.format(user_id.strip())

    if user_id or fingerprints:
        _, stdout, _ = gpg_runner.run_command(['gpg', '--batch', '--list-secret-keys', '{}'.format(*fingerprints if fingerprints else user_id)])
        lines = stdout.split('\n')
        matching_keys = [line.strip() for line in lines if line.strip().isalnum()]
        for key in matching_keys:
            # TODO: match based on key_type, key_usage, key_curve, and subkeys 
            pass
        return matching_keys
    return []


def delete_keypair(gpg_runner, matching_keys, check_mode):
    if matching_keys:
        gpg_runner.run_command([
            '--dry-run' if check_mode else '',
            '--batch',
            '--yes',
            '--delete-secret-and-public-key',
            *matching_keys
        ], check_rc=True)
        return dict(changed=True, fingerprints=matching_keys)
    return dict(changed=False, fingerprints=[])


def add_subkey(gpg_runner, fingerprint, subkey_index, subkey_type, subkey_length, subkey_curve, subkey_usage, subkey_index):
    if subkey_type in ['RSA', 'DSA'. 'ELG']:
        algo = '{}'.format(subkey_type.lower())
        if subkey_length:
            algo += str(subkey_length)
    elif subkey_curve:
        algo = subkey_curve
    else:
        algo = None
    gpg_runner.run_command([
        '--batch', '--quick-add-key', fingerprint, algo if algo else 'default', *usage, expire_date if expire_date else 0
    ])
    else:
        raise GPGError('No algorithm applied for subkey #{}'.format(subkey_index+1))


def generate_keypair(gpg_runner, params, matching_keys, check_mode):
    if matching_keys:
        return dict(changed=False, fingerprints=matching_keys)

    parameters = '''<<EOF
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        {}
        %commit
        EOF
        '''.format(
            'Key-Type: {}'.format(params['key_type'] if params['key_type'] else 'default'),
            'Key-Length: {}'.format(params['key_length']) if params['key_length'] else '',
            'Key-Curve: {}'.format(params['key_curve']) if params['key_curve'] else '',
            'Expire-Date: {}'.format(params['expire_date']) if params['expire_date'] else '',
            'Name-Real: {}'.format(params['name']) if params['name'] else '',
            'Name-Comment: {}'.format(params['comment']) if params['comment'] else '',
            'Name-Email: {}'.format(params['email']) if params['email'] else '',
            'Passphrase: {}'.format(params['passphrase']) if params['passphrase'] else '%no-protection',
            'Keyserver: {}'.format(params['keyserver']) if params['keyserver'] else '',
            '%transient-key' if params['transient_key'] else ''
        )

    _, stdout, _ = gpg_runner.run_command([
        '--dry-run' if check_mode else '',
        '--batch',
        '--log-file',
        '/dev/stdout',
        '--gen-key',
        parameters
    ])

    fingerprint = re.search(r"([a-zA-Z0-9]*)\.rev", stdout)
   
    for index, subkey in enumerate(params['subkeys']):
        add_subkey(gpg_runner, fingerprint, index, subkey['subkey_type'], subkey['subkey_length'], subkey['subkey_curve'], subkey['subkey_usage'])

    return dict(changed=True, fingerprints=[fingerprint])


def run_module(params, check_mode = False):
    validate_params(params)
    gpg_runner = PluginGPGRunner()
    matching_keys = list_matching_keys(
        params['name'],
        params['comment'],
        params['email'],
        params['fingerprints']
    )
    if params['state'] = present:
        result = generate_keypair(gpg_runner, params, matching_keys, check_mode)
    else:
        result = delete_keypair(gpg_runner, matching_keys, check_mode)
    return result


def main():
    key_types = ['RSA', 'DSA', 'ECDSA', 'EDDSA', 'ECDH', 'ELG']
    key_curves = ['nistp256', 'nistp384', 'nistp521', 'brainpoolP256r1', 'brainpoolP384r1', 'brainpoolP512r1', 'secp256k1', 'ed25519', 'cv25519']
    key_usages = ['encrypt', 'sign', 'auth', 'cert']

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            key_type=dict(type='str', choices=key_types[:-2]),
            key_length=dict(type='int'),
            key_curve=dict(type='str', choices=key_curves[:-1]),
            key_usage=dict(type='list', elements='str', choices=key_usages),
            subkeys=dict(type='list', elements='dict', options=dict(
                subkey_type=dict(type='str', choices=key_types),
                subkey_length=dict(type='int'),
                subkey_curve=dict(type='str', choices=key_curves),
                subkey_usage=dict(type='list', elements='str', choices=key_usages[:-1])

            )),
            name=dict(type='str', default=None),
            comment=dict(type='str', default=None),
            email=dict(type='str', default=None),
            passphrase=dict(type='str', default=None, no_log=True),
            fingerprints=dict(type='list', elements='str', default=None, no_log=True),
            keyserver=dict(type='str', default=None),
            transient_key=dict(type='bool', default=False)
        ),
        supports_check_mode=True,
        required_if=[
            ['state', 'present', ['name', 'comment', 'email']],
            ['state', 'absent', ['name', 'comment', 'email', 'fingerprints']]
        ]
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
