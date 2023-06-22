#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: acme_account
author: "Felix Fontein (@felixfontein)"
short_description: Create, modify or delete ACME accounts
description:
  - "Allows to create, modify or delete accounts with a CA supporting the
     L(ACME protocol,https://tools.ietf.org/html/rfc8555),
     such as L(Let's Encrypt,https://letsencrypt.org/)."
  - "This module only works with the ACME v2 protocol."
notes:
  - "The M(community.crypto.acme_certificate) module also allows to do basic account management.
     When using both modules, it is recommended to disable account management
     for M(community.crypto.acme_certificate). For that, use the O(community.crypto.acme_certificate#module:modify_account) option of
     M(community.crypto.acme_certificate)."
seealso:
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - module: community.crypto.acme_account_info
    description: Retrieves facts about an ACME account.
  - module: community.crypto.openssl_privatekey
    description: Can be used to create a private account key.
  - module: community.crypto.openssl_privatekey_pipe
    description: Can be used to create a private account key without writing it to disk.
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
extends_documentation_fragment:
  - community.crypto.acme
  - community.crypto.attributes
  - community.crypto.attributes.actiongroup_acme
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
options:
  state:
    description:
      - "The state of the account, to be identified by its account key."
      - "If the state is V(absent), the account will either not exist or be
         deactivated."
      - "If the state is V(changed_key), the account must exist. The account
         key will be changed; no other information will be touched."
    type: str
    required: true
    choices:
    - present
    - absent
    - changed_key
  allow_creation:
    description:
      - "Whether account creation is allowed (when state is V(present))."
    type: bool
    default: true
  contact:
    description:
      - "A list of contact URLs."
      - "Email addresses must be prefixed with C(mailto:)."
      - "See U(https://tools.ietf.org/html/rfc8555#section-7.3)
         for what is allowed."
      - "Must be specified when state is V(present). Will be ignored
         if state is V(absent) or V(changed_key)."
    type: list
    elements: str
    default: []
  terms_agreed:
    description:
      - "Boolean indicating whether you agree to the terms of service document."
      - "ACME servers can require this to be V(true)."
    type: bool
    default: false
  new_account_key_src:
    description:
      - "Path to a file containing the ACME account RSA or Elliptic Curve key to change to."
      - "Same restrictions apply as to O(account_key_src)."
      - "Mutually exclusive with O(new_account_key_content)."
      - "Required if O(new_account_key_content) is not used and O(state) is V(changed_key)."
    type: path
  new_account_key_content:
    description:
      - "Content of the ACME account RSA or Elliptic Curve key to change to."
      - "Same restrictions apply as to O(account_key_content)."
      - "Mutually exclusive with O(new_account_key_src)."
      - "Required if O(new_account_key_src) is not used and O(state) is V(changed_key)."
    type: str
  new_account_key_passphrase:
    description:
      - Phassphrase to use to decode the new account key.
      - "B(Note:) this is not supported by the C(openssl) backend, only by the C(cryptography) backend."
    type: str
    version_added: 1.6.0
  external_account_binding:
    description:
      - Allows to provide external account binding data during account creation.
      - This is used by CAs like Sectigo to bind a new ACME account to an existing CA-specific
        account, to be able to properly identify a customer.
      - Only used when creating a new account. Can not be specified for ACME v1.
    type: dict
    suboptions:
      kid:
        description:
          - The key identifier provided by the CA.
        type: str
        required: true
      alg:
        description:
          - The MAC algorithm provided by the CA.
          - If not specified by the CA, this is probably V(HS256).
        type: str
        required: true
        choices: [ HS256, HS384, HS512 ]
      key:
        description:
          - Base64 URL encoded value of the MAC key provided by the CA.
          - Padding (V(=) symbols at the end) can be omitted.
        type: str
        required: true
    version_added: 1.1.0
'''

EXAMPLES = '''
- name: Make sure account exists and has given contacts. We agree to TOS.
  community.crypto.acme_account:
    account_key_src: /etc/pki/cert/private/account.key
    state: present
    terms_agreed: true
    contact:
    - mailto:me@example.com
    - mailto:myself@example.org

- name: Make sure account has given email address. Do not create account if it does not exist
  community.crypto.acme_account:
    account_key_src: /etc/pki/cert/private/account.key
    state: present
    allow_creation: false
    contact:
    - mailto:me@example.com

- name: Change account's key to the one stored in the variable new_account_key
  community.crypto.acme_account:
    account_key_src: /etc/pki/cert/private/account.key
    new_account_key_content: '{{ new_account_key }}'
    state: changed_key

- name: Delete account (we have to use the new key)
  community.crypto.acme_account:
    account_key_content: '{{ new_account_key }}'
    state: absent
'''

RETURN = '''
account_uri:
  description: ACME account URI, or None if account does not exist.
  returned: always
  type: str
'''

import base64

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    create_backend,
    get_default_argspec,
    ACMEClient,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.account import (
    ACMEAccount,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
    KeyParsingError,
)


def main():
    argument_spec = get_default_argspec()
    argument_spec.update(dict(
        terms_agreed=dict(type='bool', default=False),
        state=dict(type='str', required=True, choices=['absent', 'present', 'changed_key']),
        allow_creation=dict(type='bool', default=True),
        contact=dict(type='list', elements='str', default=[]),
        new_account_key_src=dict(type='path'),
        new_account_key_content=dict(type='str', no_log=True),
        new_account_key_passphrase=dict(type='str', no_log=True),
        external_account_binding=dict(type='dict', options=dict(
            kid=dict(type='str', required=True),
            alg=dict(type='str', required=True, choices=['HS256', 'HS384', 'HS512']),
            key=dict(type='str', required=True, no_log=True),
        ))
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(
            ['account_key_src', 'account_key_content'],
        ),
        mutually_exclusive=(
            ['account_key_src', 'account_key_content'],
            ['new_account_key_src', 'new_account_key_content'],
        ),
        required_if=(
            # Make sure that for state == changed_key, one of
            # new_account_key_src and new_account_key_content are specified
            ['state', 'changed_key', ['new_account_key_src', 'new_account_key_content'], True],
        ),
        supports_check_mode=True,
    )
    backend = create_backend(module, True)

    if module.params['external_account_binding']:
        # Make sure padding is there
        key = module.params['external_account_binding']['key']
        if len(key) % 4 != 0:
            key = key + ('=' * (4 - (len(key) % 4)))
        # Make sure key is Base64 encoded
        try:
            base64.urlsafe_b64decode(key)
        except Exception as e:
            module.fail_json(msg='Key for external_account_binding must be Base64 URL encoded (%s)' % e)
        module.params['external_account_binding']['key'] = key

    try:
        client = ACMEClient(module, backend)
        account = ACMEAccount(client)
        changed = False
        state = module.params.get('state')
        diff_before = {}
        diff_after = {}
        if state == 'absent':
            created, account_data = account.setup_account(allow_creation=False)
            if account_data:
                diff_before = dict(account_data)
                diff_before['public_account_key'] = client.account_key_data['jwk']
            if created:
                raise AssertionError('Unwanted account creation')
            if account_data is not None:
                # Account is not yet deactivated
                if not module.check_mode:
                    # Deactivate it
                    payload = {
                        'status': 'deactivated'
                    }
                    result, info = client.send_signed_request(
                        client.account_uri, payload, error_msg='Failed to deactivate account', expected_status_codes=[200])
                changed = True
        elif state == 'present':
            allow_creation = module.params.get('allow_creation')
            contact = [str(v) for v in module.params.get('contact')]
            terms_agreed = module.params.get('terms_agreed')
            external_account_binding = module.params.get('external_account_binding')
            created, account_data = account.setup_account(
                contact,
                terms_agreed=terms_agreed,
                allow_creation=allow_creation,
                external_account_binding=external_account_binding,
            )
            if account_data is None:
                raise ModuleFailException(msg='Account does not exist or is deactivated.')
            if created:
                diff_before = {}
            else:
                diff_before = dict(account_data)
                diff_before['public_account_key'] = client.account_key_data['jwk']
            updated = False
            if not created:
                updated, account_data = account.update_account(account_data, contact)
            changed = created or updated
            diff_after = dict(account_data)
            diff_after['public_account_key'] = client.account_key_data['jwk']
        elif state == 'changed_key':
            # Parse new account key
            try:
                new_key_data = client.parse_key(
                    module.params.get('new_account_key_src'),
                    module.params.get('new_account_key_content'),
                    passphrase=module.params.get('new_account_key_passphrase'),
                )
            except KeyParsingError as e:
                raise ModuleFailException("Error while parsing new account key: {msg}".format(msg=e.msg))
            # Verify that the account exists and has not been deactivated
            created, account_data = account.setup_account(allow_creation=False)
            if created:
                raise AssertionError('Unwanted account creation')
            if account_data is None:
                raise ModuleFailException(msg='Account does not exist or is deactivated.')
            diff_before = dict(account_data)
            diff_before['public_account_key'] = client.account_key_data['jwk']
            # Now we can start the account key rollover
            if not module.check_mode:
                # Compose inner signed message
                # https://tools.ietf.org/html/rfc8555#section-7.3.5
                url = client.directory['keyChange']
                protected = {
                    "alg": new_key_data['alg'],
                    "jwk": new_key_data['jwk'],
                    "url": url,
                }
                payload = {
                    "account": client.account_uri,
                    "newKey": new_key_data['jwk'],  # specified in draft 12 and older
                    "oldKey": client.account_jwk,  # specified in draft 13 and newer
                }
                data = client.sign_request(protected, payload, new_key_data)
                # Send request and verify result
                result, info = client.send_signed_request(
                    url, data, error_msg='Failed to rollover account key', expected_status_codes=[200])
                if module._diff:
                    client.account_key_data = new_key_data
                    client.account_jws_header['alg'] = new_key_data['alg']
                    diff_after = account.get_account_data()
            elif module._diff:
                # Kind of fake diff_after
                diff_after = dict(diff_before)
            diff_after['public_account_key'] = new_key_data['jwk']
            changed = True
        result = {
            'changed': changed,
            'account_uri': client.account_uri,
        }
        if module._diff:
            result['diff'] = {
                'before': diff_before,
                'after': diff_after,
            }
        module.exit_json(**result)
    except ModuleFailException as e:
        e.do_fail(module)


if __name__ == '__main__':
    main()
