#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: acme_certificate_deactivate_authz
author: "Felix Fontein (@felixfontein)"
version_added: 2.20.0
short_description: Deactivate all authz for an ACME v2 order
description:
  - "Deactivate all authentication objects (authz) for an ACME v2 order,
     which effectively deactivates (invalidates) the order itself."
  - "Authentication objects are bound to an account key and remain valid
     for a certain amount of time, and can be used to issue certificates
     without having to re-authenticate the domain. This can be a security
     concern."
  - "Another reason to use this module is to deactivate an order whose
     processing failed when using O(community.crypto.acme_certificate#module:include_renewal_cert_id)."
seealso:
  - module: community.crypto.acme_certificate
extends_documentation_fragment:
  - community.crypto.acme.basic
  - community.crypto.acme.account
  - community.crypto.attributes
  - community.crypto.attributes.actiongroup_acme
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
options:
  order_uri:
    description:
      - The ACME v2 order to deactivate.
      - Can be obtained from RV(community.crypto.acme_certificate#module:order_uri).
    type: str
    required: true
'''

EXAMPLES = r'''
- name: Deactivate all authzs for an order
  community.crypto.acme_certificate_deactivate_authz:
    account_key_content: "{{ account_private_key }}"
    order_uri: "{{ certificate_result.order_uri }}"
'''

RETURN = '''#'''

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    create_backend,
    create_default_argspec,
    ACMEClient,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.account import (
    ACMEAccount,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.orders import (
    Order,
)


def main():
    argument_spec = create_default_argspec()
    argument_spec.update_argspec(
        order_uri=dict(type='str', required=True),
    )
    module = argument_spec.create_ansible_module(supports_check_mode=True)
    if module.params['acme_version'] == 1:
        module.fail_json('The module does not support acme_version=1')

    backend = create_backend(module, False)

    try:
        client = ACMEClient(module, backend)
        account = ACMEAccount(client)

        dummy, account_data = account.setup_account(allow_creation=False)
        if account_data is None:
            raise ModuleFailException(msg='Account does not exist or is deactivated.')

        order = Order.from_url(client, module.params['order_uri'])
        order.load_authorizations(client)

        changed = False
        for authz in order.authorizations.values():
            if not authz.can_deactivate():
                continue
            changed = True
            if module.check_mode:
                continue
            try:
                authz.deactivate(client)
            except Exception:
                # ignore errors
                pass
            if authz.status != 'deactivated':
                module.warn(warning='Could not deactivate authz object {0}.'.format(authz.url))

        module.exit_json(changed=changed)
    except ModuleFailException as e:
        e.do_fail(module)


if __name__ == '__main__':
    main()
