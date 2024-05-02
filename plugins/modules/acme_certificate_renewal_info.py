#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: acme_certificate_renewal_info
author: "Felix Fontein (@felixfontein)"
version_added: 2.20.0
short_description: Determine whether a certificate should be renewed or not
description:
  - Uses various information to determine whether a certificate should be renewed or not.
  - If available, the ARI extension (ACME Renewal Information, U(https://datatracker.ietf.org/doc/draft-ietf-acme-ari/))
    is used. This module implements version 3 of the ARI draft."
extends_documentation_fragment:
  - community.crypto.acme.basic
  - community.crypto.acme.no_account
  - community.crypto.attributes
  - community.crypto.attributes.info_module
options:
  certificate_path:
    description:
      - A path to the X.509 certificate to determine renewal of.
      - In case the certificate does not exist, the module will always return RV(should_renew=true).
      - O(certificate_path) and O(certificate_content) are mutually exclusive.
    type: path
  certificate_content:
    description:
      - The content of the X.509 certificate to determine renewal of.
      - O(certificate_path) and O(certificate_content) are mutually exclusive.
    type: str
  use_ari:
    description:
      - Whether to use ARI information, if available.
      - Set this to V(false) if the ACME server implements ARI in a way that is incompatible with this module.
    type: bool
    default: true
  ari_algorithm:
    description:
      - If ARI information is used, selects which algorithm is used to determine whether to renew now.
      - V(standard) selects the L(algorithm provided in the the ARI specification,
        https://www.ietf.org/archive/id/draft-ietf-acme-ari-03.html#name-renewalinfo-objects).
      - V(start) returns RV(should_renew=true) once the start of the renewal interval has been reached.
    type: str
    choices:
      - standard
      - start
    default: standard
  remaining_days:
    description:
      - The number of days the certificate must have left being valid.
      - For example, if O(remaining_days=20), this check causes RV(should_renew=true) if the
        certificate is valid for less than 20 days.
    type: int
  remaining_percentage:
    description:
      - The percentage of the certificate's validity period that should be left.
      - For example, if O(remaining_percentage=0.1), and the certificate's validity period is 90 days,
        this check causes RV(should_renew=true) if the certificate is valid for less than 9 days.
      - Must be a value between 0 and 1.
    type: float
seealso:
  - module: community.crypto.acme_certificate
    description: Allows to obtain a certificate using the ACME protocol
  - module: community.crypto.acme_ari_info
    description: Obtain renewal information for a certificate
'''

EXAMPLES = '''
- name: Retrieve renewal information for a certificate
  community.crypto.acme_certificate_renewal_info:
    certificate_path: /etc/httpd/ssl/sample.com.crt
  register: cert_data

- name: Should the certificate be renewed?
  ansible.builtin.debug:
    var: cert_data.should_renew
'''

RETURN = '''
should_renew:
  description:
    - Whether the certificate should be renewed.
    - If no certificate is provided, or the certificate is expired, will always be V(true).
  returned: success
  type: bool
  sample: true

msg:
  description:
    - Information on the reason for renewal.
    - Should be shown to the user, as in case of ARI triggered renewal it can contain important
      information, for example on forced revocations for misissued certificates.
  type: str
  returned: success
  sample: The certificate does not exist.

supports_ari:
  description:
    - Whether ARI information was used to determine renewal. This can be used to determine whether to
      specify O(community.crypto.acme_certificate#module:include_renewal_cert_id=when_ari_supported)
      for the M(community.crypto.acme_certificate) module.
    - If O(use_ari=false), this will always be V(false).
  returned: success
  type: bool
  sample: true
'''

import os
import random

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    create_backend,
    get_default_argspec,
    ACMEClient,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import ModuleFailException


def main():
    argument_spec = get_default_argspec(with_account=False)
    argument_spec.update(dict(
        certificate_path=dict(type='path'),
        certificate_content=dict(type='str'),
        use_ari=dict(type='bool', default=True),
        ari_algorithm=dict(type='str', choices=['standard', 'start'], default='standard'),
        remaining_days=dict(type='int'),
        remaining_percentage=dict(type='float'),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=(
            ['certificate_path', 'certificate_content'],
        ),
        supports_check_mode=True,
    )
    backend = create_backend(module, True)

    if not module.params['certificate_path'] and not module.params['certificate_content']:
        module.exit_json(
            changed=False,
            should_renew=True,
            msg='No certificate was specified',
            supports_ari=False,
        )

    if module.params['certificate_path'] is not None and not os.path.exists(module.params['certificate_path']):
        module.exit_json(
            changed=False,
            should_renew=True,
            msg='The certificate file does not exist',
            supports_ari=False,
        )

    try:
        cert_info = backend.get_cert_information(
            cert_filename=module.params['certificate_path'],
            cert_content=module.params['certificate_content'],
        )
        now = backend.get_now()
        no_renewal_msg = 'The certificate is still valid and no condition was reached'
        renewal_ari = False

        if now >= cert_info.not_valid_after:
            module.exit_json(
                changed=False,
                should_renew=True,
                msg='The certificate already expired',
                supports_ari=False,
            )

        client = ACMEClient(module, backend)
        if client.directory.has_renewal_info_endpoint():
            renewal_info = client.get_renewal_info(cert_info=cert_info)
            window_start = backend.parse_acme_timestamp(renewal_info['suggestedWindow']['start'])
            window_end = backend.parse_acme_timestamp(renewal_info['suggestedWindow']['end'])
            msg_append = ''
            if 'explanationURL' in renewal_info:
                msg_append = 'Information on renewal interval: {0}'.format(renewal_info['explanationURL'])
            renewal_ari = True
            if now > window_end:
                module.exit_json(
                    changed=False,
                    should_renew=True,
                    msg='The suggested renewal interval provided by ARI is in the past',
                    supports_ari=True,
                )
            if module.params['ari_algorithm'] == 'start':
                if now > window_start:
                    module.exit_json(
                        changed=False,
                        should_renew=True,
                        msg='The suggested renewal interval provided by ARI has begun',
                        supports_ari=True,
                    )
            else:
                random_time = backend.interpolate_timestamp(window_start, window_end, random.random())
                if now > random_time:
                    module.exit_json(
                        changed=False,
                        should_renew=True,
                        msg='The picked random renewal time {0} in sugested renewal internal provided by ARI is in the past'.format(random_time),
                        supports_ari=True,
                    )

        # TODO check remaining_days
        if module.params['remaining_days'] is not None:
            remaining_days = (cert_info.not_valid_after - now).days
            if remaining_days < module.params['remaining_days']:
                module.exit_json(
                    changed=False,
                    should_renew=True,
                    msg='The certificate expires in {0} days'.format(remaining_days),
                    supports_ari=False,
                )

        # TODO check remaining_percentage
        if module.params['remaining_percentage'] is not None:
            timestamp = backend.interpolate_timestamp(cert_info.not_valid_before, cert_info.not_valid_after, 1 - module.params['remaining_percentage'])
            if timestamp < now:
                module.exit_json(
                    changed=False,
                    should_renew=True,
                    msg="The remaining percentage {0}% of the certificate's lifespan was reached on {1}".format(
                        module.params['remaining_percentage'] * 100,
                        timestamp,
                    ),
                    supports_ari=False,
                )

        module.exit_json(
            changed=False,
            should_renew=False,
            msg=no_renewal_msg,
            supports_ari=renewal_ari,
        )
    except ModuleFailException as e:
        e.do_fail(module)


if __name__ == '__main__':
    main()
