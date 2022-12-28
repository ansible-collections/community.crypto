#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: x509_crl_info
version_added: '1.0.0'
short_description: Retrieve information on Certificate Revocation Lists (CRLs)
description:
    - This module allows one to retrieve information on Certificate Revocation Lists (CRLs).
requirements:
    - cryptography >= 1.2
author:
    - Felix Fontein (@felixfontein)
extends_documentation_fragment:
    - community.crypto.attributes
    - community.crypto.attributes.info_module
    - community.crypto.name_encoding
options:
    path:
        description:
            - Remote absolute path where the generated CRL file should be created or is already located.
            - Either I(path) or I(content) must be specified, but not both.
        type: path
    content:
        description:
            - Content of the X.509 CRL in PEM format, or Base64-encoded X.509 CRL.
            - Either I(path) or I(content) must be specified, but not both.
        type: str
    list_revoked_certificates:
        description:
            - If set to C(false), the list of revoked certificates is not included in the result.
            - This is useful when retrieving information on large CRL files. Enumerating all revoked
              certificates can take some time, including serializing the result as JSON, sending it to
              the Ansible controller, and decoding it again.
        type: bool
        default: true
        version_added: 1.7.0

notes:
    - All timestamp values are provided in ASN.1 TIME format, in other words, following the C(YYYYMMDDHHMMSSZ) pattern.
      They are all in UTC.
seealso:
    - module: community.crypto.x509_crl
    - ref: community.crypto.x509_crl_info filter <ansible_collections.community.crypto.x509_crl_info_filter>
    # - plugin: community.crypto.x509_crl_info
    #   plugin_type: filter
      description: A filter variant of this module.
'''

EXAMPLES = r'''
- name: Get information on CRL
  community.crypto.x509_crl_info:
    path: /etc/ssl/my-ca.crl
  register: result

- name: Print the information
  ansible.builtin.debug:
    msg: "{{ result }}"

- name: Get information on CRL without list of revoked certificates
  community.crypto.x509_crl_info:
    path: /etc/ssl/very-large.crl
    list_revoked_certificates: false
  register: result
'''

RETURN = r'''
format:
    description:
        - Whether the CRL is in PEM format (C(pem)) or in DER format (C(der)).
    returned: success
    type: str
    sample: pem
issuer:
    description:
        - The CRL's issuer.
        - Note that for repeated values, only the last one will be returned.
        - See I(name_encoding) for how IDNs are handled.
    returned: success
    type: dict
    sample: {"organizationName": "Ansible", "commonName": "ca.example.com"}
issuer_ordered:
    description: The CRL's issuer as an ordered list of tuples.
    returned: success
    type: list
    elements: list
    sample: [["organizationName", "Ansible"], ["commonName": "ca.example.com"]]
last_update:
    description: The point in time from which this CRL can be trusted as ASN.1 TIME.
    returned: success
    type: str
    sample: '20190413202428Z'
next_update:
    description: The point in time from which a new CRL will be issued and the client has to check for it as ASN.1 TIME.
    returned: success
    type: str
    sample: '20190413202428Z'
digest:
    description: The signature algorithm used to sign the CRL.
    returned: success
    type: str
    sample: sha256WithRSAEncryption
revoked_certificates:
    description: List of certificates to be revoked.
    returned: success if I(list_revoked_certificates=true)
    type: list
    elements: dict
    contains:
        serial_number:
            description: Serial number of the certificate.
            type: int
            sample: 1234
        revocation_date:
            description: The point in time the certificate was revoked as ASN.1 TIME.
            type: str
            sample: '20190413202428Z'
        issuer:
            description:
                - The certificate's issuer.
                - See I(name_encoding) for how IDNs are handled.
            type: list
            elements: str
            sample: ["DNS:ca.example.org"]
        issuer_critical:
            description: Whether the certificate issuer extension is critical.
            type: bool
            sample: false
        reason:
            description:
                - The value for the revocation reason extension.
                - One of C(unspecified), C(key_compromise), C(ca_compromise), C(affiliation_changed), C(superseded),
                  C(cessation_of_operation), C(certificate_hold), C(privilege_withdrawn), C(aa_compromise), and
                  C(remove_from_crl).
            type: str
            sample: key_compromise
        reason_critical:
            description: Whether the revocation reason extension is critical.
            type: bool
            sample: false
        invalidity_date:
            description: |
                The point in time it was known/suspected that the private key was compromised
                or that the certificate otherwise became invalid as ASN.1 TIME.
            type: str
            sample: '20190413202428Z'
        invalidity_date_critical:
            description: Whether the invalidity date extension is critical.
            type: bool
            sample: false
'''


import base64
import binascii

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_pem_format,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.crl_info import (
    get_crl_info,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
            list_revoked_certificates=dict(type='bool', default=True),
            name_encoding=dict(type='str', default='ignore', choices=['ignore', 'idna', 'unicode']),
        ),
        required_one_of=(
            ['path', 'content'],
        ),
        mutually_exclusive=(
            ['path', 'content'],
        ),
        supports_check_mode=True,
    )

    if module.params['content'] is None:
        try:
            with open(module.params['path'], 'rb') as f:
                data = f.read()
        except (IOError, OSError) as e:
            module.fail_json(msg='Error while reading CRL file from disk: {0}'.format(e))
    else:
        data = module.params['content'].encode('utf-8')
        if not identify_pem_format(data):
            try:
                data = base64.b64decode(module.params['content'])
            except (binascii.Error, TypeError) as e:
                module.fail_json(msg='Error while Base64 decoding content: {0}'.format(e))

    try:
        result = get_crl_info(module, data, list_revoked_certificates=module.params['list_revoked_certificates'])
        module.exit_json(**result)
    except OpenSSLObjectError as e:
        module.fail_json(msg=to_native(e))


if __name__ == "__main__":
    main()
