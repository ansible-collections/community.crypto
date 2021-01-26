#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

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

notes:
    - All timestamp values are provided in ASN.1 TIME format, in other words, following the C(YYYYMMDDHHMMSSZ) pattern.
      They are all in UTC.
    - Supports C(check_mode).
seealso:
    - module: community.crypto.x509_crl
'''

EXAMPLES = r'''
- name: Get information on CRL
  community.crypto.x509_crl_info:
    path: /etc/ssl/my-ca.crl
  register: result

- name: Print the information
  ansible.builtin.debug:
    msg: "{{ result }}"
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
    returned: success
    type: dict
    sample: '{"organizationName": "Ansible", "commonName": "ca.example.com"}'
issuer_ordered:
    description: The CRL's issuer as an ordered list of tuples.
    returned: success
    type: list
    elements: list
    sample: '[["organizationName", "Ansible"], ["commonName": "ca.example.com"]]'
last_update:
    description: The point in time from which this CRL can be trusted as ASN.1 TIME.
    returned: success
    type: str
    sample: 20190413202428Z
next_update:
    description: The point in time from which a new CRL will be issued and the client has to check for it as ASN.1 TIME.
    returned: success
    type: str
    sample: 20190413202428Z
digest:
    description: The signature algorithm used to sign the CRL.
    returned: success
    type: str
    sample: sha256WithRSAEncryption
revoked_certificates:
    description: List of certificates to be revoked.
    returned: success
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
            sample: 20190413202428Z
        issuer:
            description: The certificate's issuer.
            type: list
            elements: str
            sample: '["DNS:ca.example.org"]'
        issuer_critical:
            description: Whether the certificate issuer extension is critical.
            type: bool
            sample: no
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
            sample: no
        invalidity_date:
            description: |
                The point in time it was known/suspected that the private key was compromised
                or that the certificate otherwise became invalid as ASN.1 TIME.
            type: str
            sample: 20190413202428Z
        invalidity_date_critical:
            description: Whether the invalidity date extension is critical.
            type: bool
            sample: no
'''


import base64
import traceback

from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_oid_to_name,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_crl import (
    TIMESTAMP_FORMAT,
    cryptography_decode_revoked_certificate,
    cryptography_dump_revoked,
    cryptography_get_signature_algorithm_oid_from_crl,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_pem_format,
)

# crypto_utils

MINIMAL_CRYPTOGRAPHY_VERSION = '1.2'

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


class CRLError(OpenSSLObjectError):
    pass


class CRLInfo(OpenSSLObject):
    """The main module implementation."""

    def __init__(self, module):
        super(CRLInfo, self).__init__(
            module.params['path'] or '',
            'present',
            False,
            module.check_mode
        )

        self.content = module.params['content']

        self.module = module

        self.crl = None
        if self.content is None:
            try:
                with open(self.path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                self.module.fail_json(msg='Error while reading CRL file from disk: {0}'.format(e))
        else:
            data = self.content.encode('utf-8')
            if not identify_pem_format(data):
                data = base64.b64decode(self.content)

        self.crl_pem = identify_pem_format(data)
        try:
            if self.crl_pem:
                self.crl = x509.load_pem_x509_crl(data, default_backend())
            else:
                self.crl = x509.load_der_x509_crl(data, default_backend())
        except Exception as e:
            self.module.fail_json(msg='Error while decoding CRL: {0}'.format(e))

    def get_info(self):
        result = {
            'changed': False,
            'format': 'pem' if self.crl_pem else 'der',
            'last_update': None,
            'next_update': None,
            'digest': None,
            'issuer_ordered': None,
            'issuer': None,
            'revoked_certificates': [],
        }

        result['last_update'] = self.crl.last_update.strftime(TIMESTAMP_FORMAT)
        result['next_update'] = self.crl.next_update.strftime(TIMESTAMP_FORMAT)
        result['digest'] = cryptography_oid_to_name(cryptography_get_signature_algorithm_oid_from_crl(self.crl))
        issuer = []
        for attribute in self.crl.issuer:
            issuer.append([cryptography_oid_to_name(attribute.oid), attribute.value])
        result['issuer_ordered'] = issuer
        result['issuer'] = {}
        for k, v in issuer:
            result['issuer'][k] = v
        result['revoked_certificates'] = []
        for cert in self.crl:
            entry = cryptography_decode_revoked_certificate(cert)
            result['revoked_certificates'].append(cryptography_dump_revoked(entry))

        return result

    def generate(self):
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self):
        # Empty method because OpenSSLObject wants this
        pass


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
        ),
        required_one_of=(
            ['path', 'content'],
        ),
        mutually_exclusive=(
            ['path', 'content'],
        ),
        supports_check_mode=True,
    )

    if not CRYPTOGRAPHY_FOUND:
        module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                         exception=CRYPTOGRAPHY_IMP_ERR)

    try:
        crl = CRLInfo(module)
        result = crl.get_info()
        module.exit_json(**result)
    except OpenSSLObjectError as e:
        module.fail_json(msg=to_native(e))


if __name__ == "__main__":
    main()
