#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: x509_certificate_revocation_info
short_description: Query revocation information for X.509 certificates
description:
    - This module allows one to query revocation information for X.509 certificates.
requirements:
    - cryptography >= 1.2
author:
  - Felix Fontein (@felixfontein)
options:
    path:
        description:
            - Remote absolute path where the certificate file is loaded from.
            - Exactly one of I(path), I(content) or I(serial_number) must be specified.
        type: path
    content:
        description:
            - Content of the X.509 certificate in PEM format.
            - Exactly one of I(path), I(content) or I(serial_number) must be specified.
        type: str
    serial_number:
        description:
            - The X.509 certificate's serial number.
            - Exactly one of I(path), I(content) or I(serial_number) must be specified.
        type: int
    crl_path:
        description:
            - Path to CRL to check the certificate against.
        type: path
    crl_url:
        description:
            - URL of CRL to check the certificate against.
        type: str
    crl_from_cert:
        description:
            - If set to C(ignore), will ignore CRL Distribution Points specified in the certificate.
            - If set to C(check), will check CRL Distribution Points specified in the certificate
              until a CRL is found which contains the certificate. Will fail if a CRL cannot be
              retrieved.
            - If set to C(check_soft_fail), will check CRL Distribution Points specified in the certificate
              until a CRL is found which contains the certificate. Will only warn if a CRL cannot be
              retrieved.
        type: str
        default: ignore
        choices: [ignore, check, check_soft_fail]

notes:
    - All timestamp values are provided in ASN.1 TIME format, i.e. following the C(YYYYMMDDHHMMSSZ) pattern.
      They are all in UTC.
seealso:
- module: x509_certificate
- module: x509_certificate_info
- module: x509_crl
- module: x509_crl_info
'''

EXAMPLES = r'''
- name: Check revocation
  community.crypto.x509_certificate_revocation_info:
    path: /etc/ssl/crt/ansible.com.crt
  register: result

- name: Dump information
  debug:
    var: result
'''

RETURN = r'''
revoked:
    description: Whether the certificate was determined to be revoked
    returned: success
    type: bool
crl_contained:
    description: Whether the certificate has been found in a CRL.
    returned: I(crl_path) has been specified
    type: bool
crl_record:
    description: Whether the certificate is expired (i.e. C(notAfter) is in the past)
    returned: I(crl_path) has been specified
    type: dict
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
crl_source:
    description: CRL where certificate was found in
    returned: I(crl_path) has been specified and I(crl_contained) is C(true)
    type: str
'''


import os
import traceback

from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native
from ansible.module_utils.urls import fetch_url

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_certificate,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_crl import (
    cryptography_decode_revoked_certificate,
    cryptography_dump_revoked,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_serial_number_of_cert,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.identify import (
    identify_pem_format,
)

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


TIMESTAMP_FORMAT = "%Y%m%d%H%M%SZ"


class CertificateRevocationInfo(OpenSSLObject):
    def __init__(self, module):
        super(CertificateRevocationInfo, self).__init__(
            module.params['path'] or '',
            'present',
            False,
            module.check_mode,
        )
        self.backend = 'cryptography'
        self.module = module

        self.content = module.params['content']
        if self.content is not None:
            self.content = self.content.encode('utf-8')

        self.cert_serial_number = module.params['serial_number']
        self.cert = None

    def load(self):
        if self.content is not None or self.module.params['path'] is not None:
            self.cert = load_certificate(self.path, content=self.content, backend=self.backend)
            self.cert_serial_number = cryptography_serial_number_of_cert(self.cert)
        if self.cert_serial_number is None:
            raise AssertionError('Internal error - no certificate serial number found')

    def generate(self):
        # Empty method because OpenSSLObject wants this
        pass

    def dump(self):
        # Empty method because OpenSSLObject wants this
        pass

    def _get_ocsp_uri(self):
        try:
            ext = self.cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in ext.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        return desc.access_location.value
        except x509.ExtensionNotFound as dummy:
            pass
        return None

    def _check_crl(self, result, crl_blob, crl_source):
        # Decode CRL
        try:
            if identify_pem_format(crl_blob):
                crl = x509.load_pem_x509_crl(crl_blob, default_backend())
            else:
                crl = x509.load_der_x509_crl(crl_blob, default_backend())
        except Exception as e:
            self.module.fail_json(msg='Error while decoding CRL from {1}: {0}'.format(e, crl_source))

        # Check revoced certificates
        if 'crl_contained' not in result:
            result['crl_contained'] = False
            result['crl_record'] = None
        for cert in crl:
            if cert.serial_number == self.cert_serial_number:
                result['crl_contained'] = True
                result['crl_record'] = cryptography_dump_revoked(cryptography_decode_revoked_certificate(cert))
                result['crl_source'] = crl_source
                result['revoked'] = True

    def _report_error(self, soft_fail, msg):
        if soft_fail:
            self.module.fail_json(msg=msg)
        else:
            self.module.warn(msg)

    def _check_crl_url(self, result, crl_url, soft_fail=False):
        resp, info = fetch_url(self.module, crl_url, method='GET')
        if info['status'] != 200:
            self._report_error(soft_fail, 'HTTP error while loading CRL from {0}: {1}'.format(crl_url, info['status']))
        else:
            try:
                crl_blob = resp.read()
            except AttributeError as e:
                self._report_error(soft_fail, 'Error while loading CRL from {0}: {1}'.format(crl_url, to_native(e)))
                crl_blob = None
            if crl_blob is not None:
                self._check_crl(result, crl_blob, crl_url)

    def check_revocation(self):
        result = dict()
        result['revoked'] = False

        if self.module.params['crl_path'] is not None:
            crl_path = self.module.params['crl_path']
            try:
                with open(crl_path, 'rb') as f:
                    crl_blob = f.read()
            except Exception as e:
                self.module.fail_json(msg='Error while reading CRL file from disk: {0}'.format(e))
            self._check_crl(result, crl_blob, crl_source=crl_path)

        if self.module.params['crl_url'] is not None:
            self._check_crl_url(result, self.module.params['crl_url'])

        if self.module.params['crl_from_cert'] != 'ignore':
            soft_fail = (self.module.params['crl_from_cert'] == 'check_soft_fail')
            ext = None
            try:
                ext = self.cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            except x509.ExtensionNotFound:
                pass
            if ext is None:
                self._report_error(soft_fail, 'No CRL Distribution Points extension found in certificate')
            else:
                for distribution_point in ext.value:
                    if distribution_point.relative_name is not None:
                        self._report_error(soft_fail, 'Distribution point with relative name found in certificate')
                    if distribution_point.full_name is not None:
                        had_crl_url = False
                        for name in distribution_point.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                had_crl_url = True
                                self._check_crl_url(result, name.value, soft_fail=soft_fail)
                        if not had_crl_url:
                            self._report_error(soft_fail, 'Distribution point with full name found in certificate which does not contain a URI')
                    if result.get('crl_contained'):
                        continue

        # result['ocsp_uri'] = self._get_ocsp_uri()

        return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
            serial_number=dict(type='int'),
            crl_path=dict(type='path'),
            crl_url=dict(type='str'),
            crl_from_cert=dict(type='str', default='ignore', choices=['ignore', 'check', 'check_soft_fail']),
        ),
        required_if=(
            ['crl_from_cert', 'check', ['path', 'content'], True],
            ['crl_from_cert', 'check_soft_fail', ['path', 'content'], True],
        ),
        required_one_of=(
            ['path', 'content', 'serial_number'],
        ),
        mutually_exclusive=(
            ['path', 'content', 'serial_number'],
        ),
        supports_check_mode=True,
    )

    try:
        if module.params['path'] is not None:
            base_dir = os.path.dirname(module.params['path']) or '.'
            if not os.path.isdir(base_dir):
                module.fail_json(
                    name=base_dir,
                    msg='The directory %s does not exist or the file is not a directory' % base_dir
                )

        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)

        certificate = CertificateRevocationInfo(module)
        certificate.load()
        result = certificate.check_revocation()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
