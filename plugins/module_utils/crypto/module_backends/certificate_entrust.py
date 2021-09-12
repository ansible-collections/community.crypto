# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import datetime
import time
import os

from ansible.module_utils.common.text.converters import to_native, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.ecs.api import ECSClient, RestOperationException, SessionConfigurationException

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_certificate,
    get_relative_time_option,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_serial_number_of_cert,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    CertificateError,
    CertificateBackend,
    CertificateProvider,
)

try:
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


class EntrustCertificateBackend(CertificateBackend):
    def __init__(self, module, backend):
        super(EntrustCertificateBackend, self).__init__(module, backend)
        self.trackingId = None
        self.notAfter = get_relative_time_option(module.params['entrust_not_after'], 'entrust_not_after', backend=self.backend)

        if self.csr_content is None and self.csr_path is None:
            raise CertificateError(
                'csr_path or csr_content is required for entrust provider'
            )
        if self.csr_content is None and not os.path.exists(self.csr_path):
            raise CertificateError(
                'The certificate signing request file {0} does not exist'.format(self.csr_path)
            )

        self._ensure_csr_loaded()

        # ECS API defaults to using the validated organization tied to the account.
        # We want to always force behavior of trying to use the organization provided in the CSR.
        # To that end we need to parse out the organization from the CSR.
        self.csr_org = None
        if self.backend == 'cryptography':
            csr_subject_orgs = self.csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            if len(csr_subject_orgs) == 1:
                self.csr_org = csr_subject_orgs[0].value
            elif len(csr_subject_orgs) > 1:
                self.module.fail_json(msg=("Entrust provider does not currently support multiple validated organizations. Multiple organizations found in "
                                           "Subject DN: '{0}'. ".format(self.csr.subject)))
        # If no organization in the CSR, explicitly tell ECS that it should be blank in issued cert, not defaulted to
        # organization tied to the account.
        if self.csr_org is None:
            self.csr_org = ''

        try:
            self.ecs_client = ECSClient(
                entrust_api_user=self.module.params['entrust_api_user'],
                entrust_api_key=self.module.params['entrust_api_key'],
                entrust_api_cert=self.module.params['entrust_api_client_cert_path'],
                entrust_api_cert_key=self.module.params['entrust_api_client_cert_key_path'],
                entrust_api_specification_path=self.module.params['entrust_api_specification_path']
            )
        except SessionConfigurationException as e:
            module.fail_json(msg='Failed to initialize Entrust Provider: {0}'.format(to_native(e.message)))

    def generate_certificate(self):
        """(Re-)Generate certificate."""
        body = {}

        # Read the CSR that was generated for us
        if self.csr_content is not None:
            # csr_content contains bytes
            body['csr'] = to_native(self.csr_content)
        else:
            with open(self.csr_path, 'r') as csr_file:
                body['csr'] = csr_file.read()

        body['certType'] = self.module.params['entrust_cert_type']

        # Handle expiration (30 days if not specified)
        expiry = self.notAfter
        if not expiry:
            gmt_now = datetime.datetime.fromtimestamp(time.mktime(time.gmtime()))
            expiry = gmt_now + datetime.timedelta(days=365)

        expiry_iso3339 = expiry.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        body['certExpiryDate'] = expiry_iso3339
        body['org'] = self.csr_org
        body['tracking'] = {
            'requesterName': self.module.params['entrust_requester_name'],
            'requesterEmail': self.module.params['entrust_requester_email'],
            'requesterPhone': self.module.params['entrust_requester_phone'],
        }

        try:
            result = self.ecs_client.NewCertRequest(Body=body)
            self.trackingId = result.get('trackingId')
        except RestOperationException as e:
            self.module.fail_json(msg='Failed to request new certificate from Entrust Certificate Services (ECS): {0}'.format(to_native(e.message)))

        self.cert_bytes = to_bytes(result.get('endEntityCert'))
        self.cert = load_certificate(path=None, content=self.cert_bytes, backend=self.backend)

    def get_certificate_data(self):
        """Return bytes for self.cert."""
        return self.cert_bytes

    def needs_regeneration(self):
        parent_check = super(EntrustCertificateBackend, self).needs_regeneration()

        try:
            cert_details = self._get_cert_details()
        except RestOperationException as e:
            self.module.fail_json(msg='Failed to get status of existing certificate from Entrust Certificate Services (ECS): {0}.'.format(to_native(e.message)))

        # Always issue a new certificate if the certificate is expired, suspended or revoked
        status = cert_details.get('status', False)
        if status == 'EXPIRED' or status == 'SUSPENDED' or status == 'REVOKED':
            return True

        # If the requested cert type was specified and it is for a different certificate type than the initial certificate, a new one is needed
        if self.module.params['entrust_cert_type'] and cert_details.get('certType') and self.module.params['entrust_cert_type'] != cert_details.get('certType'):
            return True

        return parent_check

    def _get_cert_details(self):
        cert_details = {}
        try:
            self._ensure_existing_certificate_loaded()
        except Exception as dummy:
            return
        if self.existing_certificate:
            serial_number = None
            expiry = None
            if self.backend == 'cryptography':
                serial_number = "{0:X}".format(cryptography_serial_number_of_cert(self.existing_certificate))
                expiry = self.existing_certificate.not_valid_after

            # get some information about the expiry of this certificate
            expiry_iso3339 = expiry.strftime("%Y-%m-%dT%H:%M:%S.00Z")
            cert_details['expiresAfter'] = expiry_iso3339

            # If a trackingId is not already defined (from the result of a generate)
            # use the serial number to identify the tracking Id
            if self.trackingId is None and serial_number is not None:
                cert_results = self.ecs_client.GetCertificates(serialNumber=serial_number).get('certificates', {})

                # Finding 0 or more than 1 result is a very unlikely use case, it simply means we cannot perform additional checks
                # on the 'state' as returned by Entrust Certificate Services (ECS). The general certificate validity is
                # still checked as it is in the rest of the module.
                if len(cert_results) == 1:
                    self.trackingId = cert_results[0].get('trackingId')

        if self.trackingId is not None:
            cert_details.update(self.ecs_client.GetCertificate(trackingId=self.trackingId))

        return cert_details


class EntrustCertificateProvider(CertificateProvider):
    def validate_module_args(self, module):
        pass

    def needs_version_two_certs(self, module):
        return False

    def create_backend(self, module, backend):
        return EntrustCertificateBackend(module, backend)


def add_entrust_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('entrust')
    argument_spec.argument_spec.update(dict(
        entrust_cert_type=dict(type='str', default='STANDARD_SSL',
                               choices=['STANDARD_SSL', 'ADVANTAGE_SSL', 'UC_SSL', 'EV_SSL', 'WILDCARD_SSL',
                                        'PRIVATE_SSL', 'PD_SSL', 'CDS_ENT_LITE', 'CDS_ENT_PRO', 'SMIME_ENT']),
        entrust_requester_email=dict(type='str'),
        entrust_requester_name=dict(type='str'),
        entrust_requester_phone=dict(type='str'),
        entrust_api_user=dict(type='str'),
        entrust_api_key=dict(type='str', no_log=True),
        entrust_api_client_cert_path=dict(type='path'),
        entrust_api_client_cert_key_path=dict(type='path', no_log=True),
        entrust_api_specification_path=dict(type='path', default='https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml'),
        entrust_not_after=dict(type='str', default='+365d'),
    ))
    argument_spec.required_if.append(
        ['provider', 'entrust', ['entrust_requester_email', 'entrust_requester_name', 'entrust_requester_phone',
                                 'entrust_api_user', 'entrust_api_key', 'entrust_api_client_cert_path',
                                 'entrust_api_client_cert_key_path']]
    )
