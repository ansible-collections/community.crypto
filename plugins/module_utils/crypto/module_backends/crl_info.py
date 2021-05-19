# -*- coding: utf-8 -*-
#
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import traceback

from distutils.version import LooseVersion

from ansible.module_utils.basic import missing_required_lib

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


class CRLInfoRetrieval(object):
    def __init__(self, module, content, list_revoked_certificates=True):
        # content must be a bytes string
        self.module = module
        self.content = content
        self.list_revoked_certificates = list_revoked_certificates

    def get_info(self):
        self.crl_pem = identify_pem_format(self.content)
        try:
            if self.crl_pem:
                self.crl = x509.load_pem_x509_crl(self.content, default_backend())
            else:
                self.crl = x509.load_der_x509_crl(self.content, default_backend())
        except ValueError as e:
            self.module.fail_json(msg='Error while decoding CRL: {0}'.format(e))

        result = {
            'changed': False,
            'format': 'pem' if self.crl_pem else 'der',
            'last_update': None,
            'next_update': None,
            'digest': None,
            'issuer_ordered': None,
            'issuer': None,
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
        if self.list_revoked_certificates:
            result['revoked_certificates'] = []
            for cert in self.crl:
                entry = cryptography_decode_revoked_certificate(cert)
                result['revoked_certificates'].append(cryptography_dump_revoked(entry))

        return result


def get_crl_info(module, content, list_revoked_certificates=True):
    if not CRYPTOGRAPHY_FOUND:
        module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                         exception=CRYPTOGRAPHY_IMP_ERR)

    info = CRLInfoRetrieval(module, content, list_revoked_certificates=list_revoked_certificates)
    return info.get_info()
