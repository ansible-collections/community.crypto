# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import binascii

from ansible.module_utils._text import to_bytes, to_native

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    der_to_pem,
    process_links,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    parse_name_field,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_name_to_oid,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    split_pem_list,
)

try:
    import cryptography
    import cryptography.hazmat.backends
    import cryptography.x509
except ImportError:
    pass


class CertificateChain(object):
    '''
    Download and parse the certificate chain.
    https://tools.ietf.org/html/rfc8555#section-7.4.2
    '''

    def __init__(self, url):
        self.url = url
        self.cert = None
        self.chain = []
        self.alternates = []

    @classmethod
    def download(cls, client, url):
        content, info = client.get_request(url, parse_json_result=False, headers={'Accept': 'application/pem-certificate-chain'})

        if not content or not info['content-type'].startswith('application/pem-certificate-chain'):
            raise ModuleFailException(
                "Cannot download certificate chain from {0}, as content type is not application/pem-certificate-chain: {1} (headers: {2})".format(
                    url, content, info))

        result = cls(url)

        # Parse data
        certs = split_pem_list(content.decode('utf-8'), keep_inbetween=True)
        if certs:
            result.cert = certs[0]
            result.chain = certs[1:]

        process_links(info, lambda link, relation: result._process_links(client, link, relation))

        if result.cert is None:
            raise ModuleFailException("Failed to parse certificate chain download from {0}: {1} (headers: {2})".format(url, content, info))

        return result

    def _process_links(self, client, link, relation):
        if relation == 'up':
            # Process link-up headers if there was no chain in reply
            if not self.chain:
                chain_result, chain_info = client.get_request(link, parse_json_result=False)
                if chain_info['status'] in [200, 201]:
                    self.chain.append(der_to_pem(chain_result))
        elif relation == 'alternate':
            self.alternates.append(link)

    def to_json(self):
        cert = self.cert.encode('utf8')
        chain = ('\n'.join(self.chain)).encode('utf8')
        return {
            'cert': cert,
            'chain': chain,
            'full_chain': cert + chain,
        }


class Criterium(object):
    def __init__(self, criterium, index=None):
        self.index = index
        self.test_certificates = criterium['test_certificates']
        self.subject = criterium['subject']
        self.issuer = criterium['issuer']
        self.subject_key_identifier = criterium['subject_key_identifier']
        self.authority_key_identifier = criterium['authority_key_identifier']


class ChainMatcher(object):
    @staticmethod
    def _parse_key_identifier(key_identifier, name, criterium_idx, client):
        if key_identifier:
            try:
                return binascii.unhexlify(key_identifier.replace(':', ''))
            except Exception:
                if criterium_idx is None:
                    client.module.warn('Criterium has invalid {0} value. Ignoring criterium.'.format(name))
                else:
                    client.module.warn('Criterium {0} in select_chain has invalid {1} value. '
                                       'Ignoring criterium.'.format(criterium_idx, name))
        return None

    def __init__(self, criterium, client):
        self.criterium = criterium
        self.test_certificates = criterium.test_certificates
        self.subject = []
        self.issuer = []
        if criterium.subject:
            self.subject = [
                (cryptography_name_to_oid(k), to_native(v)) for k, v in parse_name_field(criterium.subject)
            ]
        if criterium.issuer:
            self.issuer = [
                (cryptography_name_to_oid(k), to_native(v)) for k, v in parse_name_field(criterium.issuer)
            ]
        self.subject_key_identifier = ChainMatcher._parse_key_identifier(
            criterium.subject_key_identifier, 'subject_key_identifier', criterium.index, client)
        self.authority_key_identifier = ChainMatcher._parse_key_identifier(
            criterium.authority_key_identifier, 'authority_key_identifier', criterium.index, client)

    def _match_subject(self, x509_subject, match_subject):
        for oid, value in match_subject:
            found = False
            for attribute in x509_subject:
                if attribute.oid == oid and value == to_native(attribute.value):
                    found = True
                    break
            if not found:
                return False
        return True

    def match(self, certificate):
        '''
        Check whether an alternate chain matches the specified criterium.
        '''
        chain = certificate.chain
        if self.test_certificates == 'last':
            chain = chain[-1:]
        elif self.test_certificates == 'first':
            chain = chain[:1]
        for cert in chain:
            try:
                x509 = cryptography.x509.load_pem_x509_certificate(to_bytes(cert), cryptography.hazmat.backends.default_backend())
                matches = True
                if not self._match_subject(x509.subject, self.subject):
                    matches = False
                if not self._match_subject(x509.issuer, self.issuer):
                    matches = False
                if self.subject_key_identifier:
                    try:
                        ext = x509.extensions.get_extension_for_class(cryptography.x509.SubjectKeyIdentifier)
                        if self.subject_key_identifier != ext.value.digest:
                            matches = False
                    except cryptography.x509.ExtensionNotFound:
                        matches = False
                if self.authority_key_identifier:
                    try:
                        ext = x509.extensions.get_extension_for_class(cryptography.x509.AuthorityKeyIdentifier)
                        if self.authority_key_identifier != ext.value.key_identifier:
                            matches = False
                    except cryptography.x509.ExtensionNotFound:
                        matches = False
                if matches:
                    return True
            except Exception as e:
                self.module.warn('Error while loading certificate {0}: {1}'.format(cert, e))
        return False
