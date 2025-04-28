# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import abc

from ansible.module_utils import six
from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    der_to_pem,
    nopad_b64,
    process_links,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    split_pem_list,
)


class CertificateChain(object):
    """
    Download and parse the certificate chain.
    https://tools.ietf.org/html/rfc8555#section-7.4.2
    """

    def __init__(self, url):
        self.url = url
        self.cert = None
        self.chain = []
        self.alternates = []

    @classmethod
    def download(cls, client, url):
        content, info = client.get_request(
            url,
            parse_json_result=False,
            headers={"Accept": "application/pem-certificate-chain"},
        )

        if not content or not info["content-type"].startswith(
            "application/pem-certificate-chain"
        ):
            raise ModuleFailException(
                "Cannot download certificate chain from {0}, as content type is not application/pem-certificate-chain: {1} (headers: {2})".format(
                    url, content, info
                )
            )

        result = cls(url)

        # Parse data
        certs = split_pem_list(content.decode("utf-8"), keep_inbetween=True)
        if certs:
            result.cert = certs[0]
            result.chain = certs[1:]

        process_links(
            info, lambda link, relation: result._process_links(client, link, relation)
        )

        if result.cert is None:
            raise ModuleFailException(
                "Failed to parse certificate chain download from {0}: {1} (headers: {2})".format(
                    url, content, info
                )
            )

        return result

    def _process_links(self, client, link, relation):
        if relation == "up":
            # Process link-up headers if there was no chain in reply
            if not self.chain:
                chain_result, chain_info = client.get_request(
                    link, parse_json_result=False
                )
                if chain_info["status"] in [200, 201]:
                    self.chain.append(der_to_pem(chain_result))
        elif relation == "alternate":
            self.alternates.append(link)

    def to_json(self):
        cert = self.cert.encode("utf8")
        chain = ("\n".join(self.chain)).encode("utf8")
        return {
            "cert": cert,
            "chain": chain,
            "full_chain": cert + chain,
        }


class Criterium(object):
    def __init__(self, criterium, index=None):
        self.index = index
        self.test_certificates = criterium["test_certificates"]
        self.subject = criterium["subject"]
        self.issuer = criterium["issuer"]
        self.subject_key_identifier = criterium["subject_key_identifier"]
        self.authority_key_identifier = criterium["authority_key_identifier"]


@six.add_metaclass(abc.ABCMeta)
class ChainMatcher(object):
    @abc.abstractmethod
    def match(self, certificate):
        """
        Check whether a certificate chain (CertificateChain instance) matches.
        """


def retrieve_acme_v1_certificate(client, csr_der):
    """
    Create a new certificate based on the CSR (ACME v1 protocol).
    Return the certificate object as dict
    https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.5
    """
    new_cert = {
        "resource": "new-cert",
        "csr": nopad_b64(csr_der),
    }
    result, info = client.send_signed_request(
        client.directory["new-cert"],
        new_cert,
        error_msg="Failed to receive certificate",
        expected_status_codes=[200, 201],
    )
    cert = CertificateChain(info["location"])
    cert.cert = der_to_pem(result)

    def f(link, relation):
        if relation == "up":
            chain_result, chain_info = client.get_request(link, parse_json_result=False)
            if chain_info["status"] in [200, 201]:
                del cert.chain[:]
                cert.chain.append(der_to_pem(chain_result))

    process_links(info, f)
    return cert
