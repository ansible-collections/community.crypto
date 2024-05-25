#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: acme_certificate_revoke
author: "Felix Fontein (@felixfontein)"
short_description: Revoke certificates with the ACME protocol
description:
  - "Allows to revoke certificates issued by a CA supporting the
     L(ACME protocol,https://tools.ietf.org/html/rfc8555),
     such as L(Let's Encrypt,https://letsencrypt.org/)."
notes:
  - "Exactly one of O(account_key_src), O(account_key_content),
     O(private_key_src), or O(private_key_content) must be specified."
  - "Trying to revoke an already revoked certificate
     should result in an unchanged status, even if the revocation reason
     was different than the one specified here. Also, depending on the
     server, it can happen that some other error is returned if the
     certificate has already been revoked."
seealso:
  - name: The Let's Encrypt documentation
    description: Documentation for the Let's Encrypt Certification Authority.
                 Provides useful information for example on rate limits.
    link: https://letsencrypt.org/docs/
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
extends_documentation_fragment:
  - community.crypto.acme
  - community.crypto.attributes
  - community.crypto.attributes.actiongroup_acme
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
  certificate:
    description:
      - "Path to the certificate to revoke."
    type: path
    required: true
  account_key_src:
    description:
      - "Path to a file containing the ACME account RSA or Elliptic Curve
         key."
      - "RSA keys can be created with C(openssl rsa ...). Elliptic curve keys can
         be created with C(openssl ecparam -genkey ...). Any other tool creating
         private keys in PEM format can be used as well."
      - "Mutually exclusive with O(account_key_content)."
      - "Required if O(account_key_content) is not used."
  account_key_content:
    description:
      - "Content of the ACME account RSA or Elliptic Curve key."
      - "Note that exactly one of O(account_key_src), O(account_key_content),
         O(private_key_src), or O(private_key_content) must be specified."
      - "I(Warning): the content will be written into a temporary file, which will
         be deleted by Ansible when the module completes. Since this is an
         important private key — it can be used to change the account key,
         or to revoke your certificates without knowing their private keys
         —, this might not be acceptable."
      - "In case C(cryptography) is used, the content is not written into a
         temporary file. It can still happen that it is written to disk by
         Ansible in the process of moving the module with its argument to
         the node where it is executed."
  private_key_src:
    description:
      - "Path to the certificate's private key."
      - "Note that exactly one of O(account_key_src), O(account_key_content),
         O(private_key_src), or O(private_key_content) must be specified."
    type: path
  private_key_content:
    description:
      - "Content of the certificate's private key."
      - "Note that exactly one of O(account_key_src), O(account_key_content),
         O(private_key_src), or O(private_key_content) must be specified."
      - "I(Warning): the content will be written into a temporary file, which will
         be deleted by Ansible when the module completes. Since this is an
         important private key — it can be used to change the account key,
         or to revoke your certificates without knowing their private keys
         —, this might not be acceptable."
      - "In case C(cryptography) is used, the content is not written into a
         temporary file. It can still happen that it is written to disk by
         Ansible in the process of moving the module with its argument to
         the node where it is executed."
    type: str
  private_key_passphrase:
    description:
      - Phassphrase to use to decode the certificate's private key.
      - "B(Note:) this is not supported by the C(openssl) backend, only by the C(cryptography) backend."
    type: str
    version_added: 1.6.0
  revoke_reason:
    description:
      - "One of the revocation reasonCodes defined in
         L(Section 5.3.1 of RFC5280,https://tools.ietf.org/html/rfc5280#section-5.3.1)."
      - "Possible values are V(0) (unspecified), V(1) (keyCompromise),
         V(2) (cACompromise), V(3) (affiliationChanged), V(4) (superseded),
         V(5) (cessationOfOperation), V(6) (certificateHold),
         V(8) (removeFromCRL), V(9) (privilegeWithdrawn),
         V(10) (aACompromise)."
    type: int
'''

EXAMPLES = '''
- name: Revoke certificate with account key
  community.crypto.acme_certificate_revoke:
    account_key_src: /etc/pki/cert/private/account.key
    certificate: /etc/httpd/ssl/sample.com.crt

- name: Revoke certificate with certificate's private key
  community.crypto.acme_certificate_revoke:
    private_key_src: /etc/httpd/ssl/sample.com.key
    certificate: /etc/httpd/ssl/sample.com.crt
'''

RETURN = '''#'''

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
    ACMEProtocolException,
    ModuleFailException,
    KeyParsingError,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
    pem_to_der,
)


def main():
    argument_spec = get_default_argspec()
    argument_spec.update(dict(
        private_key_src=dict(type='path'),
        private_key_content=dict(type='str', no_log=True),
        private_key_passphrase=dict(type='str', no_log=True),
        certificate=dict(type='path', required=True),
        revoke_reason=dict(type='int'),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(
            ['account_key_src', 'account_key_content', 'private_key_src', 'private_key_content'],
        ),
        mutually_exclusive=(
            ['account_key_src', 'account_key_content', 'private_key_src', 'private_key_content'],
        ),
        supports_check_mode=False,
    )
    backend = create_backend(module, False)

    try:
        client = ACMEClient(module, backend)
        account = ACMEAccount(client)
        # Load certificate
        certificate = pem_to_der(module.params.get('certificate'))
        certificate = nopad_b64(certificate)
        # Construct payload
        payload = {
            'certificate': certificate
        }
        if module.params.get('revoke_reason') is not None:
            payload['reason'] = module.params.get('revoke_reason')
        # Determine endpoint
        if module.params.get('acme_version') == 1:
            endpoint = client.directory['revoke-cert']
            payload['resource'] = 'revoke-cert'
        else:
            endpoint = client.directory['revokeCert']
        # Get hold of private key (if available) and make sure it comes from disk
        private_key = module.params.get('private_key_src')
        private_key_content = module.params.get('private_key_content')
        # Revoke certificate
        if private_key or private_key_content:
            passphrase = module.params['private_key_passphrase']
            # Step 1: load and parse private key
            try:
                private_key_data = client.parse_key(private_key, private_key_content, passphrase=passphrase)
            except KeyParsingError as e:
                raise ModuleFailException("Error while parsing private key: {msg}".format(msg=e.msg))
            # Step 2: sign revokation request with private key
            jws_header = {
                "alg": private_key_data['alg'],
                "jwk": private_key_data['jwk'],
            }
            result, info = client.send_signed_request(
                endpoint, payload, key_data=private_key_data, jws_header=jws_header, fail_on_error=False)
        else:
            # Step 1: get hold of account URI
            created, account_data = account.setup_account(allow_creation=False)
            if created:
                raise AssertionError('Unwanted account creation')
            if account_data is None:
                raise ModuleFailException(msg='Account does not exist or is deactivated.')
            # Step 2: sign revokation request with account key
            result, info = client.send_signed_request(endpoint, payload, fail_on_error=False)
        if info['status'] != 200:
            already_revoked = False
            # Standardized error from draft 14 on (https://tools.ietf.org/html/rfc8555#section-7.6)
            if result.get('type') == 'urn:ietf:params:acme:error:alreadyRevoked':
                already_revoked = True
            else:
                # Hack for Boulder errors
                if module.params.get('acme_version') == 1:
                    error_type = 'urn:acme:error:malformed'
                else:
                    error_type = 'urn:ietf:params:acme:error:malformed'
                if result.get('type') == error_type and result.get('detail') == 'Certificate already revoked':
                    # Fallback: boulder returns this in case the certificate was already revoked.
                    already_revoked = True
            # If we know the certificate was already revoked, we do not fail,
            # but successfully terminate while indicating no change
            if already_revoked:
                module.exit_json(changed=False)
            raise ACMEProtocolException(module, 'Failed to revoke certificate', info=info, content_json=result)
        module.exit_json(changed=True)
    except ModuleFailException as e:
        e.do_fail(module)


if __name__ == '__main__':
    main()
