#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: acme_certificate
author: "Michael Gruener (@mgruener)"
short_description: Create SSL/TLS certificates with the ACME protocol
description:
   - "Create and renew SSL/TLS certificates with a CA supporting the
      L(ACME protocol,https://tools.ietf.org/html/rfc8555),
      such as L(Let's Encrypt,https://letsencrypt.org/) or
      L(Buypass,https://www.buypass.com/). The current implementation
      supports the C(http-01), C(dns-01) and C(tls-alpn-01) challenges."
   - "To use this module, it has to be executed twice. Either as two
      different tasks in the same run or during two runs. Note that the output
      of the first run needs to be recorded and passed to the second run as the
      module argument C(data)."
   - "Between these two tasks you have to fulfill the required steps for the
      chosen challenge by whatever means necessary. For C(http-01) that means
      creating the necessary challenge file on the destination webserver. For
      C(dns-01) the necessary dns record has to be created. For C(tls-alpn-01)
      the necessary certificate has to be created and served.
      It is I(not) the responsibility of this module to perform these steps."
   - "For details on how to fulfill these challenges, you might have to read through
      L(the main ACME specification,https://tools.ietf.org/html/rfc8555#section-8)
      and the L(TLS-ALPN-01 specification,https://www.rfc-editor.org/rfc/rfc8737.html#section-3).
      Also, consider the examples provided for this module."
   - "The module includes experimental support for IP identifiers according to
      the L(RFC 8738,https://www.rfc-editor.org/rfc/rfc8738.html)."
notes:
   - "At least one of C(dest) and C(fullchain_dest) must be specified."
   - "This module includes basic account management functionality.
      If you want to have more control over your ACME account, use the
      M(community.crypto.acme_account) module and disable account management
      for this module using the C(modify_account) option."
   - "This module was called C(letsencrypt) before Ansible 2.6. The usage
      did not change."
seealso:
  - name: The Let's Encrypt documentation
    description: Documentation for the Let's Encrypt Certification Authority.
                 Provides useful information for example on rate limits.
    link: https://letsencrypt.org/docs/
  - name: Buypass Go SSL
    description: Documentation for the Buypass Certification Authority.
                 Provides useful information for example on rate limits.
    link: https://www.buypass.com/ssl/products/acme
  - name: Automatic Certificate Management Environment (ACME)
    description: The specification of the ACME protocol (RFC 8555).
    link: https://tools.ietf.org/html/rfc8555
  - name: ACME TLS ALPN Challenge Extension
    description: The specification of the C(tls-alpn-01) challenge (RFC 8737).
    link: https://www.rfc-editor.org/rfc/rfc8737.html-05
  - module: community.crypto.acme_challenge_cert_helper
    description: Helps preparing C(tls-alpn-01) challenges.
  - module: community.crypto.openssl_privatekey
    description: Can be used to create private keys (both for certificates and accounts).
  - module: community.crypto.openssl_privatekey_pipe
    description: Can be used to create private keys without writing it to disk (both for certificates and accounts).
  - module: community.crypto.openssl_csr
    description: Can be used to create a Certificate Signing Request (CSR).
  - module: community.crypto.openssl_csr_pipe
    description: Can be used to create a Certificate Signing Request (CSR) without writing it to disk.
  - module: community.crypto.certificate_complete_chain
    description: Allows to find the root certificate for the returned fullchain.
  - module: community.crypto.acme_certificate_revoke
    description: Allows to revoke certificates.
  - module: community.crypto.acme_account
    description: Allows to create, modify or delete an ACME account.
  - module: community.crypto.acme_inspect
    description: Allows to debug problems.
extends_documentation_fragment:
- community.crypto.acme

options:
  account_email:
    description:
      - "The email address associated with this account."
      - "It will be used for certificate expiration warnings."
      - "Note that when C(modify_account) is not set to C(no) and you also
         used the M(community.crypto.acme_account) module to specify more than one contact
         for your account, this module will update your account and restrict
         it to the (at most one) contact email address specified here."
    type: str
  agreement:
    description:
      - "URI to a terms of service document you agree to when using the
         ACME v1 service at C(acme_directory)."
      - Default is latest gathered from C(acme_directory) URL.
      - This option will only be used when C(acme_version) is 1.
    type: str
  terms_agreed:
    description:
      - "Boolean indicating whether you agree to the terms of service document."
      - "ACME servers can require this to be true."
      - This option will only be used when C(acme_version) is not 1.
    type: bool
    default: no
  modify_account:
    description:
      - "Boolean indicating whether the module should create the account if
         necessary, and update its contact data."
      - "Set to C(no) if you want to use the M(community.crypto.acme_account) module to manage
         your account instead, and to avoid accidental creation of a new account
         using an old key if you changed the account key with M(community.crypto.acme_account)."
      - "If set to C(no), C(terms_agreed) and C(account_email) are ignored."
    type: bool
    default: yes
  challenge:
    description: The challenge to be performed.
    type: str
    default: 'http-01'
    choices: [ 'http-01', 'dns-01', 'tls-alpn-01' ]
  csr:
    description:
      - "File containing the CSR for the new certificate."
      - "Can be created with M(community.crypto.openssl_csr) or C(openssl req ...)."
      - "The CSR may contain multiple Subject Alternate Names, but each one
         will lead to an individual challenge that must be fulfilled for the
         CSR to be signed."
      - "I(Note): the private key used to create the CSR I(must not) be the
         account key. This is a bad idea from a security point of view, and
         the CA should not accept the CSR. The ACME server should return an
         error in this case."
      - Precisely one of I(csr) or I(csr_content) must be specified.
    type: path
    aliases: ['src']
  csr_content:
    description:
      - "Content of the CSR for the new certificate."
      - "Can be created with M(community.crypto.openssl_csr_pipe) or C(openssl req ...)."
      - "The CSR may contain multiple Subject Alternate Names, but each one
         will lead to an individual challenge that must be fulfilled for the
         CSR to be signed."
      - "I(Note): the private key used to create the CSR I(must not) be the
         account key. This is a bad idea from a security point of view, and
         the CA should not accept the CSR. The ACME server should return an
         error in this case."
      - Precisely one of I(csr) or I(csr_content) must be specified.
    type: str
    version_added: 1.2.0
  data:
    description:
      - "The data to validate ongoing challenges. This must be specified for
         the second run of the module only."
      - "The value that must be used here will be provided by a previous use
         of this module. See the examples for more details."
      - "Note that for ACME v2, only the C(order_uri) entry of C(data) will
         be used. For ACME v1, C(data) must be non-empty to indicate the
         second stage is active; all needed data will be taken from the
         CSR."
      - "I(Note): the C(data) option was marked as C(no_log) up to
         Ansible 2.5. From Ansible 2.6 on, it is no longer marked this way
         as it causes error messages to be come unusable, and C(data) does
         not contain any information which can be used without having
         access to the account key or which are not public anyway."
    type: dict
  dest:
    description:
      - "The destination file for the certificate."
      - "Required if C(fullchain_dest) is not specified."
    type: path
    aliases: ['cert']
  fullchain_dest:
    description:
      - "The destination file for the full chain (i.e. certificate followed
         by chain of intermediate certificates)."
      - "Required if C(dest) is not specified."
    type: path
    aliases: ['fullchain']
  chain_dest:
    description:
      - If specified, the intermediate certificate will be written to this file.
    type: path
    aliases: ['chain']
  remaining_days:
    description:
      - "The number of days the certificate must have left being valid.
         If C(cert_days < remaining_days), then it will be renewed.
         If the certificate is not renewed, module return values will not
         include C(challenge_data)."
      - "To make sure that the certificate is renewed in any case, you can
         use the C(force) option."
    type: int
    default: 10
  deactivate_authzs:
    description:
      - "Deactivate authentication objects (authz) after issuing a certificate,
         or when issuing the certificate failed."
      - "Authentication objects are bound to an account key and remain valid
         for a certain amount of time, and can be used to issue certificates
         without having to re-authenticate the domain. This can be a security
         concern."
    type: bool
    default: no
  force:
    description:
      - Enforces the execution of the challenge and validation, even if an
        existing certificate is still valid for more than C(remaining_days).
      - This is especially helpful when having an updated CSR e.g. with
        additional domains for which a new certificate is desired.
    type: bool
    default: no
  retrieve_all_alternates:
    description:
      - "When set to C(yes), will retrieve all alternate trust chains offered by the ACME CA.
         These will not be written to disk, but will be returned together with the main
         chain as C(all_chains). See the documentation for the C(all_chains) return
         value for details."
    type: bool
    default: no
  select_chain:
    description:
      - "Allows to specify criteria by which an (alternate) trust chain can be selected."
      - "The list of criteria will be processed one by one until a chain is found
         matching a criterium. If such a chain is found, it will be used by the
         module instead of the default chain."
      - "If a criterium matches multiple chains, the first one matching will be
         returned. The order is determined by the ordering of the C(Link) headers
         returned by the ACME server and might not be deterministic."
      - "Every criterium can consist of multiple different conditions, like I(issuer)
         and I(subject). For the criterium to match a chain, all conditions must apply
         to the same certificate in the chain."
      - "This option can only be used with the C(cryptography) backend."
    type: list
    elements: dict
    version_added: '1.0.0'
    suboptions:
      test_certificates:
        description:
          - "Determines which certificates in the chain will be tested."
          - "I(all) tests all certificates in the chain (excluding the leaf, which is
             identical in all chains)."
          - "I(first) only tests the first certificate in the chain, i.e. the one which
             signed the leaf."
          - "I(last) only tests the last certificate in the chain, i.e. the one furthest
             away from the leaf. Its issuer is the root certificate of this chain."
        type: str
        default: all
        choices: [first, last, all]
      issuer:
        description:
          - "Allows to specify parts of the issuer of a certificate in the chain must
             have to be selected."
          - "If I(issuer) is empty, any certificate will match."
          - 'An example value would be C({"commonName": "My Preferred CA Root"}).'
        type: dict
      subject:
        description:
          - "Allows to specify parts of the subject of a certificate in the chain must
             have to be selected."
          - "If I(subject) is empty, any certificate will match."
          - 'An example value would be C({"CN": "My Preferred CA Intermediate"})'
        type: dict
      subject_key_identifier:
        description:
          - "Checks for the SubjectKeyIdentifier extension. This is an identifier based
             on the private key of the intermediate certificate."
          - "The identifier must be of the form
             C(A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1)."
        type: str
      authority_key_identifier:
        description:
          - "Checks for the AuthorityKeyIdentifier extension. This is an identifier based
             on the private key of the issuer of the intermediate certificate."
          - "The identifier must be of the form
             C(C4:A7:B1:A4:7B:2C:71:FA:DB:E1:4B:90:75:FF:C4:15:60:85:89:10)."
        type: str
'''

EXAMPLES = r'''
### Example with HTTP challenge ###

- name: Create a challenge for sample.com using a account key from a variable.
  community.crypto.acme_certificate:
    account_key_content: "{{ account_private_key }}"
    csr: /etc/pki/cert/csr/sample.com.csr
    dest: /etc/httpd/ssl/sample.com.crt
  register: sample_com_challenge

# Alternative first step:
- name: Create a challenge for sample.com using a account key from hashi vault.
  community.crypto.acme_certificate:
    account_key_content: "{{ lookup('hashi_vault', 'secret=secret/account_private_key:value') }}"
    csr: /etc/pki/cert/csr/sample.com.csr
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
  register: sample_com_challenge

# Alternative first step:
- name: Create a challenge for sample.com using a account key file.
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    csr_content: "{{ lookup('file', '/etc/pki/cert/csr/sample.com.csr') }}"
    dest: /etc/httpd/ssl/sample.com.crt
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
  register: sample_com_challenge

# perform the necessary steps to fulfill the challenge
# for example:
#
# - copy:
#     dest: /var/www/html/{{ sample_com_challenge['challenge_data']['sample.com']['http-01']['resource'] }}
#     content: "{{ sample_com_challenge['challenge_data']['sample.com']['http-01']['resource_value'] }}"
#     when: sample_com_challenge is changed and 'sample.com' in sample_com_challenge['challenge_data']
#
# Alternative way:
#
# - copy:
#     dest: /var/www/{{ item.key }}/{{ item.value['http-01']['resource'] }}
#     content: "{{ item.value['http-01']['resource_value'] }}"
#   loop: "{{ sample_com_challenge.challenge_data | dict2items }}"
#   when: sample_com_challenge is changed

- name: Let the challenge be validated and retrieve the cert and intermediate certificate
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    csr: /etc/pki/cert/csr/sample.com.csr
    dest: /etc/httpd/ssl/sample.com.crt
    fullchain_dest: /etc/httpd/ssl/sample.com-fullchain.crt
    chain_dest: /etc/httpd/ssl/sample.com-intermediate.crt
    data: "{{ sample_com_challenge }}"

### Example with DNS challenge against production ACME server ###

- name: Create a challenge for sample.com using a account key file.
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    account_email: myself@sample.com
    src: /etc/pki/cert/csr/sample.com.csr
    cert: /etc/httpd/ssl/sample.com.crt
    challenge: dns-01
    acme_directory: https://acme-v01.api.letsencrypt.org/directory
    # Renew if the certificate is at least 30 days old
    remaining_days: 60
  register: sample_com_challenge

# perform the necessary steps to fulfill the challenge
# for example:
#
# - community.aws.route53:
#     zone: sample.com
#     record: "{{ sample_com_challenge.challenge_data['sample.com']['dns-01'].record }}"
#     type: TXT
#     ttl: 60
#     state: present
#     wait: yes
#     # Note: route53 requires TXT entries to be enclosed in quotes
#     value: "{{ sample_com_challenge.challenge_data['sample.com']['dns-01'].resource_value | regex_replace('^(.*)$', '\"\\1\"') }}"
#   when: sample_com_challenge is changed and 'sample.com' in sample_com_challenge.challenge_data
#
# Alternative way:
#
# - community.aws.route53:
#     zone: sample.com
#     record: "{{ item.key }}"
#     type: TXT
#     ttl: 60
#     state: present
#     wait: yes
#     # Note: item.value is a list of TXT entries, and route53
#     # requires every entry to be enclosed in quotes
#     value: "{{ item.value | map('regex_replace', '^(.*)$', '\"\\1\"' ) | list }}"
#   loop: "{{ sample_com_challenge.challenge_data_dns | dict2items }}"
#   when: sample_com_challenge is changed

- name: Let the challenge be validated and retrieve the cert and intermediate certificate
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    account_email: myself@sample.com
    src: /etc/pki/cert/csr/sample.com.csr
    cert: /etc/httpd/ssl/sample.com.crt
    fullchain: /etc/httpd/ssl/sample.com-fullchain.crt
    chain: /etc/httpd/ssl/sample.com-intermediate.crt
    challenge: dns-01
    acme_directory: https://acme-v01.api.letsencrypt.org/directory
    remaining_days: 60
    data: "{{ sample_com_challenge }}"
  when: sample_com_challenge is changed

# Alternative second step:
- name: Let the challenge be validated and retrieve the cert and intermediate certificate
  community.crypto.acme_certificate:
    account_key_src: /etc/pki/cert/private/account.key
    account_email: myself@sample.com
    src: /etc/pki/cert/csr/sample.com.csr
    cert: /etc/httpd/ssl/sample.com.crt
    fullchain: /etc/httpd/ssl/sample.com-fullchain.crt
    chain: /etc/httpd/ssl/sample.com-intermediate.crt
    challenge: tls-alpn-01
    remaining_days: 60
    data: "{{ sample_com_challenge }}"
    # We use Let's Encrypt's ACME v2 endpoint
    acme_directory: https://acme-v02.api.letsencrypt.org/directory
    acme_version: 2
    # The following makes sure that if a chain with /CN=DST Root CA X3 in its issuer is provided
    # as an alternative, it will be selected. These are the roots cross-signed by IdenTrust.
    # As long as Let's Encrypt provides alternate chains with the cross-signed root(s) when
    # switching to their own ISRG Root X1 root, this will use the chain ending with a cross-signed
    # root. This chain is more compatible with older TLS clients.
    select_chain:
      - test_certificates: last
        issuer:
          CN: DST Root CA X3
          O: Digital Signature Trust Co.
  when: sample_com_challenge is changed
'''

RETURN = '''
cert_days:
  description: The number of days the certificate remains valid.
  returned: success
  type: int
challenge_data:
  description:
    - Per identifier / challenge type challenge data.
    - Since Ansible 2.8.5, only challenges which are not yet valid are returned.
  returned: changed
  type: list
  elements: dict
  contains:
    resource:
      description: The challenge resource that must be created for validation.
      returned: changed
      type: str
      sample: .well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA
    resource_original:
      description:
        - The original challenge resource including type identifier for C(tls-alpn-01)
          challenges.
      returned: changed and challenge is C(tls-alpn-01)
      type: str
      sample: DNS:example.com
    resource_value:
      description:
        - The value the resource has to produce for the validation.
        - For C(http-01) and C(dns-01) challenges, the value can be used as-is.
        - "For C(tls-alpn-01) challenges, note that this return value contains a
           Base64 encoded version of the correct binary blob which has to be put
           into the acmeValidation x509 extension; see
           U(https://www.rfc-editor.org/rfc/rfc8737.html#section-3)
           for details. To do this, you might need the C(b64decode) Jinja filter
           to extract the binary blob from this return value."
      returned: changed
      type: str
      sample: IlirfxKKXA...17Dt3juxGJ-PCt92wr-oA
    record:
      description: The full DNS record's name for the challenge.
      returned: changed and challenge is C(dns-01)
      type: str
      sample: _acme-challenge.example.com
challenge_data_dns:
  description:
    - List of TXT values per DNS record, in case challenge is C(dns-01).
    - Since Ansible 2.8.5, only challenges which are not yet valid are returned.
  returned: changed
  type: dict
authorizations:
  description:
    - ACME authorization data.
    - Maps an identifier to ACME authorization objects. See U(https://tools.ietf.org/html/rfc8555#section-7.1.4).
  returned: changed
  type: dict
  sample: '{"example.com":{...}}'
order_uri:
  description: ACME order URI.
  returned: changed
  type: str
finalization_uri:
  description: ACME finalization URI.
  returned: changed
  type: str
account_uri:
  description: ACME account URI.
  returned: changed
  type: str
all_chains:
  description:
    - When I(retrieve_all_alternates) is set to C(yes), the module will query the ACME server
      for alternate chains. This return value will contain a list of all chains returned,
      the first entry being the main chain returned by the server.
    - See L(Section 7.4.2 of RFC8555,https://tools.ietf.org/html/rfc8555#section-7.4.2) for details.
  returned: when certificate was retrieved and I(retrieve_all_alternates) is set to C(yes)
  type: list
  elements: dict
  contains:
    cert:
      description:
        - The leaf certificate itself, in PEM format.
      type: str
      returned: always
    chain:
      description:
        - The certificate chain, excluding the root, as concatenated PEM certificates.
      type: str
      returned: always
    full_chain:
      description:
        - The certificate chain, excluding the root, but including the leaf certificate,
          as concatenated PEM certificates.
      type: str
      returned: always
'''

import os

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    create_backend,
    get_default_argspec,
    ACMEClient,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.account import (
    ACMEAccount,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.challenges import (
    combine_identifier,
    split_identifier,
    Authorization,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.certificates import (
    retrieve_acme_v1_certificate,
    CertificateChain,
    Criterium,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.io import (
    write_file,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.orders import (
    Order,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    pem_to_der,
)


class ACMECertificateClient(object):
    '''
    ACME client class. Uses an ACME account object and a CSR to
    start and validate ACME challenges and download the respective
    certificates.
    '''

    def __init__(self, module, backend):
        self.module = module
        self.version = module.params['acme_version']
        self.challenge = module.params['challenge']
        self.csr = module.params['csr']
        self.csr_content = module.params['csr_content']
        self.dest = module.params.get('dest')
        self.fullchain_dest = module.params.get('fullchain_dest')
        self.chain_dest = module.params.get('chain_dest')
        self.client = ACMEClient(module, backend)
        self.account = ACMEAccount(self.client)
        self.directory = self.client.directory
        self.data = module.params['data']
        self.authorizations = None
        self.cert_days = -1
        self.order = None
        self.order_uri = self.data.get('order_uri') if self.data else None
        self.all_chains = None
        self.select_chain_matcher = []

        if self.module.params['select_chain']:
            for criterium_idx, criterium in enumerate(self.module.params['select_chain']):
                self.select_chain_matcher.append(
                    self.client.backend.create_chain_matcher(
                        Criterium(criterium, index=criterium_idx)))

        # Make sure account exists
        modify_account = module.params['modify_account']
        if modify_account or self.version > 1:
            contact = []
            if module.params['account_email']:
                contact.append('mailto:' + module.params['account_email'])
            created, account_data = self.account.setup_account(
                contact,
                agreement=module.params.get('agreement'),
                terms_agreed=module.params.get('terms_agreed'),
                allow_creation=modify_account,
            )
            if account_data is None:
                raise ModuleFailException(msg='Account does not exist or is deactivated.')
            updated = False
            if not created and account_data and modify_account:
                updated, account_data = self.account.update_account(account_data, contact)
            self.changed = created or updated
        else:
            # This happens if modify_account is False and the ACME v1
            # protocol is used. In this case, we do not call setup_account()
            # to avoid accidental creation of an account. This is OK
            # since for ACME v1, the account URI is not needed to send a
            # signed ACME request.
            pass

        if self.csr is not None and not os.path.exists(self.csr):
            raise ModuleFailException("CSR %s not found" % (self.csr))

        # Extract list of identifiers from CSR
        self.identifiers = self.client.backend.get_csr_identifiers(csr_filename=self.csr, csr_content=self.csr_content)

    def is_first_step(self):
        '''
        Return True if this is the first execution of this module, i.e. if a
        sufficient data object from a first run has not been provided.
        '''
        if self.data is None:
            return True
        if self.version == 1:
            # As soon as self.data is a non-empty object, we are in the second stage.
            return not self.data
        else:
            # We are in the second stage if data.order_uri is given (which has been
            # stored in self.order_uri by the constructor).
            return self.order_uri is None

    def start_challenges(self):
        '''
        Create new authorizations for all identifiers of the CSR,
        respectively start a new order for ACME v2.
        '''
        self.authorizations = {}
        if self.version == 1:
            for identifier_type, identifier in self.identifiers:
                if identifier_type != 'dns':
                    raise ModuleFailException('ACME v1 only supports DNS identifiers!')
            for identifier_type, identifier in self.identifiers:
                authz = Authorization.create(self.client, identifier_type, identifier)
                self.authorizations[authz.combined_identifier] = authz
        else:
            self.order = Order.create(self.client, self.identifiers)
            self.order_uri = self.order.url
            self.order.load_authorizations(self.client)
            self.authorizations.update(self.order.authorizations)
        self.changed = True

    def get_challenges_data(self, first_step):
        '''
        Get challenge details for the chosen challenge type.
        Return a tuple of generic challenge details, and specialized DNS challenge details.
        '''
        # Get general challenge data
        data = {}
        for type_identifier, authz in self.authorizations.items():
            identifier_type, identifier = split_identifier(type_identifier)
            # Skip valid authentications: their challenges are already valid
            # and do not need to be returned
            if authz.status == 'valid':
                continue
            # We drop the type from the key to preserve backwards compatibility
            data[identifier] = authz.get_challenge_data(self.client)
            if first_step and self.challenge not in data[identifier]:
                raise ModuleFailException("Found no challenge of type '{0}' for identifier {1}!".format(
                    self.challenge, type_identifier))
        # Get DNS challenge data
        data_dns = {}
        if self.challenge == 'dns-01':
            for identifier, challenges in data.items():
                if self.challenge in challenges:
                    values = data_dns.get(challenges[self.challenge]['record'])
                    if values is None:
                        values = []
                        data_dns[challenges[self.challenge]['record']] = values
                    values.append(challenges[self.challenge]['resource_value'])
        return data, data_dns

    def finish_challenges(self):
        '''
        Verify challenges for all identifiers of the CSR.
        '''
        self.authorizations = {}

        # Step 1: obtain challenge information
        if self.version == 1:
            # For ACME v1, we attempt to create new authzs. Existing ones
            # will be returned instead.
            for identifier_type, identifier in self.identifiers:
                authz = Authorization.create(self.client, identifier_type, identifier)
                self.authorizations[combine_identifier(identifier_type, identifier)] = authz
        else:
            # For ACME v2, we obtain the order object by fetching the
            # order URI, and extract the information from there.
            self.order = Order.from_url(self.client, self.order_uri)
            self.order.load_authorizations(self.client)
            self.authorizations.update(self.order.authorizations)

        # Step 2: validate pending challenges
        for type_identifier, authz in self.authorizations.items():
            if authz.status == 'pending':
                identifier_type, identifier = split_identifier(type_identifier)
                authz.call_validate(self.client, self.challenge)
                self.changed = True

    def download_alternate_chains(self, cert):
        alternate_chains = []
        for alternate in cert.alternates:
            try:
                alt_cert = CertificateChain.download(self.client, alternate)
            except ModuleFailException as e:
                self.module.warn('Error while downloading alternative certificate {0}: {1}'.format(alternate, e))
                continue
            alternate_chains.append(alt_cert)
        return alternate_chains

    def find_matching_chain(self, chains):
        for criterium_idx, matcher in enumerate(self.select_chain_matcher):
            for chain in chains:
                if matcher.match(chain):
                    self.module.debug('Found matching chain for criterium {0}'.format(criterium_idx))
                    return chain
        return None

    def get_certificate(self):
        '''
        Request a new certificate and write it to the destination file.
        First verifies whether all authorizations are valid; if not, aborts
        with an error.
        '''
        for identifier_type, identifier in self.identifiers:
            authz = self.authorizations.get(combine_identifier(identifier_type, identifier))
            if authz is None:
                raise ModuleFailException('Found no authorization information for "{identifier}"!'.format(
                    identifier=combine_identifier(identifier_type, identifier)))
            if authz.status != 'valid':
                authz.raise_error('Status is "{status}" and not "valid"'.format(status=authz.status), module=self.module)

        if self.version == 1:
            cert = retrieve_acme_v1_certificate(self.client, pem_to_der(self.csr, self.csr_content))
        else:
            self.order.finalize(self.client, pem_to_der(self.csr, self.csr_content))
            cert = CertificateChain.download(self.client, self.order.certificate_uri)
            if self.module.params['retrieve_all_alternates'] or self.select_chain_matcher:
                # Retrieve alternate chains
                alternate_chains = self.download_alternate_chains(cert)

                # Prepare return value for all alternate chains
                if self.module.params['retrieve_all_alternates']:
                    self.all_chains = [cert.to_json()]
                    for alt_chain in alternate_chains:
                        self.all_chains.append(alt_chain.to_json())

                # Try to select alternate chain depending on criteria
                if self.select_chain_matcher:
                    matching_chain = self.find_matching_chain([cert] + alternate_chains)
                    if matching_chain:
                        cert = matching_chain
                    else:
                        self.module.debug('Found no matching alternative chain')

        if cert.cert is not None:
            pem_cert = cert.cert
            chain = cert.chain

            if self.dest and write_file(self.module, self.dest, pem_cert.encode('utf8')):
                self.cert_days = self.client.backend.get_cert_days(self.dest)
                self.changed = True

            if self.fullchain_dest and write_file(self.module, self.fullchain_dest, (pem_cert + "\n".join(chain)).encode('utf8')):
                self.cert_days = self.client.backend.get_cert_days(self.fullchain_dest)
                self.changed = True

            if self.chain_dest and write_file(self.module, self.chain_dest, ("\n".join(chain)).encode('utf8')):
                self.changed = True

    def deactivate_authzs(self):
        '''
        Deactivates all valid authz's. Does not raise exceptions.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        '''
        for authz in self.authorizations.values():
            try:
                authz.deactivate(self.client)
            except Exception:
                # ignore errors
                pass
            if authz.status != 'deactivated':
                self.module.warn(warning='Could not deactivate authz object {0}.'.format(authz.url))


def main():
    argument_spec = get_default_argspec()
    argument_spec.update(dict(
        modify_account=dict(type='bool', default=True),
        account_email=dict(type='str'),
        agreement=dict(type='str'),
        terms_agreed=dict(type='bool', default=False),
        challenge=dict(type='str', default='http-01', choices=['http-01', 'dns-01', 'tls-alpn-01']),
        csr=dict(type='path', aliases=['src']),
        csr_content=dict(type='str'),
        data=dict(type='dict'),
        dest=dict(type='path', aliases=['cert']),
        fullchain_dest=dict(type='path', aliases=['fullchain']),
        chain_dest=dict(type='path', aliases=['chain']),
        remaining_days=dict(type='int', default=10),
        deactivate_authzs=dict(type='bool', default=False),
        force=dict(type='bool', default=False),
        retrieve_all_alternates=dict(type='bool', default=False),
        select_chain=dict(type='list', elements='dict', options=dict(
            test_certificates=dict(type='str', default='all', choices=['first', 'last', 'all']),
            issuer=dict(type='dict'),
            subject=dict(type='dict'),
            subject_key_identifier=dict(type='str'),
            authority_key_identifier=dict(type='str'),
        )),
    ))
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_one_of=(
            ['account_key_src', 'account_key_content'],
            ['dest', 'fullchain_dest'],
            ['csr', 'csr_content'],
        ),
        mutually_exclusive=(
            ['account_key_src', 'account_key_content'],
            ['csr', 'csr_content'],
        ),
        supports_check_mode=True,
    )
    backend = create_backend(module, False)

    try:
        if module.params.get('dest'):
            cert_days = backend.get_cert_days(module.params['dest'])
        else:
            cert_days = backend.get_cert_days(module.params['fullchain_dest'])

        if module.params['force'] or cert_days < module.params['remaining_days']:
            # If checkmode is active, base the changed state solely on the status
            # of the certificate file as all other actions (accessing an account, checking
            # the authorization status...) would lead to potential changes of the current
            # state
            if module.check_mode:
                module.exit_json(changed=True, authorizations={}, challenge_data={}, cert_days=cert_days)
            else:
                client = ACMECertificateClient(module, backend)
                client.cert_days = cert_days
                other = dict()
                is_first_step = client.is_first_step()
                if is_first_step:
                    # First run: start challenges / start new order
                    client.start_challenges()
                else:
                    # Second run: finish challenges, and get certificate
                    try:
                        client.finish_challenges()
                        client.get_certificate()
                        if client.all_chains is not None:
                            other['all_chains'] = client.all_chains
                    finally:
                        if module.params['deactivate_authzs']:
                            client.deactivate_authzs()
                data, data_dns = client.get_challenges_data(first_step=is_first_step)
                auths = dict()
                for k, v in client.authorizations.items():
                    # Remove "type:" from key
                    auths[split_identifier(k)[1]] = v.to_json()
                module.exit_json(
                    changed=client.changed,
                    authorizations=auths,
                    finalize_uri=client.order.finalize_uri if client.order else None,
                    order_uri=client.order_uri,
                    account_uri=client.client.account_uri,
                    challenge_data=data,
                    challenge_data_dns=data_dns,
                    cert_days=client.cert_days,
                    **other
                )
        else:
            module.exit_json(changed=False, cert_days=cert_days)
    except ModuleFailException as e:
        e.do_fail(module)


if __name__ == '__main__':
    main()
