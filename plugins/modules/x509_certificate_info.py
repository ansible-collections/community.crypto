#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: x509_certificate_info
short_description: Provide information of OpenSSL X.509 certificates
description:
    - This module allows one to query information on OpenSSL certificates.
    - It uses the cryptography python library to interact with OpenSSL.
    - Note that this module was called C(openssl_certificate_info) when included directly in Ansible
      up to version 2.9.  When moved to the collection C(community.crypto), it was renamed to
      M(community.crypto.x509_certificate_info). From Ansible 2.10 on, it can still be used by the
      old short name (or by C(ansible.builtin.openssl_certificate_info)), which redirects to
      C(community.crypto.x509_certificate_info). When using FQCNs or when using the
      L(collections,https://docs.ansible.com/ansible/latest/user_guide/collections_using.html#using-collections-in-a-playbook)
      keyword, the new name M(community.crypto.x509_certificate_info) should be used to avoid
      a deprecation warning.
requirements:
    - cryptography >= 1.6
author:
    - Felix Fontein (@felixfontein)
    - Yanis Guenane (@Spredzy)
    - Markus Teufelberger (@MarkusTeufelberger)
extends_documentation_fragment:
    - community.crypto.attributes
    - community.crypto.attributes.info_module
    - community.crypto.name_encoding
options:
    path:
        description:
            - Remote absolute path where the certificate file is loaded from.
            - Either I(path) or I(content) must be specified, but not both.
        type: path
    content:
        description:
            - Content of the X.509 certificate in PEM format.
            - Either I(path) or I(content) must be specified, but not both.
        type: str
        version_added: '1.0.0'
    valid_at:
        description:
            - A dict of names mapping to time specifications. Every time specified here
              will be checked whether the certificate is valid at this point. See the
              C(valid_at) return value for informations on the result.
            - Time can be specified either as relative time or as absolute timestamp.
            - Time will always be interpreted as UTC.
            - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
              + C([w | d | h | m | s]) (for example C(+32w1d2h)), and ASN.1 TIME (in other words, pattern C(YYYYMMDDHHMMSSZ)).
              Note that all timestamps will be treated as being in UTC.
        type: dict
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]

notes:
    - All timestamp values are provided in ASN.1 TIME format, in other words, following the C(YYYYMMDDHHMMSSZ) pattern.
      They are all in UTC.
seealso:
    - module: community.crypto.x509_certificate
    - module: community.crypto.x509_certificate_pipe
'''

EXAMPLES = r'''
- name: Generate a Self Signed OpenSSL certificate
  community.crypto.x509_certificate:
    path: /etc/ssl/crt/ansible.com.crt
    privatekey_path: /etc/ssl/private/ansible.com.pem
    csr_path: /etc/ssl/csr/ansible.com.csr
    provider: selfsigned


# Get information on the certificate

- name: Get information on generated certificate
  community.crypto.x509_certificate_info:
    path: /etc/ssl/crt/ansible.com.crt
  register: result

- name: Dump information
  ansible.builtin.debug:
    var: result


# Check whether the certificate is valid or not valid at certain times, fail
# if this is not the case. The first task (x509_certificate_info) collects
# the information, and the second task (assert) validates the result and
# makes the playbook fail in case something is not as expected.

- name: Test whether that certificate is valid tomorrow and/or in three weeks
  community.crypto.x509_certificate_info:
    path: /etc/ssl/crt/ansible.com.crt
    valid_at:
      point_1: "+1d"
      point_2: "+3w"
  register: result

- name: Validate that certificate is valid tomorrow, but not in three weeks
  assert:
    that:
      - result.valid_at.point_1      # valid in one day
      - not result.valid_at.point_2  # not valid in three weeks
'''

RETURN = r'''
expired:
    description: Whether the certificate is expired (in other words, C(notAfter) is in the past).
    returned: success
    type: bool
basic_constraints:
    description: Entries in the C(basic_constraints) extension, or C(none) if extension is not present.
    returned: success
    type: list
    elements: str
    sample: ["CA:TRUE", "pathlen:1"]
basic_constraints_critical:
    description: Whether the C(basic_constraints) extension is critical.
    returned: success
    type: bool
extended_key_usage:
    description: Entries in the C(extended_key_usage) extension, or C(none) if extension is not present.
    returned: success
    type: list
    elements: str
    sample: [Biometric Info, DVCS, Time Stamping]
extended_key_usage_critical:
    description: Whether the C(extended_key_usage) extension is critical.
    returned: success
    type: bool
extensions_by_oid:
    description: Returns a dictionary for every extension OID.
    returned: success
    type: dict
    contains:
        critical:
            description: Whether the extension is critical.
            returned: success
            type: bool
        value:
            description:
              - The Base64 encoded value (in DER format) of the extension.
              - B(Note) that depending on the C(cryptography) version used, it is
                not possible to extract the ASN.1 content of the extension, but only
                to provide the re-encoded content of the extension in case it was
                parsed by C(cryptography). This should usually result in exactly the
                same value, except if the original extension value was malformed.
            returned: success
            type: str
            sample: "MAMCAQU="
    sample: {"1.3.6.1.5.5.7.1.24": { "critical": false, "value": "MAMCAQU="}}
key_usage:
    description: Entries in the C(key_usage) extension, or C(none) if extension is not present.
    returned: success
    type: str
    sample: [Key Agreement, Data Encipherment]
key_usage_critical:
    description: Whether the C(key_usage) extension is critical.
    returned: success
    type: bool
subject_alt_name:
    description:
        - Entries in the C(subject_alt_name) extension, or C(none) if extension is not present.
        - See I(name_encoding) for how IDNs are handled.
    returned: success
    type: list
    elements: str
    sample: ["DNS:www.ansible.com", "IP:1.2.3.4"]
subject_alt_name_critical:
    description: Whether the C(subject_alt_name) extension is critical.
    returned: success
    type: bool
ocsp_must_staple:
    description: C(true) if the OCSP Must Staple extension is present, C(none) otherwise.
    returned: success
    type: bool
ocsp_must_staple_critical:
    description: Whether the C(ocsp_must_staple) extension is critical.
    returned: success
    type: bool
issuer:
    description:
        - The certificate's issuer.
        - Note that for repeated values, only the last one will be returned.
    returned: success
    type: dict
    sample: {"organizationName": "Ansible", "commonName": "ca.example.com"}
issuer_ordered:
    description: The certificate's issuer as an ordered list of tuples.
    returned: success
    type: list
    elements: list
    sample: [["organizationName", "Ansible"], ["commonName": "ca.example.com"]]
subject:
    description:
        - The certificate's subject as a dictionary.
        - Note that for repeated values, only the last one will be returned.
    returned: success
    type: dict
    sample: {"commonName": "www.example.com", "emailAddress": "test@example.com"}
subject_ordered:
    description: The certificate's subject as an ordered list of tuples.
    returned: success
    type: list
    elements: list
    sample: [["commonName", "www.example.com"], ["emailAddress": "test@example.com"]]
not_after:
    description: C(notAfter) date as ASN.1 TIME.
    returned: success
    type: str
    sample: '20190413202428Z'
not_before:
    description: C(notBefore) date as ASN.1 TIME.
    returned: success
    type: str
    sample: '20190331202428Z'
public_key:
    description: Certificate's public key in PEM format.
    returned: success
    type: str
    sample: "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A..."
public_key_type:
    description:
        - The certificate's public key's type.
        - One of C(RSA), C(DSA), C(ECC), C(Ed25519), C(X25519), C(Ed448), or C(X448).
        - Will start with C(unknown) if the key type cannot be determined.
    returned: success
    type: str
    version_added: 1.7.0
    sample: RSA
public_key_data:
    description:
        - Public key data. Depends on the public key's type.
    returned: success
    type: dict
    version_added: 1.7.0
    contains:
        size:
            description:
                - Bit size of modulus (RSA) or prime number (DSA).
            type: int
            returned: When C(public_key_type=RSA) or C(public_key_type=DSA)
        modulus:
            description:
                - The RSA key's modulus.
            type: int
            returned: When C(public_key_type=RSA)
        exponent:
            description:
                - The RSA key's public exponent.
            type: int
            returned: When C(public_key_type=RSA)
        p:
            description:
                - The C(p) value for DSA.
                - This is the prime modulus upon which arithmetic takes place.
            type: int
            returned: When C(public_key_type=DSA)
        q:
            description:
                - The C(q) value for DSA.
                - This is a prime that divides C(p - 1), and at the same time the order of the subgroup of the
                  multiplicative group of the prime field used.
            type: int
            returned: When C(public_key_type=DSA)
        g:
            description:
                - The C(g) value for DSA.
                - This is the element spanning the subgroup of the multiplicative group of the prime field used.
            type: int
            returned: When C(public_key_type=DSA)
        curve:
            description:
                - The curve's name for ECC.
            type: str
            returned: When C(public_key_type=ECC)
        exponent_size:
            description:
                - The maximum number of bits of a private key. This is basically the bit size of the subgroup used.
            type: int
            returned: When C(public_key_type=ECC)
        x:
            description:
                - The C(x) coordinate for the public point on the elliptic curve.
            type: int
            returned: When C(public_key_type=ECC)
        y:
            description:
                - For C(public_key_type=ECC), this is the C(y) coordinate for the public point on the elliptic curve.
                - For C(public_key_type=DSA), this is the publicly known group element whose discrete logarithm w.r.t. C(g) is the private key.
            type: int
            returned: When C(public_key_type=DSA) or C(public_key_type=ECC)
public_key_fingerprints:
    description:
        - Fingerprints of certificate's public key.
        - For every hash algorithm available, the fingerprint is computed.
    returned: success
    type: dict
    sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
              'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
fingerprints:
    description:
        - Fingerprints of the DER-encoded form of the whole certificate.
        - For every hash algorithm available, the fingerprint is computed.
    returned: success
    type: dict
    sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
              'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
    version_added: 1.2.0
signature_algorithm:
    description: The signature algorithm used to sign the certificate.
    returned: success
    type: str
    sample: sha256WithRSAEncryption
serial_number:
    description: The certificate's serial number.
    returned: success
    type: int
    sample: 1234
version:
    description: The certificate version.
    returned: success
    type: int
    sample: 3
valid_at:
    description: For every time stamp provided in the I(valid_at) option, a
                 boolean whether the certificate is valid at that point in time
                 or not.
    returned: success
    type: dict
subject_key_identifier:
    description:
        - The certificate's subject key identifier.
        - The identifier is returned in hexadecimal, with C(:) used to separate bytes.
        - Is C(none) if the C(SubjectKeyIdentifier) extension is not present.
    returned: success
    type: str
    sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
authority_key_identifier:
    description:
        - The certificate's authority key identifier.
        - The identifier is returned in hexadecimal, with C(:) used to separate bytes.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
    returned: success
    type: str
    sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
authority_cert_issuer:
    description:
        - The certificate's authority cert issuer as a list of general names.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
        - See I(name_encoding) for how IDNs are handled.
    returned: success
    type: list
    elements: str
    sample: ["DNS:www.ansible.com", "IP:1.2.3.4"]
authority_cert_serial_number:
    description:
        - The certificate's authority cert serial number.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
    returned: success
    type: int
    sample: 12345
ocsp_uri:
    description: The OCSP responder URI, if included in the certificate. Will be
                 C(none) if no OCSP responder URI is included.
    returned: success
    type: str
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    get_relative_time_option,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate_info import (
    select_backend,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
            valid_at=dict(type='dict'),
            name_encoding=dict(type='str', default='ignore', choices=['ignore', 'idna', 'unicode']),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography']),
        ),
        required_one_of=(
            ['path', 'content'],
        ),
        mutually_exclusive=(
            ['path', 'content'],
        ),
        supports_check_mode=True,
    )

    if module.params['content'] is not None:
        data = module.params['content'].encode('utf-8')
    else:
        try:
            with open(module.params['path'], 'rb') as f:
                data = f.read()
        except (IOError, OSError) as e:
            module.fail_json(msg='Error while reading certificate file from disk: {0}'.format(e))

    backend, module_backend = select_backend(module, module.params['select_crypto_backend'], data)

    valid_at = module.params['valid_at']
    if valid_at:
        for k, v in valid_at.items():
            if not isinstance(v, string_types):
                module.fail_json(
                    msg='The value for valid_at.{0} must be of type string (got {1})'.format(k, type(v))
                )
            valid_at[k] = get_relative_time_option(v, 'valid_at.{0}'.format(k))

    try:
        result = module_backend.get_info()

        not_before = module_backend.get_not_before()
        not_after = module_backend.get_not_after()

        result['valid_at'] = dict()
        if valid_at:
            for k, v in valid_at.items():
                result['valid_at'][k] = not_before <= v <= not_after

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
