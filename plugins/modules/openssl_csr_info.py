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
module: openssl_csr_info
short_description: Provide information of OpenSSL Certificate Signing Requests (CSR)
description:
    - This module allows one to query information on OpenSSL Certificate Signing Requests (CSR).
    - In case the CSR signature cannot be validated, the module will fail. In this case, all return
      variables are still returned.
    - It uses the cryptography python library to interact with OpenSSL.
requirements:
    - cryptography >= 1.3
author:
    - Felix Fontein (@felixfontein)
    - Yanis Guenane (@Spredzy)
extends_documentation_fragment:
    - community.crypto.attributes
    - community.crypto.attributes.info_module
    - community.crypto.name_encoding
options:
    path:
        description:
            - Remote absolute path where the CSR file is loaded from.
            - Either I(path) or I(content) must be specified, but not both.
        type: path
    content:
        description:
            - Content of the CSR file.
            - Either I(path) or I(content) must be specified, but not both.
        type: str
        version_added: "1.0.0"
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]

seealso:
    - module: community.crypto.openssl_csr
    - module: community.crypto.openssl_csr_pipe
    - ref: community.crypto.openssl_csr_info filter <ansible_collections.community.crypto.openssl_csr_info_filter>
    # - plugin: community.crypto.openssl_csr_info
    #   plugin_type: filter
      description: A filter variant of this module.
'''

EXAMPLES = r'''
- name: Generate an OpenSSL Certificate Signing Request
  community.crypto.openssl_csr:
    path: /etc/ssl/csr/www.ansible.com.csr
    privatekey_path: /etc/ssl/private/ansible.com.pem
    common_name: www.ansible.com

- name: Get information on the CSR
  community.crypto.openssl_csr_info:
    path: /etc/ssl/csr/www.ansible.com.csr
  register: result

- name: Dump information
  ansible.builtin.debug:
    var: result
'''

RETURN = r'''
signature_valid:
    description:
        - Whether the CSR's signature is valid.
        - In case the check returns C(false), the module will fail.
    returned: success
    type: bool
basic_constraints:
    description: Entries in the C(basic_constraints) extension, or C(none) if extension is not present.
    returned: success
    type: list
    elements: str
    sample: ['CA:TRUE', 'pathlen:1']
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
    description: Returns a dictionary for every extension OID
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
name_constraints_permitted:
    description: List of permitted subtrees to sign certificates for.
    returned: success
    type: list
    elements: str
    sample: ['email:.somedomain.com']
    version_added: 1.1.0
name_constraints_excluded:
    description:
        - List of excluded subtrees the CA cannot sign certificates for.
        - Is C(none) if extension is not present.
        - See I(name_encoding) for how IDNs are handled.
    returned: success
    type: list
    elements: str
    sample: ['email:.com']
    version_added: 1.1.0
name_constraints_critical:
    description:
        - Whether the C(name_constraints) extension is critical.
        - Is C(none) if extension is not present.
    returned: success
    type: bool
    version_added: 1.1.0
subject:
    description:
        - The CSR's subject as a dictionary.
        - Note that for repeated values, only the last one will be returned.
    returned: success
    type: dict
    sample: {"commonName": "www.example.com", "emailAddress": "test@example.com"}
subject_ordered:
    description: The CSR's subject as an ordered list of tuples.
    returned: success
    type: list
    elements: list
    sample: [["commonName", "www.example.com"], ["emailAddress": "test@example.com"]]
public_key:
    description: CSR's public key in PEM format
    returned: success
    type: str
    sample: "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A..."
public_key_type:
    description:
        - The CSR's public key's type.
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
        - Fingerprints of CSR's public key.
        - For every hash algorithm available, the fingerprint is computed.
    returned: success
    type: dict
    sample: "{'sha256': 'd4:b3:aa:6d:c8:04:ce:4e:ba:f6:29:4d:92:a3:94:b0:c2:ff:bd:bf:33:63:11:43:34:0f:51:b0:95:09:2f:63',
              'sha512': 'f7:07:4a:f0:b0:f0:e6:8b:95:5f:f9:e6:61:0a:32:68:f1..."
subject_key_identifier:
    description:
        - The CSR's subject key identifier.
        - The identifier is returned in hexadecimal, with C(:) used to separate bytes.
        - Is C(none) if the C(SubjectKeyIdentifier) extension is not present.
    returned: success
    type: str
    sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
authority_key_identifier:
    description:
        - The CSR's authority key identifier.
        - The identifier is returned in hexadecimal, with C(:) used to separate bytes.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
    returned: success
    type: str
    sample: '00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33'
authority_cert_issuer:
    description:
        - The CSR's authority cert issuer as a list of general names.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
        - See I(name_encoding) for how IDNs are handled.
    returned: success
    type: list
    elements: str
    sample: ["DNS:www.ansible.com", "IP:1.2.3.4"]
authority_cert_serial_number:
    description:
        - The CSR's authority cert serial number.
        - Is C(none) if the C(AuthorityKeyIdentifier) extension is not present.
    returned: success
    type: int
    sample: 12345
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.csr_info import (
    select_backend,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path'),
            content=dict(type='str'),
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
            module.fail_json(msg='Error while reading CSR file from disk: {0}'.format(e))

    backend, module_backend = select_backend(module, module.params['select_crypto_backend'], data, validate_signature=True)

    try:
        result = module_backend.get_info()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
