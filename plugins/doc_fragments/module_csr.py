# -*- coding: utf-8 -*-

# Copyright (c) 2017, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r'''
description:
    - This module allows one to (re)generate OpenSSL certificate signing requests.
    - This module supports the subjectAltName, keyUsage, extendedKeyUsage, basicConstraints and OCSP Must Staple
      extensions.
requirements:
    - cryptography >= 1.3
options:
    digest:
        description:
            - The digest used when signing the certificate signing request with the private key.
        type: str
        default: sha256
    privatekey_path:
        description:
            - The path to the private key to use when signing the certificate signing request.
            - Either I(privatekey_path) or I(privatekey_content) must be specified if I(state) is C(present), but not both.
        type: path
    privatekey_content:
        description:
            - The content of the private key to use when signing the certificate signing request.
            - Either I(privatekey_path) or I(privatekey_content) must be specified if I(state) is C(present), but not both.
        type: str
    privatekey_passphrase:
        description:
            - The passphrase for the private key.
            - This is required if the private key is password protected.
        type: str
    version:
        description:
            - The version of the certificate signing request.
            - "The only allowed value according to L(RFC 2986,https://tools.ietf.org/html/rfc2986#section-4.1)
               is 1."
            - This option no longer accepts unsupported values since community.crypto 2.0.0.
        type: int
        default: 1
        choices:
            - 1
    subject:
        description:
            - Key/value pairs that will be present in the subject name field of the certificate signing request.
            - If you need to specify more than one value with the same key, use a list as value.
            - If the order of the components is important, use I(subject_ordered).
            - Mutually exclusive with I(subject_ordered).
        type: dict
    subject_ordered:
        description:
            - A list of dictionaries, where every dictionary must contain one key/value pair. This key/value pair
              will be present in the subject name field of the certificate signing request.
            - If you want to specify more than one value with the same key in a row, you can use a list as value.
            - Mutually exclusive with I(subject), and any other subject field option, such as I(country_name),
              I(state_or_province_name), I(locality_name), I(organization_name), I(organizational_unit_name),
              I(common_name), or I(email_address).
        type: list
        elements: dict
        version_added: 2.0.0
    country_name:
        description:
            - The countryName field of the certificate signing request subject.
        type: str
        aliases: [ C, countryName ]
    state_or_province_name:
        description:
            - The stateOrProvinceName field of the certificate signing request subject.
        type: str
        aliases: [ ST, stateOrProvinceName ]
    locality_name:
        description:
            - The localityName field of the certificate signing request subject.
        type: str
        aliases: [ L, localityName ]
    organization_name:
        description:
            - The organizationName field of the certificate signing request subject.
        type: str
        aliases: [ O, organizationName ]
    organizational_unit_name:
        description:
            - The organizationalUnitName field of the certificate signing request subject.
        type: str
        aliases: [ OU, organizationalUnitName ]
    common_name:
        description:
            - The commonName field of the certificate signing request subject.
        type: str
        aliases: [ CN, commonName ]
    email_address:
        description:
            - The emailAddress field of the certificate signing request subject.
        type: str
        aliases: [ E, emailAddress ]
    subject_alt_name:
        description:
            - Subject Alternative Name (SAN) extension to attach to the certificate signing request.
            - Values must be prefixed by their options. (These are C(email), C(URI), C(DNS), C(RID), C(IP), C(dirName),
              C(otherName), and the ones specific to your CA).
            - Note that if no SAN is specified, but a common name, the common
              name will be added as a SAN except if C(useCommonNameForSAN) is
              set to I(false).
            - More at U(https://tools.ietf.org/html/rfc5280#section-4.2.1.6).
        type: list
        elements: str
        aliases: [ subjectAltName ]
    subject_alt_name_critical:
        description:
            - Should the subjectAltName extension be considered as critical.
        type: bool
        default: false
        aliases: [ subjectAltName_critical ]
    use_common_name_for_san:
        description:
            - If set to C(true), the module will fill the common name in for
              C(subject_alt_name) with C(DNS:) prefix if no SAN is specified.
        type: bool
        default: true
        aliases: [ useCommonNameForSAN ]
    key_usage:
        description:
            - This defines the purpose (for example encipherment, signature, certificate signing)
              of the key contained in the certificate.
        type: list
        elements: str
        aliases: [ keyUsage ]
    key_usage_critical:
        description:
            - Should the keyUsage extension be considered as critical.
        type: bool
        default: false
        aliases: [ keyUsage_critical ]
    extended_key_usage:
        description:
            - Additional restrictions (for example client authentication, server authentication)
              on the allowed purposes for which the public key may be used.
        type: list
        elements: str
        aliases: [ extKeyUsage, extendedKeyUsage ]
    extended_key_usage_critical:
        description:
            - Should the extkeyUsage extension be considered as critical.
        type: bool
        default: false
        aliases: [ extKeyUsage_critical, extendedKeyUsage_critical ]
    basic_constraints:
        description:
            - Indicates basic constraints, such as if the certificate is a CA.
        type: list
        elements: str
        aliases: [ basicConstraints ]
    basic_constraints_critical:
        description:
            - Should the basicConstraints extension be considered as critical.
        type: bool
        default: false
        aliases: [ basicConstraints_critical ]
    ocsp_must_staple:
        description:
            - Indicates that the certificate should contain the OCSP Must Staple
              extension (U(https://tools.ietf.org/html/rfc7633)).
        type: bool
        default: false
        aliases: [ ocspMustStaple ]
    ocsp_must_staple_critical:
        description:
            - Should the OCSP Must Staple extension be considered as critical.
            - Note that according to the RFC, this extension should not be marked
              as critical, as old clients not knowing about OCSP Must Staple
              are required to reject such certificates
              (see U(https://tools.ietf.org/html/rfc7633#section-4)).
        type: bool
        default: false
        aliases: [ ocspMustStaple_critical ]
    name_constraints_permitted:
        description:
            - For CA certificates, this specifies a list of identifiers which describe
              subtrees of names that this CA is allowed to issue certificates for.
            - Values must be prefixed by their options. (i.e., C(email), C(URI), C(DNS), C(RID), C(IP), C(dirName),
              C(otherName) and the ones specific to your CA).
        type: list
        elements: str
    name_constraints_excluded:
        description:
            - For CA certificates, this specifies a list of identifiers which describe
              subtrees of names that this CA is B(not) allowed to issue certificates for.
            - Values must be prefixed by their options. (i.e., C(email), C(URI), C(DNS), C(RID), C(IP), C(dirName),
              C(otherName) and the ones specific to your CA).
        type: list
        elements: str
    name_constraints_critical:
        description:
            - Should the Name Constraints extension be considered as critical.
        type: bool
        default: false
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
        type: str
        default: auto
        choices: [ auto, cryptography ]
    create_subject_key_identifier:
        description:
            - Create the Subject Key Identifier from the public key.
            - "Please note that commercial CAs can ignore the value, respectively use a value of
               their own choice instead. Specifying this option is mostly useful for self-signed
               certificates or for own CAs."
            - Note that this is only supported if the C(cryptography) backend is used!
        type: bool
        default: false
    subject_key_identifier:
        description:
            - The subject key identifier as a hex string, where two bytes are separated by colons.
            - "Example: C(00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33)"
            - "Please note that commercial CAs ignore this value, respectively use a value of their
               own choice. Specifying this option is mostly useful for self-signed certificates
               or for own CAs."
            - Note that this option can only be used if I(create_subject_key_identifier) is C(false).
            - Note that this is only supported if the C(cryptography) backend is used!
        type: str
    authority_key_identifier:
        description:
            - The authority key identifier as a hex string, where two bytes are separated by colons.
            - "Example: C(00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33)"
            - "Please note that commercial CAs ignore this value, respectively use a value of their
               own choice. Specifying this option is mostly useful for self-signed certificates
               or for own CAs."
            - Note that this is only supported if the C(cryptography) backend is used!
            - The C(AuthorityKeyIdentifier) extension will only be added if at least one of I(authority_key_identifier),
              I(authority_cert_issuer) and I(authority_cert_serial_number) is specified.
        type: str
    authority_cert_issuer:
        description:
            - Names that will be present in the authority cert issuer field of the certificate signing request.
            - Values must be prefixed by their options. (i.e., C(email), C(URI), C(DNS), C(RID), C(IP), C(dirName),
              C(otherName) and the ones specific to your CA)
            - "Example: C(DNS:ca.example.org)"
            - If specified, I(authority_cert_serial_number) must also be specified.
            - "Please note that commercial CAs ignore this value, respectively use a value of their
               own choice. Specifying this option is mostly useful for self-signed certificates
               or for own CAs."
            - Note that this is only supported if the C(cryptography) backend is used!
            - The C(AuthorityKeyIdentifier) extension will only be added if at least one of I(authority_key_identifier),
              I(authority_cert_issuer) and I(authority_cert_serial_number) is specified.
        type: list
        elements: str
    authority_cert_serial_number:
        description:
            - The authority cert serial number.
            - If specified, I(authority_cert_issuer) must also be specified.
            - Note that this is only supported if the C(cryptography) backend is used!
            - "Please note that commercial CAs ignore this value, respectively use a value of their
               own choice. Specifying this option is mostly useful for self-signed certificates
               or for own CAs."
            - The C(AuthorityKeyIdentifier) extension will only be added if at least one of I(authority_key_identifier),
              I(authority_cert_issuer) and I(authority_cert_serial_number) is specified.
        type: int
    crl_distribution_points:
        description:
            - Allows to specify one or multiple CRL distribution points.
            - Only supported by the C(cryptography) backend.
        type: list
        elements: dict
        suboptions:
            full_name:
                description:
                    - Describes how the CRL can be retrieved.
                    - Mutually exclusive with I(relative_name).
                    - "Example: C(URI:https://ca.example.com/revocations.crl)."
                type: list
                elements: str
            relative_name:
                description:
                    - Describes how the CRL can be retrieved relative to the CRL issuer.
                    - Mutually exclusive with I(full_name).
                    - "Example: C(/CN=example.com)."
                    - Can only be used when cryptography >= 1.6 is installed.
                type: list
                elements: str
            crl_issuer:
                description:
                    - Information about the issuer of the CRL.
                type: list
                elements: str
            reasons:
                description:
                    - List of reasons that this distribution point can be used for when performing revocation checks.
                type: list
                elements: str
                choices:
                    - key_compromise
                    - ca_compromise
                    - affiliation_changed
                    - superseded
                    - cessation_of_operation
                    - certificate_hold
                    - privilege_withdrawn
                    - aa_compromise
        version_added: 1.4.0
notes:
    - If the certificate signing request already exists it will be checked whether subjectAltName,
      keyUsage, extendedKeyUsage and basicConstraints only contain the requested values, whether
      OCSP Must Staple is as requested, and if the request was signed by the given private key.
seealso:
- module: community.crypto.x509_certificate
- module: community.crypto.x509_certificate_pipe
- module: community.crypto.openssl_dhparam
- module: community.crypto.openssl_pkcs12
- module: community.crypto.openssl_privatekey
- module: community.crypto.openssl_privatekey_pipe
- module: community.crypto.openssl_publickey
- module: community.crypto.openssl_csr_info
'''
