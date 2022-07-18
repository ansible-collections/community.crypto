# -*- coding: utf-8 -*-
#
# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import binascii
import traceback

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_certificate_request,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_decode_name,
    cryptography_get_extensions_from_csr,
    cryptography_oid_to_name,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.publickey_info import (
    get_publickey_info,
)

MINIMAL_CRYPTOGRAPHY_VERSION = '1.3'

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


TIMESTAMP_FORMAT = "%Y%m%d%H%M%SZ"


@six.add_metaclass(abc.ABCMeta)
class CSRInfoRetrieval(object):
    def __init__(self, module, backend, content, validate_signature):
        # content must be a bytes string
        self.module = module
        self.backend = backend
        self.content = content
        self.validate_signature = validate_signature

    @abc.abstractmethod
    def _get_subject_ordered(self):
        pass

    @abc.abstractmethod
    def _get_key_usage(self):
        pass

    @abc.abstractmethod
    def _get_extended_key_usage(self):
        pass

    @abc.abstractmethod
    def _get_basic_constraints(self):
        pass

    @abc.abstractmethod
    def _get_ocsp_must_staple(self):
        pass

    @abc.abstractmethod
    def _get_subject_alt_name(self):
        pass

    @abc.abstractmethod
    def _get_name_constraints(self):
        pass

    @abc.abstractmethod
    def _get_public_key_pem(self):
        pass

    @abc.abstractmethod
    def _get_public_key_object(self):
        pass

    @abc.abstractmethod
    def _get_subject_key_identifier(self):
        pass

    @abc.abstractmethod
    def _get_authority_key_identifier(self):
        pass

    @abc.abstractmethod
    def _get_all_extensions(self):
        pass

    @abc.abstractmethod
    def _is_signature_valid(self):
        pass

    def get_info(self, prefer_one_fingerprint=False):
        result = dict()
        self.csr = load_certificate_request(None, content=self.content, backend=self.backend)

        subject = self._get_subject_ordered()
        result['subject'] = dict()
        for k, v in subject:
            result['subject'][k] = v
        result['subject_ordered'] = subject
        result['key_usage'], result['key_usage_critical'] = self._get_key_usage()
        result['extended_key_usage'], result['extended_key_usage_critical'] = self._get_extended_key_usage()
        result['basic_constraints'], result['basic_constraints_critical'] = self._get_basic_constraints()
        result['ocsp_must_staple'], result['ocsp_must_staple_critical'] = self._get_ocsp_must_staple()
        result['subject_alt_name'], result['subject_alt_name_critical'] = self._get_subject_alt_name()
        (
            result['name_constraints_permitted'],
            result['name_constraints_excluded'],
            result['name_constraints_critical'],
        ) = self._get_name_constraints()

        result['public_key'] = self._get_public_key_pem()

        public_key_info = get_publickey_info(
            self.module,
            self.backend,
            key=self._get_public_key_object(),
            prefer_one_fingerprint=prefer_one_fingerprint)
        result.update({
            'public_key_type': public_key_info['type'],
            'public_key_data': public_key_info['public_data'],
            'public_key_fingerprints': public_key_info['fingerprints'],
        })

        ski = self._get_subject_key_identifier()
        if ski is not None:
            ski = to_native(binascii.hexlify(ski))
            ski = ':'.join([ski[i:i + 2] for i in range(0, len(ski), 2)])
        result['subject_key_identifier'] = ski

        aki, aci, acsn = self._get_authority_key_identifier()
        if aki is not None:
            aki = to_native(binascii.hexlify(aki))
            aki = ':'.join([aki[i:i + 2] for i in range(0, len(aki), 2)])
        result['authority_key_identifier'] = aki
        result['authority_cert_issuer'] = aci
        result['authority_cert_serial_number'] = acsn

        result['extensions_by_oid'] = self._get_all_extensions()

        result['signature_valid'] = self._is_signature_valid()
        if self.validate_signature and not result['signature_valid']:
            self.module.fail_json(
                msg='CSR signature is invalid!',
                **result
            )
        return result


class CSRInfoRetrievalCryptography(CSRInfoRetrieval):
    """Validate the supplied CSR, using the cryptography backend"""
    def __init__(self, module, content, validate_signature):
        super(CSRInfoRetrievalCryptography, self).__init__(module, 'cryptography', content, validate_signature)
        self.name_encoding = module.params.get('name_encoding', 'ignore')

    def _get_subject_ordered(self):
        result = []
        for attribute in self.csr.subject:
            result.append([cryptography_oid_to_name(attribute.oid), attribute.value])
        return result

    def _get_key_usage(self):
        try:
            current_key_ext = self.csr.extensions.get_extension_for_class(x509.KeyUsage)
            current_key_usage = current_key_ext.value
            key_usage = dict(
                digital_signature=current_key_usage.digital_signature,
                content_commitment=current_key_usage.content_commitment,
                key_encipherment=current_key_usage.key_encipherment,
                data_encipherment=current_key_usage.data_encipherment,
                key_agreement=current_key_usage.key_agreement,
                key_cert_sign=current_key_usage.key_cert_sign,
                crl_sign=current_key_usage.crl_sign,
                encipher_only=False,
                decipher_only=False,
            )
            if key_usage['key_agreement']:
                key_usage.update(dict(
                    encipher_only=current_key_usage.encipher_only,
                    decipher_only=current_key_usage.decipher_only
                ))

            key_usage_names = dict(
                digital_signature='Digital Signature',
                content_commitment='Non Repudiation',
                key_encipherment='Key Encipherment',
                data_encipherment='Data Encipherment',
                key_agreement='Key Agreement',
                key_cert_sign='Certificate Sign',
                crl_sign='CRL Sign',
                encipher_only='Encipher Only',
                decipher_only='Decipher Only',
            )
            return sorted([
                key_usage_names[name] for name, value in key_usage.items() if value
            ]), current_key_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_extended_key_usage(self):
        try:
            ext_keyusage_ext = self.csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            return sorted([
                cryptography_oid_to_name(eku) for eku in ext_keyusage_ext.value
            ]), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_basic_constraints(self):
        try:
            ext_keyusage_ext = self.csr.extensions.get_extension_for_class(x509.BasicConstraints)
            result = ['CA:{0}'.format('TRUE' if ext_keyusage_ext.value.ca else 'FALSE')]
            if ext_keyusage_ext.value.path_length is not None:
                result.append('pathlen:{0}'.format(ext_keyusage_ext.value.path_length))
            return sorted(result), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_ocsp_must_staple(self):
        try:
            try:
                # This only works with cryptography >= 2.1
                tlsfeature_ext = self.csr.extensions.get_extension_for_class(x509.TLSFeature)
                value = cryptography.x509.TLSFeatureType.status_request in tlsfeature_ext.value
            except AttributeError:
                # Fallback for cryptography < 2.1
                oid = x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.1.24")
                tlsfeature_ext = self.csr.extensions.get_extension_for_oid(oid)
                value = tlsfeature_ext.value.value == b"\x30\x03\x02\x01\x05"
            return value, tlsfeature_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_subject_alt_name(self):
        try:
            san_ext = self.csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result = [cryptography_decode_name(san, idn_rewrite=self.name_encoding) for san in san_ext.value]
            return result, san_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_name_constraints(self):
        try:
            nc_ext = self.csr.extensions.get_extension_for_class(x509.NameConstraints)
            permitted = [cryptography_decode_name(san, idn_rewrite=self.name_encoding) for san in nc_ext.value.permitted_subtrees or []]
            excluded = [cryptography_decode_name(san, idn_rewrite=self.name_encoding) for san in nc_ext.value.excluded_subtrees or []]
            return permitted, excluded, nc_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, None, False

    def _get_public_key_pem(self):
        return self.csr.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_public_key_object(self):
        return self.csr.public_key()

    def _get_subject_key_identifier(self):
        try:
            ext = self.csr.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            return ext.value.digest
        except cryptography.x509.ExtensionNotFound:
            return None

    def _get_authority_key_identifier(self):
        try:
            ext = self.csr.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            issuer = None
            if ext.value.authority_cert_issuer is not None:
                issuer = [cryptography_decode_name(san, idn_rewrite=self.name_encoding) for san in ext.value.authority_cert_issuer]
            return ext.value.key_identifier, issuer, ext.value.authority_cert_serial_number
        except cryptography.x509.ExtensionNotFound:
            return None, None, None

    def _get_all_extensions(self):
        return cryptography_get_extensions_from_csr(self.csr)

    def _is_signature_valid(self):
        return self.csr.is_signature_valid


def get_csr_info(module, backend, content, validate_signature=True, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = CSRInfoRetrievalCryptography(module, content, validate_signature=validate_signature)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content, validate_signature=True):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Try cryptography
        if can_use_cryptography:
            backend = 'cryptography'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Cannot detect the required Python library "
                                  "cryptography (>= {0})").format(MINIMAL_CRYPTOGRAPHY_VERSION))

    if backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, CSRInfoRetrievalCryptography(module, content, validate_signature=validate_signature)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
