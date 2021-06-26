# -*- coding: utf-8 -*-
#
# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import binascii
import datetime
import re
import traceback

from distutils.version import LooseVersion

from ansible.module_utils import six
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_certificate,
    get_fingerprint_of_bytes,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_decode_name,
    cryptography_get_extensions_from_cert,
    cryptography_oid_to_name,
    cryptography_serial_number_of_cert,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pyopenssl_support import (
    pyopenssl_get_extensions_from_cert,
    pyopenssl_normalize_name,
    pyopenssl_normalize_name_attribute,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.publickey_info import (
    get_publickey_info,
)

MINIMAL_CRYPTOGRAPHY_VERSION = '1.6'
MINIMAL_PYOPENSSL_VERSION = '0.15'

PYOPENSSL_IMP_ERR = None
try:
    import OpenSSL
    from OpenSSL import crypto
    PYOPENSSL_VERSION = LooseVersion(OpenSSL.__version__)
    if OpenSSL.SSL.OPENSSL_VERSION_NUMBER >= 0x10100000:
        # OpenSSL 1.1.0 or newer
        OPENSSL_MUST_STAPLE_NAME = b"tlsfeature"
        OPENSSL_MUST_STAPLE_VALUE = b"status_request"
    else:
        # OpenSSL 1.0.x or older
        OPENSSL_MUST_STAPLE_NAME = b"1.3.6.1.5.5.7.1.24"
        OPENSSL_MUST_STAPLE_VALUE = b"DER:30:03:02:01:05"
except ImportError:
    PYOPENSSL_IMP_ERR = traceback.format_exc()
    PYOPENSSL_FOUND = False
else:
    PYOPENSSL_FOUND = True

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
class CertificateInfoRetrieval(object):
    def __init__(self, module, backend, content):
        # content must be a bytes string
        self.module = module
        self.backend = backend
        self.content = content

    @abc.abstractmethod
    def _get_der_bytes(self):
        pass

    @abc.abstractmethod
    def _get_signature_algorithm(self):
        pass

    @abc.abstractmethod
    def _get_subject_ordered(self):
        pass

    @abc.abstractmethod
    def _get_issuer_ordered(self):
        pass

    @abc.abstractmethod
    def _get_version(self):
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
    def get_not_before(self):
        pass

    @abc.abstractmethod
    def get_not_after(self):
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
    def _get_serial_number(self):
        pass

    @abc.abstractmethod
    def _get_all_extensions(self):
        pass

    @abc.abstractmethod
    def _get_ocsp_uri(self):
        pass

    def get_info(self, prefer_one_fingerprint=False):
        result = dict()
        self.cert = load_certificate(None, content=self.content, backend=self.backend)

        result['signature_algorithm'] = self._get_signature_algorithm()
        subject = self._get_subject_ordered()
        issuer = self._get_issuer_ordered()
        result['subject'] = dict()
        for k, v in subject:
            result['subject'][k] = v
        result['subject_ordered'] = subject
        result['issuer'] = dict()
        for k, v in issuer:
            result['issuer'][k] = v
        result['issuer_ordered'] = issuer
        result['version'] = self._get_version()
        result['key_usage'], result['key_usage_critical'] = self._get_key_usage()
        result['extended_key_usage'], result['extended_key_usage_critical'] = self._get_extended_key_usage()
        result['basic_constraints'], result['basic_constraints_critical'] = self._get_basic_constraints()
        result['ocsp_must_staple'], result['ocsp_must_staple_critical'] = self._get_ocsp_must_staple()
        result['subject_alt_name'], result['subject_alt_name_critical'] = self._get_subject_alt_name()

        not_before = self.get_not_before()
        not_after = self.get_not_after()
        result['not_before'] = not_before.strftime(TIMESTAMP_FORMAT)
        result['not_after'] = not_after.strftime(TIMESTAMP_FORMAT)
        result['expired'] = not_after < datetime.datetime.utcnow()

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

        result['fingerprints'] = get_fingerprint_of_bytes(
            self._get_der_bytes(), prefer_one=prefer_one_fingerprint)

        if self.backend != 'pyopenssl':
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

        result['serial_number'] = self._get_serial_number()
        result['extensions_by_oid'] = self._get_all_extensions()
        result['ocsp_uri'] = self._get_ocsp_uri()

        return result


class CertificateInfoRetrievalCryptography(CertificateInfoRetrieval):
    """Validate the supplied cert, using the cryptography backend"""
    def __init__(self, module, content):
        super(CertificateInfoRetrievalCryptography, self).__init__(module, 'cryptography', content)

    def _get_der_bytes(self):
        return self.cert.public_bytes(serialization.Encoding.DER)

    def _get_signature_algorithm(self):
        return cryptography_oid_to_name(self.cert.signature_algorithm_oid)

    def _get_subject_ordered(self):
        result = []
        for attribute in self.cert.subject:
            result.append([cryptography_oid_to_name(attribute.oid), attribute.value])
        return result

    def _get_issuer_ordered(self):
        result = []
        for attribute in self.cert.issuer:
            result.append([cryptography_oid_to_name(attribute.oid), attribute.value])
        return result

    def _get_version(self):
        if self.cert.version == x509.Version.v1:
            return 1
        if self.cert.version == x509.Version.v3:
            return 3
        return "unknown"

    def _get_key_usage(self):
        try:
            current_key_ext = self.cert.extensions.get_extension_for_class(x509.KeyUsage)
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
            ext_keyusage_ext = self.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            return sorted([
                cryptography_oid_to_name(eku) for eku in ext_keyusage_ext.value
            ]), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_basic_constraints(self):
        try:
            ext_keyusage_ext = self.cert.extensions.get_extension_for_class(x509.BasicConstraints)
            result = []
            result.append('CA:{0}'.format('TRUE' if ext_keyusage_ext.value.ca else 'FALSE'))
            if ext_keyusage_ext.value.path_length is not None:
                result.append('pathlen:{0}'.format(ext_keyusage_ext.value.path_length))
            return sorted(result), ext_keyusage_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_ocsp_must_staple(self):
        try:
            try:
                # This only works with cryptography >= 2.1
                tlsfeature_ext = self.cert.extensions.get_extension_for_class(x509.TLSFeature)
                value = cryptography.x509.TLSFeatureType.status_request in tlsfeature_ext.value
            except AttributeError:
                # Fallback for cryptography < 2.1
                oid = x509.oid.ObjectIdentifier("1.3.6.1.5.5.7.1.24")
                tlsfeature_ext = self.cert.extensions.get_extension_for_oid(oid)
                value = tlsfeature_ext.value.value == b"\x30\x03\x02\x01\x05"
            return value, tlsfeature_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def _get_subject_alt_name(self):
        try:
            san_ext = self.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            result = [cryptography_decode_name(san) for san in san_ext.value]
            return result, san_ext.critical
        except cryptography.x509.ExtensionNotFound:
            return None, False

    def get_not_before(self):
        return self.cert.not_valid_before

    def get_not_after(self):
        return self.cert.not_valid_after

    def _get_public_key_pem(self):
        return self.cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_public_key_object(self):
        return self.cert.public_key()

    def _get_subject_key_identifier(self):
        try:
            ext = self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            return ext.value.digest
        except cryptography.x509.ExtensionNotFound:
            return None

    def _get_authority_key_identifier(self):
        try:
            ext = self.cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            issuer = None
            if ext.value.authority_cert_issuer is not None:
                issuer = [cryptography_decode_name(san) for san in ext.value.authority_cert_issuer]
            return ext.value.key_identifier, issuer, ext.value.authority_cert_serial_number
        except cryptography.x509.ExtensionNotFound:
            return None, None, None

    def _get_serial_number(self):
        return cryptography_serial_number_of_cert(self.cert)

    def _get_all_extensions(self):
        return cryptography_get_extensions_from_cert(self.cert)

    def _get_ocsp_uri(self):
        try:
            ext = self.cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in ext.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                        return desc.access_location.value
        except x509.ExtensionNotFound as dummy:
            pass
        return None


class CertificateInfoRetrievalPyOpenSSL(CertificateInfoRetrieval):
    """validate the supplied certificate."""

    def __init__(self, module, content):
        super(CertificateInfoRetrievalPyOpenSSL, self).__init__(module, 'pyopenssl', content)

    def _get_der_bytes(self):
        return crypto.dump_certificate(crypto.FILETYPE_ASN1, self.cert)

    def _get_signature_algorithm(self):
        return to_text(self.cert.get_signature_algorithm())

    def __get_name(self, name):
        result = []
        for sub in name.get_components():
            result.append([pyopenssl_normalize_name(sub[0]), to_text(sub[1])])
        return result

    def _get_subject_ordered(self):
        return self.__get_name(self.cert.get_subject())

    def _get_issuer_ordered(self):
        return self.__get_name(self.cert.get_issuer())

    def _get_version(self):
        # Version numbers in certs are off by one:
        # v1: 0, v2: 1, v3: 2 ...
        return self.cert.get_version() + 1

    def _get_extension(self, short_name):
        for extension_idx in range(0, self.cert.get_extension_count()):
            extension = self.cert.get_extension(extension_idx)
            if extension.get_short_name() == short_name:
                result = [
                    pyopenssl_normalize_name(usage.strip()) for usage in to_text(extension, errors='surrogate_or_strict').split(',')
                ]
                return sorted(result), bool(extension.get_critical())
        return None, False

    def _get_key_usage(self):
        return self._get_extension(b'keyUsage')

    def _get_extended_key_usage(self):
        return self._get_extension(b'extendedKeyUsage')

    def _get_basic_constraints(self):
        return self._get_extension(b'basicConstraints')

    def _get_ocsp_must_staple(self):
        extensions = [self.cert.get_extension(i) for i in range(0, self.cert.get_extension_count())]
        oms_ext = [
            ext for ext in extensions
            if to_bytes(ext.get_short_name()) == OPENSSL_MUST_STAPLE_NAME and to_bytes(ext) == OPENSSL_MUST_STAPLE_VALUE
        ]
        if OpenSSL.SSL.OPENSSL_VERSION_NUMBER < 0x10100000:
            # Older versions of libssl don't know about OCSP Must Staple
            oms_ext.extend([ext for ext in extensions if ext.get_short_name() == b'UNDEF' and ext.get_data() == b'\x30\x03\x02\x01\x05'])
        if oms_ext:
            return True, bool(oms_ext[0].get_critical())
        else:
            return None, False

    def _get_subject_alt_name(self):
        for extension_idx in range(0, self.cert.get_extension_count()):
            extension = self.cert.get_extension(extension_idx)
            if extension.get_short_name() == b'subjectAltName':
                result = [pyopenssl_normalize_name_attribute(altname.strip()) for altname in
                          to_text(extension, errors='surrogate_or_strict').split(', ')]
                return result, bool(extension.get_critical())
        return None, False

    def get_not_before(self):
        time_string = to_native(self.cert.get_notBefore())
        return datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")

    def get_not_after(self):
        time_string = to_native(self.cert.get_notAfter())
        return datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")

    def _get_public_key_pem(self):
        try:
            return crypto.dump_publickey(
                crypto.FILETYPE_PEM,
                self.cert.get_pubkey(),
            )
        except AttributeError:
            try:
                # pyOpenSSL < 16.0:
                bio = crypto._new_mem_buf()
                rc = crypto._lib.PEM_write_bio_PUBKEY(bio, self.cert.get_pubkey()._pkey)
                if rc != 1:
                    crypto._raise_current_error()
                return crypto._bio_to_string(bio)
            except AttributeError:
                self.module.warn('Your pyOpenSSL version does not support dumping public keys. '
                                 'Please upgrade to version 16.0 or newer, or use the cryptography backend.')

    def _get_public_key_object(self):
        return self.cert.get_pubkey()

    def _get_subject_key_identifier(self):
        # Won't be implemented
        return None

    def _get_authority_key_identifier(self):
        # Won't be implemented
        return None, None, None

    def _get_serial_number(self):
        return self.cert.get_serial_number()

    def _get_all_extensions(self):
        return pyopenssl_get_extensions_from_cert(self.cert)

    def _get_ocsp_uri(self):
        for i in range(self.cert.get_extension_count()):
            ext = self.cert.get_extension(i)
            if ext.get_short_name() == b'authorityInfoAccess':
                v = str(ext)
                m = re.search('^OCSP - URI:(.*)$', v, flags=re.MULTILINE)
                if m:
                    return m.group(1)
        return None


def get_certificate_info(module, backend, content, prefer_one_fingerprint=False):
    if backend == 'cryptography':
        info = CertificateInfoRetrievalCryptography(module, content)
    elif backend == 'pyopenssl':
        info = CertificateInfoRetrievalPyOpenSSL(module, content)
    return info.get_info(prefer_one_fingerprint=prefer_one_fingerprint)


def select_backend(module, backend, content):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)
        can_use_pyopenssl = PYOPENSSL_FOUND and PYOPENSSL_VERSION >= LooseVersion(MINIMAL_PYOPENSSL_VERSION)

        # First try cryptography, then pyOpenSSL
        if can_use_cryptography:
            backend = 'cryptography'
        elif can_use_pyopenssl:
            backend = 'pyopenssl'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Can't detect any of the required Python libraries "
                                  "cryptography (>= {0}) or PyOpenSSL (>= {1})").format(
                                      MINIMAL_CRYPTOGRAPHY_VERSION,
                                      MINIMAL_PYOPENSSL_VERSION))

    if backend == 'pyopenssl':
        if not PYOPENSSL_FOUND:
            module.fail_json(msg=missing_required_lib('pyOpenSSL >= {0}'.format(MINIMAL_PYOPENSSL_VERSION)),
                             exception=PYOPENSSL_IMP_ERR)
        try:
            getattr(crypto.X509Req, 'get_extensions')
        except AttributeError:
            module.fail_json(msg='You need to have PyOpenSSL>=0.15 to generate CSRs')

        module.deprecate('The module is using the PyOpenSSL backend. This backend has been deprecated',
                         version='2.0.0', collection_name='community.crypto')
        return backend, CertificateInfoRetrievalPyOpenSSL(module, content)
    elif backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, CertificateInfoRetrievalCryptography(module, content)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))
