# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import datetime

from ansible.module_utils._text import to_native, to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    parse_name_field,
    get_relative_time_option,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_compare_public_keys,
    cryptography_get_name,
    cryptography_name_to_oid,
    cryptography_parse_key_usage_params,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pyopenssl_support import (
    pyopenssl_normalize_name_attribute,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    CertificateBackend,
    CertificateProvider,
)

try:
    import OpenSSL
    from OpenSSL import crypto
except ImportError:
    pass

try:
    import cryptography
    from cryptography import x509
    from cryptography.x509 import NameAttribute, Name
except ImportError:
    pass


def compare_sets(subset, superset, equality=False):
    if equality:
        return set(subset) == set(superset)
    else:
        return all(x in superset for x in subset)


def compare_dicts(subset, superset, equality=False):
    if equality:
        return subset == superset
    else:
        return all(superset.get(x) == v for x, v in subset.items())


NO_EXTENSION = 'no extension'


class AssertOnlyCertificateBackend(CertificateBackend):
    def __init__(self, module, backend):
        super(AssertOnlyCertificateBackend, self).__init__(module, backend)

        self.signature_algorithms = module.params['signature_algorithms']
        if module.params['subject']:
            self.subject = parse_name_field(module.params['subject'])
        else:
            self.subject = []
        self.subject_strict = module.params['subject_strict']
        if module.params['issuer']:
            self.issuer = parse_name_field(module.params['issuer'])
        else:
            self.issuer = []
        self.issuer_strict = module.params['issuer_strict']
        self.has_expired = module.params['has_expired']
        self.version = module.params['version']
        self.key_usage = module.params['key_usage']
        self.key_usage_strict = module.params['key_usage_strict']
        self.extended_key_usage = module.params['extended_key_usage']
        self.extended_key_usage_strict = module.params['extended_key_usage_strict']
        self.subject_alt_name = module.params['subject_alt_name']
        self.subject_alt_name_strict = module.params['subject_alt_name_strict']
        self.not_before = module.params['not_before']
        self.not_after = module.params['not_after']
        self.valid_at = module.params['valid_at']
        self.invalid_at = module.params['invalid_at']
        self.valid_in = module.params['valid_in']
        if self.valid_in and not self.valid_in.startswith("+") and not self.valid_in.startswith("-"):
            try:
                int(self.valid_in)
            except ValueError:
                module.fail_json(msg='The supplied value for "valid_in" (%s) is not an integer or a valid timespec' % self.valid_in)
            self.valid_in = "+" + self.valid_in + "s"

        # Load objects
        self._ensure_private_key_loaded()
        self._ensure_csr_loaded()

    @abc.abstractmethod
    def _validate_privatekey(self):
        pass

    @abc.abstractmethod
    def _validate_csr_signature(self):
        pass

    @abc.abstractmethod
    def _validate_csr_subject(self):
        pass

    @abc.abstractmethod
    def _validate_csr_extensions(self):
        pass

    @abc.abstractmethod
    def _validate_signature_algorithms(self):
        pass

    @abc.abstractmethod
    def _validate_subject(self):
        pass

    @abc.abstractmethod
    def _validate_issuer(self):
        pass

    @abc.abstractmethod
    def _validate_has_expired(self):
        pass

    @abc.abstractmethod
    def _validate_version(self):
        pass

    @abc.abstractmethod
    def _validate_key_usage(self):
        pass

    @abc.abstractmethod
    def _validate_extended_key_usage(self):
        pass

    @abc.abstractmethod
    def _validate_subject_alt_name(self):
        pass

    @abc.abstractmethod
    def _validate_not_before(self):
        pass

    @abc.abstractmethod
    def _validate_not_after(self):
        pass

    @abc.abstractmethod
    def _validate_valid_at(self):
        pass

    @abc.abstractmethod
    def _validate_invalid_at(self):
        pass

    @abc.abstractmethod
    def _validate_valid_in(self):
        pass

    def assertonly(self):
        messages = []
        if self.privatekey_path is not None or self.privatekey_content is not None:
            if not self._validate_privatekey():
                messages.append(
                    'Certificate %s and private key %s do not match' %
                    (self.path, self.privatekey_path or '(provided in module options)')
                )

        if self.csr_path is not None or self.csr_content is not None:
            if not self._validate_csr_signature():
                messages.append(
                    'Certificate %s and CSR %s do not match: private key mismatch' %
                    (self.path, self.csr_path or '(provided in module options)')
                )
            if not self._validate_csr_subject():
                messages.append(
                    'Certificate %s and CSR %s do not match: subject mismatch' %
                    (self.path, self.csr_path or '(provided in module options)')
                )
            if not self._validate_csr_extensions():
                messages.append(
                    'Certificate %s and CSR %s do not match: extensions mismatch' %
                    (self.path, self.csr_path or '(provided in module options)')
                )

        if self.signature_algorithms is not None:
            wrong_alg = self._validate_signature_algorithms()
            if wrong_alg:
                messages.append(
                    'Invalid signature algorithm (got %s, expected one of %s)' %
                    (wrong_alg, self.signature_algorithms)
                )

        if self.subject is not None:
            failure = self._validate_subject()
            if failure:
                dummy, cert_subject = failure
                messages.append(
                    'Invalid subject component (got %s, expected all of %s to be present)' %
                    (cert_subject, self.subject)
                )

        if self.issuer is not None:
            failure = self._validate_issuer()
            if failure:
                dummy, cert_issuer = failure
                messages.append(
                    'Invalid issuer component (got %s, expected all of %s to be present)' % (cert_issuer, self.issuer)
                )

        if self.has_expired is not None:
            cert_expired = self._validate_has_expired()
            if cert_expired != self.has_expired:
                messages.append(
                    'Certificate expiration check failed (certificate expiration is %s, expected %s)' %
                    (cert_expired, self.has_expired)
                )

        if self.version is not None:
            cert_version = self._validate_version()
            if cert_version != self.version:
                messages.append(
                    'Invalid certificate version number (got %s, expected %s)' %
                    (cert_version, self.version)
                )

        if self.key_usage is not None:
            failure = self._validate_key_usage()
            if failure == NO_EXTENSION:
                messages.append('Found no keyUsage extension')
            elif failure:
                dummy, cert_key_usage = failure
                messages.append(
                    'Invalid keyUsage components (got %s, expected all of %s to be present)' %
                    (cert_key_usage, self.key_usage)
                )

        if self.extended_key_usage is not None:
            failure = self._validate_extended_key_usage()
            if failure == NO_EXTENSION:
                messages.append('Found no extendedKeyUsage extension')
            elif failure:
                dummy, ext_cert_key_usage = failure
                messages.append(
                    'Invalid extendedKeyUsage component (got %s, expected all of %s to be present)' % (ext_cert_key_usage, self.extended_key_usage)
                )

        if self.subject_alt_name is not None:
            failure = self._validate_subject_alt_name()
            if failure == NO_EXTENSION:
                messages.append('Found no subjectAltName extension')
            elif failure:
                dummy, cert_san = failure
                messages.append(
                    'Invalid subjectAltName component (got %s, expected all of %s to be present)' %
                    (cert_san, self.subject_alt_name)
                )

        if self.not_before is not None:
            cert_not_valid_before = self._validate_not_before()
            if cert_not_valid_before != get_relative_time_option(self.not_before, 'not_before', backend=self.backend):
                messages.append(
                    'Invalid not_before component (got %s, expected %s to be present)' %
                    (cert_not_valid_before, self.not_before)
                )

        if self.not_after is not None:
            cert_not_valid_after = self._validate_not_after()
            if cert_not_valid_after != get_relative_time_option(self.not_after, 'not_after', backend=self.backend):
                messages.append(
                    'Invalid not_after component (got %s, expected %s to be present)' %
                    (cert_not_valid_after, self.not_after)
                )

        if self.valid_at is not None:
            not_before, valid_at, not_after = self._validate_valid_at()
            if not (not_before <= valid_at <= not_after):
                messages.append(
                    'Certificate is not valid for the specified date (%s) - not_before: %s - not_after: %s' %
                    (self.valid_at, not_before, not_after)
                )

        if self.invalid_at is not None:
            not_before, invalid_at, not_after = self._validate_invalid_at()
            if not_before <= invalid_at <= not_after:
                messages.append(
                    'Certificate is not invalid for the specified date (%s) - not_before: %s - not_after: %s' %
                    (self.invalid_at, not_before, not_after)
                )

        if self.valid_in is not None:
            not_before, valid_in, not_after = self._validate_valid_in()
            if not not_before <= valid_in <= not_after:
                messages.append(
                    'Certificate is not valid in %s from now (that would be %s) - not_before: %s - not_after: %s' %
                    (self.valid_in, valid_in, not_before, not_after)
                )
        return messages

    def needs_regeneration(self):
        self._ensure_existing_certificate_loaded()
        if self.existing_certificate is None:
            self.messages = ['Certificate not provided']
        else:
            self.messages = self.assertonly()

        return len(self.messages) != 0

    def generate_certificate(self):
        self.module.fail_json(msg=' | '.join(self.messages))

    def get_certificate_data(self):
        return self.existing_certificate_bytes


class AssertOnlyCertificateBackendCryptography(AssertOnlyCertificateBackend):
    """Validate the supplied cert, using the cryptography backend"""
    def __init__(self, module):
        super(AssertOnlyCertificateBackendCryptography, self).__init__(module, 'cryptography')

    def _validate_privatekey(self):
        return cryptography_compare_public_keys(self.existing_certificate.public_key(), self.privatekey.public_key())

    def _validate_csr_signature(self):
        if not self.csr.is_signature_valid:
            return False
        return cryptography_compare_public_keys(self.csr.public_key(), self.existing_certificate.public_key())

    def _validate_csr_subject(self):
        return self.csr.subject == self.existing_certificate.subject

    def _validate_csr_extensions(self):
        cert_exts = self.existing_certificate.extensions
        csr_exts = self.csr.extensions
        if len(cert_exts) != len(csr_exts):
            return False
        for cert_ext in cert_exts:
            try:
                csr_ext = csr_exts.get_extension_for_oid(cert_ext.oid)
                if cert_ext != csr_ext:
                    return False
            except cryptography.x509.ExtensionNotFound as dummy:
                return False
        return True

    def _validate_signature_algorithms(self):
        if self.existing_certificate.signature_algorithm_oid._name not in self.signature_algorithms:
            return self.existing_certificate.signature_algorithm_oid._name

    def _validate_subject(self):
        expected_subject = Name([NameAttribute(oid=cryptography_name_to_oid(sub[0]), value=to_text(sub[1]))
                                 for sub in self.subject])
        cert_subject = self.existing_certificate.subject
        if not compare_sets(expected_subject, cert_subject, self.subject_strict):
            return expected_subject, cert_subject

    def _validate_issuer(self):
        expected_issuer = Name([NameAttribute(oid=cryptography_name_to_oid(iss[0]), value=to_text(iss[1]))
                                for iss in self.issuer])
        cert_issuer = self.existing_certificate.issuer
        if not compare_sets(expected_issuer, cert_issuer, self.issuer_strict):
            return self.issuer, cert_issuer

    def _validate_has_expired(self):
        cert_not_after = self.existing_certificate.not_valid_after
        cert_expired = cert_not_after < datetime.datetime.utcnow()
        return cert_expired

    def _validate_version(self):
        if self.existing_certificate.version == x509.Version.v1:
            return 1
        if self.existing_certificate.version == x509.Version.v3:
            return 3
        return "unknown"

    def _validate_key_usage(self):
        try:
            current_key_usage = self.existing_certificate.extensions.get_extension_for_class(x509.KeyUsage).value
            test_key_usage = dict(
                digital_signature=current_key_usage.digital_signature,
                content_commitment=current_key_usage.content_commitment,
                key_encipherment=current_key_usage.key_encipherment,
                data_encipherment=current_key_usage.data_encipherment,
                key_agreement=current_key_usage.key_agreement,
                key_cert_sign=current_key_usage.key_cert_sign,
                crl_sign=current_key_usage.crl_sign,
                encipher_only=False,
                decipher_only=False
            )
            if test_key_usage['key_agreement']:
                test_key_usage.update(dict(
                    encipher_only=current_key_usage.encipher_only,
                    decipher_only=current_key_usage.decipher_only
                ))

            key_usages = cryptography_parse_key_usage_params(self.key_usage)
            if not compare_dicts(key_usages, test_key_usage, self.key_usage_strict):
                return self.key_usage, [k for k, v in test_key_usage.items() if v is True]

        except cryptography.x509.ExtensionNotFound:
            # This is only bad if the user specified a non-empty list
            if self.key_usage:
                return NO_EXTENSION

    def _validate_extended_key_usage(self):
        try:
            current_ext_keyusage = self.existing_certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            usages = [cryptography_name_to_oid(usage) for usage in self.extended_key_usage]
            expected_ext_keyusage = x509.ExtendedKeyUsage(usages)
            if not compare_sets(expected_ext_keyusage, current_ext_keyusage, self.extended_key_usage_strict):
                return [eku.value for eku in expected_ext_keyusage], [eku.value for eku in current_ext_keyusage]

        except cryptography.x509.ExtensionNotFound:
            # This is only bad if the user specified a non-empty list
            if self.extended_key_usage:
                return NO_EXTENSION

    def _validate_subject_alt_name(self):
        try:
            current_san = self.existing_certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            expected_san = [cryptography_get_name(san) for san in self.subject_alt_name]
            if not compare_sets(expected_san, current_san, self.subject_alt_name_strict):
                return self.subject_alt_name, current_san
        except cryptography.x509.ExtensionNotFound:
            # This is only bad if the user specified a non-empty list
            if self.subject_alt_name:
                return NO_EXTENSION

    def _validate_not_before(self):
        return self.existing_certificate.not_valid_before

    def _validate_not_after(self):
        return self.existing_certificate.not_valid_after

    def _validate_valid_at(self):
        rt = get_relative_time_option(self.valid_at, 'valid_at', backend=self.backend)
        return self.existing_certificate.not_valid_before, rt, self.existing_certificate.not_valid_after

    def _validate_invalid_at(self):
        rt = get_relative_time_option(self.invalid_at, 'invalid_at', backend=self.backend)
        return self.existing_certificate.not_valid_before, rt, self.existing_certificate.not_valid_after

    def _validate_valid_in(self):
        valid_in_date = get_relative_time_option(self.valid_in, "valid_in", backend=self.backend)
        return self.existing_certificate.not_valid_before, valid_in_date, self.existing_certificate.not_valid_after


class AssertOnlyCertificateBackendPyOpenSSL(AssertOnlyCertificateBackend):
    """validate the supplied certificate."""

    def __init__(self, module):
        super(AssertOnlyCertificateBackendPyOpenSSL, self).__init__(module, 'pyopenssl')

        # Ensure inputs are properly sanitized before comparison.
        for param in ['signature_algorithms', 'key_usage', 'extended_key_usage',
                      'subject_alt_name', 'subject', 'issuer', 'not_before',
                      'not_after', 'valid_at', 'invalid_at']:
            attr = getattr(self, param)
            if isinstance(attr, list) and attr:
                if isinstance(attr[0], str):
                    setattr(self, param, [to_bytes(item) for item in attr])
                elif isinstance(attr[0], tuple):
                    setattr(self, param, [(to_bytes(item[0]), to_bytes(item[1])) for item in attr])
            elif isinstance(attr, tuple):
                setattr(self, param, dict((to_bytes(k), to_bytes(v)) for (k, v) in attr.items()))
            elif isinstance(attr, dict):
                setattr(self, param, dict((to_bytes(k), to_bytes(v)) for (k, v) in attr.items()))
            elif isinstance(attr, str):
                setattr(self, param, to_bytes(attr))

    def _validate_privatekey(self):
        ctx = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
        ctx.use_privatekey(self.privatekey)
        ctx.use_certificate(self.existing_certificate)
        try:
            ctx.check_privatekey()
            return True
        except OpenSSL.SSL.Error:
            return False

    def _validate_csr_signature(self):
        try:
            self.csr.verify(self.existing_certificate.get_pubkey())
        except OpenSSL.crypto.Error:
            return False

    def _validate_csr_subject(self):
        if self.csr.get_subject() != self.existing_certificate.get_subject():
            return False

    def _validate_csr_extensions(self):
        csr_extensions = self.csr.get_extensions()
        cert_extension_count = self.existing_certificate.get_extension_count()
        if len(csr_extensions) != cert_extension_count:
            return False
        for extension_number in range(0, cert_extension_count):
            cert_extension = self.existing_certificate.get_extension(extension_number)
            csr_extension = filter(lambda extension: extension.get_short_name() == cert_extension.get_short_name(), csr_extensions)
            if cert_extension.get_data() != list(csr_extension)[0].get_data():
                return False
        return True

    def _validate_signature_algorithms(self):
        if self.existing_certificate.get_signature_algorithm() not in self.signature_algorithms:
            return self.existing_certificate.get_signature_algorithm()

    def _validate_subject(self):
        expected_subject = [(OpenSSL._util.lib.OBJ_txt2nid(sub[0]), sub[1]) for sub in self.subject]
        cert_subject = self.existing_certificate.get_subject().get_components()
        current_subject = [(OpenSSL._util.lib.OBJ_txt2nid(sub[0]), sub[1]) for sub in cert_subject]
        if not compare_sets(expected_subject, current_subject, self.subject_strict):
            return expected_subject, current_subject

    def _validate_issuer(self):
        expected_issuer = [(OpenSSL._util.lib.OBJ_txt2nid(iss[0]), iss[1]) for iss in self.issuer]
        cert_issuer = self.existing_certificate.get_issuer().get_components()
        current_issuer = [(OpenSSL._util.lib.OBJ_txt2nid(iss[0]), iss[1]) for iss in cert_issuer]
        if not compare_sets(expected_issuer, current_issuer, self.issuer_strict):
            return self.issuer, cert_issuer

    def _validate_has_expired(self):
        # The following 3 lines are the same as the current PyOpenSSL code for cert.has_expired().
        # Older version of PyOpenSSL have a buggy implementation,
        # to avoid issues with those we added the code from a more recent release here.

        time_string = to_native(self.existing_certificate.get_notAfter())
        not_after = datetime.datetime.strptime(time_string, "%Y%m%d%H%M%SZ")
        cert_expired = not_after < datetime.datetime.utcnow()
        return cert_expired

    def _validate_version(self):
        # Version numbers in certs are off by one:
        # v1: 0, v2: 1, v3: 2 ...
        return self.existing_certificate.get_version() + 1

    def _validate_key_usage(self):
        found = False
        for extension_idx in range(0, self.existing_certificate.get_extension_count()):
            extension = self.existing_certificate.get_extension(extension_idx)
            if extension.get_short_name() == b'keyUsage':
                found = True
                expected_extension = crypto.X509Extension(b"keyUsage", False, b', '.join(self.key_usage))
                key_usage = [usage.strip() for usage in to_text(expected_extension, errors='surrogate_or_strict').split(',')]
                current_ku = [usage.strip() for usage in to_text(extension, errors='surrogate_or_strict').split(',')]
                if not compare_sets(key_usage, current_ku, self.key_usage_strict):
                    return self.key_usage, str(extension).split(', ')
        if not found:
            # This is only bad if the user specified a non-empty list
            if self.key_usage:
                return NO_EXTENSION

    def _validate_extended_key_usage(self):
        found = False
        for extension_idx in range(0, self.existing_certificate.get_extension_count()):
            extension = self.existing_certificate.get_extension(extension_idx)
            if extension.get_short_name() == b'extendedKeyUsage':
                found = True
                extKeyUsage = [OpenSSL._util.lib.OBJ_txt2nid(keyUsage) for keyUsage in self.extended_key_usage]
                current_xku = [OpenSSL._util.lib.OBJ_txt2nid(usage.strip()) for usage in
                               to_bytes(extension, errors='surrogate_or_strict').split(b',')]
                if not compare_sets(extKeyUsage, current_xku, self.extended_key_usage_strict):
                    return self.extended_key_usage, str(extension).split(', ')
        if not found:
            # This is only bad if the user specified a non-empty list
            if self.extended_key_usage:
                return NO_EXTENSION

    def _validate_subject_alt_name(self):
        found = False
        for extension_idx in range(0, self.existing_certificate.get_extension_count()):
            extension = self.existing_certificate.get_extension(extension_idx)
            if extension.get_short_name() == b'subjectAltName':
                found = True
                l_altnames = [pyopenssl_normalize_name_attribute(altname.strip()) for altname in
                              to_text(extension, errors='surrogate_or_strict').split(', ')]
                sans = [pyopenssl_normalize_name_attribute(to_text(san, errors='surrogate_or_strict')) for san in self.subject_alt_name]
                if not compare_sets(sans, l_altnames, self.subject_alt_name_strict):
                    return self.subject_alt_name, l_altnames
        if not found:
            # This is only bad if the user specified a non-empty list
            if self.subject_alt_name:
                return NO_EXTENSION

    def _validate_not_before(self):
        return self.existing_certificate.get_notBefore()

    def _validate_not_after(self):
        return self.existing_certificate.get_notAfter()

    def _validate_valid_at(self):
        rt = get_relative_time_option(self.valid_at, "valid_at", backend=self.backend)
        rt = to_bytes(rt, errors='surrogate_or_strict')
        return self.existing_certificate.get_notBefore(), rt, self.existing_certificate.get_notAfter()

    def _validate_invalid_at(self):
        rt = get_relative_time_option(self.invalid_at, "invalid_at", backend=self.backend)
        rt = to_bytes(rt, errors='surrogate_or_strict')
        return self.existing_certificate.get_notBefore(), rt, self.existing_certificate.get_notAfter()

    def _validate_valid_in(self):
        valid_in_asn1 = get_relative_time_option(self.valid_in, "valid_in", backend=self.backend)
        valid_in_date = to_bytes(valid_in_asn1, errors='surrogate_or_strict')
        return self.existing_certificate.get_notBefore(), valid_in_date, self.existing_certificate.get_notAfter()


class AssertOnlyCertificateProvider(CertificateProvider):
    def validate_module_args(self, module):
        module.deprecate("The 'assertonly' provider is deprecated; please see the examples of "
                         "the 'x509_certificate' module on how to replace it with other modules",
                         version='2.0.0', collection_name='community.crypto')

    def needs_version_two_certs(self, module):
        return False

    def create_backend(self, module, backend):
        if backend == 'cryptography':
            return AssertOnlyCertificateBackendCryptography(module)
        if backend == 'pyopenssl':
            return AssertOnlyCertificateBackendPyOpenSSL(module)


def add_assertonly_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('assertonly')
    argument_spec.argument_spec.update(dict(
        signature_algorithms=dict(type='list', elements='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        issuer=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        issuer_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        has_expired=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        version=dict(type='int', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        key_usage=dict(type='list', elements='str', aliases=['keyUsage'],
                       removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        key_usage_strict=dict(type='bool', default=False, aliases=['keyUsage_strict'],
                              removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        extended_key_usage=dict(type='list', elements='str', aliases=['extendedKeyUsage'],
                                removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        extended_key_usage_strict=dict(type='bool', default=False, aliases=['extendedKeyUsage_strict'],
                                       removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_alt_name=dict(type='list', elements='str', aliases=['subjectAltName'],
                              removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_alt_name_strict=dict(type='bool', default=False, aliases=['subjectAltName_strict'],
                                     removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        not_before=dict(type='str', aliases=['notBefore'], removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        not_after=dict(type='str', aliases=['notAfter'], removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        valid_at=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        invalid_at=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        valid_in=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
    ))
