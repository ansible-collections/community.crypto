# -*- coding: utf-8 -*-

# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import os
from random import randrange

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLBadPassphraseError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_compare_public_keys,
    cryptography_key_needs_digest_for_signing,
    cryptography_serial_number_of_cert,
    cryptography_verify_certificate_signature,
    get_not_valid_after,
    get_not_valid_before,
    set_not_valid_after,
    set_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    CRYPTOGRAPHY_VERSION,
    CertificateBackend,
    CertificateError,
    CertificateProvider,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_certificate,
    load_privatekey,
    select_message_digest,
)
from ansible_collections.community.crypto.plugins.module_utils.time import (
    get_relative_time_option,
)
from ansible_collections.community.crypto.plugins.module_utils.version import (
    LooseVersion,
)


try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    pass


class OwnCACertificateBackendCryptography(CertificateBackend):
    def __init__(self, module):
        super(OwnCACertificateBackendCryptography, self).__init__(
            module, "cryptography"
        )

        self.create_subject_key_identifier = module.params[
            "ownca_create_subject_key_identifier"
        ]
        self.create_authority_key_identifier = module.params[
            "ownca_create_authority_key_identifier"
        ]
        self.notBefore = get_relative_time_option(
            module.params["ownca_not_before"],
            "ownca_not_before",
            backend=self.backend,
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.notAfter = get_relative_time_option(
            module.params["ownca_not_after"],
            "ownca_not_after",
            backend=self.backend,
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.digest = select_message_digest(module.params["ownca_digest"])
        self.version = module.params["ownca_version"]
        self.serial_number = x509.random_serial_number()
        self.ca_cert_path = module.params["ownca_path"]
        self.ca_cert_content = module.params["ownca_content"]
        if self.ca_cert_content is not None:
            self.ca_cert_content = self.ca_cert_content.encode("utf-8")
        self.ca_privatekey_path = module.params["ownca_privatekey_path"]
        self.ca_privatekey_content = module.params["ownca_privatekey_content"]
        if self.ca_privatekey_content is not None:
            self.ca_privatekey_content = self.ca_privatekey_content.encode("utf-8")
        self.ca_privatekey_passphrase = module.params["ownca_privatekey_passphrase"]

        if self.csr_content is None and self.csr_path is None:
            raise CertificateError(
                "csr_path or csr_content is required for ownca provider"
            )
        if self.csr_content is None and not os.path.exists(self.csr_path):
            raise CertificateError(
                "The certificate signing request file {0} does not exist".format(
                    self.csr_path
                )
            )
        if self.ca_cert_content is None and not os.path.exists(self.ca_cert_path):
            raise CertificateError(
                "The CA certificate file {0} does not exist".format(self.ca_cert_path)
            )
        if self.ca_privatekey_content is None and not os.path.exists(
            self.ca_privatekey_path
        ):
            raise CertificateError(
                "The CA private key file {0} does not exist".format(
                    self.ca_privatekey_path
                )
            )

        self._ensure_csr_loaded()
        self.ca_cert = load_certificate(
            path=self.ca_cert_path, content=self.ca_cert_content, backend=self.backend
        )
        try:
            self.ca_private_key = load_privatekey(
                path=self.ca_privatekey_path,
                content=self.ca_privatekey_content,
                passphrase=self.ca_privatekey_passphrase,
                backend=self.backend,
            )
        except OpenSSLBadPassphraseError as exc:
            module.fail_json(msg=str(exc))

        if not cryptography_compare_public_keys(
            self.ca_cert.public_key(), self.ca_private_key.public_key()
        ):
            raise CertificateError(
                "The CA private key does not belong to the CA certificate"
            )

        if cryptography_key_needs_digest_for_signing(self.ca_private_key):
            if self.digest is None:
                raise CertificateError(
                    "The digest %s is not supported with the cryptography backend"
                    % module.params["ownca_digest"]
                )
        else:
            self.digest = None

    def generate_certificate(self):
        """(Re-)Generate certificate."""
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(self.csr.subject)
        cert_builder = cert_builder.issuer_name(self.ca_cert.subject)
        cert_builder = cert_builder.serial_number(self.serial_number)
        cert_builder = set_not_valid_before(cert_builder, self.notBefore)
        cert_builder = set_not_valid_after(cert_builder, self.notAfter)
        cert_builder = cert_builder.public_key(self.csr.public_key())
        has_ski = False
        for extension in self.csr.extensions:
            if isinstance(extension.value, x509.SubjectKeyIdentifier):
                if self.create_subject_key_identifier == "always_create":
                    continue
                has_ski = True
            if self.create_authority_key_identifier and isinstance(
                extension.value, x509.AuthorityKeyIdentifier
            ):
                continue
            cert_builder = cert_builder.add_extension(
                extension.value, critical=extension.critical
            )
        if not has_ski and self.create_subject_key_identifier != "never_create":
            cert_builder = cert_builder.add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.csr.public_key()),
                critical=False,
            )
        if self.create_authority_key_identifier:
            try:
                ext = self.ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                cert_builder = cert_builder.add_extension(
                    (
                        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                            ext.value
                        )
                        if CRYPTOGRAPHY_VERSION >= LooseVersion("2.7")
                        else x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                            ext
                        )
                    ),
                    critical=False,
                )
            except cryptography.x509.ExtensionNotFound:
                cert_builder = cert_builder.add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        self.ca_cert.public_key()
                    ),
                    critical=False,
                )

        try:
            certificate = cert_builder.sign(
                private_key=self.ca_private_key,
                algorithm=self.digest,
                backend=default_backend(),
            )
        except TypeError as e:
            if (
                str(e) == "Algorithm must be a registered hash algorithm."
                and self.digest is None
            ):
                self.module.fail_json(
                    msg="Signing with Ed25519 and Ed448 keys requires cryptography 2.8 or newer."
                )
            raise

        self.cert = certificate

    def get_certificate_data(self):
        """Return bytes for self.cert."""
        return self.cert.public_bytes(Encoding.PEM)

    def needs_regeneration(self):
        if super(OwnCACertificateBackendCryptography, self).needs_regeneration(
            not_before=self.notBefore, not_after=self.notAfter
        ):
            return True

        self._ensure_existing_certificate_loaded()

        # Check whether certificate is signed by CA certificate
        if not cryptography_verify_certificate_signature(
            self.existing_certificate, self.ca_cert.public_key()
        ):
            return True

        # Check subject
        if self.ca_cert.subject != self.existing_certificate.issuer:
            return True

        # Check AuthorityKeyIdentifier
        if self.create_authority_key_identifier:
            try:
                ext = self.ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                )
                expected_ext = (
                    x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                        ext.value
                    )
                    if CRYPTOGRAPHY_VERSION >= LooseVersion("2.7")
                    else x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                        ext
                    )
                )
            except cryptography.x509.ExtensionNotFound:
                expected_ext = x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()
                )

            try:
                ext = self.existing_certificate.extensions.get_extension_for_class(
                    x509.AuthorityKeyIdentifier
                )
                if ext.value != expected_ext:
                    return True
            except cryptography.x509.ExtensionNotFound:
                return True

        return False

    def dump(self, include_certificate):
        result = super(OwnCACertificateBackendCryptography, self).dump(
            include_certificate
        )
        result.update(
            {
                "ca_cert": self.ca_cert_path,
                "ca_privatekey": self.ca_privatekey_path,
            }
        )

        if self.module.check_mode:
            result.update(
                {
                    "notBefore": self.notBefore.strftime("%Y%m%d%H%M%SZ"),
                    "notAfter": self.notAfter.strftime("%Y%m%d%H%M%SZ"),
                    "serial_number": self.serial_number,
                }
            )
        else:
            if self.cert is None:
                self.cert = self.existing_certificate
            result.update(
                {
                    "notBefore": get_not_valid_before(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "notAfter": get_not_valid_after(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "serial_number": cryptography_serial_number_of_cert(self.cert),
                }
            )

        return result


def generate_serial_number():
    """Generate a serial number for a certificate"""
    while True:
        result = randrange(0, 1 << 160)
        if result >= 1000:
            return result


class OwnCACertificateProvider(CertificateProvider):
    def validate_module_args(self, module):
        if (
            module.params["ownca_path"] is None
            and module.params["ownca_content"] is None
        ):
            module.fail_json(
                msg="One of ownca_path and ownca_content must be specified for the ownca provider."
            )
        if (
            module.params["ownca_privatekey_path"] is None
            and module.params["ownca_privatekey_content"] is None
        ):
            module.fail_json(
                msg="One of ownca_privatekey_path and ownca_privatekey_content must be specified for the ownca provider."
            )

    def needs_version_two_certs(self, module):
        return module.params["ownca_version"] == 2

    def create_backend(self, module, backend):
        if backend == "cryptography":
            return OwnCACertificateBackendCryptography(module)


def add_ownca_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec["provider"]["choices"].append("ownca")
    argument_spec.argument_spec.update(
        dict(
            ownca_path=dict(type="path"),
            ownca_content=dict(type="str"),
            ownca_privatekey_path=dict(type="path"),
            ownca_privatekey_content=dict(type="str", no_log=True),
            ownca_privatekey_passphrase=dict(type="str", no_log=True),
            ownca_digest=dict(type="str", default="sha256"),
            ownca_version=dict(type="int", default=3),
            ownca_not_before=dict(type="str", default="+0s"),
            ownca_not_after=dict(type="str", default="+3650d"),
            ownca_create_subject_key_identifier=dict(
                type="str",
                default="create_if_not_provided",
                choices=["create_if_not_provided", "always_create", "never_create"],
            ),
            ownca_create_authority_key_identifier=dict(type="bool", default=True),
        )
    )
    argument_spec.mutually_exclusive.extend(
        [
            ["ownca_path", "ownca_content"],
            ["ownca_privatekey_path", "ownca_privatekey_content"],
        ]
    )
