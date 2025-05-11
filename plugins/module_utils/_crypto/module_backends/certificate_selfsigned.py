# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import os
import typing as t
from random import randrange

from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_key_needs_digest_for_signing,
    cryptography_verify_certificate_signature,
    get_not_valid_after,
    get_not_valid_before,
    is_potential_certificate_issuer_private_key,
    set_not_valid_after,
    set_not_valid_before,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (
    CertificateBackend,
    CertificateError,
    CertificateProvider,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    select_message_digest,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_relative_time_option,
)


if t.TYPE_CHECKING:
    import datetime

    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.community.crypto.plugins.module_utils._argspec import (
        ArgumentSpec,
    )
    from cryptography.hazmat.primitives.asymmetric.types import (
        CertificateIssuerPrivateKeyTypes,
    )


try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    pass


class SelfSignedCertificateBackendCryptography(CertificateBackend):
    privatekey: CertificateIssuerPrivateKeyTypes

    def __init__(self, module: AnsibleModule) -> None:
        super(SelfSignedCertificateBackendCryptography, self).__init__(module)

        self.create_subject_key_identifier: t.Literal[
            "create_if_not_provided", "always_create", "never_create"
        ] = module.params["selfsigned_create_subject_key_identifier"]
        self.notBefore = get_relative_time_option(
            module.params["selfsigned_not_before"],
            "selfsigned_not_before",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.notAfter = get_relative_time_option(
            module.params["selfsigned_not_after"],
            "selfsigned_not_after",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.digest = select_message_digest(module.params["selfsigned_digest"])
        self.version: int = module.params["selfsigned_version"]
        self.serial_number = x509.random_serial_number()

        if self.csr_path is not None and not os.path.exists(self.csr_path):
            raise CertificateError(
                f"The certificate signing request file {self.csr_path} does not exist"
            )
        if self.privatekey_path is not None and not os.path.exists(
            self.privatekey_path
        ):
            raise CertificateError(
                f"The private key file {self.privatekey_path} does not exist"
            )

        self._module = module

        self._ensure_private_key_loaded()
        if self.privatekey is None:
            raise CertificateError("Private key has not been provided")
        if not is_potential_certificate_issuer_private_key(self.privatekey):
            raise CertificateError("Private key cannot be used to sign certificates")

        if cryptography_key_needs_digest_for_signing(self.privatekey):
            if self.digest is None:
                raise CertificateError(
                    f"The digest {module.params['selfsigned_digest']} is not supported with the cryptography backend"
                )
        else:
            self.digest = None

        self._ensure_csr_loaded()
        if self.csr is None:
            # Create empty CSR on the fly
            csr = cryptography.x509.CertificateSigningRequestBuilder()
            csr = csr.subject_name(cryptography.x509.Name([]))
            self.csr = csr.sign(self.privatekey, self.digest)

    def generate_certificate(self) -> None:
        """(Re-)Generate certificate."""
        if self.csr is None:
            raise AssertionError("Contract violation: csr has not been populated")
        if self.privatekey is None:
            raise AssertionError(
                "Contract violation: privatekey has not been populated"
            )
        try:
            cert_builder = x509.CertificateBuilder()
            cert_builder = cert_builder.subject_name(self.csr.subject)
            cert_builder = cert_builder.issuer_name(self.csr.subject)
            cert_builder = cert_builder.serial_number(self.serial_number)
            cert_builder = set_not_valid_before(cert_builder, self.notBefore)
            cert_builder = set_not_valid_after(cert_builder, self.notAfter)
            cert_builder = cert_builder.public_key(self.privatekey.public_key())
            has_ski = False
            for extension in self.csr.extensions:
                if isinstance(extension.value, x509.SubjectKeyIdentifier):
                    if self.create_subject_key_identifier == "always_create":
                        continue
                    has_ski = True
                cert_builder = cert_builder.add_extension(
                    extension.value, critical=extension.critical
                )
            if not has_ski and self.create_subject_key_identifier != "never_create":
                cert_builder = cert_builder.add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(
                        self.privatekey.public_key()
                    ),
                    critical=False,
                )
        except ValueError as e:
            raise CertificateError(str(e))

        certificate = cert_builder.sign(
            private_key=self.privatekey,
            algorithm=self.digest,
        )

        self.cert = certificate

    def get_certificate_data(self) -> bytes:
        """Return bytes for self.cert."""
        if self.cert is None:
            raise AssertionError("Contract violation: cert has not been populated")
        return self.cert.public_bytes(Encoding.PEM)

    def needs_regeneration(
        self,
        not_before: datetime.datetime | None = None,
        not_after: datetime.datetime | None = None,
    ) -> bool:
        assert self.privatekey is not None

        if super(SelfSignedCertificateBackendCryptography, self).needs_regeneration(
            not_before=self.notBefore, not_after=self.notAfter
        ):
            return True

        self._ensure_existing_certificate_loaded()
        assert self.existing_certificate is not None

        # Check whether certificate is signed by private key
        if not cryptography_verify_certificate_signature(
            self.existing_certificate, self.privatekey.public_key()
        ):
            return True

        return False

    def dump(self, include_certificate: bool) -> dict[str, t.Any]:
        result = super(SelfSignedCertificateBackendCryptography, self).dump(
            include_certificate
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
            assert self.cert is not None
            result.update(
                {
                    "notBefore": get_not_valid_before(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "notAfter": get_not_valid_after(self.cert).strftime(
                        "%Y%m%d%H%M%SZ"
                    ),
                    "serial_number": self.cert.serial_number,
                }
            )

        return result


def generate_serial_number() -> int:
    """Generate a serial number for a certificate"""
    while True:
        result = randrange(0, 1 << 160)
        if result >= 1000:
            return result


class SelfSignedCertificateProvider(CertificateProvider):
    def validate_module_args(self, module: AnsibleModule) -> None:
        if (
            module.params["privatekey_path"] is None
            and module.params["privatekey_content"] is None
        ):
            module.fail_json(
                msg="One of privatekey_path and privatekey_content must be specified for the selfsigned provider."
            )

    def needs_version_two_certs(self, module: AnsibleModule) -> bool:
        return module.params["selfsigned_version"] == 2

    def create_backend(
        self, module: AnsibleModule
    ) -> SelfSignedCertificateBackendCryptography:
        return SelfSignedCertificateBackendCryptography(module)


def add_selfsigned_provider_to_argument_spec(argument_spec: ArgumentSpec) -> None:
    argument_spec.argument_spec["provider"]["choices"].append("selfsigned")
    argument_spec.argument_spec.update(
        dict(
            selfsigned_version=dict(type="int", default=3),
            selfsigned_digest=dict(type="str", default="sha256"),
            selfsigned_not_before=dict(
                type="str", default="+0s", aliases=["selfsigned_notBefore"]
            ),
            selfsigned_not_after=dict(
                type="str", default="+3650d", aliases=["selfsigned_notAfter"]
            ),
            selfsigned_create_subject_key_identifier=dict(
                type="str",
                default="create_if_not_provided",
                choices=["create_if_not_provided", "always_create", "never_create"],
            ),
        )
    )
