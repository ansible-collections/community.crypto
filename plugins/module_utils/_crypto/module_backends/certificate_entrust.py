# Copyright (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import datetime
import os
import typing as t

from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible_collections.community.crypto.plugins.module_utils._crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    get_not_valid_after,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.module_backends.certificate import (
    CertificateBackend,
    CertificateError,
    CertificateProvider,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.support import (
    load_certificate,
)
from ansible_collections.community.crypto.plugins.module_utils._ecs.api import (
    ECSClient,
    RestOperationException,
    SessionConfigurationException,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_now_datetime,
    get_relative_time_option,
)


if t.TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.community.crypto.plugins.module_utils._argspec import (
        ArgumentSpec,
    )


try:
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


class EntrustCertificateBackend(CertificateBackend):
    def __init__(self, *, module: AnsibleModule) -> None:
        super().__init__(module=module)
        self.trackingId = None
        self.notAfter = get_relative_time_option(
            module.params["entrust_not_after"],
            input_name="entrust_not_after",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )

        if self.csr_content is None:
            if self.csr_path is None:
                raise CertificateError(
                    "csr_path or csr_content is required for entrust provider"
                )
            if not os.path.exists(self.csr_path):
                raise CertificateError(
                    f"The certificate signing request file {self.csr_path} does not exist"
                )

        self._ensure_csr_loaded()
        if self.csr is None:
            raise CertificateError("CSR not provided")

        # ECS API defaults to using the validated organization tied to the account.
        # We want to always force behavior of trying to use the organization provided in the CSR.
        # To that end we need to parse out the organization from the CSR.
        self.csr_org = None
        csr_subject_orgs = self.csr.subject.get_attributes_for_oid(
            NameOID.ORGANIZATION_NAME
        )
        if len(csr_subject_orgs) == 1:
            self.csr_org = csr_subject_orgs[0].value
        elif len(csr_subject_orgs) > 1:
            self.module.fail_json(
                msg=(
                    "Entrust provider does not currently support multiple validated organizations. Multiple organizations found in "
                    f"Subject DN: '{self.csr.subject}'. "
                )
            )
        # If no organization in the CSR, explicitly tell ECS that it should be blank in issued cert, not defaulted to
        # organization tied to the account.
        if self.csr_org is None:
            self.csr_org = ""

        try:
            self.ecs_client = ECSClient(
                entrust_api_user=self.module.params["entrust_api_user"],
                entrust_api_key=self.module.params["entrust_api_key"],
                entrust_api_cert=self.module.params["entrust_api_client_cert_path"],
                entrust_api_cert_key=self.module.params[
                    "entrust_api_client_cert_key_path"
                ],
                entrust_api_specification_path=self.module.params[
                    "entrust_api_specification_path"
                ],
            )
        except SessionConfigurationException as e:
            module.fail_json(msg=f"Failed to initialize Entrust Provider: {e}")

    def generate_certificate(self) -> None:
        """(Re-)Generate certificate."""
        body = {}

        # Read the CSR that was generated for us
        if self.csr_content is not None:
            # csr_content contains bytes
            body["csr"] = to_native(self.csr_content)
        else:
            assert self.csr_path is not None
            with open(self.csr_path, "r", encoding="utf-8") as csr_file:
                body["csr"] = csr_file.read()

        body["certType"] = self.module.params["entrust_cert_type"]

        # Handle expiration (30 days if not specified)
        expiry = self.notAfter
        if not expiry:
            gmt_now = get_now_datetime(with_timezone=CRYPTOGRAPHY_TIMEZONE)
            expiry = gmt_now + datetime.timedelta(days=365)

        expiry_iso3339 = expiry.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        body["certExpiryDate"] = expiry_iso3339
        body["org"] = self.csr_org
        body["tracking"] = {
            "requesterName": self.module.params["entrust_requester_name"],
            "requesterEmail": self.module.params["entrust_requester_email"],
            "requesterPhone": self.module.params["entrust_requester_phone"],
        }

        try:
            result = self.ecs_client.NewCertRequest(  # type: ignore[attr-defined]  # pylint: disable=no-member
                Body=body
            )
            self.trackingId = result.get("trackingId")
        except RestOperationException as e:
            self.module.fail_json(
                msg=f"Failed to request new certificate from Entrust Certificate Services (ECS): {e.message}"
            )

        self.cert_bytes = to_bytes(result.get("endEntityCert"))
        self.cert = load_certificate(
            path=None,
            content=self.cert_bytes,
        )

    def get_certificate_data(self) -> bytes:
        """Return bytes for self.cert."""
        return self.cert_bytes

    def needs_regeneration(
        self,
        *,
        not_before: datetime.datetime | None = None,
        not_after: datetime.datetime | None = None,
    ) -> bool:
        parent_check = super().needs_regeneration()

        try:
            cert_details = self._get_cert_details()
        except RestOperationException as e:
            self.module.fail_json(
                msg=f"Failed to get status of existing certificate from Entrust Certificate Services (ECS): {e.message}."
            )

        # Always issue a new certificate if the certificate is expired, suspended or revoked
        status = cert_details.get("status", False)
        if status == "EXPIRED" or status == "SUSPENDED" or status == "REVOKED":
            return True

        # If the requested cert type was specified and it is for a different certificate type than the initial certificate, a new one is needed
        if (
            self.module.params["entrust_cert_type"]
            and cert_details.get("certType")
            and self.module.params["entrust_cert_type"] != cert_details.get("certType")
        ):
            return True

        return parent_check

    def _get_cert_details(self) -> dict[str, t.Any]:
        cert_details: dict[str, t.Any] = {}
        try:
            self._ensure_existing_certificate_loaded()
        except Exception:
            return cert_details
        if self.existing_certificate:
            serial_number = f"{self.existing_certificate.serial_number:X}"
            expiry = get_not_valid_after(self.existing_certificate)

            # get some information about the expiry of this certificate
            expiry_iso3339 = expiry.strftime("%Y-%m-%dT%H:%M:%S.00Z")
            cert_details["expiresAfter"] = expiry_iso3339

            # If a trackingId is not already defined (from the result of a generate)
            # use the serial number to identify the tracking Id
            if self.trackingId is None and serial_number is not None:
                cert_results = self.ecs_client.GetCertificates(  # type: ignore[attr-defined]  # pylint: disable=no-member
                    serialNumber=serial_number
                ).get(
                    "certificates", {}
                )

                # Finding 0 or more than 1 result is a very unlikely use case, it simply means we cannot perform additional checks
                # on the 'state' as returned by Entrust Certificate Services (ECS). The general certificate validity is
                # still checked as it is in the rest of the module.
                if len(cert_results) == 1:
                    self.trackingId = cert_results[0].get("trackingId")

        if self.trackingId is not None:
            cert_details.update(
                self.ecs_client.GetCertificate(  # pylint: disable=no-member
                    trackingId=self.trackingId
                )
            )

        return cert_details


class EntrustCertificateProvider(CertificateProvider):
    def validate_module_args(self, module: AnsibleModule) -> None:
        pass

    def create_backend(self, module: AnsibleModule) -> EntrustCertificateBackend:
        return EntrustCertificateBackend(module=module)


def add_entrust_provider_to_argument_spec(argument_spec: ArgumentSpec) -> None:
    argument_spec.argument_spec["provider"]["choices"].append("entrust")
    argument_spec.argument_spec.update(
        dict(
            entrust_cert_type=dict(
                type="str",
                default="STANDARD_SSL",
                choices=[
                    "STANDARD_SSL",
                    "ADVANTAGE_SSL",
                    "UC_SSL",
                    "EV_SSL",
                    "WILDCARD_SSL",
                    "PRIVATE_SSL",
                    "PD_SSL",
                    "CDS_ENT_LITE",
                    "CDS_ENT_PRO",
                    "SMIME_ENT",
                ],
            ),
            entrust_requester_email=dict(type="str"),
            entrust_requester_name=dict(type="str"),
            entrust_requester_phone=dict(type="str"),
            entrust_api_user=dict(type="str"),
            entrust_api_key=dict(type="str", no_log=True),
            entrust_api_client_cert_path=dict(type="path"),
            entrust_api_client_cert_key_path=dict(type="path", no_log=True),
            entrust_api_specification_path=dict(
                type="path",
                default="https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml",
            ),
            entrust_not_after=dict(type="str", default="+365d"),
        )
    )
    argument_spec.required_if.append(
        (
            "provider",
            "entrust",
            [
                "entrust_requester_email",
                "entrust_requester_name",
                "entrust_requester_phone",
                "entrust_api_user",
                "entrust_api_key",
                "entrust_api_client_cert_path",
                "entrust_api_client_cert_key_path",
            ],
        )
    )


__all__ = (
    "EntrustCertificateBackend",
    "EntrustCertificateProvider",
    "add_entrust_provider_to_argument_spec",
)
