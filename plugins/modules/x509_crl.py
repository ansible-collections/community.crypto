#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = r"""
module: x509_crl
version_added: '1.0.0'
short_description: Generate Certificate Revocation Lists (CRLs)
description:
  - This module allows one to (re)generate or update Certificate Revocation Lists (CRLs).
  - Certificates on the revocation list can be either specified by serial number and (optionally) their issuer, or as a path
    to a certificate file in PEM format.
requirements:
  - cryptography >= 1.2
author:
  - Felix Fontein (@felixfontein)
extends_documentation_fragment:
  - ansible.builtin.files
  - community.crypto.attributes
  - community.crypto.attributes.files
  - community.crypto.name_encoding
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  safe_file_operations:
    support: full
  idempotent:
    support: partial
    details:
      - The module is not idempotent if O(force=true).
      - If relative timestamps and O(ignore_timestamps=false) (default), the module is not idempotent.
options:
  state:
    description:
      - Whether the CRL file should exist or not, taking action if the state is different from what is stated.
    type: str
    default: present
    choices: [absent, present]

  crl_mode:
    description:
      - Defines how to process entries of existing CRLs.
      - If set to V(generate), makes sure that the CRL has the exact set of revoked certificates as specified in O(revoked_certificates).
      - If set to V(update), makes sure that the CRL contains the revoked certificates from O(revoked_certificates), but can
        also contain other revoked certificates. If the CRL file already exists, all entries from the existing CRL will also
        be included in the new CRL. When using V(update), you might be interested in setting O(ignore_timestamps) to V(true).
      - The default value is V(generate).
      - This parameter was called O(mode) before community.crypto 2.13.0. It has been renamed to avoid a collision with the
        common O(mode) parameter for setting the CRL file's access mode.
    type: str
        # default: generate
    choices: [generate, update]
    version_added: 2.13.0
  mode:
    description:
      - This parameter has been renamed to O(crl_mode). The old name O(mode) is now deprecated and will be removed in community.crypto
        3.0.0. Replace usage of this parameter with O(crl_mode).
      - Note that from community.crypto 3.0.0 on, O(mode) will be used for the CRL file's mode.
    type: str
        # default: generate
    choices: [generate, update]

  force:
    description:
      - Should the CRL be forced to be regenerated.
    type: bool
    default: false

  backup:
    description:
      - Create a backup file including a timestamp so you can get the original CRL back if you overwrote it with a new one
        by accident.
    type: bool
    default: false

  path:
    description:
      - Remote absolute path where the generated CRL file should be created or is already located.
    type: path
    required: true

  format:
    description:
      - Whether the CRL file should be in PEM or DER format.
      - If an existing CRL file does match everything but O(format), it will be converted to the correct format instead of
        regenerated.
    type: str
    choices: [pem, der]
    default: pem

  privatekey_path:
    description:
      - Path to the CA's private key to use when signing the CRL.
      - Either O(privatekey_path) or O(privatekey_content) must be specified if O(state) is V(present), but not both.
    type: path

  privatekey_content:
    description:
      - The content of the CA's private key to use when signing the CRL.
      - Either O(privatekey_path) or O(privatekey_content) must be specified if O(state) is V(present), but not both.
    type: str

  privatekey_passphrase:
    description:
      - The passphrase for the O(privatekey_path).
      - This is required if the private key is password protected.
    type: str

  issuer:
    description:
      - Key/value pairs that will be present in the issuer name field of the CRL.
      - If you need to specify more than one value with the same key, use a list as value.
      - If the order of the components is important, use O(issuer_ordered).
      - One of O(issuer) and O(issuer_ordered) is required if O(state) is V(present).
      - Mutually exclusive with O(issuer_ordered).
    type: dict
  issuer_ordered:
    description:
      - A list of dictionaries, where every dictionary must contain one key/value pair. This key/value pair will be present
        in the issuer name field of the CRL.
      - If you want to specify more than one value with the same key in a row, you can use a list as value.
      - One of O(issuer) and O(issuer_ordered) is required if O(state) is V(present).
      - Mutually exclusive with O(issuer).
    type: list
    elements: dict
    version_added: 2.0.0

  last_update:
    description:
      - The point in time from which this CRL can be trusted.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer + C([w | d | h | m | s]) (for example
        V(+32w1d2h)).
      - Note that if using relative time this module is NOT idempotent, except when O(ignore_timestamps) is set to V(true).
    type: str
    default: "+0s"

  next_update:
    description:
      - The absolute latest point in time by which this O(issuer) is expected to have issued another CRL. Many clients will
        treat a CRL as expired once O(next_update) occurs.
      - Time can be specified either as relative time or as absolute timestamp.
      - Time will always be interpreted as UTC.
      - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer + C([w | d | h | m | s]) (for example
        V(+32w1d2h)).
      - Note that if using relative time this module is NOT idempotent, except when O(ignore_timestamps) is set to V(true).
      - Required if O(state) is V(present).
    type: str

  digest:
    description:
      - Digest algorithm to be used when signing the CRL.
    type: str
    default: sha256

  serial_numbers:
    description:
      - This option determines which values will be accepted for O(revoked_certificates[].serial_number).
      - If set to V(integer) (default), serial numbers are assumed to be integers, for example V(66223). (This example value
        is equivalent to the hex octet string V(01:02:AF)).
      - If set to V(hex-octets), serial numbers are assumed to be colon-separated hex octet strings, for example V(01:02:AF).
        (This example value is equivalent to the integer V(66223)).
    type: str
    choices:
      - integer
      - hex-octets
    default: integer
    version_added: 2.18.0

  revoked_certificates:
    description:
      - List of certificates to be revoked.
      - Required if O(state) is V(present).
    type: list
    elements: dict
    suboptions:
      path:
        description:
          - Path to a certificate in PEM format.
          - The serial number and issuer will be extracted from the certificate.
          - Mutually exclusive with O(revoked_certificates[].content) and O(revoked_certificates[].serial_number). One of
            these three options must be specified.
        type: path
      content:
        description:
          - Content of a certificate in PEM format.
          - The serial number and issuer will be extracted from the certificate.
          - Mutually exclusive with O(revoked_certificates[].path) and O(revoked_certificates[].serial_number). One of these
            three options must be specified.
        type: str
      serial_number:
        description:
          - Serial number of the certificate.
          - Mutually exclusive with O(revoked_certificates[].path) and O(revoked_certificates[].content). One of these three
            options must be specified.
          - This option accepts integers or hex octet strings, depending on the value of O(serial_numbers).
          - If O(serial_numbers=integer), integers such as V(66223) must be provided.
          - If O(serial_numbers=hex-octets), strings such as V(01:02:AF) must be provided.
          - You can use the filters P(community.crypto.parse_serial#filter) and P(community.crypto.to_serial#filter) to convert
            these two representations.
        type: raw
      revocation_date:
        description:
          - The point in time the certificate was revoked.
          - Time can be specified either as relative time or as absolute timestamp.
          - Time will always be interpreted as UTC.
          - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer + C([w | d | h | m | s]) (for example
            V(+32w1d2h)).
          - Note that if using relative time this module is NOT idempotent, except when O(ignore_timestamps) is set to V(true).
        type: str
        default: "+0s"
      issuer:
        description:
          - The certificate's issuer.
          - 'Example: V(DNS:ca.example.org).'
        type: list
        elements: str
      issuer_critical:
        description:
          - Whether the certificate issuer extension should be critical.
        type: bool
        default: false
      reason:
        description:
          - The value for the revocation reason extension.
        type: str
        choices:
          - unspecified
          - key_compromise
          - ca_compromise
          - affiliation_changed
          - superseded
          - cessation_of_operation
          - certificate_hold
          - privilege_withdrawn
          - aa_compromise
          - remove_from_crl
      reason_critical:
        description:
          - Whether the revocation reason extension should be critical.
        type: bool
        default: false
      invalidity_date:
        description:
          - The point in time it was known/suspected that the private key was compromised or that the certificate otherwise
            became invalid.
          - Time can be specified either as relative time or as absolute timestamp.
          - Time will always be interpreted as UTC.
          - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer + C([w | d | h | m | s]) (for example
            V(+32w1d2h)).
          - Note that if using relative time this module is NOT idempotent. This will NOT change when O(ignore_timestamps)
            is set to V(true).
        type: str
      invalidity_date_critical:
        description:
          - Whether the invalidity date extension should be critical.
        type: bool
        default: false

  ignore_timestamps:
    description:
      - Whether the timestamps O(last_update), O(next_update) and O(revoked_certificates[].revocation_date) should be ignored
        for idempotency checks. The timestamp O(revoked_certificates[].invalidity_date) will never be ignored.
      - Use this in combination with relative timestamps for these values to get idempotency.
    type: bool
    default: false

  return_content:
    description:
      - If set to V(true), will return the (current or generated) CRL's content as RV(crl).
    type: bool
    default: false

notes:
  - All ASN.1 TIME values should be specified following the YYYYMMDDHHMMSSZ pattern.
  - Date specified should be UTC. Minutes and seconds are mandatory.
seealso:
  - plugin: community.crypto.parse_serial
    plugin_type: filter
  - plugin: community.crypto.to_serial
    plugin_type: filter
"""

EXAMPLES = r"""
---
- name: Generate a CRL
  community.crypto.x509_crl:
    path: /etc/ssl/my-ca.crl
    privatekey_path: /etc/ssl/private/my-ca.pem
    issuer:
      CN: My CA
    last_update: "+0s"
    next_update: "+7d"
    revoked_certificates:
      - serial_number: 1234
        revocation_date: 20190331202428Z
        issuer:
          CN: My CA
      - serial_number: 2345
        revocation_date: 20191013152910Z
        reason: affiliation_changed
        invalidity_date: 20191001000000Z
      - path: /etc/ssl/crt/revoked-cert.pem
        revocation_date: 20191010010203Z
"""

RETURN = r"""
filename:
  description: Path to the generated CRL.
  returned: changed or success
  type: str
  sample: /path/to/my-ca.crl
backup_file:
  description: Name of backup file created.
  returned: changed and if O(backup) is V(true)
  type: str
  sample: /path/to/my-ca.crl.2019-03-09@11:22~
privatekey:
  description: Path to the private CA key.
  returned: changed or success
  type: str
  sample: /path/to/my-ca.pem
format:
  description:
    - Whether the CRL is in PEM format (V(pem)) or in DER format (V(der)).
  returned: success
  type: str
  sample: pem
  choices:
    - pem
    - der
issuer:
  description:
    - The CRL's issuer.
    - Note that for repeated values, only the last one will be returned.
    - See O(name_encoding) for how IDNs are handled.
  returned: success
  type: dict
  sample: {"organizationName": "Ansible", "commonName": "ca.example.com"}
issuer_ordered:
  description: The CRL's issuer as an ordered list of tuples.
  returned: success
  type: list
  elements: list
  sample: [["organizationName", "Ansible"], ["commonName": "ca.example.com"]]
last_update:
  description: The point in time from which this CRL can be trusted as ASN.1 TIME.
  returned: success
  type: str
  sample: 20190413202428Z
next_update:
  description: The point in time from which a new CRL will be issued and the client has to check for it as ASN.1 TIME.
  returned: success
  type: str
  sample: 20190413202428Z
digest:
  description: The signature algorithm used to sign the CRL.
  returned: success
  type: str
  sample: sha256WithRSAEncryption
revoked_certificates:
  description: List of certificates to be revoked.
  returned: success
  type: list
  elements: dict
  contains:
    serial_number:
      description:
        - Serial number of the certificate.
        - This return value is an B(integer). If you need the serial numbers as a colon-separated hex string, such as C(11:22:33),
          you need to convert it to that form with P(community.crypto.to_serial#filter).
      type: int
      sample: 1234
    revocation_date:
      description: The point in time the certificate was revoked as ASN.1 TIME.
      type: str
      sample: 20190413202428Z
    issuer:
      description:
        - The certificate's issuer.
        - See O(name_encoding) for how IDNs are handled.
      type: list
      elements: str
      sample: ["DNS:ca.example.org"]
    issuer_critical:
      description: Whether the certificate issuer extension is critical.
      type: bool
      sample: false
    reason:
      description:
        - The value for the revocation reason extension.
      type: str
      sample: key_compromise
      choices:
        - unspecified
        - key_compromise
        - ca_compromise
        - affiliation_changed
        - superseded
        - cessation_of_operation
        - certificate_hold
        - privilege_withdrawn
        - aa_compromise
        - remove_from_crl
    reason_critical:
      description: Whether the revocation reason extension is critical.
      type: bool
      sample: false
    invalidity_date:
      description: |-
        The point in time it was known/suspected that the private key was compromised
        or that the certificate otherwise became invalid as ASN.1 TIME.
      type: str
      sample: 20190413202428Z
    invalidity_date_critical:
      description: Whether the invalidity date extension is critical.
      type: bool
      sample: false
crl:
  description:
    - The (current or generated) CRL's content.
    - Will be the CRL itself if O(format) is V(pem), and Base64 of the CRL if O(format) is V(der).
  returned: if O(state) is V(present) and O(return_content) is V(true)
  type: str
"""


import base64
import os
import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_native, to_text
from ansible.module_utils.common.validation import check_type_int, check_type_str
from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLBadPassphraseError,
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_crl import (
    CRYPTOGRAPHY_TIMEZONE_INVALIDITY_DATE,
    REVOCATION_REASON_MAP,
    TIMESTAMP_FORMAT,
    cryptography_decode_revoked_certificate,
    cryptography_dump_revoked,
    cryptography_get_signature_algorithm_oid_from_crl,
    get_last_update,
    get_next_update,
    set_last_update,
    set_next_update,
    set_revocation_date,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    CRYPTOGRAPHY_TIMEZONE,
    cryptography_decode_name,
    cryptography_get_name,
    cryptography_key_needs_digest_for_signing,
    cryptography_name_to_oid,
    cryptography_oid_to_name,
    cryptography_serial_number_of_cert,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.crl_info import (
    get_crl_info,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    identify_pem_format,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_certificate,
    load_privatekey,
    parse_name_field,
    parse_ordered_name_field,
    select_message_digest,
)
from ansible_collections.community.crypto.plugins.module_utils.io import write_file
from ansible_collections.community.crypto.plugins.module_utils.serial import (
    parse_serial,
)
from ansible_collections.community.crypto.plugins.module_utils.time import (
    get_relative_time_option,
)
from ansible_collections.community.crypto.plugins.module_utils.version import (
    LooseVersion,
)


MINIMAL_CRYPTOGRAPHY_VERSION = "1.2"

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import (
        CertificateRevocationListBuilder,
        Name,
        NameAttribute,
        RevokedCertificateBuilder,
    )

    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


class CRLError(OpenSSLObjectError):
    pass


class CRL(OpenSSLObject):

    def __init__(self, module):
        super(CRL, self).__init__(
            module.params["path"],
            module.params["state"],
            module.params["force"],
            module.check_mode,
        )

        self.format = module.params["format"]

        self.update = module.params["crl_mode"] == "update"
        self.ignore_timestamps = module.params["ignore_timestamps"]
        self.return_content = module.params["return_content"]
        self.name_encoding = module.params["name_encoding"]
        self.serial_numbers_format = module.params["serial_numbers"]
        self.crl_content = None

        self.privatekey_path = module.params["privatekey_path"]
        self.privatekey_content = module.params["privatekey_content"]
        if self.privatekey_content is not None:
            self.privatekey_content = self.privatekey_content.encode("utf-8")
        self.privatekey_passphrase = module.params["privatekey_passphrase"]

        try:
            if module.params["issuer_ordered"]:
                self.issuer_ordered = True
                self.issuer = parse_ordered_name_field(
                    module.params["issuer_ordered"], "issuer_ordered"
                )
            else:
                self.issuer_ordered = False
                self.issuer = parse_name_field(module.params["issuer"], "issuer")
        except (TypeError, ValueError) as exc:
            module.fail_json(msg=to_native(exc))

        self.last_update = get_relative_time_option(
            module.params["last_update"],
            "last_update",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )
        self.next_update = get_relative_time_option(
            module.params["next_update"],
            "next_update",
            with_timezone=CRYPTOGRAPHY_TIMEZONE,
        )

        self.digest = select_message_digest(module.params["digest"])
        if self.digest is None:
            raise CRLError(
                'The digest "{0}" is not supported'.format(module.params["digest"])
            )

        self.module = module

        self.revoked_certificates = []
        for i, rc in enumerate(module.params["revoked_certificates"]):
            result = {
                "serial_number": None,
                "revocation_date": None,
                "issuer": None,
                "issuer_critical": False,
                "reason": None,
                "reason_critical": False,
                "invalidity_date": None,
                "invalidity_date_critical": False,
            }
            path_prefix = "revoked_certificates[{0}].".format(i)
            if rc["path"] is not None or rc["content"] is not None:
                # Load certificate from file or content
                try:
                    if rc["content"] is not None:
                        rc["content"] = rc["content"].encode("utf-8")
                    cert = load_certificate(
                        rc["path"], content=rc["content"], backend="cryptography"
                    )
                    result["serial_number"] = cryptography_serial_number_of_cert(cert)
                except OpenSSLObjectError as e:
                    if rc["content"] is not None:
                        module.fail_json(
                            msg="Cannot parse certificate from {0}content: {1}".format(
                                path_prefix, to_native(e)
                            )
                        )
                    else:
                        module.fail_json(
                            msg='Cannot read certificate "{1}" from {0}path: {2}'.format(
                                path_prefix, rc["path"], to_native(e)
                            )
                        )
            else:
                # Specify serial_number (and potentially issuer) directly
                result["serial_number"] = self._parse_serial_number(
                    rc["serial_number"], i
                )
            # All other options
            if rc["issuer"]:
                result["issuer"] = [
                    cryptography_get_name(issuer, "issuer") for issuer in rc["issuer"]
                ]
                result["issuer_critical"] = rc["issuer_critical"]
            result["revocation_date"] = get_relative_time_option(
                rc["revocation_date"],
                path_prefix + "revocation_date",
                with_timezone=CRYPTOGRAPHY_TIMEZONE,
            )
            if rc["reason"]:
                result["reason"] = REVOCATION_REASON_MAP[rc["reason"]]
                result["reason_critical"] = rc["reason_critical"]
            if rc["invalidity_date"]:
                result["invalidity_date"] = get_relative_time_option(
                    rc["invalidity_date"],
                    path_prefix + "invalidity_date",
                    with_timezone=CRYPTOGRAPHY_TIMEZONE_INVALIDITY_DATE,
                )
                result["invalidity_date_critical"] = rc["invalidity_date_critical"]
            self.revoked_certificates.append(result)

        self.backup = module.params["backup"]
        self.backup_file = None

        try:
            self.privatekey = load_privatekey(
                path=self.privatekey_path,
                content=self.privatekey_content,
                passphrase=self.privatekey_passphrase,
                backend="cryptography",
            )
        except OpenSSLBadPassphraseError as exc:
            raise CRLError(exc)

        self.crl = None
        try:
            with open(self.path, "rb") as f:
                data = f.read()
            self.actual_format = "pem" if identify_pem_format(data) else "der"
            if self.actual_format == "pem":
                self.crl = x509.load_pem_x509_crl(data, default_backend())
                if self.return_content:
                    self.crl_content = data
            else:
                self.crl = x509.load_der_x509_crl(data, default_backend())
                if self.return_content:
                    self.crl_content = base64.b64encode(data)
        except Exception:
            self.crl_content = None
            self.actual_format = self.format
            data = None

        self.diff_after = self.diff_before = self._get_info(data)

    def _parse_serial_number(self, value, index):
        if self.serial_numbers_format == "integer":
            try:
                return check_type_int(value)
            except TypeError as exc:
                self.module.fail_json(
                    msg="Error while parsing revoked_certificates[{idx}].serial_number as an integer: {exc}".format(
                        idx=index + 1,
                        exc=to_native(exc),
                    )
                )
        if self.serial_numbers_format == "hex-octets":
            try:
                return parse_serial(check_type_str(value))
            except (TypeError, ValueError) as exc:
                self.module.fail_json(
                    msg="Error while parsing revoked_certificates[{idx}].serial_number as an colon-separated hex octet string: {exc}".format(
                        idx=index + 1,
                        exc=to_native(exc),
                    )
                )
        raise RuntimeError(
            "Unexpected value %s of serial_numbers" % (self.serial_numbers_format,)
        )

    def _get_info(self, data):
        if data is None:
            return dict()
        try:
            result = get_crl_info(self.module, data)
            result["can_parse_crl"] = True
            return result
        except Exception:
            return dict(can_parse_crl=False)

    def remove(self):
        if self.backup:
            self.backup_file = self.module.backup_local(self.path)
        super(CRL, self).remove(self.module)

    def _compress_entry(self, entry):
        issuer = None
        if entry["issuer"] is not None:
            # Normalize to IDNA. If this is used-provided, it was already converted to
            # IDNA (by cryptography_get_name) and thus the `idna` library is present.
            # If this is coming from cryptography and is not already in IDNA (i.e. ascii),
            # cryptography < 2.1 must be in use, which depends on `idna`. So this should
            # not require `idna` except if it was already used by code earlier during
            # this invocation.
            issuer = tuple(
                cryptography_decode_name(issuer, idn_rewrite="idna")
                for issuer in entry["issuer"]
            )
        if self.ignore_timestamps:
            # Throw out revocation_date
            return (
                entry["serial_number"],
                issuer,
                entry["issuer_critical"],
                entry["reason"],
                entry["reason_critical"],
                entry["invalidity_date"],
                entry["invalidity_date_critical"],
            )
        else:
            return (
                entry["serial_number"],
                entry["revocation_date"],
                issuer,
                entry["issuer_critical"],
                entry["reason"],
                entry["reason_critical"],
                entry["invalidity_date"],
                entry["invalidity_date_critical"],
            )

    def check(self, module, perms_required=True, ignore_conversion=True):
        """Ensure the resource is in its desired state."""

        state_and_perms = super(CRL, self).check(self.module, perms_required)

        if not state_and_perms:
            return False

        if self.crl is None:
            return False

        if self.last_update != get_last_update(self.crl) and not self.ignore_timestamps:
            return False
        if self.next_update != get_next_update(self.crl) and not self.ignore_timestamps:
            return False
        if cryptography_key_needs_digest_for_signing(self.privatekey):
            if (
                self.crl.signature_hash_algorithm is None
                or self.digest.name != self.crl.signature_hash_algorithm.name
            ):
                return False
        else:
            if self.crl.signature_hash_algorithm is not None:
                return False

        want_issuer = [
            (cryptography_name_to_oid(entry[0]), entry[1]) for entry in self.issuer
        ]
        is_issuer = [(sub.oid, sub.value) for sub in self.crl.issuer]
        if not self.issuer_ordered:
            want_issuer = set(want_issuer)
            is_issuer = set(is_issuer)
        if want_issuer != is_issuer:
            return False

        old_entries = [
            self._compress_entry(cryptography_decode_revoked_certificate(cert))
            for cert in self.crl
        ]
        new_entries = [self._compress_entry(cert) for cert in self.revoked_certificates]
        if self.update:
            # We do not simply use a set so that duplicate entries are treated correctly
            for entry in new_entries:
                try:
                    old_entries.remove(entry)
                except ValueError:
                    return False
        else:
            if old_entries != new_entries:
                return False

        if self.format != self.actual_format and not ignore_conversion:
            return False

        return True

    def _generate_crl(self):
        backend = default_backend()
        crl = CertificateRevocationListBuilder()

        try:
            crl = crl.issuer_name(
                Name(
                    [
                        NameAttribute(
                            cryptography_name_to_oid(entry[0]), to_text(entry[1])
                        )
                        for entry in self.issuer
                    ]
                )
            )
        except ValueError as e:
            raise CRLError(e)

        crl = set_last_update(crl, self.last_update)
        crl = set_next_update(crl, self.next_update)

        if self.update and self.crl:
            new_entries = set(
                [self._compress_entry(entry) for entry in self.revoked_certificates]
            )
            for entry in self.crl:
                decoded_entry = self._compress_entry(
                    cryptography_decode_revoked_certificate(entry)
                )
                if decoded_entry not in new_entries:
                    crl = crl.add_revoked_certificate(entry)
        for entry in self.revoked_certificates:
            revoked_cert = RevokedCertificateBuilder()
            revoked_cert = revoked_cert.serial_number(entry["serial_number"])
            revoked_cert = set_revocation_date(revoked_cert, entry["revocation_date"])
            if entry["issuer"] is not None:
                revoked_cert = revoked_cert.add_extension(
                    x509.CertificateIssuer(entry["issuer"]), entry["issuer_critical"]
                )
            if entry["reason"] is not None:
                revoked_cert = revoked_cert.add_extension(
                    x509.CRLReason(entry["reason"]), entry["reason_critical"]
                )
            if entry["invalidity_date"] is not None:
                revoked_cert = revoked_cert.add_extension(
                    x509.InvalidityDate(entry["invalidity_date"]),
                    entry["invalidity_date_critical"],
                )
            crl = crl.add_revoked_certificate(revoked_cert.build(backend))

        digest = None
        if cryptography_key_needs_digest_for_signing(self.privatekey):
            digest = self.digest
        self.crl = crl.sign(self.privatekey, digest, backend=backend)
        if self.format == "pem":
            return self.crl.public_bytes(Encoding.PEM)
        else:
            return self.crl.public_bytes(Encoding.DER)

    def generate(self):
        result = None
        if (
            not self.check(self.module, perms_required=False, ignore_conversion=True)
            or self.force
        ):
            result = self._generate_crl()
        elif (
            not self.check(self.module, perms_required=False, ignore_conversion=False)
            and self.crl
        ):
            if self.format == "pem":
                result = self.crl.public_bytes(Encoding.PEM)
            else:
                result = self.crl.public_bytes(Encoding.DER)

        if result is not None:
            self.diff_after = self._get_info(result)
            if self.return_content:
                if self.format == "pem":
                    self.crl_content = result
                else:
                    self.crl_content = base64.b64encode(result)
            if self.backup:
                self.backup_file = self.module.backup_local(self.path)
            write_file(self.module, result)
            self.changed = True

        file_args = self.module.load_file_common_arguments(self.module.params)
        if self.module.check_file_absent_if_check_mode(file_args["path"]):
            self.changed = True
        elif self.module.set_fs_attributes_if_different(file_args, False):
            self.changed = True

    def dump(self, check_mode=False):
        result = {
            "changed": self.changed,
            "filename": self.path,
            "privatekey": self.privatekey_path,
            "format": self.format,
            "last_update": None,
            "next_update": None,
            "digest": None,
            "issuer_ordered": None,
            "issuer": None,
            "revoked_certificates": [],
        }
        if self.backup_file:
            result["backup_file"] = self.backup_file

        if check_mode:
            result["last_update"] = self.last_update.strftime(TIMESTAMP_FORMAT)
            result["next_update"] = self.next_update.strftime(TIMESTAMP_FORMAT)
            # result['digest'] = cryptography_oid_to_name(self.crl.signature_algorithm_oid)
            result["digest"] = self.module.params["digest"]
            result["issuer_ordered"] = self.issuer
            result["issuer"] = {}
            for k, v in self.issuer:
                result["issuer"][k] = v
            result["revoked_certificates"] = []
            for entry in self.revoked_certificates:
                result["revoked_certificates"].append(
                    cryptography_dump_revoked(entry, idn_rewrite=self.name_encoding)
                )
        elif self.crl:
            result["last_update"] = get_last_update(self.crl).strftime(TIMESTAMP_FORMAT)
            result["next_update"] = get_next_update(self.crl).strftime(TIMESTAMP_FORMAT)
            result["digest"] = cryptography_oid_to_name(
                cryptography_get_signature_algorithm_oid_from_crl(self.crl)
            )
            issuer = []
            for attribute in self.crl.issuer:
                issuer.append(
                    [cryptography_oid_to_name(attribute.oid), attribute.value]
                )
            result["issuer_ordered"] = issuer
            result["issuer"] = {}
            for k, v in issuer:
                result["issuer"][k] = v
            result["revoked_certificates"] = []
            for cert in self.crl:
                entry = cryptography_decode_revoked_certificate(cert)
                result["revoked_certificates"].append(
                    cryptography_dump_revoked(entry, idn_rewrite=self.name_encoding)
                )

        if self.return_content:
            result["crl"] = self.crl_content

        result["diff"] = dict(
            before=self.diff_before,
            after=self.diff_after,
        )
        return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["present", "absent"]),
            crl_mode=dict(
                type="str",
                # default='generate',
                choices=["generate", "update"],
            ),
            mode=dict(
                type="str",
                # default='generate',
                choices=["generate", "update"],
                removed_in_version="3.0.0",
                removed_from_collection="community.crypto",
            ),
            force=dict(type="bool", default=False),
            backup=dict(type="bool", default=False),
            path=dict(type="path", required=True),
            format=dict(type="str", default="pem", choices=["pem", "der"]),
            privatekey_path=dict(type="path"),
            privatekey_content=dict(type="str", no_log=True),
            privatekey_passphrase=dict(type="str", no_log=True),
            issuer=dict(type="dict"),
            issuer_ordered=dict(type="list", elements="dict"),
            last_update=dict(type="str", default="+0s"),
            next_update=dict(type="str"),
            digest=dict(type="str", default="sha256"),
            ignore_timestamps=dict(type="bool", default=False),
            return_content=dict(type="bool", default=False),
            revoked_certificates=dict(
                type="list",
                elements="dict",
                options=dict(
                    path=dict(type="path"),
                    content=dict(type="str"),
                    serial_number=dict(type="raw"),
                    revocation_date=dict(type="str", default="+0s"),
                    issuer=dict(type="list", elements="str"),
                    issuer_critical=dict(type="bool", default=False),
                    reason=dict(
                        type="str",
                        choices=[
                            "unspecified",
                            "key_compromise",
                            "ca_compromise",
                            "affiliation_changed",
                            "superseded",
                            "cessation_of_operation",
                            "certificate_hold",
                            "privilege_withdrawn",
                            "aa_compromise",
                            "remove_from_crl",
                        ],
                    ),
                    reason_critical=dict(type="bool", default=False),
                    invalidity_date=dict(type="str"),
                    invalidity_date_critical=dict(type="bool", default=False),
                ),
                required_one_of=[["path", "content", "serial_number"]],
                mutually_exclusive=[["path", "content", "serial_number"]],
            ),
            name_encoding=dict(
                type="str", default="ignore", choices=["ignore", "idna", "unicode"]
            ),
            serial_numbers=dict(
                type="str", default="integer", choices=["integer", "hex-octets"]
            ),
        ),
        required_if=[
            ("state", "present", ["privatekey_path", "privatekey_content"], True),
            ("state", "present", ["issuer", "issuer_ordered"], True),
            ("state", "present", ["next_update", "revoked_certificates"], False),
        ],
        mutually_exclusive=(
            ["privatekey_path", "privatekey_content"],
            ["issuer", "issuer_ordered"],
        ),
        supports_check_mode=True,
        add_file_common_args=True,
    )

    if module.params["mode"]:
        if module.params["crl_mode"]:
            module.fail_json(
                "You cannot use both `mode` and `crl_mode`. Use `crl_mode`."
            )
        module.params["crl_mode"] = module.params["mode"]
    # TODO: in 3.0.0, once the option `mode` has been removed, remove this:
    module.params.pop("mode", None)
    # From then on, `mode` will be the file mode of the CRL file

    if not CRYPTOGRAPHY_FOUND:
        module.fail_json(
            msg=missing_required_lib(
                "cryptography >= {0}".format(MINIMAL_CRYPTOGRAPHY_VERSION)
            ),
            exception=CRYPTOGRAPHY_IMP_ERR,
        )

    try:
        crl = CRL(module)

        if module.params["state"] == "present":
            if module.check_mode:
                result = crl.dump(check_mode=True)
                result["changed"] = (
                    module.params["force"]
                    or not crl.check(module)
                    or not crl.check(module, ignore_conversion=False)
                )
                module.exit_json(**result)

            crl.generate()
        else:
            if module.check_mode:
                result = crl.dump(check_mode=True)
                result["changed"] = os.path.exists(module.params["path"])
                module.exit_json(**result)

            crl.remove()

        result = crl.dump()
        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == "__main__":
    main()
