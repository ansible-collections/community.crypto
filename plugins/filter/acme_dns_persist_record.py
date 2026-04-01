# Copyright (c) 2026, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: acme_dns_persist_record
short_description: Craft a DNS record for ACME C(dns-persist-01) challenges
author: Felix Fontein (@felixfontein)
version_added: 3.2.0
description:
  - Craft the content for a ACME C(dns-persist-01) DNS TXT record V(_validation-persist.<domain>).
  - This filter conforms to the L(acme-dns-persist draft 01, https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html).
    Note that the supported draft version can change at any time,
    and changes will only be considered breaking once the draft reached RFC status.
options:
  _input:
    description:
      - The issuer domain name.
    type: string
    required: true
  account_uri:
    description:
      - The ACME account URI.
    type: string
    required: true
  policy:
    description:
      - The validation scope.
    type: string
    choices:
      wildcard:
        - If this value is present, the CA MAY consider this validation sufficient for issuing certificates
          for the validated FQDN, for specific subdomains of the validated FQDN
          (as covered by wildcard scope or specific subdomain validation rules),
          and for wildcard certificates (for example V(*.example.com)). See
          L(Section 5, https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html#wildcard-certificate-validation)
          and L(Section 6, https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html#subdomain-certificate-validation)
          of the L(acme-dns-persist draft 01, https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html).
  persist_until:
    description:
      - Until when the record is valid.
      - Can be specified as a UNIX time stamp (integer), as a Python datetime object,
        or as a relative time or absolute timestamp specified as a string.
      - Times specified as strings will always be interpreted as UTC.
        Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
        + C([w | d | h | m | s]) (for example V(+32w1d2h)).
    type: any
seealso:
  - module: community.crypto.acme_certificate
  - module: community.crypto.acme_certificate_order_create
  - module: community.crypto.acme_certificate_order_validate
"""

EXAMPLES = r"""
---
- name: Create _validation-persist.<domain> TXT record contents
  ansible.builtin.debug:
    msg: >-
      {{
        'letsencrypt.org' | community.crypto.acme_dns_persist_record(
          account_uri='https://acme-v02.api.letsencrypt.org/acme/acct/1234',
          policy='wildcard',
          persist_until='+1w',
        )
      }}

- name: Create _validation-persist.<domain> TXT record for example.com
  community.dns.hetzner_dns_record_set:
    prefix: _validation-persist
    zone_name: example.com
    value:
      - >-
        {{
          'letsencrypt.org' | community.crypto.acme_dns_persist_record(
            account_uri='https://acme-v02.api.letsencrypt.org/acme/acct/4321',
            persist_until='20190331202428Z',
          )
        }}
"""

RETURN = r"""
_value:
  description:
    - The content for the V(_validation-persist.<domain>) TXT record.
  type: string
"""

import datetime
import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError

from ansible_collections.community.crypto.plugins.module_utils._caa import (
    join_issue_value,
)
from ansible_collections.community.crypto.plugins.module_utils._crypto.basic import (
    OpenSSLObjectError,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    get_epoch_seconds,
    get_now_datetime,
    get_relative_time_option,
)


def acme_dns_persist_record(
    domain_issuer_name: t.Any,
    *,
    account_uri: t.Any,
    policy: t.Any | None = None,
    persist_until: t.Any | None = None,
) -> str:
    if not isinstance(domain_issuer_name, str):
        raise AnsibleFilterError(
            "The input for the community.crypto.acme_dns_persist_record filter"
            f" must be a string; got {type(domain_issuer_name)} instead"
        )
    if not isinstance(account_uri, str):
        raise AnsibleFilterError(
            "The account_uri parameter for the community.crypto.acme_dns_persist_record filter"
            f" must be a string; got {type(account_uri)} instead"
        )
    valid_policies = ("wildcard",)
    if policy is not None and policy not in valid_policies:
        choices = ", ".join(f'"{vp}"' for vp in valid_policies)
        raise AnsibleFilterError(
            "The policy parameter for the community.crypto.acme_dns_persist_record filter"
            f" must be one of {choices}; got {policy!r} instead"
        )
    if persist_until is not None:
        if isinstance(persist_until, str):
            try:
                persist_until = get_relative_time_option(
                    persist_until,
                    input_name="persist_until",
                    with_timezone=True,
                    now=get_now_datetime(with_timezone=True),
                )
            except OpenSSLObjectError as exc:
                raise AnsibleFilterError(
                    "Error parsing persist_until parameter for the community.crypto.acme_dns_persist_record filter:"
                    f" {exc}"
                ) from None
        if isinstance(persist_until, int) and not isinstance(persist_until, bool):
            pass
        elif isinstance(persist_until, datetime.datetime):
            persist_until = int(get_epoch_seconds(persist_until))
        else:
            raise AnsibleFilterError(
                "The persist_until parameter for the community.crypto.acme_dns_persist_record filter"
                f" must be an integer, a string, or a datetime object; got {type(persist_until)} instead"
            )

    parts = [("accounturi", account_uri)]
    if policy is not None:
        parts.append(("policy", policy))
    if persist_until is not None:
        parts.append(("persistUntil", str(persist_until)))
    try:
        return join_issue_value(domain_issuer_name, parts)
    except ValueError as exc:
        raise AnsibleFilterError(
            "Error composing result for the community.crypto.acme_dns_persist_record filter:"
            f" {exc}"
        ) from exc


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "acme_dns_persist_record": acme_dns_persist_record,
        }
