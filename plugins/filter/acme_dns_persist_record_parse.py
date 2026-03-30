# Copyright (c) 2026, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

DOCUMENTATION = r"""
name: acme_dns_persist_record_parse
short_description: Parse a DNS record for ACME C(dns-persist-01) challenges
author: Felix Fontein (@felixfontein)
version_added: 3.2.0
description:
  - Parse the content for a ACME C(dns-persist-01) DNS TXT record V(_validation-persist.<domain>).
  - This filter conforms to the L(acme-dns-persist draft 01, https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html).
    Note that the supported draft version can change at any time,
    and changes will only be considered breaking once the draft reached RFC status.
options:
  _input:
    description:
      - The DNS TXT record entry.
    type: string
    required: true
seealso:
  - module: community.crypto.acme_certificate
  - module: community.crypto.acme_certificate_order_create
  - module: community.crypto.acme_certificate_order_validate
"""

EXAMPLES = r"""
---
- name: Create _validation-persist.<domain> TXT record contents
  ansible.builtin.debug:
    msg: "{{ record | community.crypto.acme_dns_persist_record_parse }}"
  var:
    record: >-
      letsencrypt.org;
      accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234;
      policy=wildcard;
      persistUntil=1774813004

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
  type: dictionary
  contains:
    issuer_domain_name:
      type: string
      description:
        - The issuer domain name.
      sample: letsencrypt.org
    account_uri:
      type: string
      description:
        - The ACME account URI.
    policy:
      description:
        - The validation scope.
        - Is V(null) if not present.
      type: string
    persist_until:
      description:
        - Until when the record is valid.
        - This is a UNIX timestamp, that is the number of seconds since January 1st, 1970, in UTC.
        - Is V(null) if V(persistUntil) is not present.
      type: string
    persist_until_str:
      description:
        - A ASN.1 string representation of RV(_value.persist_until).
        - Is V(null) if V(persistUntil) is not present.
      type: string
"""

import typing as t
from collections.abc import Callable

from ansible.errors import AnsibleFilterError

from ansible_collections.community.crypto.plugins.module_utils._caa import (
    parse_issue_value,
)
from ansible_collections.community.crypto.plugins.module_utils._time import (
    from_epoch_seconds,
)

TIMESTAMP_FORMAT = "%Y%m%d%H%M%SZ"


def acme_dns_persist_record_parse(
    record_value: t.Any,
) -> dict[str, t.Any]:
    if not isinstance(record_value, str):
        raise AnsibleFilterError(
            "The input for the community.crypto.acme_dns_persist_record_parse filter"
            f" must be a string; got {type(record_value)} instead"
        )
    try:
        domain_name, pairs = parse_issue_value(record_value)
    except ValueError as exc:
        raise AnsibleFilterError(
            "community.crypto.acme_dns_persist_record_parse filter could not parse"
            f" value: {exc}"
        ) from exc
    values = dict(pairs)
    if domain_name is None:
        raise AnsibleFilterError(
            "community.crypto.acme_dns_persist_record_parse filter: domain name not present"
        )
    try:
        account_uri = values.pop("accounturi")
    except KeyError:
        raise AnsibleFilterError(
            "community.crypto.acme_dns_persist_record_parse filter: cannot find account URI"
        ) from None
    policy = values.pop("policy", None)
    if policy is not None:
        policy = policy.lower()
        # TODO unknown policy
    persist_until_v = values.pop("persistUntil", None)
    persist_until: int | None = None
    persist_until_str: str | None = None
    if persist_until_v is not None:
        try:
            persist_until = int(persist_until_v)
        except ValueError as exc:
            raise AnsibleFilterError(
                f"community.crypto.acme_dns_persist_record_parse filter: error when parsing persistUntil: {exc}"
            ) from None
        persist_until_str = from_epoch_seconds(
            persist_until, with_timezone=True
        ).strftime(TIMESTAMP_FORMAT)
    result: dict[str, t.Any] = {
        "issuer_domain_name": domain_name,
        "account_uri": account_uri,
        "policy": policy,
        "persist_until": persist_until,
        "persist_until_str": persist_until_str,
    }
    # TODO values not empty
    return result


class FilterModule:
    """Ansible jinja2 filters"""

    def filters(self) -> dict[str, Callable]:
        return {
            "acme_dns_persist_record_parse": acme_dns_persist_record_parse,
        }
