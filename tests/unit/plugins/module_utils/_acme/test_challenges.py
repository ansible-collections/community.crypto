# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import typing as t
from unittest.mock import (
    MagicMock,
)

import pytest
from ansible_collections.community.crypto.plugins.module_utils._acme.challenges import (
    Authorization,
    Challenge,
    combine_identifier,
    split_identifier,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
)


def test_combine_identifier() -> None:
    assert combine_identifier(identifier_type="", identifier="") == ":"
    assert combine_identifier(identifier_type="a", identifier="b") == "a:b"


def test_split_identifier() -> None:
    assert split_identifier(":") == ("", "")
    assert split_identifier("a:b") == ("a", "b")
    assert split_identifier("a:b:c") == ("a", "b:c")
    with pytest.raises(ModuleFailException) as exc:
        split_identifier("a")
    assert exc.value.msg == 'Identifier "a" is not of the form <type>:<identifier>'


def test_challenge_from_to_json() -> None:
    client = MagicMock()

    data = {
        "url": "xxx",
        "type": "type",
        "status": "valid",
    }
    client.version = 2
    challenge = Challenge.from_json(client=client, data=data)
    assert challenge.data == data
    assert challenge.type == "type"
    assert challenge.url == "xxx"
    assert challenge.status == "valid"
    assert challenge.token is None
    assert challenge.to_json() == data

    data = {
        "type": "type",
        "status": "valid",
        "token": "foo",
    }
    challenge = Challenge.from_json(client=None, data=data, url="xxx")  # type: ignore
    assert challenge.data == data
    assert challenge.type == "type"
    assert challenge.url == "xxx"
    assert challenge.status == "valid"
    assert challenge.token == "foo"
    assert challenge.to_json() == data


def test_authorization_from_to_json() -> None:
    client = MagicMock()
    client.version = 2

    data: dict[str, t.Any]

    data = {
        "challenges": [],
        "status": "valid",
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
    }
    authz = Authorization.from_json(client=client, data=data, url="xxx")
    assert authz.url == "xxx"
    assert authz.status == "valid"
    assert authz.identifier == "example.com"
    assert authz.identifier_type == "dns"
    assert authz.challenges == []
    assert authz.to_json() == {
        "uri": "xxx",
        "challenges": [],
        "status": "valid",
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
    }

    data = {
        "challenges": [
            {
                "url": "xxxyyy",
                "type": "type",
                "status": "valid",
            }
        ],
        "status": "valid",
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
        "wildcard": True,
    }
    authz = Authorization.from_json(client=client, data=data, url="xxx")
    assert authz.url == "xxx"
    assert authz.status == "valid"
    assert authz.identifier == "*.example.com"
    assert authz.identifier_type == "dns"
    assert len(authz.challenges) == 1
    assert authz.challenges[0].data == {
        "url": "xxxyyy",
        "type": "type",
        "status": "valid",
    }
    assert authz.to_json() == {
        "uri": "xxx",
        "challenges": [
            {
                "url": "xxxyyy",
                "type": "type",
                "status": "valid",
            }
        ],
        "status": "valid",
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
        "wildcard": True,
    }


def test_authorization_create_error() -> None:
    client = MagicMock()
    client.version = 2
    client.directory.directory = {}
    with pytest.raises(ACMEProtocolException) as exc:
        Authorization.create(
            client=client, identifier_type="dns", identifier="example.com"
        )

    assert exc.value.msg == "ACME endpoint does not support pre-authorization."


def test_wait_for_validation_error() -> None:
    client = MagicMock()
    client.version = 2
    data = {
        "challenges": [
            {
                "url": "xxxyyy1",
                "type": "dns-01",
                "status": "invalid",
                "error": {
                    "type": "dns-failed",
                    "subproblems": [
                        {
                            "type": "subproblem",
                            "detail": "example.com DNS-01 validation failed",
                        },
                    ],
                },
            },
            {
                "url": "xxxyyy2",
                "type": "http-01",
                "status": "invalid",
                "error": {
                    "type": "http-failed",
                    "subproblems": [
                        {
                            "type": "subproblem",
                            "detail": "example.com HTTP-01 validation failed",
                        },
                    ],
                },
            },
            {
                "url": "xxxyyy3",
                "type": "something-else",
                "status": "valid",
            },
        ],
        "status": "invalid",
        "identifier": {
            "type": "dns",
            "value": "example.com",
        },
    }
    client.get_request = MagicMock(return_value=(data, {}))
    authz = Authorization.from_json(client=client, data=data, url="xxx")
    with pytest.raises(ACMEProtocolException) as exc:
        authz.wait_for_validation(client=client)

    assert exc.value.msg == (
        'Failed to validate challenge for dns:example.com: Status is "invalid". Challenge dns-01: Error dns-failed Subproblems:\n'
        '(dns-01.0) Error subproblem: "example.com DNS-01 validation failed"; Challenge http-01: Error http-failed Subproblems:\n'
        '(http-01.0) Error subproblem: "example.com HTTP-01 validation failed".'
    )
    data = data.copy()
    data["uri"] = "xxx"
    assert exc.value.module_fail_args == {
        "identifier": "dns:example.com",
        "authorization": data,
    }
