# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from unittest.mock import (
    MagicMock,
)

import pytest
from ansible_collections.community.crypto.plugins.module_utils._acme.errors import (
    ACMEProtocolException,
)
from ansible_collections.community.crypto.plugins.module_utils._acme.orders import Order


def test_order_from_json() -> None:
    client = MagicMock()

    data = {
        "status": "valid",
        "identifiers": [],
        "authorizations": [],
    }
    client.version = 2
    order = Order.from_json(client=client, data=data, url="xxx")
    assert order.data == data
    assert order.url == "xxx"
    assert order.status == "valid"
    assert order.identifiers == []
    assert order.finalize_uri is None
    assert order.certificate_uri is None
    assert order.authorization_uris == []
    assert order.authorizations == {}


def test_wait_for_finalization_error() -> None:
    client = MagicMock()
    client.version = 2

    data = {
        "status": "invalid",
        "identifiers": [],
        "authorizations": [],
    }
    order = Order.from_json(client=client, data=data, url="xxx")

    client.get_request = MagicMock(return_value=(data, {}))
    with pytest.raises(ACMEProtocolException) as exc:
        order.wait_for_finalization(client=client)

    assert exc.value.msg.startswith(
        'Failed to wait for order to complete; got status "invalid". The JSON result: '
    )
    assert exc.value.module_fail_args == {}
