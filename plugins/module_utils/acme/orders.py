# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import time

from ansible_collections.community.crypto.plugins.module_utils.acme.challenges import (
    Authorization,
    normalize_combined_identifier,
)
from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ACMEProtocolException,
)
from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
)


class Order(object):
    def _setup(self, client, data):
        self.data = data

        self.status = data["status"]
        self.identifiers = []
        for identifier in data["identifiers"]:
            self.identifiers.append((identifier["type"], identifier["value"]))
        self.replaces_cert_id = data.get("replaces")
        self.finalize_uri = data.get("finalize")
        self.certificate_uri = data.get("certificate")
        self.authorization_uris = data["authorizations"]
        self.authorizations = {}

    def __init__(self, url):
        self.url = url

        self.data = None

        self.status = None
        self.identifiers = []
        self.replaces_cert_id = None
        self.finalize_uri = None
        self.certificate_uri = None
        self.authorization_uris = []
        self.authorizations = {}

    @classmethod
    def from_json(cls, client, data, url):
        result = cls(url)
        result._setup(client, data)
        return result

    @classmethod
    def from_url(cls, client, url):
        result = cls(url)
        result.refresh(client)
        return result

    @classmethod
    def create(cls, client, identifiers, replaces_cert_id=None, profile=None):
        """
        Start a new certificate order (ACME v2 protocol).
        https://tools.ietf.org/html/rfc8555#section-7.4
        """
        acme_identifiers = []
        for identifier_type, identifier in identifiers:
            acme_identifiers.append(
                {
                    "type": identifier_type,
                    "value": identifier,
                }
            )
        new_order = {"identifiers": acme_identifiers}
        if replaces_cert_id is not None:
            new_order["replaces"] = replaces_cert_id
        if profile is not None:
            new_order["profile"] = profile
        result, info = client.send_signed_request(
            client.directory["newOrder"],
            new_order,
            error_msg="Failed to start new order",
            expected_status_codes=[201],
        )
        return cls.from_json(client, result, info["location"])

    @classmethod
    def create_with_error_handling(
        cls,
        client,
        identifiers,
        error_strategy="auto",
        error_max_retries=3,
        replaces_cert_id=None,
        profile=None,
        message_callback=None,
    ):
        """
        error_strategy can be one of the following strings:

        * ``fail``: simply fail. (Same behavior as ``Order.create()``.)
        * ``retry_without_replaces_cert_id``: if ``replaces_cert_id`` is not ``None``, set it to ``None`` and retry.
          The only exception is an error of type ``urn:ietf:params:acme:error:alreadyReplaced``, that indicates that
          the certificate was already replaced.
        * ``auto``: try to be clever. Right now this is identical to ``retry_without_replaces_cert_id``, but that can
          change at any time in the future.
        * ``always``: always retry until ``error_max_retries`` has been reached.
        """
        tries = 0
        while True:
            tries += 1
            try:
                return cls.create(
                    client,
                    identifiers,
                    replaces_cert_id=replaces_cert_id,
                    profile=profile,
                )
            except ACMEProtocolException as exc:
                if tries <= error_max_retries + 1 and error_strategy != "fail":
                    if error_strategy == "always":
                        continue

                    if (
                        error_strategy in ("auto", "retry_without_replaces_cert_id")
                        and replaces_cert_id is not None
                        and not (
                            exc.error_code == 409
                            and exc.error_type
                            == "urn:ietf:params:acme:error:alreadyReplaced"
                        )
                    ):
                        if message_callback:
                            message_callback(
                                "Stop passing `replaces={replaces}` due to error {code} {type} when creating ACME order".format(
                                    code=exc.error_code,
                                    type=exc.error_type,
                                    replaces=replaces_cert_id,
                                )
                            )
                        replaces_cert_id = None
                        continue

                raise

    def refresh(self, client):
        result, dummy = client.get_request(self.url)
        changed = self.data != result
        self._setup(client, result)
        return changed

    def load_authorizations(self, client):
        for auth_uri in self.authorization_uris:
            authz = Authorization.from_url(client, auth_uri)
            self.authorizations[
                normalize_combined_identifier(authz.combined_identifier)
            ] = authz

    def wait_for_finalization(self, client):
        while True:
            self.refresh(client)
            if self.status in ["valid", "invalid", "pending", "ready"]:
                break
            time.sleep(2)

        if self.status != "valid":
            raise ACMEProtocolException(
                client.module,
                'Failed to wait for order to complete; got status "{status}"'.format(
                    status=self.status
                ),
                content_json=self.data,
            )

    def finalize(self, client, csr_der, wait=True):
        """
        Create a new certificate based on the csr.
        Return the certificate object as dict
        https://tools.ietf.org/html/rfc8555#section-7.4
        """
        new_cert = {
            "csr": nopad_b64(csr_der),
        }
        result, info = client.send_signed_request(
            self.finalize_uri,
            new_cert,
            error_msg="Failed to finalizing order",
            expected_status_codes=[200],
        )
        # It is not clear from the RFC whether the finalize call returns the order object or not.
        # Instead of using the result, we call self.refresh(client) below.

        if wait:
            self.wait_for_finalization(client)
        else:
            self.refresh(client)
            if self.status not in ["procesing", "valid", "invalid"]:
                raise ACMEProtocolException(
                    client.module,
                    'Failed to finalize order; got status "{status}"'.format(
                        status=self.status
                    ),
                    info=info,
                    content_json=result,
                )
