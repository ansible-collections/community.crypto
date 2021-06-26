# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import hashlib
import json
import re
import time

from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.compat import ipaddress as compat_ipaddress

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    format_error_problem,
    ACMEProtocolException,
    ModuleFailException,
)


def create_key_authorization(client, token):
    '''
    Returns the key authorization for the given token
    https://tools.ietf.org/html/rfc8555#section-8.1
    '''
    accountkey_json = json.dumps(client.account_jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = nopad_b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
    return "{0}.{1}".format(token, thumbprint)


def combine_identifier(identifier_type, identifier):
    return '{type}:{identifier}'.format(type=identifier_type, identifier=identifier)


def split_identifier(identifier):
    parts = identifier.split(':', 1)
    if len(parts) != 2:
        raise ModuleFailException(
            'Identifier "{identifier}" is not of the form <type>:<identifier>'.format(identifier=identifier))
    return parts


class Challenge(object):
    def __init__(self, data, url):
        self.data = data

        self.type = data['type']
        self.url = url
        self.status = data['status']
        self.token = data.get('token')

    @classmethod
    def from_json(cls, client, data, url=None):
        return cls(data, url or (data['uri'] if client.version == 1 else data['url']))

    def call_validate(self, client):
        challenge_response = {}
        if client.version == 1:
            token = re.sub(r"[^A-Za-z0-9_\-]", "_", self.token)
            key_authorization = create_key_authorization(client, token)
            challenge_response['resource'] = 'challenge'
            challenge_response['keyAuthorization'] = key_authorization
            challenge_response['type'] = self.type
        client.send_signed_request(
            self.url,
            challenge_response,
            error_msg='Failed to validate challenge',
            expected_status_codes=[200, 202],
        )

    def to_json(self):
        return self.data.copy()

    def get_validation_data(self, client, identifier_type, identifier):
        token = re.sub(r"[^A-Za-z0-9_\-]", "_", self.token)
        key_authorization = create_key_authorization(client, token)

        if self.type == 'http-01':
            # https://tools.ietf.org/html/rfc8555#section-8.3
            return {
                'resource': '.well-known/acme-challenge/{token}'.format(token=token),
                'resource_value': key_authorization,
            }

        if self.type == 'dns-01':
            if identifier_type != 'dns':
                return None
            # https://tools.ietf.org/html/rfc8555#section-8.4
            resource = '_acme-challenge'
            value = nopad_b64(hashlib.sha256(to_bytes(key_authorization)).digest())
            record = (resource + identifier[1:]) if identifier.startswith('*.') else '{0}.{1}'.format(resource, identifier)
            return {
                'resource': resource,
                'resource_value': value,
                'record': record,
            }

        if self.type == 'tls-alpn-01':
            # https://www.rfc-editor.org/rfc/rfc8737.html#section-3
            if identifier_type == 'ip':
                # IPv4/IPv6 address: use reverse mapping (RFC1034, RFC3596)
                resource = compat_ipaddress.ip_address(identifier).reverse_pointer
                if not resource.endswith('.'):
                    resource += '.'
            else:
                resource = identifier
            value = base64.b64encode(hashlib.sha256(to_bytes(key_authorization)).digest())
            return {
                'resource': resource,
                'resource_original': combine_identifier(identifier_type, identifier),
                'resource_value': value,
            }

        # Unknown challenge type: ignore
        return None


class Authorization(object):
    def _setup(self, client, data):
        data['uri'] = self.url
        self.data = data
        self.challenges = [Challenge.from_json(client, challenge) for challenge in data['challenges']]
        if client.version == 1 and 'status' not in data:
            # https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.1.2
            # "status (required, string): ...
            # If this field is missing, then the default value is "pending"."
            self.status = 'pending'
        else:
            self.status = data['status']
        self.identifier = data['identifier']['value']
        self.identifier_type = data['identifier']['type']
        if data.get('wildcard', False):
            self.identifier = '*.{0}'.format(self.identifier)

    def __init__(self, url):
        self.url = url

        self.data = None
        self.challenges = []
        self.status = None
        self.identifier_type = None
        self.identifier = None

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
    def create(cls, client, identifier_type, identifier):
        '''
        Create a new authorization for the given identifier.
        Return the authorization object of the new authorization
        https://tools.ietf.org/html/draft-ietf-acme-acme-02#section-6.4
        '''
        new_authz = {
            "identifier": {
                "type": identifier_type,
                "value": identifier,
            },
        }
        if client.version == 1:
            url = client.directory['new-authz']
            new_authz["resource"] = "new-authz"
        else:
            if 'newAuthz' not in client.directory.directory:
                raise ACMEProtocolException(client.module, 'ACME endpoint does not support pre-authorization')
            url = client.directory['newAuthz']

        result, info = client.send_signed_request(
            url, new_authz, error_msg='Failed to request challenges', expected_status_codes=[200, 201])
        return cls.from_json(client, result, info['location'])

    @property
    def combined_identifier(self):
        return combine_identifier(self.identifier_type, self.identifier)

    def to_json(self):
        return self.data.copy()

    def refresh(self, client):
        result, dummy = client.get_request(self.url)
        changed = self.data != result
        self._setup(client, result)
        return changed

    def get_challenge_data(self, client):
        '''
        Returns a dict with the data for all proposed (and supported) challenges
        of the given authorization.
        '''
        data = {}
        for challenge in self.challenges:
            validation_data = challenge.get_validation_data(client, self.identifier_type, self.identifier)
            if validation_data is not None:
                data[challenge.type] = validation_data
        return data

    def raise_error(self, error_msg, module=None):
        '''
        Aborts with a specific error for a challenge.
        '''
        error_details = []
        # multiple challenges could have failed at this point, gather error
        # details for all of them before failing
        for challenge in self.challenges:
            if challenge.status == 'invalid':
                msg = 'Challenge {type}'.format(type=challenge.type)
                if 'error' in challenge.data:
                    msg = '{msg}: {problem}'.format(
                        msg=msg,
                        problem=format_error_problem(challenge.data['error'], subproblem_prefix='{0}.'.format(challenge.type)),
                    )
                error_details.append(msg)
        raise ACMEProtocolException(
            module,
            'Failed to validate challenge for {identifier}: {error}. {details}'.format(
                identifier=self.combined_identifier,
                error=error_msg,
                details='; '.join(error_details),
            ),
            extras=dict(
                identifier=self.combined_identifier,
                authorization=self.data,
            ),
        )

    def find_challenge(self, challenge_type):
        for challenge in self.challenges:
            if challenge_type == challenge.type:
                return challenge
        return None

    def wait_for_validation(self, client, callenge_type):
        while True:
            self.refresh(client)
            if self.status in ['valid', 'invalid', 'revoked']:
                break
            time.sleep(2)

        if self.status == 'invalid':
            self.raise_error('Status is "invalid"', module=client.module)

        return self.status == 'valid'

    def call_validate(self, client, challenge_type, wait=True):
        '''
        Validate the authorization provided in the auth dict. Returns True
        when the validation was successful and False when it was not.
        '''
        challenge = self.find_challenge(challenge_type)
        if challenge is None:
            raise ModuleFailException('Found no challenge of type "{challenge}" for identifier {identifier}!'.format(
                challenge=challenge_type,
                identifier=self.combined_identifier,
            ))

        challenge.call_validate(client)

        if not wait:
            return self.status == 'valid'
        return self.wait_for_validation(client, challenge_type)

    def deactivate(self, client):
        '''
        Deactivates this authorization.
        https://community.letsencrypt.org/t/authorization-deactivation/19860/2
        https://tools.ietf.org/html/rfc8555#section-7.5.2
        '''
        if self.status != 'valid':
            return
        authz_deactivate = {
            'status': 'deactivated'
        }
        if client.version == 1:
            authz_deactivate['resource'] = 'authz'
        result, info = client.send_signed_request(self.url, authz_deactivate, fail_on_error=False)
        if 200 <= info['status'] < 300 and result.get('status') == 'deactivated':
            self.status = 'deactivated'
            return True
        return False
