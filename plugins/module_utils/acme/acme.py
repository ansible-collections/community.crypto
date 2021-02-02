# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import copy
import datetime
import hashlib
import json

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import (
    CryptographyBackend,
    CRYPTOGRAPHY_VERSION,
)

from ansible_collections.community.crypto.plugins.module_utils.acme._compatibility import (
    get_compatibility_backend,
    handle_standard_module_arguments,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import ModuleFailException

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
)


def _assert_fetch_url_success(response, info, allow_redirect=False, allow_client_error=True, allow_server_error=True):
    if info['status'] < 0:
        raise ModuleFailException(msg="Failure downloading %s, %s" % (info['url'], info['msg']))

    if (300 <= info['status'] < 400 and not allow_redirect) or \
       (400 <= info['status'] < 500 and not allow_client_error) or \
       (info['status'] >= 500 and not allow_server_error):
        raise ModuleFailException("ACME request failed: CODE: {0} MGS: {1} RESULT: {2}".format(info['status'], info['msg'], response))


class ACMEDirectory(object):
    '''
    The ACME server directory. Gives access to the available resources,
    and allows to obtain a Replay-Nonce. The acme_directory URL
    needs to support unauthenticated GET requests; ACME endpoints
    requiring authentication are not supported.
    https://tools.ietf.org/html/rfc8555#section-7.1.1
    '''

    def __init__(self, module, account):
        self.module = module
        self.directory_root = module.params['acme_directory']
        self.version = module.params['acme_version']

        self.directory, dummy = account.get_request(self.directory_root, get_only=True)

        # Check whether self.version matches what we expect
        if self.version == 1:
            for key in ('new-reg', 'new-authz', 'new-cert'):
                if key not in self.directory:
                    raise ModuleFailException("ACME directory does not seem to follow protocol ACME v1")
        if self.version == 2:
            for key in ('newNonce', 'newAccount', 'newOrder'):
                if key not in self.directory:
                    raise ModuleFailException("ACME directory does not seem to follow protocol ACME v2")

    def __getitem__(self, key):
        return self.directory[key]

    def get_nonce(self, resource=None):
        url = self.directory_root if self.version == 1 else self.directory['newNonce']
        if resource is not None:
            url = resource
        dummy, info = fetch_url(self.module, url, method='HEAD')
        if info['status'] not in (200, 204):
            raise ModuleFailException("Failed to get replay-nonce, got status {0}".format(info['status']))
        return info['replay-nonce']


class ACMEAccount(object):
    '''
    ACME account object. Handles the authorized communication with the
    ACME server. Provides access to account bound information like
    the currently active authorizations and valid certificates
    '''

    def __init__(self, module, backend=None):
        # Set to true to enable logging of all signed requests
        self._debug = False

        if backend is None:
            module.deprecate(
                'Please adjust your custom module/plugin to the ACME module_utils refactor '
                '(https://github.com/ansible-collections/community.crypto/pull/184). The '
                'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
                'your code', version='2.0.0', collection_name='community.crypto')
            backend = get_compatibility_backend(module)

        self.module = module
        self.backend = backend
        self.version = module.params['acme_version']
        # account_key path and content are mutually exclusive
        self.key = module.params['account_key_src']
        self.key_content = module.params['account_key_content']

        # Grab account URI from module parameters.
        # Make sure empty string is treated as None.
        self.uri = module.params.get('account_uri') or None

        if self.key is not None or self.key_content is not None:
            error, self.key_data = self.parse_key(self.key, self.key_content)
            if error:
                raise ModuleFailException("error while parsing account key: %s" % error)
            self.jwk = self.key_data['jwk']
            self.jws_header = {
                "alg": self.key_data['alg'],
                "jwk": self.jwk,
            }
            if self.uri:
                # Make sure self.jws_header is updated
                self.set_account_uri(self.uri)

        self.directory = ACMEDirectory(module, self)

    def get_keyauthorization(self, token):
        '''
        Returns the key authorization for the given token
        https://tools.ietf.org/html/rfc8555#section-8.1
        '''
        accountkey_json = json.dumps(self.jwk, sort_keys=True, separators=(',', ':'))
        thumbprint = nopad_b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
        return "{0}.{1}".format(token, thumbprint)

    def parse_key(self, key_file=None, key_content=None):
        '''
        Parses an RSA or Elliptic Curve key file in PEM format and returns a pair
        (error, key_data).
        '''
        if key_file is None and key_content is None:
            raise AssertionError('One of key_file and key_content must be specified!')
        return self.backend.parse_key(key_file, key_content)

    def sign_request(self, protected, payload, key_data, encode_payload=True):
        try:
            if payload is None:
                # POST-as-GET
                payload64 = ''
            else:
                # POST
                if encode_payload:
                    payload = self.module.jsonify(payload).encode('utf8')
                payload64 = nopad_b64(to_bytes(payload))
            protected64 = nopad_b64(self.module.jsonify(protected).encode('utf8'))
        except Exception as e:
            raise ModuleFailException("Failed to encode payload / headers as JSON: {0}".format(e))

        return self.backend.sign(payload64, protected64, key_data)

    def _log(self, msg, data=None):
        '''
        Write arguments to acme.log when logging is enabled.
        '''
        if self._debug:
            with open('acme.log', 'ab') as f:
                f.write('[{0}] {1}\n'.format(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%s'), msg).encode('utf-8'))
                if data is not None:
                    f.write('{0}\n\n'.format(json.dumps(data, indent=2, sort_keys=True)).encode('utf-8'))

    def send_signed_request(self, url, payload, key_data=None, jws_header=None, parse_json_result=True, encode_payload=True):
        '''
        Sends a JWS signed HTTP POST request to the ACME server and returns
        the response as dictionary
        https://tools.ietf.org/html/rfc8555#section-6.2

        If payload is None, a POST-as-GET is performed.
        (https://tools.ietf.org/html/rfc8555#section-6.3)
        '''
        key_data = key_data or self.key_data
        jws_header = jws_header or self.jws_header
        failed_tries = 0
        while True:
            protected = copy.deepcopy(jws_header)
            protected["nonce"] = self.directory.get_nonce()
            if self.version != 1:
                protected["url"] = url

            self._log('URL', url)
            self._log('protected', protected)
            self._log('payload', payload)
            data = self.sign_request(protected, payload, key_data, encode_payload=encode_payload)
            if self.version == 1:
                data["header"] = jws_header.copy()
                for k, v in protected.items():
                    hv = data["header"].pop(k, None)
            self._log('signed request', data)
            data = self.module.jsonify(data)

            headers = {
                'Content-Type': 'application/jose+json',
            }
            resp, info = fetch_url(self.module, url, data=data, headers=headers, method='POST')
            _assert_fetch_url_success(resp, info)
            result = {}
            try:
                content = resp.read()
            except AttributeError:
                content = info.pop('body', None)

            if content or not parse_json_result:
                if (parse_json_result and info['content-type'].startswith('application/json')) or 400 <= info['status'] < 600:
                    try:
                        decoded_result = self.module.from_json(content.decode('utf8'))
                        self._log('parsed result', decoded_result)
                        # In case of badNonce error, try again (up to 5 times)
                        # (https://tools.ietf.org/html/rfc8555#section-6.7)
                        if (400 <= info['status'] < 600 and
                                decoded_result.get('type') == 'urn:ietf:params:acme:error:badNonce' and
                                failed_tries <= 5):
                            failed_tries += 1
                            continue
                        if parse_json_result:
                            result = decoded_result
                        else:
                            result = content
                    except ValueError:
                        raise ModuleFailException("Failed to parse the ACME response: {0} {1}".format(url, content))
                else:
                    result = content

            return result, info

    def get_request(self, uri, parse_json_result=True, headers=None, get_only=False, fail_on_error=True):
        '''
        Perform a GET-like request. Will try POST-as-GET for ACMEv2, with fallback
        to GET if server replies with a status code of 405.
        '''
        if not get_only and self.version != 1:
            # Try POST-as-GET
            content, info = self.send_signed_request(uri, None, parse_json_result=False)
            if info['status'] == 405:
                # Instead, do unauthenticated GET
                get_only = True
        else:
            # Do unauthenticated GET
            get_only = True

        if get_only:
            # Perform unauthenticated GET
            resp, info = fetch_url(self.module, uri, method='GET', headers=headers)

            _assert_fetch_url_success(resp, info)

            try:
                content = resp.read()
            except AttributeError:
                content = info.pop('body', None)

        # Process result
        if parse_json_result:
            result = {}
            if content:
                if info['content-type'].startswith('application/json'):
                    try:
                        result = self.module.from_json(content.decode('utf8'))
                    except ValueError:
                        raise ModuleFailException("Failed to parse the ACME response: {0} {1}".format(uri, content))
                else:
                    result = content
        else:
            result = content

        if fail_on_error and (info['status'] < 200 or info['status'] >= 400):
            raise ModuleFailException("ACME request failed: CODE: {0} RESULT: {1}".format(info['status'], result))
        return result, info

    def set_account_uri(self, uri):
        '''
        Set account URI. For ACME v2, it needs to be used to sending signed
        requests.
        '''
        self.uri = uri
        if self.version != 1:
            self.jws_header.pop('jwk')
            self.jws_header['kid'] = self.uri

    def _new_reg(self, contact=None, agreement=None, terms_agreed=False, allow_creation=True,
                 external_account_binding=None):
        '''
        Registers a new ACME account. Returns a pair ``(created, data)``.
        Here, ``created`` is ``True`` if the account was created and
        ``False`` if it already existed (e.g. it was not newly created),
        or does not exist. In case the account was created or exists,
        ``data`` contains the account data; otherwise, it is ``None``.

        If specified, ``external_account_binding`` should be a dictionary
        with keys ``kid``, ``alg`` and ``key``
        (https://tools.ietf.org/html/rfc8555#section-7.3.4).

        https://tools.ietf.org/html/rfc8555#section-7.3
        '''
        contact = contact or []

        if self.version == 1:
            new_reg = {
                'resource': 'new-reg',
                'contact': contact
            }
            if agreement:
                new_reg['agreement'] = agreement
            else:
                new_reg['agreement'] = self.directory['meta']['terms-of-service']
            if external_account_binding is not None:
                raise ModuleFailException('External account binding is not supported for ACME v1')
            url = self.directory['new-reg']
        else:
            if (external_account_binding is not None or self.directory['meta'].get('externalAccountRequired')) and allow_creation:
                # Some ACME servers such as ZeroSSL do not like it when you try to register an existing account
                # and provide external_account_binding credentials. Thus we first send a request with allow_creation=False
                # to see whether the account already exists.

                # Note that we pass contact here: ZeroSSL does not accept regisration calls without contacts, even
                # if onlyReturnExisting is set to true.
                created, data = self._new_reg(contact=contact, allow_creation=False)
                if data:
                    # An account already exists! Return data
                    return created, data
                # An account does not yet exist. Try to create one next.

            new_reg = {
                'contact': contact
            }
            if not allow_creation:
                # https://tools.ietf.org/html/rfc8555#section-7.3.1
                new_reg['onlyReturnExisting'] = True
            if terms_agreed:
                new_reg['termsOfServiceAgreed'] = True
            url = self.directory['newAccount']
            if external_account_binding is not None:
                new_reg['externalAccountBinding'] = self.sign_request(
                    {
                        'alg': external_account_binding['alg'],
                        'kid': external_account_binding['kid'],
                        'url': url,
                    },
                    self.jwk,
                    self.backend.create_mac_key(external_account_binding['alg'], external_account_binding['key'])
                )
            elif self.directory['meta'].get('externalAccountRequired') and allow_creation:
                raise ModuleFailException(
                    'To create an account, an external account binding must be specified. '
                    'Use the acme_account module with the external_account_binding option.'
                )

        result, info = self.send_signed_request(url, new_reg)

        if info['status'] in ([200, 201] if self.version == 1 else [201]):
            # Account did not exist
            if 'location' in info:
                self.set_account_uri(info['location'])
            return True, result
        elif info['status'] == (409 if self.version == 1 else 200):
            # Account did exist
            if result.get('status') == 'deactivated':
                # A bug in Pebble (https://github.com/letsencrypt/pebble/issues/179) and
                # Boulder (https://github.com/letsencrypt/boulder/issues/3971): this should
                # not return a valid account object according to
                # https://tools.ietf.org/html/rfc8555#section-7.3.6:
                #     "Once an account is deactivated, the server MUST NOT accept further
                #      requests authorized by that account's key."
                if not allow_creation:
                    return False, None
                else:
                    raise ModuleFailException("Account is deactivated")
            if 'location' in info:
                self.set_account_uri(info['location'])
            return False, result
        elif info['status'] == 400 and result['type'] == 'urn:ietf:params:acme:error:accountDoesNotExist' and not allow_creation:
            # Account does not exist (and we didn't try to create it)
            return False, None
        elif info['status'] == 403 and result['type'] == 'urn:ietf:params:acme:error:unauthorized' and 'deactivated' in (result.get('detail') or ''):
            # Account has been deactivated; currently works for Pebble; hasn't been
            # implemented for Boulder (https://github.com/letsencrypt/boulder/issues/3971),
            # might need adjustment in error detection.
            if not allow_creation:
                return False, None
            else:
                raise ModuleFailException("Account is deactivated")
        else:
            raise ModuleFailException("Error registering: {0} {1}".format(info['status'], result))

    def get_account_data(self):
        '''
        Retrieve account information. Can only be called when the account
        URI is already known (such as after calling setup_account).
        Return None if the account was deactivated, or a dict otherwise.
        '''
        if self.uri is None:
            raise ModuleFailException("Account URI unknown")
        if self.version == 1:
            data = {}
            data['resource'] = 'reg'
            result, info = self.send_signed_request(self.uri, data)
        else:
            # try POST-as-GET first (draft-15 or newer)
            data = None
            result, info = self.send_signed_request(self.uri, data)
            # check whether that failed with a malformed request error
            if info['status'] >= 400 and result.get('type') == 'urn:ietf:params:acme:error:malformed':
                # retry as a regular POST (with no changed data) for pre-draft-15 ACME servers
                data = {}
                result, info = self.send_signed_request(self.uri, data)
        if info['status'] in (400, 403) and result.get('type') == 'urn:ietf:params:acme:error:unauthorized':
            # Returned when account is deactivated
            return None
        if info['status'] in (400, 404) and result.get('type') == 'urn:ietf:params:acme:error:accountDoesNotExist':
            # Returned when account does not exist
            return None
        if info['status'] < 200 or info['status'] >= 300:
            raise ModuleFailException("Error getting account data from {2}: {0} {1}".format(info['status'], result, self.uri))
        return result

    def setup_account(self, contact=None, agreement=None, terms_agreed=False,
                      allow_creation=True, remove_account_uri_if_not_exists=False,
                      external_account_binding=None):
        '''
        Detect or create an account on the ACME server. For ACME v1,
        as the only way (without knowing an account URI) to test if an
        account exists is to try and create one with the provided account
        key, this method will always result in an account being present
        (except on error situations). For ACME v2, a new account will
        only be created if ``allow_creation`` is set to True.

        For ACME v2, ``check_mode`` is fully respected. For ACME v1, the
        account might be created if it does not yet exist.

        Return a pair ``(created, account_data)``. Here, ``created`` will
        be ``True`` in case the account was created or would be created
        (check mode). ``account_data`` will be the current account data,
        or ``None`` if the account does not exist.

        The account URI will be stored in ``self.uri``; if it is ``None``,
        the account does not exist.

        If specified, ``external_account_binding`` should be a dictionary
        with keys ``kid``, ``alg`` and ``key``
        (https://tools.ietf.org/html/rfc8555#section-7.3.4).

        https://tools.ietf.org/html/rfc8555#section-7.3
        '''

        if self.uri is not None:
            created = False
            # Verify that the account key belongs to the URI.
            # (If update_contact is True, this will be done below.)
            account_data = self.get_account_data()
            if account_data is None:
                if remove_account_uri_if_not_exists and not allow_creation:
                    self.uri = None
                else:
                    raise ModuleFailException("Account is deactivated or does not exist!")
        else:
            created, account_data = self._new_reg(
                contact,
                agreement=agreement,
                terms_agreed=terms_agreed,
                allow_creation=allow_creation and not self.module.check_mode,
                external_account_binding=external_account_binding,
            )
            if self.module.check_mode and self.uri is None and allow_creation:
                created = True
                account_data = {
                    'contact': contact or []
                }
        return created, account_data

    def update_account(self, account_data, contact=None):
        '''
        Update an account on the ACME server. Check mode is fully respected.

        The current account data must be provided as ``account_data``.

        Return a pair ``(updated, account_data)``, where ``updated`` is
        ``True`` in case something changed (contact info updated) or
        would be changed (check mode), and ``account_data`` the updated
        account data.

        https://tools.ietf.org/html/rfc8555#section-7.3.2
        '''
        # Create request
        update_request = {}
        if contact is not None and account_data.get('contact', []) != contact:
            update_request['contact'] = list(contact)

        # No change?
        if not update_request:
            return False, dict(account_data)

        # Apply change
        if self.module.check_mode:
            account_data = dict(account_data)
            account_data.update(update_request)
        else:
            if self.version == 1:
                update_request['resource'] = 'reg'
            account_data, dummy = self.send_signed_request(self.uri, update_request)
        return True, account_data


def get_default_argspec():
    '''
    Provides default argument spec for the options documented in the acme doc fragment.
    '''
    return dict(
        account_key_src=dict(type='path', aliases=['account_key']),
        account_key_content=dict(type='str', no_log=True),
        account_uri=dict(type='str'),
        acme_directory=dict(type='str'),
        acme_version=dict(type='int', choices=[1, 2]),
        validate_certs=dict(type='bool', default=True),
        select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'openssl', 'cryptography']),
    )


def create_backend(module, needs_acme_v2):
    handle_standard_module_arguments(module, needs_acme_v2=needs_acme_v2)
    return get_compatibility_backend(module)
