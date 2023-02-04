# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import copy
import datetime
import json
import locale
import time
import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six import PY3

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import (
    CryptographyBackend,
    CRYPTOGRAPHY_ERROR,
    CRYPTOGRAPHY_MINIMAL_VERSION,
    CRYPTOGRAPHY_VERSION,
    HAS_CURRENT_CRYPTOGRAPHY,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ACMEProtocolException,
    NetworkException,
    ModuleFailException,
    KeyParsingError,
    format_http_status,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
)

try:
    import ipaddress  # noqa: F401, pylint: disable=unused-import
except ImportError:
    HAS_IPADDRESS = False
    IPADDRESS_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_IPADDRESS = True
    IPADDRESS_IMPORT_ERROR = None


RETRY_STATUS_CODES = (408, 429, 503)


def _decode_retry(module, response, info, retry_count):
    if info['status'] not in RETRY_STATUS_CODES:
        return False

    if retry_count >= 5:
        raise ACMEProtocolException(module, msg='Giving up after 5 retries', info=info, response=response)

    # 429 and 503 should have a Retry-After header (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After)
    try:
        retry_after = min(max(1, int(info.get('retry-after'))), 60)
    except (TypeError, ValueError) as dummy:
        retry_after = 10
    module.log('Retrieved a %s HTTP status on %s, retrying in %s seconds' % (format_http_status(info['status']), info['url'], retry_after))

    time.sleep(retry_after)
    return True


def _assert_fetch_url_success(module, response, info, allow_redirect=False, allow_client_error=True, allow_server_error=True):
    if info['status'] < 0:
        raise NetworkException(msg="Failure downloading %s, %s" % (info['url'], info['msg']))

    if (300 <= info['status'] < 400 and not allow_redirect) or \
       (400 <= info['status'] < 500 and not allow_client_error) or \
       (info['status'] >= 500 and not allow_server_error):
        raise ACMEProtocolException(module, info=info, response=response)


def _is_failed(info, expected_status_codes=None):
    if info['status'] < 200 or info['status'] >= 400:
        return True
    if expected_status_codes is not None and info['status'] not in expected_status_codes:
        return True
    return False


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

        self.request_timeout = module.params['request_timeout']

        # Check whether self.version matches what we expect
        if self.version == 1:
            for key in ('new-reg', 'new-authz', 'new-cert'):
                if key not in self.directory:
                    raise ModuleFailException("ACME directory does not seem to follow protocol ACME v1")
        if self.version == 2:
            for key in ('newNonce', 'newAccount', 'newOrder'):
                if key not in self.directory:
                    raise ModuleFailException("ACME directory does not seem to follow protocol ACME v2")
            # Make sure that 'meta' is always available
            if 'meta' not in self.directory:
                self.directory['meta'] = {}

    def __getitem__(self, key):
        return self.directory[key]

    def get_nonce(self, resource=None):
        url = self.directory_root if self.version == 1 else self.directory['newNonce']
        if resource is not None:
            url = resource
        retry_count = 0
        while True:
            response, info = fetch_url(self.module, url, method='HEAD', timeout=self.request_timeout)
            if _decode_retry(self.module, response, info, retry_count):
                retry_count += 1
                continue
            if info['status'] not in (200, 204):
                raise NetworkException("Failed to get replay-nonce, got status {0}".format(format_http_status(info['status'])))
            if 'replay-nonce' in info:
                return info['replay-nonce']
            self.module.log(
                'HEAD to {0} did return status {1}, but no replay-nonce header!'.format(url, format_http_status(info['status'])))
            if retry_count >= 5:
                raise ACMEProtocolException(
                    self.module, msg='Was not able to obtain nonce, giving up after 5 retries', info=info, response=response)
            retry_count += 1


class ACMEClient(object):
    '''
    ACME client object. Handles the authorized communication with the
    ACME server.
    '''

    def __init__(self, module, backend):
        # Set to true to enable logging of all signed requests
        self._debug = False

        self.module = module
        self.backend = backend
        self.version = module.params['acme_version']
        # account_key path and content are mutually exclusive
        self.account_key_file = module.params['account_key_src']
        self.account_key_content = module.params['account_key_content']
        self.account_key_passphrase = module.params['account_key_passphrase']

        # Grab account URI from module parameters.
        # Make sure empty string is treated as None.
        self.account_uri = module.params.get('account_uri') or None

        self.request_timeout = module.params['request_timeout']

        self.account_key_data = None
        self.account_jwk = None
        self.account_jws_header = None
        if self.account_key_file is not None or self.account_key_content is not None:
            try:
                self.account_key_data = self.parse_key(
                    key_file=self.account_key_file,
                    key_content=self.account_key_content,
                    passphrase=self.account_key_passphrase)
            except KeyParsingError as e:
                raise ModuleFailException("Error while parsing account key: {msg}".format(msg=e.msg))
            self.account_jwk = self.account_key_data['jwk']
            self.account_jws_header = {
                "alg": self.account_key_data['alg'],
                "jwk": self.account_jwk,
            }
            if self.account_uri:
                # Make sure self.account_jws_header is updated
                self.set_account_uri(self.account_uri)

        self.directory = ACMEDirectory(module, self)

    def set_account_uri(self, uri):
        '''
        Set account URI. For ACME v2, it needs to be used to sending signed
        requests.
        '''
        self.account_uri = uri
        if self.version != 1:
            self.account_jws_header.pop('jwk')
            self.account_jws_header['kid'] = self.account_uri

    def parse_key(self, key_file=None, key_content=None, passphrase=None):
        '''
        Parses an RSA or Elliptic Curve key file in PEM format and returns key_data.
        In case of an error, raises KeyParsingError.
        '''
        if key_file is None and key_content is None:
            raise AssertionError('One of key_file and key_content must be specified!')
        return self.backend.parse_key(key_file, key_content, passphrase=passphrase)

    def sign_request(self, protected, payload, key_data, encode_payload=True):
        '''
        Signs an ACME request.
        '''
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

    def send_signed_request(self, url, payload, key_data=None, jws_header=None, parse_json_result=True,
                            encode_payload=True, fail_on_error=True, error_msg=None, expected_status_codes=None):
        '''
        Sends a JWS signed HTTP POST request to the ACME server and returns
        the response as dictionary (if parse_json_result is True) or in raw form
        (if parse_json_result is False).
        https://tools.ietf.org/html/rfc8555#section-6.2

        If payload is None, a POST-as-GET is performed.
        (https://tools.ietf.org/html/rfc8555#section-6.3)
        '''
        key_data = key_data or self.account_key_data
        jws_header = jws_header or self.account_jws_header
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
                    dummy = data["header"].pop(k, None)
            self._log('signed request', data)
            data = self.module.jsonify(data)

            headers = {
                'Content-Type': 'application/jose+json',
            }
            resp, info = fetch_url(self.module, url, data=data, headers=headers, method='POST', timeout=self.request_timeout)
            if _decode_retry(self.module, resp, info, failed_tries):
                failed_tries += 1
                continue
            _assert_fetch_url_success(self.module, resp, info)
            result = {}

            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if PY3 and resp.closed:
                    raise TypeError
                content = resp.read()
            except (AttributeError, TypeError):
                content = info.pop('body', None)

            if content or not parse_json_result:
                if (parse_json_result and info['content-type'].startswith('application/json')) or 400 <= info['status'] < 600:
                    try:
                        decoded_result = self.module.from_json(content.decode('utf8'))
                        self._log('parsed result', decoded_result)
                        # In case of badNonce error, try again (up to 5 times)
                        # (https://tools.ietf.org/html/rfc8555#section-6.7)
                        if all((
                            400 <= info['status'] < 600,
                            decoded_result.get('type') == 'urn:ietf:params:acme:error:badNonce',
                            failed_tries <= 5,
                        )):
                            failed_tries += 1
                            continue
                        if parse_json_result:
                            result = decoded_result
                        else:
                            result = content
                    except ValueError:
                        raise NetworkException("Failed to parse the ACME response: {0} {1}".format(url, content))
                else:
                    result = content

            if fail_on_error and _is_failed(info, expected_status_codes=expected_status_codes):
                raise ACMEProtocolException(
                    self.module, msg=error_msg, info=info, content=content, content_json=result if parse_json_result else None)
            return result, info

    def get_request(self, uri, parse_json_result=True, headers=None, get_only=False,
                    fail_on_error=True, error_msg=None, expected_status_codes=None):
        '''
        Perform a GET-like request. Will try POST-as-GET for ACMEv2, with fallback
        to GET if server replies with a status code of 405.
        '''
        if not get_only and self.version != 1:
            # Try POST-as-GET
            content, info = self.send_signed_request(uri, None, parse_json_result=False, fail_on_error=False)
            if info['status'] == 405:
                # Instead, do unauthenticated GET
                get_only = True
        else:
            # Do unauthenticated GET
            get_only = True

        if get_only:
            # Perform unauthenticated GET
            retry_count = 0
            while True:
                resp, info = fetch_url(self.module, uri, method='GET', headers=headers, timeout=self.request_timeout)
                if not _decode_retry(self.module, resp, info, retry_count):
                    break
                retry_count += 1

            _assert_fetch_url_success(self.module, resp, info)

            try:
                # In Python 2, reading from a closed response yields a TypeError.
                # In Python 3, read() simply returns ''
                if PY3 and resp.closed:
                    raise TypeError
                content = resp.read()
            except (AttributeError, TypeError):
                content = info.pop('body', None)

        # Process result
        parsed_json_result = False
        if parse_json_result:
            result = {}
            if content:
                if info['content-type'].startswith('application/json'):
                    try:
                        result = self.module.from_json(content.decode('utf8'))
                        parsed_json_result = True
                    except ValueError:
                        raise NetworkException("Failed to parse the ACME response: {0} {1}".format(uri, content))
                else:
                    result = content
        else:
            result = content

        if fail_on_error and _is_failed(info, expected_status_codes=expected_status_codes):
            raise ACMEProtocolException(
                self.module, msg=error_msg, info=info, content=content, content_json=result if parsed_json_result else None)
        return result, info


def get_default_argspec():
    '''
    Provides default argument spec for the options documented in the acme doc fragment.
    '''
    return dict(
        account_key_src=dict(type='path', aliases=['account_key']),
        account_key_content=dict(type='str', no_log=True),
        account_key_passphrase=dict(type='str', no_log=True),
        account_uri=dict(type='str'),
        acme_directory=dict(type='str', required=True),
        acme_version=dict(type='int', required=True, choices=[1, 2]),
        validate_certs=dict(type='bool', default=True),
        select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'openssl', 'cryptography']),
        request_timeout=dict(type='int', default=10),
    )


def create_backend(module, needs_acme_v2):
    if not HAS_IPADDRESS:
        module.fail_json(msg=missing_required_lib('ipaddress'), exception=IPADDRESS_IMPORT_ERROR)

    backend = module.params['select_crypto_backend']

    # Backend autodetect
    if backend == 'auto':
        backend = 'cryptography' if HAS_CURRENT_CRYPTOGRAPHY else 'openssl'

    # Create backend object
    if backend == 'cryptography':
        if CRYPTOGRAPHY_ERROR is not None:
            # Either we couldn't import cryptography at all, or there was an unexpected error
            if CRYPTOGRAPHY_VERSION is None:
                msg = missing_required_lib('cryptography')
            else:
                msg = 'Unexpected error while preparing cryptography: {0}'.format(CRYPTOGRAPHY_ERROR.splitlines()[-1])
            module.fail_json(msg=msg, exception=CRYPTOGRAPHY_ERROR)
        if not HAS_CURRENT_CRYPTOGRAPHY:
            # We succeeded importing cryptography, but its version is too old.
            module.fail_json(
                msg='Found cryptography, but only version {0}. {1}'.format(
                    CRYPTOGRAPHY_VERSION,
                    missing_required_lib('cryptography >= {0}'.format(CRYPTOGRAPHY_MINIMAL_VERSION))))
        module.debug('Using cryptography backend (library version {0})'.format(CRYPTOGRAPHY_VERSION))
        module_backend = CryptographyBackend(module)
    elif backend == 'openssl':
        module.debug('Using OpenSSL binary backend')
        module_backend = OpenSSLCLIBackend(module)
    else:
        module.fail_json(msg='Unknown crypto backend "{0}"!'.format(backend))

    # Check common module parameters
    if not module.params['validate_certs']:
        module.warn(
            'Disabling certificate validation for communications with ACME endpoint. '
            'This should only be done for testing against a local ACME server for '
            'development purposes, but *never* for production purposes.'
        )

    if needs_acme_v2 and module.params['acme_version'] < 2:
        module.fail_json(msg='The {0} module requires the ACME v2 protocol!'.format(module._name))

    if module.params['acme_version'] == 1:
        module.deprecate("The value 1 for 'acme_version' is deprecated. Please switch to ACME v2",
                         version='3.0.0', collection_name='community.crypto')

    # AnsibleModule() changes the locale, so change it back to C because we rely
    # on datetime.datetime.strptime() when parsing certificate dates.
    locale.setlocale(locale.LC_ALL, 'C')

    return module_backend
