# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import locale

from ansible.module_utils.basic import missing_required_lib

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import HAS_CURRENT_CRYPTOGRAPHY as _ORIGINAL_HAS_CURRENT_CRYPTOGRAPHY

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import (
    CryptographyBackend,
    CRYPTOGRAPHY_VERSION,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    ACMEClient,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.account import (
    ACMEAccount,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.challenges import (
    create_key_authorization,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    KeyParsingError,
)


HAS_CURRENT_CRYPTOGRAPHY = _ORIGINAL_HAS_CURRENT_CRYPTOGRAPHY


def set_crypto_backend(module):
    '''
    Sets which crypto backend to use (default: auto detection).

    Does not care whether a new enough cryptoraphy is available or not. Must
    be called before any real stuff is done which might evaluate
    ``HAS_CURRENT_CRYPTOGRAPHY``.
    '''
    global HAS_CURRENT_CRYPTOGRAPHY

    module.deprecate(
        'Please adjust your custom module/plugin to the ACME module_utils refactor '
        '(https://github.com/ansible-collections/community.crypto/pull/184). The '
        'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
        'your code', version='2.0.0', collection_name='community.crypto')

    # Choose backend
    backend = module.params['select_crypto_backend']
    if backend == 'auto':
        pass
    elif backend == 'openssl':
        HAS_CURRENT_CRYPTOGRAPHY = False
    elif backend == 'cryptography':
        if not _ORIGINAL_HAS_CURRENT_CRYPTOGRAPHY:
            module.fail_json(msg=missing_required_lib('cryptography'))
        HAS_CURRENT_CRYPTOGRAPHY = True
    else:
        module.fail_json(msg='Unknown crypto backend "{0}"!'.format(backend))
    # Inform about choices
    if HAS_CURRENT_CRYPTOGRAPHY:
        module.debug('Using cryptography backend (library version {0})'.format(CRYPTOGRAPHY_VERSION))
        return 'cryptography'
    else:
        module.debug('Using OpenSSL binary backend')
        return 'openssl'


def handle_standard_module_arguments(module, needs_acme_v2=False):
    '''
    Do standard module setup, argument handling and warning emitting.
    '''
    backend = set_crypto_backend(module)

    if not module.params['validate_certs']:
        module.warn(
            'Disabling certificate validation for communications with ACME endpoint. '
            'This should only be done for testing against a local ACME server for '
            'development purposes, but *never* for production purposes.'
        )

    if module.params['acme_version'] is None:
        module.params['acme_version'] = 1
        module.deprecate("The option 'acme_version' will be required from community.crypto 2.0.0 on",
                         version='2.0.0', collection_name='community.crypto')

    if module.params['acme_directory'] is None:
        module.params['acme_directory'] = 'https://acme-staging.api.letsencrypt.org/directory'
        module.deprecate("The option 'acme_directory' will be required from community.crypto 2.0.0 on",
                         version='2.0.0', collection_name='community.crypto')

    if needs_acme_v2 and module.params['acme_version'] < 2:
        module.fail_json(msg='The {0} module requires the ACME v2 protocol!'.format(module._name))

    # AnsibleModule() changes the locale, so change it back to C because we rely on time.strptime() when parsing certificate dates.
    module.run_command_environ_update = dict(LANG='C', LC_ALL='C', LC_MESSAGES='C', LC_CTYPE='C')
    locale.setlocale(locale.LC_ALL, 'C')

    return backend


def get_compatibility_backend(module):
    if HAS_CURRENT_CRYPTOGRAPHY:
        return CryptographyBackend(module)
    else:
        return OpenSSLCLIBackend(module)


class ACMELegacyAccount(object):
    '''
    ACME account object. Handles the authorized communication with the
    ACME server. Provides access to account bound information like
    the currently active authorizations and valid certificates
    '''

    def __init__(self, module):
        module.deprecate(
            'Please adjust your custom module/plugin to the ACME module_utils refactor '
            '(https://github.com/ansible-collections/community.crypto/pull/184). The '
            'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
            'your code', version='2.0.0', collection_name='community.crypto')
        backend = get_compatibility_backend(module)
        self.client = ACMEClient(module, backend)
        self.account = ACMEAccount(self.client)
        self.key = self.client.account_key_file
        self.key_content = self.client.account_key_content
        self.uri = self.client.account_uri
        self.key_data = self.client.account_key_data
        self.jwk = self.client.account_jwk
        self.jws_header = self.client.account_jws_header
        self.directory = self.client.directory

    def get_keyauthorization(self, token):
        '''
        Returns the key authorization for the given token
        https://tools.ietf.org/html/rfc8555#section-8.1
        '''
        return create_key_authorization(self.client, token)

    def parse_key(self, key_file=None, key_content=None):
        '''
        Parses an RSA or Elliptic Curve key file in PEM format and returns a pair
        (error, key_data).
        '''
        try:
            return None, self.client.parse_key(key_file=key_file, key_content=key_content)
        except KeyParsingError as e:
            return e.msg, {}

    def sign_request(self, protected, payload, key_data, encode_payload=True):
        return self.client.sign_request(protected, payload, key_data, encode_payload=encode_payload)

    def send_signed_request(self, url, payload, key_data=None, jws_header=None, parse_json_result=True, encode_payload=True):
        '''
        Sends a JWS signed HTTP POST request to the ACME server and returns
        the response as dictionary
        https://tools.ietf.org/html/rfc8555#section-6.2

        If payload is None, a POST-as-GET is performed.
        (https://tools.ietf.org/html/rfc8555#section-6.3)
        '''
        return self.client.send_signed_request(
            url,
            payload,
            key_data=key_data,
            jws_header=jws_header,
            parse_json_result=parse_json_result,
            encode_payload=encode_payload,
            fail_on_error=False,
        )

    def get_request(self, uri, parse_json_result=True, headers=None, get_only=False, fail_on_error=True):
        '''
        Perform a GET-like request. Will try POST-as-GET for ACMEv2, with fallback
        to GET if server replies with a status code of 405.
        '''
        return self.client.get_request(
            uri,
            parse_json_result=parse_json_result,
            headers=headers,
            get_only=get_only,
            fail_on_error=fail_on_error,
        )

    def set_account_uri(self, uri):
        '''
        Set account URI. For ACME v2, it needs to be used to sending signed
        requests.
        '''
        self.client.set_account_uri(uri)
        self.uri = self.client.account_uri

    def get_account_data(self):
        '''
        Retrieve account information. Can only be called when the account
        URI is already known (such as after calling setup_account).
        Return None if the account was deactivated, or a dict otherwise.
        '''
        return self.account.get_account_data()

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
        result = self.account.setup_account(
            contact=contact,
            agreement=agreement,
            terms_agreed=terms_agreed,
            allow_creation=allow_creation,
            remove_account_uri_if_not_exists=remove_account_uri_if_not_exists,
            external_account_binding=external_account_binding,
        )
        self.uri = self.client.account_uri
        return result

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
        return self.account.update_account(account_data, contact=contact)
