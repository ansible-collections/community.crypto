# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ACMEProtocolException,
    ModuleFailException,
)


class ACMEAccount(object):
    '''
    ACME account object. Allows to create new accounts, check for existence of accounts,
    retrieve account data.
    '''

    def __init__(self, client):
        # Set to true to enable logging of all signed requests
        self._debug = False

        self.client = client

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

        if self.client.version == 1:
            new_reg = {
                'resource': 'new-reg',
                'contact': contact
            }
            if agreement:
                new_reg['agreement'] = agreement
            else:
                new_reg['agreement'] = self.client.directory['meta']['terms-of-service']
            if external_account_binding is not None:
                raise ModuleFailException('External account binding is not supported for ACME v1')
            url = self.client.directory['new-reg']
        else:
            if (external_account_binding is not None or self.client.directory['meta'].get('externalAccountRequired')) and allow_creation:
                # Some ACME servers such as ZeroSSL do not like it when you try to register an existing account
                # and provide external_account_binding credentials. Thus we first send a request with allow_creation=False
                # to see whether the account already exists.

                # Note that we pass contact here: ZeroSSL does not accept registration calls without contacts, even
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
            url = self.client.directory['newAccount']
            if external_account_binding is not None:
                new_reg['externalAccountBinding'] = self.client.sign_request(
                    {
                        'alg': external_account_binding['alg'],
                        'kid': external_account_binding['kid'],
                        'url': url,
                    },
                    self.client.account_jwk,
                    self.client.backend.create_mac_key(external_account_binding['alg'], external_account_binding['key'])
                )
            elif self.client.directory['meta'].get('externalAccountRequired') and allow_creation:
                raise ModuleFailException(
                    'To create an account, an external account binding must be specified. '
                    'Use the acme_account module with the external_account_binding option.'
                )

        result, info = self.client.send_signed_request(url, new_reg, fail_on_error=False)

        if info['status'] in ([200, 201] if self.client.version == 1 else [201]):
            # Account did not exist
            if 'location' in info:
                self.client.set_account_uri(info['location'])
            return True, result
        elif info['status'] == (409 if self.client.version == 1 else 200):
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
                self.client.set_account_uri(info['location'])
            return False, result
        elif info['status'] == 400 and result['type'] == 'urn:ietf:params:acme:error:accountDoesNotExist' and not allow_creation:
            # Account does not exist (and we did not try to create it)
            return False, None
        elif info['status'] == 403 and result['type'] == 'urn:ietf:params:acme:error:unauthorized' and 'deactivated' in (result.get('detail') or ''):
            # Account has been deactivated; currently works for Pebble; has not been
            # implemented for Boulder (https://github.com/letsencrypt/boulder/issues/3971),
            # might need adjustment in error detection.
            if not allow_creation:
                return False, None
            else:
                raise ModuleFailException("Account is deactivated")
        else:
            raise ACMEProtocolException(
                self.client.module, msg='Registering ACME account failed', info=info, content_json=result)

    def get_account_data(self):
        '''
        Retrieve account information. Can only be called when the account
        URI is already known (such as after calling setup_account).
        Return None if the account was deactivated, or a dict otherwise.
        '''
        if self.client.account_uri is None:
            raise ModuleFailException("Account URI unknown")
        if self.client.version == 1:
            data = {}
            data['resource'] = 'reg'
            result, info = self.client.send_signed_request(self.client.account_uri, data, fail_on_error=False)
        else:
            # try POST-as-GET first (draft-15 or newer)
            data = None
            result, info = self.client.send_signed_request(self.client.account_uri, data, fail_on_error=False)
            # check whether that failed with a malformed request error
            if info['status'] >= 400 and result.get('type') == 'urn:ietf:params:acme:error:malformed':
                # retry as a regular POST (with no changed data) for pre-draft-15 ACME servers
                data = {}
                result, info = self.client.send_signed_request(self.client.account_uri, data, fail_on_error=False)
        if info['status'] in (400, 403) and result.get('type') == 'urn:ietf:params:acme:error:unauthorized':
            # Returned when account is deactivated
            return None
        if info['status'] in (400, 404) and result.get('type') == 'urn:ietf:params:acme:error:accountDoesNotExist':
            # Returned when account does not exist
            return None
        if info['status'] < 200 or info['status'] >= 300:
            raise ACMEProtocolException(
                self.client.module, msg='Error retrieving account data', info=info, content_json=result)
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

        The account URI will be stored in ``client.account_uri``; if it is ``None``,
        the account does not exist.

        If specified, ``external_account_binding`` should be a dictionary
        with keys ``kid``, ``alg`` and ``key``
        (https://tools.ietf.org/html/rfc8555#section-7.3.4).

        https://tools.ietf.org/html/rfc8555#section-7.3
        '''

        if self.client.account_uri is not None:
            created = False
            # Verify that the account key belongs to the URI.
            # (If update_contact is True, this will be done below.)
            account_data = self.get_account_data()
            if account_data is None:
                if remove_account_uri_if_not_exists and not allow_creation:
                    self.client.account_uri = None
                else:
                    raise ModuleFailException("Account is deactivated or does not exist!")
        else:
            created, account_data = self._new_reg(
                contact,
                agreement=agreement,
                terms_agreed=terms_agreed,
                allow_creation=allow_creation and not self.client.module.check_mode,
                external_account_binding=external_account_binding,
            )
            if self.client.module.check_mode and self.client.account_uri is None and allow_creation:
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
        if self.client.module.check_mode:
            account_data = dict(account_data)
            account_data.update(update_request)
        else:
            if self.client.version == 1:
                update_request['resource'] = 'reg'
            account_data, dummy = self.client.send_signed_request(self.client.account_uri, update_request)
        return True, account_data
