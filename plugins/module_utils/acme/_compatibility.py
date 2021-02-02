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
