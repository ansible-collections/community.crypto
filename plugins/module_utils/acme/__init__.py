# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import binascii
import copy
import datetime
import hashlib
import json
import locale
import os
import re
import shutil
import sys
import tempfile
import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import fetch_url
from ansible.module_utils.six.moves.urllib.parse import unquote
from ansible.module_utils.common.text.converters import to_native, to_text, to_bytes

from ansible_collections.community.crypto.plugins.module_utils.acme.acme import (
    get_default_argspec,
    ACMEDirectory,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_cryptography import (
    CryptographyBackend,
    CRYPTOGRAPHY_VERSION,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.backend_openssl_cli import (
    OpenSSLCLIBackend,
)

from ansible_collections.community.crypto.plugins.module_utils.acme._compatibility import (
    handle_standard_module_arguments,
    set_crypto_backend,
    HAS_CURRENT_CRYPTOGRAPHY,
)

from ansible_collections.community.crypto.plugins.module_utils.acme._compatibility import ACMELegacyAccount as ACMEAccount

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import ModuleFailException

from ansible_collections.community.crypto.plugins.module_utils.acme.io import (
    read_file,
    write_file,
)

from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
    pem_to_der,
    process_links,
)


def openssl_get_csr_identifiers(openssl_binary, module, csr_filename, csr_content=None):
    module.deprecate(
        'Please adjust your custom module/plugin to the ACME module_utils refactor '
        '(https://github.com/ansible-collections/community.crypto/pull/184). The '
        'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
        'your code', version='2.0.0', collection_name='community.crypto')
    return OpenSSLCLIBackend(module, openssl_binary=openssl_binary).get_csr_identifiers(csr_filename=csr_filename, csr_content=csr_content)


def cryptography_get_csr_identifiers(module, csr_filename, csr_content=None):
    module.deprecate(
        'Please adjust your custom module/plugin to the ACME module_utils refactor '
        '(https://github.com/ansible-collections/community.crypto/pull/184). The '
        'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
        'your code', version='2.0.0', collection_name='community.crypto')
    return CryptographyBackend(module).get_csr_identifiers(csr_filename=csr_filename, csr_content=csr_content)


def cryptography_get_cert_days(module, cert_file, now=None):
    module.deprecate(
        'Please adjust your custom module/plugin to the ACME module_utils refactor '
        '(https://github.com/ansible-collections/community.crypto/pull/184). The '
        'compatibility layer will be removed in community.crypto 2.0.0, thus breaking '
        'your code', version='2.0.0', collection_name='community.crypto')
    return CryptographyBackend(module).get_cert_days(cert_filename=cert_file, now=now)
