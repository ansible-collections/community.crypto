# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import hashlib
import json


from ansible_collections.community.crypto.plugins.module_utils.acme.utils import (
    nopad_b64,
)


def create_key_authorization(client, token):
    '''
    Returns the key authorization for the given token
    https://tools.ietf.org/html/rfc8555#section-8.1
    '''
    accountkey_json = json.dumps(client.account_jwk, sort_keys=True, separators=(',', ':'))
    thumbprint = nopad_b64(hashlib.sha256(accountkey_json.encode('utf8')).digest())
    return "{0}.{1}".format(token, thumbprint)
