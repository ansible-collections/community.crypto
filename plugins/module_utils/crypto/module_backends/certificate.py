#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.common import ArgumentSpec


def get_certificate_argument_spec():
    return ArgumentSpec(
        argument_spec=dict(
            provider=dict(type='str', choices=['acme', 'assertonly', 'entrust', 'ownca', 'selfsigned']),
            force=dict(type='bool', default=False,),
            csr_path=dict(type='path'),
            csr_content=dict(type='str'),
            select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),

            # General properties of a certificate
            privatekey_path=dict(type='path'),
            privatekey_content=dict(type='str', no_log=True),
            privatekey_passphrase=dict(type='str', no_log=True),
        ),
        mutually_exclusive=[
            ['csr_path', 'csr_content'],
            ['privatekey_path', 'privatekey_content'],
        ],
    )
