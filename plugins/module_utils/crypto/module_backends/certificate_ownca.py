#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def add_ownca_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('ownca')
    argument_spec.argument_spec.update(dict(
        ownca_path=dict(type='path'),
        ownca_content=dict(type='str'),
        ownca_privatekey_path=dict(type='path'),
        ownca_privatekey_content=dict(type='str', no_log=True),
        ownca_privatekey_passphrase=dict(type='str', no_log=True),
        ownca_digest=dict(type='str', default='sha256'),
        ownca_version=dict(type='int', default=3),
        ownca_not_before=dict(type='str', default='+0s'),
        ownca_not_after=dict(type='str', default='+3650d'),
        ownca_create_subject_key_identifier=dict(
            type='str',
            default='create_if_not_provided',
            choices=['create_if_not_provided', 'always_create', 'never_create']
        ),
        ownca_create_authority_key_identifier=dict(type='bool', default=True),
    ))
    argument_spec.mutually_exclusive.extend([
        ['ownca_path', 'ownca_content'],
        ['ownca_privatekey_path', 'ownca_privatekey_content'],
    ])
