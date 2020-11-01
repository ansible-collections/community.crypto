#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def add_entrust_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('entrust')
    argument_spec.argument_spec.update(dict(
        entrust_cert_type=dict(type='str', default='STANDARD_SSL',
                               choices=['STANDARD_SSL', 'ADVANTAGE_SSL', 'UC_SSL', 'EV_SSL', 'WILDCARD_SSL',
                                        'PRIVATE_SSL', 'PD_SSL', 'CDS_ENT_LITE', 'CDS_ENT_PRO', 'SMIME_ENT']),
        entrust_requester_email=dict(type='str'),
        entrust_requester_name=dict(type='str'),
        entrust_requester_phone=dict(type='str'),
        entrust_api_user=dict(type='str'),
        entrust_api_key=dict(type='str', no_log=True),
        entrust_api_client_cert_path=dict(type='path'),
        entrust_api_client_cert_key_path=dict(type='path', no_log=True),
        entrust_api_specification_path=dict(type='path', default='https://cloud.entrust.net/EntrustCloud/documentation/cms-api-2.1.0.yaml'),
        entrust_not_after=dict(type='str', default='+365d'),
    ))
    argument_spec.required_if.append(
        ['provider', 'entrust', ['entrust_requester_email', 'entrust_requester_name', 'entrust_requester_phone',
                                 'entrust_api_user', 'entrust_api_key', 'entrust_api_client_cert_path',
                                 'entrust_api_client_cert_key_path']]
    )
