#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def add_selfsigned_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('selfsigned')
    argument_spec.argument_spec.update(dict(
        selfsigned_version=dict(type='int', default=3),
        selfsigned_digest=dict(type='str', default='sha256'),
        selfsigned_not_before=dict(type='str', default='+0s', aliases=['selfsigned_notBefore']),
        selfsigned_not_after=dict(type='str', default='+3650d', aliases=['selfsigned_notAfter']),
        selfsigned_create_subject_key_identifier=dict(
            type='str',
            default='create_if_not_provided',
            choices=['create_if_not_provided', 'always_create', 'never_create']
        ),
    ))
