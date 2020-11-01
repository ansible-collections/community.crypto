# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def add_acme_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('acme')
    argument_spec.argument_spec.update(dict(
        acme_accountkey_path=dict(type='path'),
        acme_challenge_path=dict(type='path'),
        acme_chain=dict(type='bool', default=False),
        acme_directory=dict(type='str', default="https://acme-v02.api.letsencrypt.org/directory"),
    ))
