# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


def add_assertonly_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('assertonly')
    argument_spec.argument_spec.update(dict(
        signature_algorithms=dict(type='list', elements='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        issuer=dict(type='dict', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        issuer_strict=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        has_expired=dict(type='bool', default=False, removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        version=dict(type='int', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        key_usage=dict(type='list', elements='str', aliases=['keyUsage'],
                       removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        key_usage_strict=dict(type='bool', default=False, aliases=['keyUsage_strict'],
                              removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        extended_key_usage=dict(type='list', elements='str', aliases=['extendedKeyUsage'],
                                removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        extended_key_usage_strict=dict(type='bool', default=False, aliases=['extendedKeyUsage_strict'],
                                       removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_alt_name=dict(type='list', elements='str', aliases=['subjectAltName'],
                              removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        subject_alt_name_strict=dict(type='bool', default=False, aliases=['subjectAltName_strict'],
                                     removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        not_before=dict(type='str', aliases=['notBefore'], removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        not_after=dict(type='str', aliases=['notAfter'], removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        valid_at=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        invalid_at=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
        valid_in=dict(type='str', removed_in_version='2.0.0', removed_from_collection='community.crypto'),
    ))
