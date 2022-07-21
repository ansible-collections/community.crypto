# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible.module_utils.basic import AnsibleModule


class ArgumentSpec:
    def __init__(self, argument_spec, mutually_exclusive=None, required_together=None, required_one_of=None, required_if=None, required_by=None):
        self.argument_spec = argument_spec
        self.mutually_exclusive = mutually_exclusive or []
        self.required_together = required_together or []
        self.required_one_of = required_one_of or []
        self.required_if = required_if or []
        self.required_by = required_by or {}

    def create_ansible_module_helper(self, clazz, args, **kwargs):
        return clazz(
            *args,
            argument_spec=self.argument_spec,
            mutually_exclusive=self.mutually_exclusive,
            required_together=self.required_together,
            required_one_of=self.required_one_of,
            required_if=self.required_if,
            required_by=self.required_by,
            **kwargs)

    def create_ansible_module(self, **kwargs):
        return self.create_ansible_module_helper(AnsibleModule, (), **kwargs)
