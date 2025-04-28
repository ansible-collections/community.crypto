# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible.module_utils.basic import AnsibleModule


def _ensure_list(value):
    if value is None:
        return []
    return list(value)


class ArgumentSpec:
    def __init__(
        self,
        argument_spec=None,
        mutually_exclusive=None,
        required_together=None,
        required_one_of=None,
        required_if=None,
        required_by=None,
    ):
        self.argument_spec = argument_spec or {}
        self.mutually_exclusive = _ensure_list(mutually_exclusive)
        self.required_together = _ensure_list(required_together)
        self.required_one_of = _ensure_list(required_one_of)
        self.required_if = _ensure_list(required_if)
        self.required_by = required_by or {}

    def update_argspec(self, **kwargs):
        self.argument_spec.update(kwargs)
        return self

    def update(
        self,
        mutually_exclusive=None,
        required_together=None,
        required_one_of=None,
        required_if=None,
        required_by=None,
    ):
        if mutually_exclusive:
            self.mutually_exclusive.extend(mutually_exclusive)
        if required_together:
            self.required_together.extend(required_together)
        if required_one_of:
            self.required_one_of.extend(required_one_of)
        if required_if:
            self.required_if.extend(required_if)
        if required_by:
            for k, v in required_by.items():
                if k in self.required_by:
                    v = list(self.required_by[k]) + list(v)
                self.required_by[k] = v
        return self

    def merge(self, other):
        self.update_argspec(**other.argument_spec)
        self.update(
            mutually_exclusive=other.mutually_exclusive,
            required_together=other.required_together,
            required_one_of=other.required_one_of,
            required_if=other.required_if,
            required_by=other.required_by,
        )
        return self

    def create_ansible_module_helper(self, clazz, args, **kwargs):
        return clazz(
            *args,
            argument_spec=self.argument_spec,
            mutually_exclusive=self.mutually_exclusive,
            required_together=self.required_together,
            required_one_of=self.required_one_of,
            required_if=self.required_if,
            required_by=self.required_by,
            **kwargs
        )

    def create_ansible_module(self, **kwargs):
        return self.create_ansible_module_helper(AnsibleModule, (), **kwargs)


__all__ = ("ArgumentSpec",)
