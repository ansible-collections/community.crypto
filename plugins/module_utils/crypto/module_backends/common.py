# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.community.crypto.plugins.module_utils.argspec import (
    ArgumentSpec as _ArgumentSpec,
)


class ArgumentSpec(_ArgumentSpec):
    def create_ansible_module_helper(self, clazz, args, **kwargs):
        result = super(ArgumentSpec, self).create_ansible_module_helper(
            clazz, args, **kwargs
        )
        result.deprecate(
            "The crypto.module_backends.common module utils is deprecated and will be removed from community.crypto 3.0.0."
            " Use the argspec module utils from community.crypto instead.",
            version="3.0.0",
            collection_name="community.crypto",
        )
        return result


__all__ = ("AnsibleModule", "ArgumentSpec")
