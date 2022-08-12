#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: smoke_ipaddress
short_description: Check whether ipaddress is present
author:
  - Felix Fontein (@felixfontein)
description:
  - Check whether C(ipaddress) is present.
options: {}
'''

EXAMPLES = r''' # '''

RETURN = r''' # '''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import ipaddress
    HAS_IPADDRESS = True
    IPADDRESS_IMP_ERR = None
except ImportError as exc:
    IPADDRESS_IMP_ERR = traceback.format_exc()
    HAS_IPADDRESS = False


def main():
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=True)

    if not HAS_IPADDRESS:
        module.fail_json(msg=missing_required_lib('ipaddress'), exception=IPADDRESS_IMP_ERR)

    module.exit_json(msg='Everything is ok')


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
