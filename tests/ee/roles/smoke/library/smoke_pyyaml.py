#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: smoke_pyyaml
short_description: Check whether PyYAML is present
author:
  - Felix Fontein (@felixfontein)
description:
  - Check whether C(yaml) is present.
options: {}
'''

EXAMPLES = r''' # '''

RETURN = r''' # '''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import yaml  # noqa: F401, pylint: disable=unused-import
    HAS_PYYAML = True
    PYYAML_IMP_ERR = None
except ImportError as exc:
    PYYAML_IMP_ERR = traceback.format_exc()
    HAS_PYYAML = False


def main():
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=True)

    if not HAS_PYYAML:
        module.fail_json(msg=missing_required_lib('PyYAML'), exception=PYYAML_IMP_ERR)

    module.exit_json(msg='Everything is ok')


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
