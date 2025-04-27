# -*- coding: utf-8 -*-
# Copyright (c) 2022 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# NOTE: THIS IS ONLY FOR FILTER PLUGINS!

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible.errors import AnsibleFilterError


class FilterModuleMock(object):
    def __init__(self, params):
        self.check_mode = True
        self.params = params
        self._diff = False

    def fail_json(self, msg, **kwargs):
        raise AnsibleFilterError(msg)
