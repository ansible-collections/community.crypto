# -*- coding: utf-8 -*-
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
name: gpg_fingerprint
short_description: Retrieve a GPG fingerprint from a GPG public or private key file
author: Felix Fontein (@felixfontein)
version_added: 2.15.0
description:
  - "Takes the input lists and returns a list with elements that are lists, dictionaries,
     or template expressions which evaluate to lists or dicts, composed of the elements of
     the input evaluated lists and dictionaries."
options:
  _terms:
    description:
      - A path to a GPG public or private key.
    type: path
    required: true
requirements:
  - GnuPG (C(gpg) executable)
"""

EXAMPLES = """
- name: Show fingerprint of GPG public key
  ansible.builtin.debug:
    msg: "{{ lookup('community.crypto.gpg_fingerprint', '/path/to/public_key.gpg') }}"
"""

RETURN = """
  _value:
    description:
      - The fingerprint of the provided public or private GPG key.
      - The list as entry for every path provided.
    type: list
    elements: string
"""

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.gnupg.cli import GPGError, get_fingerprint_from_file
from ansible_collections.community.crypto.plugins.plugin_utils.gnupg import PluginGPGRunner


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        self.set_options(direct=kwargs)

        try:
            gpg = PluginGPGRunner(cwd=self._loader.get_basedir())
            result = []
            for path in terms:
                result.append(get_fingerprint_from_file(gpg, path))
            return result
        except GPGError as exc:
            raise AnsibleLookupError(to_native(exc))
