# -*- coding: utf-8 -*-
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = r"""
name: gpg_fingerprint
short_description: Retrieve a GPG fingerprint from a GPG public or private key
author: Felix Fontein (@felixfontein)
version_added: 2.15.0
description:
  - Takes the content of a private or public GPG key as input and returns its fingerprint.
options:
  _input:
    description:
      - The content of a GPG public or private key.
    type: string
    required: true
requirements:
  - GnuPG (C(gpg) executable)
seealso:
  - plugin: community.crypto.gpg_fingerprint
    plugin_type: lookup
"""

EXAMPLES = r"""
---
- name: Show fingerprint of GPG public key
  ansible.builtin.debug:
    msg: "{{ lookup('file', '/path/to/public_key.gpg') | community.crypto.gpg_fingerprint }}"
"""

RETURN = r"""
_value:
  description:
    - The fingerprint of the provided public or private GPG key.
  type: string
"""

from ansible.errors import AnsibleFilterError
from ansible.module_utils.common.text.converters import to_bytes, to_native
from ansible.module_utils.six import string_types
from ansible_collections.community.crypto.plugins.module_utils.gnupg.cli import (
    GPGError,
    get_fingerprint_from_bytes,
)
from ansible_collections.community.crypto.plugins.plugin_utils.gnupg import (
    PluginGPGRunner,
)


def gpg_fingerprint(input):
    if not isinstance(input, string_types):
        raise AnsibleFilterError(
            "The input for the community.crypto.gpg_fingerprint filter must be a string; got {type} instead".format(
                type=type(input)
            )
        )
    try:
        gpg = PluginGPGRunner()
        return get_fingerprint_from_bytes(gpg, to_bytes(input))
    except GPGError as exc:
        raise AnsibleFilterError(to_native(exc))


class FilterModule(object):
    """Ansible jinja2 filters"""

    def filters(self):
        return {
            "gpg_fingerprint": gpg_fingerprint,
        }
