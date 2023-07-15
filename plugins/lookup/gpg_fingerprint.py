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

from subprocess import Popen, PIPE

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_native


class LookupModule(LookupBase):
    def get_fingerprint(self, path):
        command = ['gpg', '--with-colons', '--import-options', 'show-only', '--import', path]
        p = Popen(command, shell=False, cwd=self._loader.get_basedir(), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            raise AnsibleLookupError('Running {cmd} yielded return code {rc} with stdout: "{stdout}" and stderr: "{stderr}")'.format(
                cmd=command,
                rc=p.returncode,
                stdout=stdout,
                stderr=stderr,
            ))
        lines = to_native(stdout).splitlines(False)
        for line in lines:
            if line.startswith('fpr:'):
                return line.split(':')[9]
        raise AnsibleLookupError('Cannot extract fingerprint for {path} from stdout "{stdout}"'.format(path=path, stdout=stdout))

    def run(self, terms, variables=None, **kwargs):
        self.set_options(direct=kwargs)

        result = []
        for path in terms:
            result.append(self.get_fingerprint(path))
        return result
