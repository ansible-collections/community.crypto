# -*- coding: utf-8 -*-
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from subprocess import Popen, PIPE

from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.gnupg.cli import GPGError, GPGRunner


class PluginGPGRunner(GPGRunner):
    def __init__(self, executable=None, cwd=None):
        if executable is None:
            try:
                executable = get_bin_path('gpg')
            except ValueError as e:
                raise GPGError('Cannot find the `gpg` executable on the controller')
        self.executable = executable
        self.cwd = cwd

    def run_command(self, command, check_rc=True, data=None):
        """
        Run ``[gpg] + command`` and return ``(rc, stdout, stderr)``.

        If ``data`` is not ``None``, it will be provided as stdin.
        The code assumes it is a bytes string.

        Returned stdout and stderr are native Python strings.
        Pass ``check_rc=False`` to allow return codes != 0.

        Raises a ``GPGError`` in case of errors.
        """
        command = [self.executable] + command
        p = Popen(command, shell=False, cwd=self.cwd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate(input=data)
        stdout = to_native(stdout, errors='surrogate_or_replace')
        stderr = to_native(stderr, errors='surrogate_or_replace')
        if check_rc and p.returncode != 0:
            raise GPGError('Running {cmd} yielded return code {rc} with stdout: "{stdout}" and stderr: "{stderr}")'.format(
                cmd=' '.join(command),
                rc=p.returncode,
                stdout=to_native(stdout, errors='surrogate_or_replace'),
                stderr=to_native(stderr, errors='surrogate_or_replace'),
            ))
        return p.returncode, stdout, stderr
