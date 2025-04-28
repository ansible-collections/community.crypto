# -*- coding: utf-8 -*-
# Copyright (c) 2023, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import abc
import os

from ansible.module_utils import six


class GPGError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class GPGRunner(object):
    @abc.abstractmethod
    def run_command(self, command, check_rc=True, data=None):
        """
        Run ``[gpg] + command`` and return ``(rc, stdout, stderr)``.

        If ``data`` is not ``None``, it will be provided as stdin.
        The code assumes it is a bytes string.

        Returned stdout and stderr are native Python strings.
        Pass ``check_rc=False`` to allow return codes != 0.

        Raises a ``GPGError`` in case of errors.
        """
        pass


def get_fingerprint_from_stdout(stdout):
    lines = stdout.splitlines(False)
    for line in lines:
        if line.startswith("fpr:"):
            parts = line.split(":")
            if len(parts) <= 9 or not parts[9]:
                raise GPGError(
                    'Result line "{line}" does not have fingerprint as 10th component'.format(
                        line=line
                    )
                )
            return parts[9]
    raise GPGError(
        'Cannot extract fingerprint from stdout "{stdout}"'.format(stdout=stdout)
    )


def get_fingerprint_from_file(gpg_runner, path):
    if not os.path.exists(path):
        raise GPGError("{path} does not exist".format(path=path))
    stdout = gpg_runner.run_command(
        [
            "--no-keyring",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            path,
        ],
        check_rc=True,
    )[1]
    return get_fingerprint_from_stdout(stdout)


def get_fingerprint_from_bytes(gpg_runner, content):
    stdout = gpg_runner.run_command(
        [
            "--no-keyring",
            "--with-colons",
            "--import-options",
            "show-only",
            "--import",
            "/dev/stdin",
        ],
        data=content,
        check_rc=True,
    )[1]
    return get_fingerprint_from_stdout(stdout)
