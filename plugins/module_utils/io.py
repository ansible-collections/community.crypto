# -*- coding: utf-8 -*-
#
# Copyright (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import errno
import os
import tempfile


def load_file(path, module=None):
    """
    Load the file as a bytes string.
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as exc:
        if module is None:
            raise
        module.fail_json("Error while loading {0} - {1}".format(path, str(exc)))


def load_file_if_exists(path, module=None, ignore_errors=False):
    """
    Load the file as a bytes string. If the file does not exist, ``None`` is returned.

    If ``ignore_errors`` is ``True``, will ignore errors. Otherwise, errors are
    raised as exceptions if ``module`` is not specified, and result in ``module.fail_json``
    being called when ``module`` is specified.
    """
    try:
        with open(path, "rb") as f:
            return f.read()
    except EnvironmentError as exc:
        if exc.errno == errno.ENOENT:
            return None
        if ignore_errors:
            return None
        if module is None:
            raise
        module.fail_json("Error while loading {0} - {1}".format(path, str(exc)))
    except Exception as exc:
        if ignore_errors:
            return None
        if module is None:
            raise
        module.fail_json("Error while loading {0} - {1}".format(path, str(exc)))


def write_file(module, content, default_mode=None, path=None):
    """
    Writes content into destination file as securely as possible.
    Uses file arguments from module.
    """
    # Find out parameters for file
    try:
        file_args = module.load_file_common_arguments(module.params, path=path)
    except TypeError:
        # The path argument is only supported in Ansible 2.10+. Fall back to
        # pre-2.10 behavior of module_utils/crypto.py for older Ansible versions.
        file_args = module.load_file_common_arguments(module.params)
        if path is not None:
            file_args["path"] = path
    if file_args["mode"] is None:
        file_args["mode"] = default_mode
    # Create tempfile name
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=b".ansible_tmp")
    try:
        os.close(tmp_fd)
    except Exception:
        pass
    module.add_cleanup_file(tmp_name)  # if we fail, let Ansible try to remove the file
    try:
        try:
            # Create tempfile
            file = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.write(file, content)
            os.close(file)
        except Exception as e:
            try:
                os.remove(tmp_name)
            except Exception:
                pass
            module.fail_json(
                msg="Error while writing result into temporary file: {0}".format(e)
            )
        # Update destination to wanted permissions
        if os.path.exists(file_args["path"]):
            module.set_fs_attributes_if_different(file_args, False)
        # Move tempfile to final destination
        module.atomic_move(
            os.path.abspath(tmp_name), os.path.abspath(file_args["path"])
        )
        # Try to update permissions again
        if not module.check_file_absent_if_check_mode(file_args["path"]):
            module.set_fs_attributes_if_different(file_args, False)
    except Exception as e:
        try:
            os.remove(tmp_name)
        except Exception:
            pass
        module.fail_json(msg="Error while writing result: {0}".format(e))
