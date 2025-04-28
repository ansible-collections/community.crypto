# -*- coding: utf-8 -*-

# Copyright (c) 2013, Romeo Theriault <romeot () hawaii.edu>
# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import os
import shutil
import tempfile
import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)


def read_file(fn, mode="b"):
    try:
        with open(fn, "r" + mode) as f:
            return f.read()
    except Exception as e:
        raise ModuleFailException('Error while reading file "{0}": {1}'.format(fn, e))


# This function was adapted from an earlier version of https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/uri.py
def write_file(module, dest, content):
    """
    Write content to destination file dest, only if the content
    has changed.
    """
    changed = False
    # create a tempfile
    fd, tmpsrc = tempfile.mkstemp(text=False)
    f = os.fdopen(fd, "wb")
    try:
        f.write(content)
    except Exception as err:
        try:
            f.close()
        except Exception:
            pass
        os.remove(tmpsrc)
        raise ModuleFailException(
            "failed to create temporary content file: %s" % to_native(err),
            exception=traceback.format_exc(),
        )
    f.close()
    checksum_src = None
    checksum_dest = None
    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        try:
            os.remove(tmpsrc)
        except Exception:
            pass
        raise ModuleFailException("Source %s does not exist" % (tmpsrc))
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        raise ModuleFailException("Source %s not readable" % (tmpsrc))
    checksum_src = module.sha1(tmpsrc)
    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            raise ModuleFailException("Destination %s not writable" % (dest))
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            raise ModuleFailException("Destination %s not readable" % (dest))
        checksum_dest = module.sha1(dest)
    else:
        dirname = os.path.dirname(dest) or "."
        if not os.access(dirname, os.W_OK):
            os.remove(tmpsrc)
            raise ModuleFailException("Destination dir %s not writable" % (dirname))
    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
            changed = True
        except Exception as err:
            os.remove(tmpsrc)
            raise ModuleFailException(
                "failed to copy %s to %s: %s" % (tmpsrc, dest, to_native(err)),
                exception=traceback.format_exc(),
            )
    os.remove(tmpsrc)
    return changed
