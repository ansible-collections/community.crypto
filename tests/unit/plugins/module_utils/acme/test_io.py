# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible_collections.community.crypto.plugins.module_utils.acme.io import (
    read_file,
    write_file,
)
from ansible_collections.community.internal_test_tools.tests.unit.compat.mock import (
    MagicMock,
)


TEST_TEXT = r"""1234
5678"""


def test_read_file(tmpdir):
    fn = tmpdir / "test.txt"
    fn.write(TEST_TEXT)
    assert read_file(str(fn), "t") == TEST_TEXT
    assert read_file(str(fn), "b") == TEST_TEXT.encode("utf-8")


def test_write_file(tmpdir):
    fn = tmpdir / "test.txt"
    module = MagicMock()
    write_file(module, str(fn), TEST_TEXT.encode("utf-8"))
    assert fn.read() == TEST_TEXT
