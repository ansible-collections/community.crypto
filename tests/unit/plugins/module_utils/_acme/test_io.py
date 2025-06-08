# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import pathlib
from unittest.mock import (
    MagicMock,
)

from ansible_collections.community.crypto.plugins.module_utils._acme.io import (
    read_file,
    write_file,
)


TEST_TEXT = r"""1234
5678"""


def test_read_file(tmp_path: pathlib.Path) -> None:
    fn = tmp_path / "test.txt"
    fn.write_text(TEST_TEXT)
    assert read_file(str(fn)) == TEST_TEXT.encode("utf-8")


def test_write_file(tmp_path: pathlib.Path) -> None:
    fn = tmp_path / "test.txt"
    module = MagicMock()
    write_file(module=module, dest=str(fn), content=TEST_TEXT.encode("utf-8"))
    assert fn.read_text() == TEST_TEXT
