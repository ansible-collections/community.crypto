# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import typing as t

import pytest

from ansible_collections.community.crypto.plugins.module_utils._openssh.backends.keypair_backend import (
    KeypairBackendOpensshBin,
)

BAD_PERMISSIONS_STDERR = """@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/tmp/key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "/tmp/key": bad permissions
"""


class FailJson(Exception):
    pass


class FakeModule:
    check_mode = False

    def __init__(self, path: str, rc: int, stderr: str) -> None:
        self.params: dict[str, t.Any] = {
            "comment": None,
            "path": path,
            "regenerate": "partial_idempotence",
            "force": False,
            "state": "present",
            "type": "ed25519",
            "size": None,
            "private_key_format": "auto",
        }
        self._rc = rc
        self._stderr = stderr

    def get_bin_path(self, name: str, required: bool = False) -> str:
        return f"/usr/bin/{name}"

    def run_command(self, args: list[str], **kwargs: t.Any) -> tuple[int, str, str]:
        return self._rc, "", self._stderr

    def fail_json(self, **kwargs: t.Any) -> t.NoReturn:
        raise FailJson(kwargs["msg"])


def _validate(tmp_path: t.Any, rc: int, stderr: str) -> str:
    key = tmp_path / "key"
    key.write_text("dummy")
    backend = KeypairBackendOpensshBin(
        module=FakeModule(str(key), rc, stderr)  # type: ignore[arg-type]
    )
    backend.original_private_key = object()  # type: ignore[assignment]
    with pytest.raises(FailJson) as exc:
        backend._validate_key_load()  # pylint: disable=protected-access
    return str(exc.value)


def test_unreadable_key_bad_permissions_message(tmp_path: t.Any) -> None:
    msg = _validate(tmp_path, 255, BAD_PERMISSIONS_STDERR)
    assert "permissions are too open" in msg
    assert "backend=cryptography" in msg
    assert "protected with a passphrase" not in msg


def test_unreadable_key_default_message(tmp_path: t.Any) -> None:
    msg = _validate(tmp_path, 255, 'Load key "/tmp/key": incorrect passphrase supplied')
    assert "The key is protected with a passphrase or broken." in msg
