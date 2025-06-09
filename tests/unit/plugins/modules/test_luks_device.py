# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import typing as t

import pytest
from ansible_collections.community.crypto.plugins.modules import luks_device


class DummyModule:
    # module to mock AnsibleModule class
    def __init__(self) -> None:
        self.params: dict[str, t.Any] = {}

    def fail_json(self, msg: str = "") -> t.NoReturn:
        raise ValueError(msg)

    def get_bin_path(self, command: str, dummy: bool) -> str | None:
        return command


# ===== Handler & CryptHandler methods tests =====


def test_generate_luks_name(monkeypatch: pytest.MonkeyPatch) -> None:
    module = DummyModule()
    module.params["passphrase_encoding"] = "text"
    monkeypatch.setattr(
        luks_device.Handler, "_run_command", lambda x, y: [0, "UUID", ""]
    )
    crypt = luks_device.CryptHandler(module)  # type: ignore
    assert crypt.generate_luks_name("/dev/dummy") == "luks-UUID"


def test_get_container_name_by_device(monkeypatch: pytest.MonkeyPatch) -> None:
    module = DummyModule()
    module.params["passphrase_encoding"] = "text"
    monkeypatch.setattr(
        luks_device.Handler,
        "_run_command",
        lambda x, y: [0, "crypt container_name", ""],
    )
    crypt = luks_device.CryptHandler(module)  # type: ignore
    assert crypt.get_container_name_by_device("/dev/dummy") == "container_name"


def test_get_container_device_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    module = DummyModule()
    module.params["passphrase_encoding"] = "text"
    monkeypatch.setattr(
        luks_device.Handler,
        "_run_command",
        lambda x, y: [0, "device:  /dev/luksdevice", ""],
    )
    crypt = luks_device.CryptHandler(module)  # type: ignore
    assert crypt.get_container_device_by_name("dummy") == "/dev/luksdevice"


def test_run_luks_remove(monkeypatch: pytest.MonkeyPatch) -> None:
    def run_command_check(
        self: luks_device.Handler, command: list[str]
    ) -> tuple[int, str, str]:
        # check that wipefs command is actually called
        assert command[0] == "wipefs"
        return 0, "", ""

    module = DummyModule()
    module.params["passphrase_encoding"] = "text"
    monkeypatch.setattr(
        luks_device.CryptHandler, "get_container_name_by_device", lambda x, y: None
    )
    monkeypatch.setattr(luks_device.Handler, "_run_command", run_command_check)
    monkeypatch.setattr(luks_device, "wipe_luks_headers", lambda device: True)
    crypt = luks_device.CryptHandler(module)  # type: ignore
    crypt.run_luks_remove("dummy")


# ===== ConditionsHandler methods data and tests =====

# device, key, passphrase, state, is_luks, label, cipher, hash, expected
LUKS_CREATE_DATA: list[
    tuple[
        str | None,
        str | None,
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        bool,
        str | None,
        str | None,
        str | None,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "key", None, "present", False, None, "dummy", "dummy", True),
    (None, "key", None, "present", False, None, "dummy", "dummy", False),
    (None, "key", None, "present", False, "labelName", "dummy", "dummy", True),
    ("dummy", None, None, "present", False, None, "dummy", "dummy", False),
    ("dummy", "key", None, "absent", False, None, "dummy", "dummy", False),
    ("dummy", "key", None, "opened", True, None, "dummy", "dummy", False),
    ("dummy", "key", None, "closed", True, None, "dummy", "dummy", False),
    ("dummy", "key", None, "present", True, None, "dummy", "dummy", False),
    ("dummy", None, "foo", "present", False, None, "dummy", "dummy", True),
    (None, None, "bar", "present", False, None, "dummy", "dummy", False),
    (None, None, "baz", "present", False, "labelName", "dummy", "dummy", True),
    ("dummy", None, None, "present", False, None, "dummy", "dummy", False),
    ("dummy", None, "quz", "absent", False, None, "dummy", "dummy", False),
    ("dummy", None, "qux", "opened", True, None, "dummy", "dummy", False),
    ("dummy", None, "quux", "closed", True, None, "dummy", "dummy", False),
    ("dummy", None, "corge", "present", True, None, "dummy", "dummy", False),
    ("dummy", "key", None, "present", False, None, None, None, True),
    ("dummy", "key", None, "present", False, None, None, "dummy", True),
    ("dummy", "key", None, "present", False, None, "dummy", None, True),
]

# device, state, is_luks, expected
LUKS_REMOVE_DATA: list[
    tuple[
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        bool,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "absent", True, True),
    (None, "absent", True, False),
    ("dummy", "present", True, False),
    ("dummy", "absent", False, False),
]

# device, key, passphrase, state, name, name_by_dev, expected
LUKS_OPEN_DATA: list[
    tuple[
        str | None,
        str | None,
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        str | None,
        str | None,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "key", None, "present", "name", None, False),
    ("dummy", "key", None, "absent", "name", None, False),
    ("dummy", "key", None, "closed", "name", None, False),
    ("dummy", "key", None, "opened", "name", None, True),
    (None, "key", None, "opened", "name", None, False),
    ("dummy", None, None, "opened", "name", None, False),
    ("dummy", "key", None, "opened", "name", "name", False),
    ("dummy", "key", None, "opened", "beer", "name", "exception"),
    ("dummy", None, "foo", "present", "name", None, False),
    ("dummy", None, "bar", "absent", "name", None, False),
    ("dummy", None, "baz", "closed", "name", None, False),
    ("dummy", None, "qux", "opened", "name", None, True),
    (None, None, "quux", "opened", "name", None, False),
    ("dummy", None, None, "opened", "name", None, False),
    ("dummy", None, "quuz", "opened", "name", "name", False),
    ("dummy", None, "corge", "opened", "beer", "name", "exception"),
]

# device, dev_by_name, name, name_by_dev, state, label, expected
LUKS_CLOSE_DATA: list[
    tuple[
        str | None,
        str | None,
        str | None,
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        str | None,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "dummy", "name", "name", "present", None, False),
    ("dummy", "dummy", "name", "name", "absent", None, False),
    ("dummy", "dummy", "name", "name", "opened", None, False),
    ("dummy", "dummy", "name", "name", "closed", None, True),
    (None, "dummy", "name", "name", "closed", None, True),
    ("dummy", "dummy", None, "name", "closed", None, True),
    (None, "dummy", None, "name", "closed", None, False),
]

# device, key, passphrase, new_key, new_passphrase, state, label, expected
LUKS_ADD_KEY_DATA: list[
    tuple[
        str | None,
        str | None,
        str | None,
        str | None,
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        str | None,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "key", None, "new_key", None, "present", None, True),
    (None, "key", None, "new_key", None, "present", "labelName", True),
    (None, "key", None, "new_key", None, "present", None, False),
    ("dummy", None, None, "new_key", None, "present", None, False),
    ("dummy", "key", None, None, None, "present", None, False),
    ("dummy", "key", None, "new_key", None, "absent", None, "exception"),
    ("dummy", None, "pass", "new_key", None, "present", None, True),
    (None, None, "pass", "new_key", None, "present", "labelName", True),
    ("dummy", "key", None, None, "new_pass", "present", None, True),
    (None, "key", None, None, "new_pass", "present", "labelName", True),
    (None, "key", None, None, "new_pass", "present", None, False),
    ("dummy", None, None, None, "new_pass", "present", None, False),
    ("dummy", "key", None, None, None, "present", None, False),
    ("dummy", "key", None, None, "new_pass", "absent", None, "exception"),
    ("dummy", None, "pass", None, "new_pass", "present", None, True),
    (None, None, "pass", None, "new_pass", "present", "labelName", True),
]

# device, remove_key, remove_passphrase, remove_keyslot, state, label, expected
LUKS_REMOVE_KEY_DATA: list[
    tuple[
        str | None,
        str | None,
        str | None,
        str | None,
        t.Literal["present", "absent", "opened", "closed"],
        str | None,
        bool | t.Literal["exception"],
    ]
] = [
    ("dummy", "key", None, None, "present", None, True),
    (None, "key", None, None, "present", None, False),
    (None, "key", None, None, "present", "labelName", True),
    ("dummy", None, None, None, "present", None, False),
    ("dummy", "key", None, None, "absent", None, "exception"),
    ("dummy", None, "foo", None, "present", None, True),
    (None, None, "foo", None, "present", None, False),
    (None, None, "foo", None, "present", "labelName", True),
    ("dummy", None, None, None, "present", None, False),
    ("dummy", None, "foo", None, "absent", None, "exception"),
]


@pytest.mark.parametrize(
    "device, keyfile, passphrase, state, is_luks, " + "label, cipher, hash_, expected",
    ((d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]) for d in LUKS_CREATE_DATA),
)
def test_luks_create(
    device: str | None,
    keyfile: str | None,
    passphrase: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    is_luks: bool,
    label: str | None,
    cipher: str | None,
    hash_: str | None,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()

    module.params["device"] = device
    module.params["keyfile"] = keyfile
    module.params["passphrase"] = passphrase
    module.params["passphrase_encoding"] = "text"
    module.params["state"] = state
    module.params["label"] = label
    module.params["cipher"] = cipher
    module.params["hash"] = hash_

    monkeypatch.setattr(luks_device.CryptHandler, "is_luks", lambda x, y: is_luks)
    crypt = luks_device.CryptHandler(module)  # type: ignore
    if device is None:
        monkeypatch.setattr(
            luks_device.Handler,
            "get_device_by_label",
            lambda x, y: [0, "/dev/dummy", ""],
        )
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_create() == expected
    except ValueError:
        assert expected == "exception"


@pytest.mark.parametrize(
    "device, state, is_luks, expected",
    ((d[0], d[1], d[2], d[3]) for d in LUKS_REMOVE_DATA),
)
def test_luks_remove(
    device: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    is_luks: bool,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()

    module.params["device"] = device
    module.params["passphrase_encoding"] = "text"
    module.params["state"] = state

    monkeypatch.setattr(luks_device.CryptHandler, "is_luks", lambda x, y: is_luks)
    crypt = luks_device.CryptHandler(module)  # type: ignore
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_remove() == expected
    except ValueError:
        assert expected == "exception"


@pytest.mark.parametrize(
    "device, keyfile, passphrase, state, name, name_by_dev, expected",
    ((d[0], d[1], d[2], d[3], d[4], d[5], d[6]) for d in LUKS_OPEN_DATA),
)
def test_luks_open(
    device: str | None,
    keyfile: str | None,
    passphrase: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    name: str | None,
    name_by_dev: str | None,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()
    module.params["device"] = device
    module.params["keyfile"] = keyfile
    module.params["passphrase"] = passphrase
    module.params["passphrase_encoding"] = "text"
    module.params["state"] = state
    module.params["name"] = name

    monkeypatch.setattr(
        luks_device.CryptHandler,
        "get_container_name_by_device",
        lambda x, y: name_by_dev,
    )
    monkeypatch.setattr(
        luks_device.CryptHandler, "get_container_device_by_name", lambda x, y: device
    )
    monkeypatch.setattr(
        luks_device.Handler, "_run_command", lambda x, y: [0, device, ""]
    )
    crypt = luks_device.CryptHandler(module)  # type: ignore
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_open() == expected
    except ValueError:
        assert expected == "exception"


@pytest.mark.parametrize(
    "device, dev_by_name, name, name_by_dev, state, label, expected",
    ((d[0], d[1], d[2], d[3], d[4], d[5], d[6]) for d in LUKS_CLOSE_DATA),
)
def test_luks_close(
    device: str | None,
    dev_by_name: str | None,
    name: str | None,
    name_by_dev: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    label: str | None,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()
    module.params["device"] = device
    module.params["name"] = name
    module.params["passphrase_encoding"] = "text"
    module.params["state"] = state
    module.params["label"] = label

    monkeypatch.setattr(
        luks_device.CryptHandler,
        "get_container_name_by_device",
        lambda x, y: name_by_dev,
    )
    monkeypatch.setattr(
        luks_device.CryptHandler,
        "get_container_device_by_name",
        lambda x, y: dev_by_name,
    )
    crypt = luks_device.CryptHandler(module)  # type: ignore
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_close() == expected
    except ValueError:
        assert expected == "exception"


@pytest.mark.parametrize(
    "device, keyfile, passphrase, new_keyfile, "
    + "new_passphrase, state, label, expected",
    ((d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]) for d in LUKS_ADD_KEY_DATA),
)
def test_luks_add_key(
    device: str | None,
    keyfile: str | None,
    passphrase: str | None,
    new_keyfile: str | None,
    new_passphrase: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    label: str | None,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()
    module.params["device"] = device
    module.params["keyfile"] = keyfile
    module.params["passphrase"] = passphrase
    module.params["passphrase_encoding"] = "text"
    module.params["new_keyfile"] = new_keyfile
    module.params["new_passphrase"] = new_passphrase
    module.params["new_keyslot"] = None
    module.params["state"] = state
    module.params["label"] = label

    monkeypatch.setattr(
        luks_device.Handler, "get_device_by_label", lambda x, y: [0, "/dev/dummy", ""]
    )
    monkeypatch.setattr(
        luks_device.CryptHandler, "luks_test_key", lambda x, y, z, w: False
    )

    crypt = luks_device.CryptHandler(module)  # type: ignore
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_add_key() == expected
    except ValueError:
        assert expected == "exception"


@pytest.mark.parametrize(
    "device, remove_keyfile, remove_passphrase, remove_keyslot, "
    + "state, label, expected",
    ((d[0], d[1], d[2], d[3], d[4], d[5], d[6]) for d in LUKS_REMOVE_KEY_DATA),
)
def test_luks_remove_key(
    device: str | None,
    remove_keyfile: str | None,
    remove_passphrase: str | None,
    remove_keyslot: str | None,
    state: t.Literal["present", "absent", "opened", "closed"],
    label: str | None,
    expected: bool | t.Literal["exception"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = DummyModule()
    module.params["device"] = device
    module.params["passphrase_encoding"] = "text"
    module.params["remove_keyfile"] = remove_keyfile
    module.params["remove_passphrase"] = remove_passphrase
    module.params["remove_keyslot"] = remove_keyslot
    module.params["state"] = state
    module.params["label"] = label

    monkeypatch.setattr(
        luks_device.Handler, "get_device_by_label", lambda x, y: [0, "/dev/dummy", ""]
    )
    monkeypatch.setattr(
        luks_device.Handler, "_run_command", lambda x, y: [0, device, ""]
    )
    monkeypatch.setattr(
        luks_device.CryptHandler, "luks_test_key", lambda x, y, z, w: True
    )

    crypt = luks_device.CryptHandler(module)  # type: ignore
    try:
        conditions = luks_device.ConditionsHandler(module, crypt)  # type: ignore
        assert conditions.luks_remove_key() == expected
    except ValueError:
        assert expected == "exception"
