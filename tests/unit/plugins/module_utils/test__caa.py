# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import re
import typing as t

import pytest

from ansible_collections.community.crypto.plugins.module_utils._caa import (
    _check_domain_name,
    _check_label,
    _check_value,
    join_issue_value,
    parse_issue_value,
)

TEST_CHECK_VALUE: list[tuple[str, str | None]] = [
    ("", None),
    ("a", None),
    (
        "!\"#$%&'()*+,-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        None,
    ),
    ("a=b", None),
    ("\x1f", "Invalid value '\\x1f'"),
    (" ", "Invalid value ' '"),
    (";", "Invalid value ';'"),
    ("\x7f", "Invalid value '\\x7f'"),
    ("a b", "Invalid value 'a b'"),
]


@pytest.mark.parametrize("value, error", TEST_CHECK_VALUE)
def test_check_value(
    value: str,
    error: str | None,
) -> None:
    if error is None:
        _check_value(value)
    else:
        with pytest.raises(ValueError, match=f"^{re.escape(error)}$"):
            _check_value(value)


TEST_CHECK_LABEL: list[tuple[str, str | None]] = [
    ("", "Invalid value ''"),
    ("a", None),
    ("0", None),
    ("a-", None),
    ("a=", "Invalid value 'a='"),
    ("-a", "Invalid value '-a'"),
    (" ", "Invalid value ' '"),
    ("\t", "Invalid value '\\t'"),
    ("a0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-", None),
]


@pytest.mark.parametrize("value, error", TEST_CHECK_LABEL)
def test_check_label(
    value: str,
    error: str | None,
) -> None:
    if error is None:
        _check_label(value, "value")
    else:
        with pytest.raises(ValueError, match=f"^{re.escape(error)}$"):
            _check_label(value, "value")


TEST_CHECK_DOMAIN_NAME: list[tuple[str, str | None]] = [
    ("", "Invalid label ''"),
    ("a.", "Invalid label ''"),
    (".a", "Invalid label ''"),
    ("a.-", "Invalid label '-'"),
    ("a.b", None),
    ("a.b.c.d.e.f.g.h.i.j.k.l", None),
    ("letsencrypt.org", None),
]


@pytest.mark.parametrize("value, error", TEST_CHECK_DOMAIN_NAME)
def test_check_domain_name(
    value: str,
    error: str | None,
) -> None:
    if error is None:
        _check_domain_name(value)
    else:
        with pytest.raises(ValueError, match=f"^{re.escape(error)}$"):
            _check_domain_name(value)


TEST_PARSE_ISSUE_VALUE: list[
    tuple[str, dict[str, t.Any], str | None, list[tuple[str, str]]]
] = [
    ("", {}, None, []),
    (";", {}, None, []),
    ("a=b", {"strict": False}, "a=b", []),
    ("; a=b", {"strict": False}, None, [("a", "b")]),
    ("a; a=b", {"strict": False}, "a", [("a", "b")]),
    ("a; a=b; c-d=e", {"strict": False}, "a", [("a", "b"), ("c-d", "e")]),
    ("ca1.example.net", {}, "ca1.example.net", []),
    ("ca1.example.net; account=230123", {}, "ca1.example.net", [("account", "230123")]),
]


@pytest.mark.parametrize(
    "value, kwargs, expected_domain_name, expected_pairs", TEST_PARSE_ISSUE_VALUE
)
def test_parse_issue_value(
    value: str,
    kwargs: dict[str, t.Any],
    expected_domain_name: str | None,
    expected_pairs: list[tuple[str, str]],
) -> None:
    assert parse_issue_value(value, **kwargs) == (expected_domain_name, expected_pairs)


TEST_PARSE_ISSUE_VALUE_FAIL: list[tuple[str, dict[str, t.Any], str]] = [
    ("a=b", {}, "Invalid label 'a=b'"),
    ("a; a.b=b", {}, "Invalid tag 'a.b'"),
    ("a; a=b; a=c", {}, "Tag 'a' appears multiple times"),
    ("%%%%%", {}, "Invalid label '%%%%%'"),
]


@pytest.mark.parametrize("value, kwargs, expected_error", TEST_PARSE_ISSUE_VALUE_FAIL)
def test_parse_issue_value_fail(
    value: str, kwargs: dict[str, t.Any], expected_error: str
) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(expected_error)}$"):
        parse_issue_value(value, **kwargs)


TEST_JOIN_ISSUE_VALUE: list[
    tuple[str | None, list[tuple[str, str]], dict[str, t.Any], str]
] = [
    (None, [], {}, ""),
    ("a", [], {}, "a"),
    (None, [("a", "b")], {}, "; a=b"),
    ("a", [("a", "b")], {}, "a; a=b"),
]


@pytest.mark.parametrize(
    "domain_name, pairs, kwargs, expected_result", TEST_JOIN_ISSUE_VALUE
)
def test_join_issue_value(
    domain_name: str | None,
    pairs: list[tuple[str, str]],
    kwargs: dict[str, t.Any],
    expected_result: str,
) -> None:
    assert join_issue_value(domain_name, pairs, **kwargs) == expected_result


TEST_JOIN_ISSUE_VALUE_FAIL: list[
    tuple[str | None, list[tuple[str, str]], dict[str, t.Any], str]
] = [
    ("", [], {}, "Invalid label ''"),
    (None, [("", "")], {}, "Invalid tag ''"),
    (None, [("a", " ")], {}, "Invalid value ' '"),
    (None, [("a", "a"), ("a", "b")], {}, "Tag 'a' appears multiple times"),
]


@pytest.mark.parametrize(
    "domain_name, pairs, kwargs, expected_error", TEST_JOIN_ISSUE_VALUE_FAIL
)
def test_join_issue_value_fail(
    domain_name: str | None,
    pairs: list[tuple[str, str]],
    kwargs: dict[str, t.Any],
    expected_error: str,
) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(expected_error)}$"):
        join_issue_value(domain_name, pairs, **kwargs)
