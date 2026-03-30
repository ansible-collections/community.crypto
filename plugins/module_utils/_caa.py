# Copyright (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

import re

_VALUE_RE = re.compile("^[\x21-\x3a\x3c-\x7e]*$")
_LABEL_RE = re.compile("^[0-9a-zA-Z][0-9a-zA-Z-]*$")


def _check_value(value: str) -> None:
    if not _VALUE_RE.match(value):
        raise ValueError(f"Invalid value {value!r}")


def _check_label(label: str, what: str) -> None:
    if not _LABEL_RE.match(label):
        raise ValueError(f"Invalid {what} {label!r}")


def _check_domain_name(value: str) -> None:
    for p in value.split("."):
        _check_label(p, "label")


def parse_issue_value(
    value: str, *, check_for_duplicates: bool = True, strict: bool = True
) -> tuple[str | None, list[tuple[str, str]]]:
    """
    Given a CAA issue property, parses it according to the syntax defined in RFC 8659.

    More precisely, see https://www.rfc-editor.org/rfc/rfc8659.html#section-4.2.

    If ``check_for_duplicates == True``, duplicate tags are reported as an error.
    If ``strict == True``, invalid characters are reported as an error.
    """
    parts = [v.strip(" \t") for v in value.split(";")]
    if len(parts) > 1 and not parts[-1]:
        del parts[-1]
    domain_name = parts[0] or None
    if domain_name is not None and strict:
        _check_domain_name(domain_name)
    pairs = []
    previous_tags: set[str] = set()
    for part in parts[1:]:
        pieces = part.split("=", 1)
        if len(pieces) != 2:
            raise ValueError(f"{part!r} is not of the form tag=value")
        tag, value = pieces[0].rstrip(" \t"), pieces[1].lstrip(" \t")
        if strict:
            _check_label(tag, "tag")
            _check_value(value)
        pairs.append((tag, value))
        if check_for_duplicates:
            if tag in previous_tags:
                raise ValueError(f"Tag {tag!r} appears multiple times")
            previous_tags.add(tag)
    return domain_name, pairs


def join_issue_value(
    domain_name: str | None,
    pairs: list[tuple[str, str]],
    *,
    check_for_duplicates: bool = True,
    strict: bool = True,
) -> str:
    """
    Given a domain name and a list of tag-value pairs, joins them according
    to the syntax defined in RFC 8659.

    More precisely, see https://www.rfc-editor.org/rfc/rfc8659.html#section-4.2.

    If ``check_for_duplicates == True``, duplicate tags are reported as an error.
    If ``strict == True``, invalid characters are reported as an error.
    """
    if domain_name is not None and strict:
        _check_domain_name(domain_name)
    parts = [domain_name or ""]
    previous_tags: set[str] = set()
    for tag, value in pairs:
        if strict:
            _check_label(tag, "tag")
            _check_value(value)
        parts.append(f"{tag}={value}")
        if check_for_duplicates:
            if tag in previous_tags:
                raise ValueError(f"Tag {tag!r} appears multiple times")
            previous_tags.add(tag)
    return "; ".join(parts)


__all__ = ("parse_issue_value",)
