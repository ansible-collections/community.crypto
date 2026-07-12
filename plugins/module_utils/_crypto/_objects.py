# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note that this module util is **PRIVATE** to the collection. It can have breaking changes at any time.
# Do not use this from other collections or standalone plugins/modules!

from __future__ import annotations

from ansible_collections.community.crypto.plugins.module_utils._crypto._objects_data import (
    OID_MAP,
)

DOTTED_LOOKUP: dict[str, str] = {}
OID_LOOKUP: dict[str, str] = {}
NORMALIZE_NAMES: dict[str, str] = {}
NORMALIZE_NAMES_SHORT: dict[str, str] = {}

for dotted, names_or_names_list in OID_MAP.items():
    names_list: list[tuple[str, ...]] = (
        names_or_names_list
        if isinstance(names_or_names_list, list)
        else [names_or_names_list]
    )
    primary_names = names_list[0]
    DOTTED_LOOKUP[dotted] = primary_names[0]
    for names in names_list:
        for name in names:
            if name in NORMALIZE_NAMES and OID_LOOKUP[name] != dotted:
                raise AssertionError(  # pragma: no cover
                    f'Name collision during setup: "{name}" for OIDs {dotted} and {OID_LOOKUP[name]}'
                )
            NORMALIZE_NAMES[name] = primary_names[0]
            NORMALIZE_NAMES_SHORT[name] = primary_names[-1]
            OID_LOOKUP[name] = dotted
for alias, original in [("userID", "userId")]:
    if alias in NORMALIZE_NAMES:
        raise AssertionError(  # pragma: no cover
            f'Name collision during adding aliases: "{alias}" (alias for "{original}") is already mapped to OID {OID_LOOKUP[alias]}'
        )
    NORMALIZE_NAMES[alias] = original
    NORMALIZE_NAMES_SHORT[alias] = NORMALIZE_NAMES_SHORT[original]
    OID_LOOKUP[alias] = OID_LOOKUP[original]


__all__ = ("NORMALIZE_NAMES", "NORMALIZE_NAMES_SHORT", "OID_LOOKUP")
