# Copyright (c) 2025 Ansible project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Module utils for cryptography requirements.

Must be kept in sync with plugins/doc_fragments/cryptography_dep.py.
"""

from __future__ import annotations

import traceback

from ansible.module_utils.basic import missing_required_lib
from ansible_collections.community.crypto.plugins.module_utils.version import (
    LooseVersion,
)


_CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography import x509  # noqa: F401, pylint: disable=unused-import

    _CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    _CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    _CRYPTOGRAPHY_FOUND = False
else:
    _CRYPTOGRAPHY_FOUND = True


# Corresponds to the community.crypto.cryptography_dep.minimum doc fragment
COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION = "3.3"


def assert_required_cryptography_version(
    module,
    *,
    minimum_cryptography_version: str = COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION,
) -> None:
    if not _CRYPTOGRAPHY_FOUND:
        module.fail_json(
            msg=missing_required_lib(f"cryptography >= {minimum_cryptography_version}"),
            exception=_CRYPTOGRAPHY_IMP_ERR,
        )
    if _CRYPTOGRAPHY_VERSION < LooseVersion(minimum_cryptography_version):
        module.fail_json(
            msg=f"Cannot detect the required Python library cryptography (>= {minimum_cryptography_version})",
        )


__all__ = (
    "COLLECTION_MINIMUM_CRYPTOGRAPHY_VERSION",
    "assert_required_cryptography_version",
)
