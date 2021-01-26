# -*- coding: utf-8 -*-
#
# (c) 2016, Yanis Guenane <yanis+ansible@guenane.org>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


# THIS FILE IS FOR COMPATIBILITY ONLY! YOU SHALL NOT IMPORT IT!
#
# This fill will be removed eventually, so if you're using it,
# please stop doing so.

from .basic import (
    HAS_PYOPENSSL,
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X25519_FULL,
    CRYPTOGRAPHY_HAS_X448,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    HAS_CRYPTOGRAPHY,
    OpenSSLObjectError,
    OpenSSLBadPassphraseError,
)

from .cryptography_crl import (
    REVOCATION_REASON_MAP,
    REVOCATION_REASON_MAP_INVERSE,
    cryptography_decode_revoked_certificate,
)

from .cryptography_support import (
    cryptography_get_extensions_from_cert,
    cryptography_get_extensions_from_csr,
    cryptography_name_to_oid,
    cryptography_oid_to_name,
    cryptography_get_name,
    cryptography_decode_name,
    cryptography_parse_key_usage_params,
    cryptography_get_basic_constraints,
    cryptography_key_needs_digest_for_signing,
    cryptography_compare_public_keys,
)

from .pem import (
    identify_private_key_format,
)

from .math import (
    binary_exp_mod,
    simple_gcd,
    quick_is_not_prime,
    count_bits,
)

from ._obj2txt import obj2txt as _obj2txt

from ._objects_data import OID_MAP as _OID_MAP

from ._objects import OID_LOOKUP as _OID_LOOKUP
from ._objects import NORMALIZE_NAMES as _NORMALIZE_NAMES
from ._objects import NORMALIZE_NAMES_SHORT as _NORMALIZE_NAMES_SHORT

from .pyopenssl_support import (
    pyopenssl_normalize_name,
    pyopenssl_get_extensions_from_cert,
    pyopenssl_get_extensions_from_csr,
)

from .support import (
    get_fingerprint_of_bytes,
    get_fingerprint,
    load_privatekey,
    load_certificate,
    load_certificate_request,
    parse_name_field,
    convert_relative_to_datetime,
    get_relative_time_option,
    select_message_digest,
    OpenSSLObject,
)

from ..io import (
    load_file_if_exists,
    write_file,
)
