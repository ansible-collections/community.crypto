# -*- coding: utf-8 -*-
#
# (c) 2019, Felix Fontein <felix@fontein.de>
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


import base64

from ansible.module_utils.common.text.converters import to_bytes, to_text, to_native

from ansible_collections.community.crypto.plugins.module_utils.compat import ipaddress as compat_ipaddress

from ._objects import OID_LOOKUP

try:
    import OpenSSL
except ImportError:
    # Error handled in the calling module.
    pass

from ._objects import (
    NORMALIZE_NAMES_SHORT,
    NORMALIZE_NAMES,
)

from ._obj2txt import obj2txt

from .basic import (
    OpenSSLObjectError,
)


def pyopenssl_normalize_name(name, short=False):
    nid = OpenSSL._util.lib.OBJ_txt2nid(to_bytes(name))
    if nid != 0:
        b_name = OpenSSL._util.lib.OBJ_nid2ln(nid)
        name = to_text(OpenSSL._util.ffi.string(b_name))
    if short:
        return NORMALIZE_NAMES_SHORT.get(name, name)
    else:
        return NORMALIZE_NAMES.get(name, name)


def pyopenssl_normalize_name_attribute(san):
    # apparently openssl returns 'IP address' not 'IP' as specifier when converting the subjectAltName to string
    # although it won't accept this specifier when generating the CSR. (https://github.com/openssl/openssl/issues/4004)
    if san.startswith('IP Address:'):
        san = 'IP:' + san[len('IP Address:'):]
    if san.startswith('IP:'):
        address = san[3:]
        if '/' in address:
            ip = compat_ipaddress.ip_network(address)
            san = 'IP:{0}/{1}'.format(ip.network_address.compressed, ip.prefixlen)
        else:
            ip = compat_ipaddress.ip_address(address)
            san = 'IP:{0}'.format(ip.compressed)
    if san.startswith('Registered ID:'):
        san = 'RID:' + san[len('Registered ID:'):]
    # Some versions of OpenSSL apparently forgot the colon. Happens in CI with Ubuntu 16.04 and FreeBSD 11.1
    if san.startswith('Registered ID'):
        san = 'RID:' + san[len('Registered ID'):]
    return san


def pyopenssl_get_extensions_from_cert(cert):
    # While pyOpenSSL allows us to get an extension's DER value, it won't
    # give us the dotted string for an OID. So we have to do some magic to
    # get hold of it.
    result = dict()
    ext_count = cert.get_extension_count()
    for i in range(0, ext_count):
        ext = cert.get_extension(i)
        entry = dict(
            critical=bool(ext.get_critical()),
            value=base64.b64encode(ext.get_data()),
        )
        try:
            oid = obj2txt(
                OpenSSL._util.lib,
                OpenSSL._util.ffi,
                OpenSSL._util.lib.X509_EXTENSION_get_object(ext._extension)
            )
            # This could also be done a bit simpler:
            #
            #   oid = obj2txt(OpenSSL._util.lib, OpenSSL._util.ffi, OpenSSL._util.lib.OBJ_nid2obj(ext._nid))
            #
            # Unfortunately this gives the wrong result in case the linked OpenSSL
            # doesn't know the OID. That's why we have to get the OID dotted string
            # similarly to how cryptography does it.
        except AttributeError:
            # When PyOpenSSL is used with cryptography >= 35.0.0, obj2txt cannot be used.
            # We try to figure out the OID with our internal lookup table, and if we fail,
            # we use the short name OpenSSL returns.
            oid = to_native(ext.get_short_name())
            oid = OID_LOOKUP.get(oid, oid)
        result[oid] = entry
    return result


def pyopenssl_get_extensions_from_csr(csr):
    # While pyOpenSSL allows us to get an extension's DER value, it won't
    # give us the dotted string for an OID. So we have to do some magic to
    # get hold of it.
    result = dict()
    for ext in csr.get_extensions():
        entry = dict(
            critical=bool(ext.get_critical()),
            value=base64.b64encode(ext.get_data()),
        )
        try:
            oid = obj2txt(
                OpenSSL._util.lib,
                OpenSSL._util.ffi,
                OpenSSL._util.lib.X509_EXTENSION_get_object(ext._extension)
            )
            # This could also be done a bit simpler:
            #
            #   oid = obj2txt(OpenSSL._util.lib, OpenSSL._util.ffi, OpenSSL._util.lib.OBJ_nid2obj(ext._nid))
            #
            # Unfortunately this gives the wrong result in case the linked OpenSSL
            # doesn't know the OID. That's why we have to get the OID dotted string
            # similarly to how cryptography does it.
        except AttributeError:
            # When PyOpenSSL is used with cryptography >= 35.0.0, obj2txt cannot be used.
            # We try to figure out the OID with our internal lookup table, and if we fail,
            # we use the short name OpenSSL returns.
            oid = to_native(ext.get_short_name())
            oid = OID_LOOKUP.get(oid, oid)
        result[oid] = entry
    return result


def pyopenssl_parse_name_constraints(name_constraints_extension):
    lines = to_text(name_constraints_extension, errors='surrogate_or_strict').splitlines()
    exclude = None
    excluded = []
    permitted = []
    for line in lines:
        if line.startswith(' ') or line.startswith('\t'):
            name = pyopenssl_normalize_name_attribute(line.strip())
            if exclude is True:
                excluded.append(name)
            elif exclude is False:
                permitted.append(name)
            else:
                raise OpenSSLObjectError('Unexpected nameConstraint line: "{0}"'.format(line))
        else:
            line_lc = line.lower()
            if line_lc.startswith('exclud'):
                exclude = True
            elif line_lc.startswith('includ') or line_lc.startswith('permitt'):
                exclude = False
            else:
                raise OpenSSLObjectError('Cannot parse nameConstraint line: "{0}"'.format(line))
    return permitted, excluded
