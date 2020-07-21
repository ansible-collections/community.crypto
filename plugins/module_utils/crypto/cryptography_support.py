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
import binascii
import re

from ansible.module_utils._text import to_text
from ._asn1 import serialize_asn1_string_as_der

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    import ipaddress
except ImportError:
    # Error handled in the calling module.
    pass

from .basic import (
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED448,
    OpenSSLObjectError,
)

from ._objects import (
    OID_LOOKUP,
    OID_MAP,
    NORMALIZE_NAMES_SHORT,
    NORMALIZE_NAMES,
)

from ._obj2txt import obj2txt


DOTTED_OID = re.compile(r'^\d+(?:\.\d+)+$')


def cryptography_get_extensions_from_cert(cert):
    # Since cryptography won't give us the DER value for an extension
    # (that is only stored for unrecognized extensions), we have to re-do
    # the extension parsing outselves.
    result = dict()
    backend = cert._backend
    x509_obj = cert._x509

    for i in range(backend._lib.X509_get_ext_count(x509_obj)):
        ext = backend._lib.X509_get_ext(x509_obj, i)
        if ext == backend._ffi.NULL:
            continue
        crit = backend._lib.X509_EXTENSION_get_critical(ext)
        data = backend._lib.X509_EXTENSION_get_data(ext)
        backend.openssl_assert(data != backend._ffi.NULL)
        der = backend._ffi.buffer(data.data, data.length)[:]
        entry = dict(
            critical=(crit == 1),
            value=base64.b64encode(der),
        )
        oid = obj2txt(backend._lib, backend._ffi, backend._lib.X509_EXTENSION_get_object(ext))
        result[oid] = entry
    return result


def cryptography_get_extensions_from_csr(csr):
    # Since cryptography won't give us the DER value for an extension
    # (that is only stored for unrecognized extensions), we have to re-do
    # the extension parsing outselves.
    result = dict()
    backend = csr._backend

    extensions = backend._lib.X509_REQ_get_extensions(csr._x509_req)
    extensions = backend._ffi.gc(
        extensions,
        lambda ext: backend._lib.sk_X509_EXTENSION_pop_free(
            ext,
            backend._ffi.addressof(backend._lib._original_lib, "X509_EXTENSION_free")
        )
    )

    for i in range(backend._lib.sk_X509_EXTENSION_num(extensions)):
        ext = backend._lib.sk_X509_EXTENSION_value(extensions, i)
        if ext == backend._ffi.NULL:
            continue
        crit = backend._lib.X509_EXTENSION_get_critical(ext)
        data = backend._lib.X509_EXTENSION_get_data(ext)
        backend.openssl_assert(data != backend._ffi.NULL)
        der = backend._ffi.buffer(data.data, data.length)[:]
        entry = dict(
            critical=(crit == 1),
            value=base64.b64encode(der),
        )
        oid = obj2txt(backend._lib, backend._ffi, backend._lib.X509_EXTENSION_get_object(ext))
        result[oid] = entry
    return result


def cryptography_name_to_oid(name):
    dotted = OID_LOOKUP.get(name)
    if dotted is None:
        if DOTTED_OID.match(name):
            return x509.oid.ObjectIdentifier(name)
        raise OpenSSLObjectError('Cannot find OID for "{0}"'.format(name))
    return x509.oid.ObjectIdentifier(dotted)


def cryptography_oid_to_name(oid, short=False):
    dotted_string = oid.dotted_string
    names = OID_MAP.get(dotted_string)
    if names:
        name = names[0]
    else:
        name = oid._name
        if name == 'Unknown OID':
            name = dotted_string
    if short:
        return NORMALIZE_NAMES_SHORT.get(name, name)
    else:
        return NORMALIZE_NAMES.get(name, name)


def _get_hex(bytesstr):
    if bytesstr is None:
        return bytesstr
    data = binascii.hexlify(bytesstr)
    data = to_text(b':'.join(data[i:i + 2] for i in range(0, len(data), 2)))
    return data


def _parse_hex(bytesstr):
    if bytesstr is None:
        return bytesstr
    data = ''.join([('0' * (2 - len(p)) + p) if len(p) < 2 else p for p in to_text(bytesstr).split(':')])
    data = binascii.unhexlify(data)
    return data


def _parse_dn(name):
    '''
    Parse a Distinguished Name.

    Can be of the form ``CN=Test, O = Something`` or ``CN = Test,O= Something``.
    '''
    original_name = name
    name = name.lstrip()
    sep = ','
    if name.startswith('/'):
        sep = '/'
        name = name[1:]
    sep_str = sep + '\\'
    result = []
    start_re = re.compile(r'^ *([a-zA-z0-9]+) *= *')
    while name:
        m = start_re.match(name)
        if not m:
            raise OpenSSLObjectError('Error while parsing distinguished name "{0}": cannot start part in "{1}"'.format(original_name, name))
        oid = cryptography_name_to_oid(m.group(1))
        idx = len(m.group(0))
        decoded_name = []
        length = len(name)
        while idx < length:
            i = idx
            while i < length and name[i] not in sep_str:
                i += 1
            if i > idx:
                decoded_name.append(name[idx:i])
                idx = i
            while idx + 1 < length and name[idx] == '\\':
                decoded_name.append(name[idx + 1])
                idx += 2
            if idx < length and name[idx] == sep:
                break
        result.append(x509.NameAttribute(oid, ''.join(decoded_name)))
        name = name[idx:]
        if name:
            if name[0] != sep or len(name) < 2:
                raise OpenSSLObjectError('Error while parsing distinguished name "{0}": unexpected end of string'.format(original_name))
            name = name[1:]
    return result


def cryptography_get_name(name):
    '''
    Given a name string, returns a cryptography x509.Name object.
    Raises an OpenSSLObjectError if the name is unknown or cannot be parsed.
    '''
    try:
        if name.startswith('DNS:'):
            return x509.DNSName(to_text(name[4:]))
        if name.startswith('IP:'):
            address = to_text(name[3:])
            if '/' in address:
                return x509.IPAddress(ipaddress.ip_network(address))
            return x509.IPAddress(ipaddress.ip_address(address))
        if name.startswith('email:'):
            return x509.RFC822Name(to_text(name[6:]))
        if name.startswith('URI:'):
            return x509.UniformResourceIdentifier(to_text(name[4:]))
        if name.startswith('RID:'):
            m = re.match(r'^([0-9]+(?:\.[0-9]+)*)$', to_text(name[4:]))
            if not m:
                raise OpenSSLObjectError('Cannot parse Subject Alternative Name "{0}"'.format(name))
            return x509.RegisteredID(x509.oid.ObjectIdentifier(m.group(1)))
        if name.startswith('otherName:'):
            # otherName can either be a raw ASN.1 hex string or in the format that OpenSSL works with.
            m = re.match(r'^([0-9]+(?:\.[0-9]+)*);([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2})*)$', to_text(name[10:]))
            if m:
                return x509.OtherName(x509.oid.ObjectIdentifier(m.group(1)), _parse_hex(m.group(2)))

            # See https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html - Subject Alternative Name for more
            # defailts on the format expected.
            name = to_text(name[10:], errors='surrogate_or_strict')
            if ';' not in name:
                raise OpenSSLObjectError('Cannot parse Subject Alternative Name otherName "{0}", must be in the '
                                         'format "otherName:<OID>;<ASN.1 OpenSSL Encoded String>" or '
                                         '"otherName:<OID>;<hex string>"'.format(name))

            oid, value = name.split(';', 1)
            b_value = serialize_asn1_string_as_der(value)
            return x509.OtherName(x509.ObjectIdentifier(oid), b_value)
        if name.startswith('dirName:'):
            return x509.DirectoryName(x509.Name(_parse_dn(to_text(name[8:]))))
    except Exception as e:
        raise OpenSSLObjectError('Cannot parse Subject Alternative Name "{0}": {1}'.format(name, e))
    if ':' not in name:
        raise OpenSSLObjectError('Cannot parse Subject Alternative Name "{0}" (forgot "DNS:" prefix?)'.format(name))
    raise OpenSSLObjectError('Cannot parse Subject Alternative Name "{0}" (potentially unsupported by cryptography backend)'.format(name))


def _dn_escape_value(value):
    '''
    Escape Distinguished Name's attribute value.
    '''
    value = value.replace('\\', '\\\\')
    for ch in [',', '#', '+', '<', '>', ';', '"', '=', '/']:
        value = value.replace(ch, '\\%s' % ch)
    if value.startswith(' '):
        value = r'\ ' + value[1:]
    return value


def cryptography_decode_name(name):
    '''
    Given a cryptography x509.Name object, returns a string.
    Raises an OpenSSLObjectError if the name is not supported.
    '''
    if isinstance(name, x509.DNSName):
        return 'DNS:{0}'.format(name.value)
    if isinstance(name, x509.IPAddress):
        if isinstance(name.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return 'IP:{0}/{1}'.format(name.value.network_address.compressed, name.value.prefixlen)
        return 'IP:{0}'.format(name.value.compressed)
    if isinstance(name, x509.RFC822Name):
        return 'email:{0}'.format(name.value)
    if isinstance(name, x509.UniformResourceIdentifier):
        return 'URI:{0}'.format(name.value)
    if isinstance(name, x509.DirectoryName):
        return 'dirName:' + ''.join([
            '/{0}={1}'.format(cryptography_oid_to_name(attribute.oid, short=True), _dn_escape_value(attribute.value))
            for attribute in name.value
        ])
    if isinstance(name, x509.RegisteredID):
        return 'RID:{0}'.format(name.value.dotted_string)
    if isinstance(name, x509.OtherName):
        return 'otherName:{0};{1}'.format(name.type_id.dotted_string, _get_hex(name.value))
    raise OpenSSLObjectError('Cannot decode name "{0}"'.format(name))


def _cryptography_get_keyusage(usage):
    '''
    Given a key usage identifier string, returns the parameter name used by cryptography's x509.KeyUsage().
    Raises an OpenSSLObjectError if the identifier is unknown.
    '''
    if usage in ('Digital Signature', 'digitalSignature'):
        return 'digital_signature'
    if usage in ('Non Repudiation', 'nonRepudiation'):
        return 'content_commitment'
    if usage in ('Key Encipherment', 'keyEncipherment'):
        return 'key_encipherment'
    if usage in ('Data Encipherment', 'dataEncipherment'):
        return 'data_encipherment'
    if usage in ('Key Agreement', 'keyAgreement'):
        return 'key_agreement'
    if usage in ('Certificate Sign', 'keyCertSign'):
        return 'key_cert_sign'
    if usage in ('CRL Sign', 'cRLSign'):
        return 'crl_sign'
    if usage in ('Encipher Only', 'encipherOnly'):
        return 'encipher_only'
    if usage in ('Decipher Only', 'decipherOnly'):
        return 'decipher_only'
    raise OpenSSLObjectError('Unknown key usage "{0}"'.format(usage))


def cryptography_parse_key_usage_params(usages):
    '''
    Given a list of key usage identifier strings, returns the parameters for cryptography's x509.KeyUsage().
    Raises an OpenSSLObjectError if an identifier is unknown.
    '''
    params = dict(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    for usage in usages:
        params[_cryptography_get_keyusage(usage)] = True
    return params


def cryptography_get_basic_constraints(constraints):
    '''
    Given a list of constraints, returns a tuple (ca, path_length).
    Raises an OpenSSLObjectError if a constraint is unknown or cannot be parsed.
    '''
    ca = False
    path_length = None
    if constraints:
        for constraint in constraints:
            if constraint.startswith('CA:'):
                if constraint == 'CA:TRUE':
                    ca = True
                elif constraint == 'CA:FALSE':
                    ca = False
                else:
                    raise OpenSSLObjectError('Unknown basic constraint value "{0}" for CA'.format(constraint[3:]))
            elif constraint.startswith('pathlen:'):
                v = constraint[len('pathlen:'):]
                try:
                    path_length = int(v)
                except Exception as e:
                    raise OpenSSLObjectError('Cannot parse path length constraint "{0}" ({1})'.format(v, e))
            else:
                raise OpenSSLObjectError('Unknown basic constraint "{0}"'.format(constraint))
    return ca, path_length


def cryptography_key_needs_digest_for_signing(key):
    '''Tests whether the given private key requires a digest algorithm for signing.

    Ed25519 and Ed448 keys do not; they need None to be passed as the digest algorithm.
    '''
    if CRYPTOGRAPHY_HAS_ED25519 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey):
        return False
    if CRYPTOGRAPHY_HAS_ED448 and isinstance(key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey):
        return False
    return True


def cryptography_compare_public_keys(key1, key2):
    '''Tests whether two public keys are the same.

    Needs special logic for Ed25519 and Ed448 keys, since they do not have public_numbers().
    '''
    if CRYPTOGRAPHY_HAS_ED25519:
        a = isinstance(key1, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey)
        b = isinstance(key2, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey)
        if a or b:
            if not a or not b:
                return False
            a = key1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            b = key2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return a == b
    if CRYPTOGRAPHY_HAS_ED448:
        a = isinstance(key1, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey)
        b = isinstance(key2, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey)
        if a or b:
            if not a or not b:
                return False
            a = key1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            b = key2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return a == b
    return key1.public_numbers() == key2.public_numbers()


def cryptography_serial_number_of_cert(cert):
    '''Returns cert.serial_number.

    Also works for old versions of cryptography.
    '''
    try:
        return cert.serial_number
    except AttributeError:
        # The property was called "serial" before cryptography 1.4
        return cert.serial
