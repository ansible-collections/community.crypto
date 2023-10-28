# -*- coding: utf-8 -*-
#
# Copyright (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import binascii
import re
import sys
import traceback

from ansible.module_utils.common.text.converters import to_text, to_bytes, to_native
from ansible.module_utils.six.moves.urllib.parse import urlparse, urlunparse, ParseResult

from ._asn1 import serialize_asn1_string_as_der

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

try:
    import cryptography
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    import ipaddress
except ImportError:
    # Error handled in the calling module.
    pass

try:
    import cryptography.hazmat.primitives.asymmetric.rsa
except ImportError:
    pass
try:
    import cryptography.hazmat.primitives.asymmetric.ec
except ImportError:
    pass
try:
    import cryptography.hazmat.primitives.asymmetric.dsa
except ImportError:
    pass
try:
    import cryptography.hazmat.primitives.asymmetric.ed25519
except ImportError:
    pass
try:
    import cryptography.hazmat.primitives.asymmetric.ed448
except ImportError:
    pass

try:
    # This is a separate try/except since this is only present in cryptography 2.5 or newer
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_key_and_certificates as _load_key_and_certificates,
    )
except ImportError:
    # Error handled in the calling module.
    _load_key_and_certificates = None

try:
    # This is a separate try/except since this is only present in cryptography 36.0.0 or newer
    from cryptography.hazmat.primitives.serialization.pkcs12 import (
        load_pkcs12 as _load_pkcs12,
    )
except ImportError:
    # Error handled in the calling module.
    _load_pkcs12 = None

try:
    import idna

    HAS_IDNA = True
except ImportError:
    HAS_IDNA = False
    IDNA_IMP_ERROR = traceback.format_exc()

from ansible.module_utils.basic import missing_required_lib

from .basic import (
    CRYPTOGRAPHY_HAS_DSA_SIGN,
    CRYPTOGRAPHY_HAS_EC_SIGN,
    CRYPTOGRAPHY_HAS_ED25519,
    CRYPTOGRAPHY_HAS_ED25519_SIGN,
    CRYPTOGRAPHY_HAS_ED448,
    CRYPTOGRAPHY_HAS_ED448_SIGN,
    CRYPTOGRAPHY_HAS_RSA_SIGN,
    CRYPTOGRAPHY_HAS_X25519,
    CRYPTOGRAPHY_HAS_X25519_FULL,
    CRYPTOGRAPHY_HAS_X448,
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
    result = dict()
    try:
        # Since cryptography will not give us the DER value for an extension
        # (that is only stored for unrecognized extensions), we have to re-do
        # the extension parsing ourselves.
        backend = default_backend()
        try:
            # For certain old versions of cryptography, backend is a MultiBackend object,
            # which has no _lib attribute. In that case, revert to the old approach.
            backend._lib
        except AttributeError:
            backend = cert._backend

        x509_obj = cert._x509
        # With cryptography 35.0.0, we can no longer use obj2txt. Unfortunately it still does
        # not allow to get the raw value of an extension, so we have to use this ugly hack:
        exts = list(cert.extensions)

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
                value=to_native(base64.b64encode(der)),
            )
            try:
                oid = obj2txt(backend._lib, backend._ffi, backend._lib.X509_EXTENSION_get_object(ext))
            except AttributeError:
                oid = exts[i].oid.dotted_string
            result[oid] = entry

    except Exception:
        # In case the above method breaks, we likely have cryptography 36.0.0 or newer.
        # Use it's public_bytes() feature in that case. We will later switch this around
        # so that this code will be the default, but for now this will act as a fallback
        # since it will re-serialize de-serialized data, which can be different (if the
        # original data was not canonicalized) from what was contained in the certificate.
        for ext in cert.extensions:
            result[ext.oid.dotted_string] = dict(
                critical=ext.critical,
                value=to_native(base64.b64encode(ext.value.public_bytes())),
            )

    return result


def cryptography_get_extensions_from_csr(csr):
    result = dict()
    try:
        # Since cryptography will not give us the DER value for an extension
        # (that is only stored for unrecognized extensions), we have to re-do
        # the extension parsing ourselves.
        backend = default_backend()
        try:
            # For certain old versions of cryptography, backend is a MultiBackend object,
            # which has no _lib attribute. In that case, revert to the old approach.
            backend._lib
        except AttributeError:
            backend = csr._backend

        extensions = backend._lib.X509_REQ_get_extensions(csr._x509_req)
        extensions = backend._ffi.gc(
            extensions,
            lambda ext: backend._lib.sk_X509_EXTENSION_pop_free(
                ext,
                backend._ffi.addressof(backend._lib._original_lib, "X509_EXTENSION_free")
            )
        )

        # With cryptography 35.0.0, we can no longer use obj2txt. Unfortunately it still does
        # not allow to get the raw value of an extension, so we have to use this ugly hack:
        exts = list(csr.extensions)

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
                value=to_native(base64.b64encode(der)),
            )
            try:
                oid = obj2txt(backend._lib, backend._ffi, backend._lib.X509_EXTENSION_get_object(ext))
            except AttributeError:
                oid = exts[i].oid.dotted_string
            result[oid] = entry

    except Exception:
        # In case the above method breaks, we likely have cryptography 36.0.0 or newer.
        # Use it's public_bytes() feature in that case. We will later switch this around
        # so that this code will be the default, but for now this will act as a fallback
        # since it will re-serialize de-serialized data, which can be different (if the
        # original data was not canonicalized) from what was contained in the CSR.
        for ext in csr.extensions:
            result[ext.oid.dotted_string] = dict(
                critical=ext.critical,
                value=to_native(base64.b64encode(ext.value.public_bytes())),
            )

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


DN_COMPONENT_START_RE = re.compile(b'^ *([a-zA-z0-9.]+) *= *')
DN_HEX_LETTER = b'0123456789abcdef'


if sys.version_info[0] < 3:
    _int_to_byte = chr
else:
    def _int_to_byte(value):
        return bytes((value, ))


def _parse_dn_component(name, sep=b',', decode_remainder=True):
    m = DN_COMPONENT_START_RE.match(name)
    if not m:
        raise OpenSSLObjectError(u'cannot start part in "{0}"'.format(to_text(name)))
    oid = cryptography_name_to_oid(to_text(m.group(1)))
    idx = len(m.group(0))
    decoded_name = []
    sep_str = sep + b'\\'
    if decode_remainder:
        length = len(name)
        if length > idx and name[idx:idx + 1] == b'#':
            # Decoding a hex string
            idx += 1
            while idx + 1 < length:
                ch1 = name[idx:idx + 1]
                ch2 = name[idx + 1:idx + 2]
                idx1 = DN_HEX_LETTER.find(ch1.lower())
                idx2 = DN_HEX_LETTER.find(ch2.lower())
                if idx1 < 0 or idx2 < 0:
                    raise OpenSSLObjectError(u'Invalid hex sequence entry "{0}"'.format(to_text(ch1 + ch2)))
                idx += 2
                decoded_name.append(_int_to_byte(idx1 * 16 + idx2))
        else:
            # Decoding a regular string
            while idx < length:
                i = idx
                while i < length and name[i:i + 1] not in sep_str:
                    i += 1
                if i > idx:
                    decoded_name.append(name[idx:i])
                    idx = i
                while idx + 1 < length and name[idx:idx + 1] == b'\\':
                    ch = name[idx + 1:idx + 2]
                    idx1 = DN_HEX_LETTER.find(ch.lower())
                    if idx1 >= 0:
                        if idx + 2 >= length:
                            raise OpenSSLObjectError(u'Hex escape sequence "\\{0}" incomplete at end of string'.format(to_text(ch)))
                        ch2 = name[idx + 2:idx + 3]
                        idx2 = DN_HEX_LETTER.find(ch2.lower())
                        if idx2 < 0:
                            raise OpenSSLObjectError(u'Hex escape sequence "\\{0}" has invalid second letter'.format(to_text(ch + ch2)))
                        ch = _int_to_byte(idx1 * 16 + idx2)
                        idx += 1
                    idx += 2
                    decoded_name.append(ch)
                if idx < length and name[idx:idx + 1] == sep:
                    break
    else:
        decoded_name.append(name[idx:])
        idx = len(name)
    return x509.NameAttribute(oid, to_text(b''.join(decoded_name))), name[idx:]


def _parse_dn(name):
    '''
    Parse a Distinguished Name.

    Can be of the form ``CN=Test, O = Something`` or ``CN = Test,O= Something``.
    '''
    original_name = name
    name = name.lstrip()
    sep = b','
    if name.startswith(b'/'):
        sep = b'/'
        name = name[1:]
    result = []
    while name:
        try:
            attribute, name = _parse_dn_component(name, sep=sep)
        except OpenSSLObjectError as e:
            raise OpenSSLObjectError(u'Error while parsing distinguished name "{0}": {1}'.format(to_text(original_name), e))
        result.append(attribute)
        if name:
            if name[0:1] != sep or len(name) < 2:
                raise OpenSSLObjectError(u'Error while parsing distinguished name "{0}": unexpected end of string'.format(to_text(original_name)))
            name = name[1:]
    return result


def cryptography_parse_relative_distinguished_name(rdn):
    names = []
    for part in rdn:
        try:
            names.append(_parse_dn_component(to_bytes(part), decode_remainder=False)[0])
        except OpenSSLObjectError as e:
            raise OpenSSLObjectError(u'Error while parsing relative distinguished name "{0}": {1}'.format(part, e))
    return cryptography.x509.RelativeDistinguishedName(names)


def _is_ascii(value):
    '''Check whether the Unicode string `value` contains only ASCII characters.'''
    try:
        value.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def _adjust_idn(value, idn_rewrite):
    if idn_rewrite == 'ignore' or not value:
        return value
    if idn_rewrite == 'idna' and _is_ascii(value):
        return value
    if idn_rewrite not in ('idna', 'unicode'):
        raise ValueError('Invalid value for idn_rewrite: "{0}"'.format(idn_rewrite))
    if not HAS_IDNA:
        raise OpenSSLObjectError(
            missing_required_lib('idna', reason='to transform {what} DNS name "{name}" to {dest}'.format(
                name=value,
                what='IDNA' if idn_rewrite == 'unicode' else 'Unicode',
                dest='Unicode' if idn_rewrite == 'unicode' else 'IDNA',
            )))
    # Since IDNA does not like '*' or empty labels (except one empty label at the end),
    # we split and let IDNA only handle labels that are neither empty or '*'.
    parts = value.split(u'.')
    for index, part in enumerate(parts):
        if part in (u'', u'*'):
            continue
        try:
            if idn_rewrite == 'idna':
                parts[index] = idna.encode(part).decode('ascii')
            elif idn_rewrite == 'unicode' and part.startswith(u'xn--'):
                parts[index] = idna.decode(part)
        except idna.IDNAError as exc2008:
            try:
                if idn_rewrite == 'idna':
                    parts[index] = part.encode('idna').decode('ascii')
                elif idn_rewrite == 'unicode' and part.startswith(u'xn--'):
                    parts[index] = part.encode('ascii').decode('idna')
            except Exception as exc2003:
                raise OpenSSLObjectError(
                    u'Error while transforming part "{part}" of {what} DNS name "{name}" to {dest}.'
                    u' IDNA2008 transformation resulted in "{exc2008}", IDNA2003 transformation resulted in "{exc2003}".'.format(
                        part=part,
                        name=value,
                        what='IDNA' if idn_rewrite == 'unicode' else 'Unicode',
                        dest='Unicode' if idn_rewrite == 'unicode' else 'IDNA',
                        exc2003=exc2003,
                        exc2008=exc2008,
                    ))
    return u'.'.join(parts)


def _adjust_idn_email(value, idn_rewrite):
    idx = value.find(u'@')
    if idx < 0:
        return value
    return u'{0}@{1}'.format(value[:idx], _adjust_idn(value[idx + 1:], idn_rewrite))


def _adjust_idn_url(value, idn_rewrite):
    url = urlparse(value)
    host = _adjust_idn(url.hostname, idn_rewrite)
    if url.username is not None and url.password is not None:
        host = u'{0}:{1}@{2}'.format(url.username, url.password, host)
    elif url.username is not None:
        host = u'{0}@{1}'.format(url.username, host)
    if url.port is not None:
        host = u'{0}:{1}'.format(host, url.port)
    return urlunparse(
        ParseResult(scheme=url.scheme, netloc=host, path=url.path, params=url.params, query=url.query, fragment=url.fragment))


def cryptography_get_name(name, what='Subject Alternative Name'):
    '''
    Given a name string, returns a cryptography x509.GeneralName object.
    Raises an OpenSSLObjectError if the name is unknown or cannot be parsed.
    '''
    try:
        if name.startswith('DNS:'):
            return x509.DNSName(_adjust_idn(to_text(name[4:]), 'idna'))
        if name.startswith('IP:'):
            address = to_text(name[3:])
            if '/' in address:
                return x509.IPAddress(ipaddress.ip_network(address))
            return x509.IPAddress(ipaddress.ip_address(address))
        if name.startswith('email:'):
            return x509.RFC822Name(_adjust_idn_email(to_text(name[6:]), 'idna'))
        if name.startswith('URI:'):
            return x509.UniformResourceIdentifier(_adjust_idn_url(to_text(name[4:]), 'idna'))
        if name.startswith('RID:'):
            m = re.match(r'^([0-9]+(?:\.[0-9]+)*)$', to_text(name[4:]))
            if not m:
                raise OpenSSLObjectError('Cannot parse {what} "{name}"'.format(name=name, what=what))
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
                raise OpenSSLObjectError('Cannot parse {what} otherName "{name}", must be in the '
                                         'format "otherName:<OID>;<ASN.1 OpenSSL Encoded String>" or '
                                         '"otherName:<OID>;<hex string>"'.format(name=name, what=what))

            oid, value = name.split(';', 1)
            b_value = serialize_asn1_string_as_der(value)
            return x509.OtherName(x509.ObjectIdentifier(oid), b_value)
        if name.startswith('dirName:'):
            return x509.DirectoryName(x509.Name(reversed(_parse_dn(to_bytes(name[8:])))))
    except Exception as e:
        raise OpenSSLObjectError('Cannot parse {what} "{name}": {error}'.format(name=name, what=what, error=e))
    if ':' not in name:
        raise OpenSSLObjectError('Cannot parse {what} "{name}" (forgot "DNS:" prefix?)'.format(name=name, what=what))
    raise OpenSSLObjectError('Cannot parse {what} "{name}" (potentially unsupported by cryptography backend)'.format(name=name, what=what))


def _dn_escape_value(value):
    '''
    Escape Distinguished Name's attribute value.
    '''
    value = value.replace(u'\\', u'\\\\')
    for ch in [u',', u'+', u'<', u'>', u';', u'"']:
        value = value.replace(ch, u'\\%s' % ch)
    value = value.replace(u'\0', u'\\00')
    if value.startswith((u' ', u'#')):
        value = u'\\%s' % value[0] + value[1:]
    if value.endswith(u' '):
        value = value[:-1] + u'\\ '
    return value


def cryptography_decode_name(name, idn_rewrite='ignore'):
    '''
    Given a cryptography x509.GeneralName object, returns a string.
    Raises an OpenSSLObjectError if the name is not supported.
    '''
    if idn_rewrite not in ('ignore', 'idna', 'unicode'):
        raise AssertionError('idn_rewrite must be one of "ignore", "idna", or "unicode"')
    if isinstance(name, x509.DNSName):
        return u'DNS:{0}'.format(_adjust_idn(name.value, idn_rewrite))
    if isinstance(name, x509.IPAddress):
        if isinstance(name.value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            return u'IP:{0}/{1}'.format(name.value.network_address.compressed, name.value.prefixlen)
        return u'IP:{0}'.format(name.value.compressed)
    if isinstance(name, x509.RFC822Name):
        return u'email:{0}'.format(_adjust_idn_email(name.value, idn_rewrite))
    if isinstance(name, x509.UniformResourceIdentifier):
        return u'URI:{0}'.format(_adjust_idn_url(name.value, idn_rewrite))
    if isinstance(name, x509.DirectoryName):
        # According to https://datatracker.ietf.org/doc/html/rfc4514.html#section-2.1 the
        # list needs to be reversed, and joined by commas
        return u'dirName:' + ','.join([
            u'{0}={1}'.format(to_text(cryptography_oid_to_name(attribute.oid, short=True)), _dn_escape_value(attribute.value))
            for attribute in reversed(list(name.value))
        ])
    if isinstance(name, x509.RegisteredID):
        return u'RID:{0}'.format(name.value.dotted_string)
    if isinstance(name, x509.OtherName):
        return u'otherName:{0};{1}'.format(name.type_id.dotted_string, _get_hex(name.value))
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


def _compare_public_keys(key1, key2, clazz):
    a = isinstance(key1, clazz)
    b = isinstance(key2, clazz)
    if not (a or b):
        return None
    if not a or not b:
        return False
    a = key1.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    b = key2.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return a == b


def cryptography_compare_public_keys(key1, key2):
    '''Tests whether two public keys are the same.

    Needs special logic for Ed25519 and Ed448 keys, since they do not have public_numbers().
    '''
    if CRYPTOGRAPHY_HAS_ED25519:
        res = _compare_public_keys(key1, key2, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey)
        if res is not None:
            return res
    if CRYPTOGRAPHY_HAS_ED448:
        res = _compare_public_keys(key1, key2, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey)
        if res is not None:
            return res
    return key1.public_numbers() == key2.public_numbers()


def _compare_private_keys(key1, key2, clazz, has_no_private_bytes=False):
    a = isinstance(key1, clazz)
    b = isinstance(key2, clazz)
    if not (a or b):
        return None
    if not a or not b:
        return False
    if has_no_private_bytes:
        # We do not have the private_bytes() function - compare associated public keys
        return cryptography_compare_public_keys(a.public_key(), b.public_key())
    encryption_algorithm = cryptography.hazmat.primitives.serialization.NoEncryption()
    a = key1.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, encryption_algorithm=encryption_algorithm)
    b = key2.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, encryption_algorithm=encryption_algorithm)
    return a == b


def cryptography_compare_private_keys(key1, key2):
    '''Tests whether two private keys are the same.

    Needs special logic for Ed25519, X25519, and Ed448 keys, since they do not have private_numbers().
    '''
    if CRYPTOGRAPHY_HAS_ED25519:
        res = _compare_private_keys(key1, key2, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey)
        if res is not None:
            return res
    if CRYPTOGRAPHY_HAS_X25519:
        res = _compare_private_keys(
            key1, key2, cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey, has_no_private_bytes=not CRYPTOGRAPHY_HAS_X25519_FULL)
        if res is not None:
            return res
    if CRYPTOGRAPHY_HAS_ED448:
        res = _compare_private_keys(key1, key2, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey)
        if res is not None:
            return res
    if CRYPTOGRAPHY_HAS_X448:
        res = _compare_private_keys(key1, key2, cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey)
        if res is not None:
            return res
    return key1.private_numbers() == key2.private_numbers()


def cryptography_serial_number_of_cert(cert):
    '''Returns cert.serial_number.

    Also works for old versions of cryptography.
    '''
    try:
        return cert.serial_number
    except AttributeError:
        # The property was called "serial" before cryptography 1.4
        return cert.serial


def parse_pkcs12(pkcs12_bytes, passphrase=None):
    '''Returns a tuple (private_key, certificate, additional_certificates, friendly_name).
    '''
    if _load_pkcs12 is None and _load_key_and_certificates is None:
        raise ValueError('neither load_pkcs12() nor load_key_and_certificates() present in the current cryptography version')

    if passphrase is not None:
        passphrase = to_bytes(passphrase)

    # Main code for cryptography 36.0.0 and forward
    if _load_pkcs12 is not None:
        return _parse_pkcs12_36_0_0(pkcs12_bytes, passphrase)

    if LooseVersion(cryptography.__version__) >= LooseVersion('35.0'):
        return _parse_pkcs12_35_0_0(pkcs12_bytes, passphrase)

    return _parse_pkcs12_legacy(pkcs12_bytes, passphrase)


def _parse_pkcs12_36_0_0(pkcs12_bytes, passphrase=None):
    # Requires cryptography 36.0.0 or newer
    pkcs12 = _load_pkcs12(pkcs12_bytes, passphrase)
    additional_certificates = [cert.certificate for cert in pkcs12.additional_certs]
    private_key = pkcs12.key
    certificate = None
    friendly_name = None
    if pkcs12.cert:
        certificate = pkcs12.cert.certificate
        friendly_name = pkcs12.cert.friendly_name
    return private_key, certificate, additional_certificates, friendly_name


def _parse_pkcs12_35_0_0(pkcs12_bytes, passphrase=None):
    # Backwards compatibility code for cryptography 35.x
    private_key, certificate, additional_certificates = _load_key_and_certificates(pkcs12_bytes, passphrase)

    friendly_name = None
    if certificate:
        # See https://github.com/pyca/cryptography/issues/5760#issuecomment-842687238
        backend = default_backend()

        # This code basically does what load_key_and_certificates() does, but without error-checking.
        # Since load_key_and_certificates succeeded, it should not fail.
        pkcs12 = backend._ffi.gc(
            backend._lib.d2i_PKCS12_bio(backend._bytes_to_bio(pkcs12_bytes).bio, backend._ffi.NULL),
            backend._lib.PKCS12_free)
        certificate_x509_ptr = backend._ffi.new("X509 **")
        with backend._zeroed_null_terminated_buf(to_bytes(passphrase) if passphrase is not None else None) as passphrase_buffer:
            backend._lib.PKCS12_parse(
                pkcs12,
                passphrase_buffer,
                backend._ffi.new("EVP_PKEY **"),
                certificate_x509_ptr,
                backend._ffi.new("Cryptography_STACK_OF_X509 **"))
        if certificate_x509_ptr[0] != backend._ffi.NULL:
            maybe_name = backend._lib.X509_alias_get0(certificate_x509_ptr[0], backend._ffi.NULL)
            if maybe_name != backend._ffi.NULL:
                friendly_name = backend._ffi.string(maybe_name)

    return private_key, certificate, additional_certificates, friendly_name


def _parse_pkcs12_legacy(pkcs12_bytes, passphrase=None):
    # Backwards compatibility code for cryptography < 35.0.0
    private_key, certificate, additional_certificates = _load_key_and_certificates(pkcs12_bytes, passphrase)

    friendly_name = None
    if certificate:
        # See https://github.com/pyca/cryptography/issues/5760#issuecomment-842687238
        backend = certificate._backend
        maybe_name = backend._lib.X509_alias_get0(certificate._x509, backend._ffi.NULL)
        if maybe_name != backend._ffi.NULL:
            friendly_name = backend._ffi.string(maybe_name)
    return private_key, certificate, additional_certificates, friendly_name


def cryptography_verify_signature(signature, data, hash_algorithm, signer_public_key):
    '''
    Check whether the given signature of the given data was signed by the given public key object.
    '''
    try:
        if CRYPTOGRAPHY_HAS_RSA_SIGN and isinstance(signer_public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            signer_public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
            return True
        if CRYPTOGRAPHY_HAS_EC_SIGN and isinstance(signer_public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
            signer_public_key.verify(signature, data, cryptography.hazmat.primitives.asymmetric.ec.ECDSA(hash_algorithm))
            return True
        if CRYPTOGRAPHY_HAS_DSA_SIGN and isinstance(signer_public_key, cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey):
            signer_public_key.verify(signature, data, hash_algorithm)
            return True
        if CRYPTOGRAPHY_HAS_ED25519_SIGN and isinstance(signer_public_key, cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey):
            signer_public_key.verify(signature, data)
            return True
        if CRYPTOGRAPHY_HAS_ED448_SIGN and isinstance(signer_public_key, cryptography.hazmat.primitives.asymmetric.ed448.Ed448PublicKey):
            signer_public_key.verify(signature, data)
            return True
        raise OpenSSLObjectError(u'Unsupported public key type {0}'.format(type(signer_public_key)))
    except InvalidSignature:
        return False


def cryptography_verify_certificate_signature(certificate, signer_public_key):
    '''
    Check whether the given X509 certificate object was signed by the given public key object.
    '''
    return cryptography_verify_signature(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        certificate.signature_hash_algorithm,
        signer_public_key
    )
