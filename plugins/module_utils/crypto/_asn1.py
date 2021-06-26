# -*- coding: utf-8 -*-

# (c) 2020, Jordan Borean <jborean93@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import re

from ansible.module_utils.common.text.converters import to_bytes


"""
An ASN.1 serialized as a string in the OpenSSL format:
    [modifier,]type[:value]

modifier:
    The modifier can be 'IMPLICIT:<tag_number><tag_class>,' or 'EXPLICIT:<tag_number><tag_class>' where IMPLICIT
    changes the tag of the universal value to encode and EXPLICIT prefixes its tag to the existing universal value.
    The tag_number must be set while the tag_class can be 'U', 'A', 'P', or 'C" for 'Universal', 'Application',
    'Private', or 'Context Specific' with C being the default.

type:
    The underlying ASN.1 type of the value specified. Currently only the following have been implemented:
        UTF8: The value must be a UTF-8 encoded string.

value:
    The value to encode, the format of this value depends on the <type> specified.
"""
ASN1_STRING_REGEX = re.compile(r'^((?P<tag_type>IMPLICIT|EXPLICIT):(?P<tag_number>\d+)(?P<tag_class>U|A|P|C)?,)?'
                               r'(?P<value_type>[\w\d]+):(?P<value>.*)')


class TagClass:
    universal = 0
    application = 1
    context_specific = 2
    private = 3


# Universal tag numbers that can be encoded.
class TagNumber:
    utf8_string = 12


def _pack_octet_integer(value):
    """ Packs an integer value into 1 or multiple octets. """
    # NOTE: This is *NOT* the same as packing an ASN.1 INTEGER like value.
    octets = bytearray()

    # Continue to shift the number by 7 bits and pack into an octet until the
    # value is fully packed.
    while value:
        octet_value = value & 0b01111111

        # First round (last octet) must have the MSB set.
        if len(octets):
            octet_value |= 0b10000000

        octets.append(octet_value)
        value >>= 7

    # Reverse to ensure the higher order octets are first.
    octets.reverse()
    return bytes(octets)


def serialize_asn1_string_as_der(value):
    """ Deserializes an ASN.1 string to a DER encoded byte string. """
    asn1_match = ASN1_STRING_REGEX.match(value)
    if not asn1_match:
        raise ValueError("The ASN.1 serialized string must be in the format [modifier,]type[:value]")

    tag_type = asn1_match.group('tag_type')
    tag_number = asn1_match.group('tag_number')
    tag_class = asn1_match.group('tag_class') or 'C'
    value_type = asn1_match.group('value_type')
    asn1_value = asn1_match.group('value')

    if value_type != 'UTF8':
        raise ValueError('The ASN.1 serialized string is not a known type "{0}", only UTF8 types are '
                         'supported'.format(value_type))

    b_value = to_bytes(asn1_value, encoding='utf-8', errors='surrogate_or_strict')

    # We should only do a universal type tag if not IMPLICITLY tagged or the tag class is not universal.
    if not tag_type or (tag_type == 'EXPLICIT' and tag_class != 'U'):
        b_value = pack_asn1(TagClass.universal, False, TagNumber.utf8_string, b_value)

    if tag_type:
        tag_class = {
            'U': TagClass.universal,
            'A': TagClass.application,
            'P': TagClass.private,
            'C': TagClass.context_specific,
        }[tag_class]

        # When adding support for more types this should be looked into further. For now it works with UTF8Strings.
        constructed = tag_type == 'EXPLICIT' and tag_class != TagClass.universal
        b_value = pack_asn1(tag_class, constructed, int(tag_number), b_value)

    return b_value


def pack_asn1(tag_class, constructed, tag_number, b_data):
    """Pack the value into an ASN.1 data structure.

    The structure for an ASN.1 element is

    | Identifier Octet(s) | Length Octet(s) | Data Octet(s) |
    """
    b_asn1_data = bytearray()

    if tag_class < 0 or tag_class > 3:
        raise ValueError("tag_class must be between 0 and 3 not %s" % tag_class)

    # Bit 8 and 7 denotes the class.
    identifier_octets = tag_class << 6
    # Bit 6 denotes whether the value is primitive or constructed.
    identifier_octets |= ((1 if constructed else 0) << 5)

    # Bits 5-1 contain the tag number, if it cannot be encoded in these 5 bits
    # then they are set and another octet(s) is used to denote the tag number.
    if tag_number < 31:
        identifier_octets |= tag_number
        b_asn1_data.append(identifier_octets)
    else:
        identifier_octets |= 31
        b_asn1_data.append(identifier_octets)
        b_asn1_data.extend(_pack_octet_integer(tag_number))

    length = len(b_data)

    # If the length can be encoded in 7 bits only 1 octet is required.
    if length < 128:
        b_asn1_data.append(length)

    else:
        # Otherwise the length must be encoded across multiple octets
        length_octets = bytearray()
        while length:
            length_octets.append(length & 0b11111111)
            length >>= 8

        length_octets.reverse()  # Reverse to make the higher octets first.

        # The first length octet must have the MSB set alongside the number of
        # octets the length was encoded in.
        b_asn1_data.append(len(length_octets) | 0b10000000)
        b_asn1_data.extend(length_octets)

    return bytes(b_asn1_data) + b_data
