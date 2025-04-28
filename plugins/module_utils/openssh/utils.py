# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Doug Stanley <doug+ansible@technologixllc.com>
# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import os
import re
from contextlib import contextmanager
from struct import Struct

from ansible.module_utils.six import PY3


# Protocol References
# -------------------
# https://datatracker.ietf.org/doc/html/rfc4251
# https://datatracker.ietf.org/doc/html/rfc4253
# https://datatracker.ietf.org/doc/html/rfc5656
# https://datatracker.ietf.org/doc/html/rfc8032
#
# Inspired by:
# ------------
# https://github.com/pyca/cryptography/blob/main/src/cryptography/hazmat/primitives/serialization/ssh.py
# https://github.com/paramiko/paramiko/blob/master/paramiko/message.py

if PY3:
    long = int

# 0 (False) or 1 (True) encoded as a single byte
_BOOLEAN = Struct(b"?")
# Unsigned 8-bit integer in network-byte-order
_UBYTE = Struct(b"!B")
_UBYTE_MAX = 0xFF
# Unsigned 32-bit integer in network-byte-order
_UINT32 = Struct(b"!I")
# Unsigned 32-bit little endian integer
_UINT32_LE = Struct(b"<I")
_UINT32_MAX = 0xFFFFFFFF
# Unsigned 64-bit integer in network-byte-order
_UINT64 = Struct(b"!Q")
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF


def any_in(sequence, *elements):
    return any(e in sequence for e in elements)


def file_mode(path):
    if not os.path.exists(path):
        return 0o000
    return os.stat(path).st_mode & 0o777


def parse_openssh_version(version_string):
    """Parse the version output of ssh -V and return version numbers that can be compared"""

    parsed_result = re.match(
        r"^.*openssh_(?P<version>[0-9.]+)(p?[0-9]+)[^0-9]*.*$", version_string.lower()
    )
    if parsed_result is not None:
        version = parsed_result.group("version").strip()
    else:
        version = None

    return version


@contextmanager
def secure_open(path, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        yield fd
    finally:
        os.close(fd)


def secure_write(path, mode, content):
    with secure_open(path, mode) as fd:
        os.write(fd, content)


# See https://datatracker.ietf.org/doc/html/rfc4251#section-5 for SSH data types
class OpensshParser(object):
    """Parser for OpenSSH encoded objects"""

    BOOLEAN_OFFSET = 1
    UINT32_OFFSET = 4
    UINT64_OFFSET = 8

    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data must be bytes-like not %s" % type(data))

        self._data = memoryview(data) if PY3 else data
        self._pos = 0

    def boolean(self):
        next_pos = self._check_position(self.BOOLEAN_OFFSET)

        value = _BOOLEAN.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def uint32(self):
        next_pos = self._check_position(self.UINT32_OFFSET)

        value = _UINT32.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def uint64(self):
        next_pos = self._check_position(self.UINT64_OFFSET)

        value = _UINT64.unpack(self._data[self._pos : next_pos])[0]
        self._pos = next_pos
        return value

    def string(self):
        length = self.uint32()

        next_pos = self._check_position(length)

        value = self._data[self._pos : next_pos]
        self._pos = next_pos
        # Cast to bytes is required as a memoryview slice is itself a memoryview
        return value if not PY3 else bytes(value)

    def mpint(self):
        return self._big_int(self.string(), "big", signed=True)

    def name_list(self):
        raw_string = self.string()
        return raw_string.decode("ASCII").split(",")

    # Convenience function, but not an official data type from SSH
    def string_list(self):
        result = []
        raw_string = self.string()

        if raw_string:
            parser = OpensshParser(raw_string)
            while parser.remaining_bytes():
                result.append(parser.string())

        return result

    # Convenience function, but not an official data type from SSH
    def option_list(self):
        result = []
        raw_string = self.string()

        if raw_string:
            parser = OpensshParser(raw_string)

            while parser.remaining_bytes():
                name = parser.string()
                data = parser.string()
                if data:
                    # data is doubly-encoded
                    data = OpensshParser(data).string()
                result.append((name, data))

        return result

    def seek(self, offset):
        self._pos = self._check_position(offset)

        return self._pos

    def remaining_bytes(self):
        return len(self._data) - self._pos

    def _check_position(self, offset):
        if self._pos + offset > len(self._data):
            raise ValueError("Insufficient data remaining at position: %s" % self._pos)
        elif self._pos + offset < 0:
            raise ValueError("Position cannot be less than zero.")
        else:
            return self._pos + offset

    @classmethod
    def signature_data(cls, signature_string):
        signature_data = {}

        parser = cls(signature_string)
        signature_type = parser.string()
        signature_blob = parser.string()

        blob_parser = cls(signature_blob)
        if signature_type in (b"ssh-rsa", b"rsa-sha2-256", b"rsa-sha2-512"):
            # https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
            # https://datatracker.ietf.org/doc/html/rfc8332#section-3
            signature_data["s"] = cls._big_int(signature_blob, "big")
        elif signature_type == b"ssh-dss":
            # https://datatracker.ietf.org/doc/html/rfc4253#section-6.6
            signature_data["r"] = cls._big_int(signature_blob[:20], "big")
            signature_data["s"] = cls._big_int(signature_blob[20:], "big")
        elif signature_type in (
            b"ecdsa-sha2-nistp256",
            b"ecdsa-sha2-nistp384",
            b"ecdsa-sha2-nistp521",
        ):
            # https://datatracker.ietf.org/doc/html/rfc5656#section-3.1.2
            signature_data["r"] = blob_parser.mpint()
            signature_data["s"] = blob_parser.mpint()
        elif signature_type == b"ssh-ed25519":
            # https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.2
            signature_data["R"] = cls._big_int(signature_blob[:32], "little")
            signature_data["S"] = cls._big_int(signature_blob[32:], "little")
        else:
            raise ValueError("%s is not a valid signature type" % signature_type)

        signature_data["signature_type"] = signature_type

        return signature_data

    @classmethod
    def _big_int(cls, raw_string, byte_order, signed=False):
        if byte_order not in ("big", "little"):
            raise ValueError(
                "Byte_order must be one of (big, little) not %s" % byte_order
            )

        if PY3:
            return int.from_bytes(raw_string, byte_order, signed=signed)

        result = 0
        byte_length = len(raw_string)

        if byte_length > 0:
            # Check sign-bit
            msb = raw_string[0] if byte_order == "big" else raw_string[-1]
            negative = bool(ord(msb) & 0x80)
            # Match pad value for two's complement
            pad = b"\xff" if signed and negative else b"\x00"
            # The definition of ``mpint`` enforces that unnecessary bytes are not encoded so they are added back
            pad_length = 4 - byte_length % 4
            if pad_length < 4:
                raw_string = (
                    pad * pad_length + raw_string
                    if byte_order == "big"
                    else raw_string + pad * pad_length
                )
                byte_length += pad_length
            # Accumulate arbitrary precision integer bytes in the appropriate order
            if byte_order == "big":
                for i in range(0, byte_length, cls.UINT32_OFFSET):
                    left_shift = result << cls.UINT32_OFFSET * 8
                    result = (
                        left_shift
                        + _UINT32.unpack(raw_string[i : i + cls.UINT32_OFFSET])[0]
                    )
            else:
                for i in range(byte_length, 0, -cls.UINT32_OFFSET):
                    left_shift = result << cls.UINT32_OFFSET * 8
                    result = (
                        left_shift
                        + _UINT32_LE.unpack(raw_string[i - cls.UINT32_OFFSET : i])[0]
                    )
            # Adjust for two's complement
            if signed and negative:
                result -= 1 << (8 * byte_length)

        return result


class _OpensshWriter(object):
    """Writes SSH encoded values to a bytes-like buffer

    .. warning::
        This class is a private API and must not be exported outside of the openssh module_utils.
        It is not to be used to construct Openssh objects, but rather as a utility to assist
        in validating parsed material.
    """

    def __init__(self, buffer=None):
        if buffer is not None:
            if not isinstance(buffer, (bytes, bytearray)):
                raise TypeError(
                    "Buffer must be a bytes-like object not %s" % type(buffer)
                )
        else:
            buffer = bytearray()

        self._buff = buffer

    def boolean(self, value):
        if not isinstance(value, bool):
            raise TypeError("Value must be of type bool not %s" % type(value))

        self._buff.extend(_BOOLEAN.pack(value))

        return self

    def uint32(self, value):
        if not isinstance(value, int):
            raise TypeError("Value must be of type int not %s" % type(value))
        if value < 0 or value > _UINT32_MAX:
            raise ValueError(
                "Value must be a positive integer less than %s" % _UINT32_MAX
            )

        self._buff.extend(_UINT32.pack(value))

        return self

    def uint64(self, value):
        if not isinstance(value, (long, int)):
            raise TypeError("Value must be of type (long, int) not %s" % type(value))
        if value < 0 or value > _UINT64_MAX:
            raise ValueError(
                "Value must be a positive integer less than %s" % _UINT64_MAX
            )

        self._buff.extend(_UINT64.pack(value))

        return self

    def string(self, value):
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("Value must be bytes-like not %s" % type(value))
        self.uint32(len(value))
        self._buff.extend(value)

        return self

    def mpint(self, value):
        if not isinstance(value, (int, long)):
            raise TypeError("Value must be of type (long, int) not %s" % type(value))

        self.string(self._int_to_mpint(value))

        return self

    def name_list(self, value):
        if not isinstance(value, list):
            raise TypeError("Value must be a list of byte strings not %s" % type(value))

        try:
            self.string(",".join(value).encode("ASCII"))
        except UnicodeEncodeError as e:
            raise ValueError("Name-list's must consist of US-ASCII characters: %s" % e)

        return self

    def string_list(self, value):
        if not isinstance(value, list):
            raise TypeError("Value must be a list of byte string not %s" % type(value))

        writer = _OpensshWriter()
        for s in value:
            writer.string(s)

        self.string(writer.bytes())

        return self

    def option_list(self, value):
        if not isinstance(value, list) or (value and not isinstance(value[0], tuple)):
            raise TypeError("Value must be a list of tuples")

        writer = _OpensshWriter()
        for name, data in value:
            writer.string(name)
            # SSH option data is encoded twice though this behavior is not documented
            writer.string(_OpensshWriter().string(data).bytes() if data else bytes())

        self.string(writer.bytes())

        return self

    @staticmethod
    def _int_to_mpint(num):
        if PY3:
            byte_length = (num.bit_length() + 7) // 8
            try:
                result = num.to_bytes(byte_length, "big", signed=True)
            # Handles values which require \x00 or \xFF to pad sign-bit
            except OverflowError:
                result = num.to_bytes(byte_length + 1, "big", signed=True)
        else:
            result = bytes()
            # 0 and -1 are treated as special cases since they are used as sentinels for all other values
            if num == 0:
                result += b"\x00"
            elif num == -1:
                result += b"\xff"
            elif num > 0:
                while num >> 32:
                    result = _UINT32.pack(num & _UINT32_MAX) + result
                    num = num >> 32
                # Pack last 4 bytes individually to discard insignificant bytes
                while num:
                    result = _UBYTE.pack(num & _UBYTE_MAX) + result
                    num = num >> 8
                # Zero pad final byte if most-significant bit is 1 as per mpint definition
                if ord(result[0]) & 0x80:
                    result = b"\x00" + result
            else:
                while (num >> 32) < -1:
                    result = _UINT32.pack(num & _UINT32_MAX) + result
                    num = num >> 32
                while num < -1:
                    result = _UBYTE.pack(num & _UBYTE_MAX) + result
                    num = num >> 8
                if not ord(result[0]) & 0x80:
                    result = b"\xff" + result

        return result

    def bytes(self):
        return bytes(self._buff)
