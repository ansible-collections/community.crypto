# This excerpt is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file at
# https://github.com/pyca/cryptography/blob/master/LICENSE for complete details.
#
# Adapted from cryptography's hazmat/backends/openssl/decode_asn1.py
#
# Copyright (c) 2015, 2016 Paul Kehrer (@reaperhulk)
# Copyright (c) 2017 Fraser Tweedale (@frasertweedale)

# Relevant commits from cryptography project (https://github.com/pyca/cryptography):
#    pyca/cryptography@719d536dd691e84e208534798f2eb4f82aaa2e07
#    pyca/cryptography@5ab6d6a5c05572bd1c75f05baf264a2d0001894a
#    pyca/cryptography@2e776e20eb60378e0af9b7439000d0e80da7c7e3
#    pyca/cryptography@fb309ed24647d1be9e319b61b1f2aa8ebb87b90b
#    pyca/cryptography@2917e460993c475c72d7146c50dc3bbc2414280d
#    pyca/cryptography@3057f91ea9a05fb593825006d87a391286a4d828
#    pyca/cryptography@d607dd7e5bc5c08854ec0c9baff70ba4a35be36f

from __future__ import absolute_import, division, print_function
__metaclass__ = type


# WARNING: this function no longer works with cryptography 35.0.0 and newer!
#          It must **ONLY** be used in compatibility code for older
#          cryptography versions!

def obj2txt(openssl_lib, openssl_ffi, obj):
    # Set to 80 on the recommendation of
    # https://www.openssl.org/docs/crypto/OBJ_nid2ln.html#return_values
    #
    # But OIDs longer than this occur in real life (e.g. Active
    # Directory makes some very long OIDs).  So we need to detect
    # and properly handle the case where the default buffer is not
    # big enough.
    #
    buf_len = 80
    buf = openssl_ffi.new("char[]", buf_len)

    # 'res' is the number of bytes that *would* be written if the
    # buffer is large enough.  If 'res' > buf_len - 1, we need to
    # alloc a big-enough buffer and go again.
    res = openssl_lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    if res > buf_len - 1:  # account for terminating null byte
        buf_len = res + 1
        buf = openssl_ffi.new("char[]", buf_len)
        res = openssl_lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    return openssl_ffi.buffer(buf, res)[:].decode()
