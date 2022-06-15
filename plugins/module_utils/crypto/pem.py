# -*- coding: utf-8 -*-
#
# (c) 2019, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


PEM_START = '-----BEGIN '
PEM_END = '-----'
PKCS8_PRIVATEKEY_NAMES = ('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY')
PKCS1_PRIVATEKEY_SUFFIX = ' PRIVATE KEY'


def identify_pem_format(content):
    '''Given the contents of a binary file, tests whether this could be a PEM file.'''
    try:
        lines = content.decode('utf-8').splitlines(False)
        if lines[0].startswith(PEM_START) and lines[0].endswith(PEM_END) and len(lines[0]) > len(PEM_START) + len(PEM_END):
            return True
    except UnicodeDecodeError:
        pass
    return False


def identify_private_key_format(content):
    '''Given the contents of a private key file, identifies its format.'''
    # See https://github.com/openssl/openssl/blob/master/crypto/pem/pem_pkey.c#L40-L85
    # (PEM_read_bio_PrivateKey)
    # and https://github.com/openssl/openssl/blob/master/include/openssl/pem.h#L46-L47
    # (PEM_STRING_PKCS8, PEM_STRING_PKCS8INF)
    try:
        lines = content.decode('utf-8').splitlines(False)
        if lines[0].startswith(PEM_START) and lines[0].endswith(PEM_END) and len(lines[0]) > len(PEM_START) + len(PEM_END):
            name = lines[0][len(PEM_START):-len(PEM_END)]
            if name in PKCS8_PRIVATEKEY_NAMES:
                return 'pkcs8'
            if len(name) > len(PKCS1_PRIVATEKEY_SUFFIX) and name.endswith(PKCS1_PRIVATEKEY_SUFFIX):
                return 'pkcs1'
            return 'unknown-pem'
    except UnicodeDecodeError:
        pass
    return 'raw'


def split_pem_list(text, keep_inbetween=False):
    '''
    Split concatenated PEM objects into a list of strings, where each is one PEM object.
    '''
    result = []
    current = [] if keep_inbetween else None
    for line in text.splitlines(True):
        if line.strip():
            if not keep_inbetween and line.startswith('-----BEGIN '):
                current = []
            if current is not None:
                current.append(line)
                if line.startswith('-----END '):
                    result.append(''.join(current))
                    current = [] if keep_inbetween else None
    return result


def extract_first_pem(text):
    '''
    Given one PEM or multiple concatenated PEM objects, return only the first one, or None if there is none.
    '''
    all_pems = split_pem_list(text)
    if not all_pems:
        return None
    return all_pems[0]
