# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from getpass import getuser
from os import remove, rmdir
from socket import gethostname
from tempfile import mkdtemp

CRYPTOGRAPHY_UNAVAILABLE = False

try:
    from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_openssh import (
        InvalidCommentError,
        InvalidKeyFileError,
        InvalidKeySizeError,
        InvalidKeyTypeError,
        InvalidPassphraseError,
        OpenSSH_Keypair
    )
except ImportError:
    CRYPTOGRAPHY_UNAVAILABLE = True


DEFAULT_KEY_PARAMS = [
    (
        'rsa',
        None,
        None,
        None,
    ),
    (
        'dsa',
        None,
        None,
        None,
    ),
    (
        'ecdsa',
        None,
        None,
        None,
    ),
    (
        'ed25519',
        None,
        None,
        None,
    ),
]

VALID_USER_KEY_PARAMS = [
    (
        'rsa',
        8192,
        'change_me',
        'comment',
    ),
    (
        'dsa',
        1024,
        'change_me',
        'comment',
    ),
    (
        'ecdsa',
        521,
        'change_me',
        'comment',
    ),
    (
        'ed25519',
        256,
        'change_me',
        'comment',
    ),
]

INVALID_USER_KEY_PARAMS = [
    (
        'dne',
        None,
        None,
        None,
    ),
    (
        'rsa',
        None,
        [1, 2, 3],
        'comment',
    ),
    (
        'ecdsa',
        None,
        None,
        [1, 2, 3],
    ),
]

INVALID_KEY_SIZES = [
    (
        'rsa',
        1023,
        None,
        None,
    ),
    (
        'rsa',
        16385,
        None,
        None,
    ),
    (
        'dsa',
        256,
        None,
        None,
    ),
    (
        'ecdsa',
        1024,
        None,
        None,
    ),
    (
        'ed25519',
        1024,
        None,
        None,
    ),
]


@pytest.mark.parametrize("keytype,size,passphrase,comment", DEFAULT_KEY_PARAMS)
@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_default_key_params(keytype, size, passphrase, comment):
    result = True

    default_sizes = {
        'rsa': 4096,
        'dsa': 1024,
        'ecdsa': 256,
        'ed25519': 256,
    }

    default_comment = "%s@%s" % (getuser(), gethostname())
    pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    try:
        pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
        if pair.Size != default_sizes[pair.KeyType] or pair.Comment != default_comment:
            result = False
    except Exception as e:
        print(e)
        result = False

    assert result


@pytest.mark.parametrize("keytype,size,passphrase,comment", VALID_USER_KEY_PARAMS)
@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_valid_user_key_params(keytype, size, passphrase, comment):
    result = True

    try:
        pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
        if pair.KeyType != keytype or pair.Size != size or pair.Comment != comment:
            result = False
    except Exception as e:
        print(e)
        result = False

    assert result


@pytest.mark.parametrize("keytype,size,passphrase,comment", INVALID_USER_KEY_PARAMS)
@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_invalid_user_key_params(keytype, size, passphrase, comment):
    result = False

    try:
        OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    except (InvalidCommentError, InvalidKeyTypeError, InvalidPassphraseError):
        result = True
    except Exception as e:
        print(e)
        pass

    assert result


@pytest.mark.parametrize("keytype,size,passphrase,comment", INVALID_KEY_SIZES)
@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_invalid_key_sizes(keytype, size, passphrase, comment):
    result = False

    try:
        OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    except InvalidKeySizeError:
        result = True
    except Exception as e:
        print(e)
        pass

    assert result


@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_valid_comment_update():

    pair = OpenSSH_Keypair()
    new_comment = "comment"
    try:
        pair.Comment = new_comment
    except Exception as e:
        print(e)
        pass

    assert pair.Comment == new_comment and pair.PublicKey.split(b' ', 2)[2].decode() == new_comment


@pytest.mark.skipif(CRYPTOGRAPHY_UNAVAILABLE, reason="requires cryptography")
def test_invalid_comment_update():
    result = False

    pair = OpenSSH_Keypair()
    new_comment = [1, 2, 3]
    try:
        pair.Comment = new_comment
    except InvalidCommentError:
        result = True

    assert result
