# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

import os.path
from getpass import getuser
from os import remove, rmdir
from socket import gethostname
from tempfile import mkdtemp

from ansible_collections.community.crypto.plugins.module_utils.openssh.cryptography_openssh import (
    HAS_OPENSSH_SUPPORT,
    InvalidCommentError,
    InvalidKeyFileError,
    InvalidKeySizeError,
    InvalidKeyTypeError,
    InvalidPassphraseError,
    OpenSSH_Keypair
)

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
@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_default_key_params(keytype, size, passphrase, comment):
    result = True

    default_sizes = {
        'rsa': 2048,
        'dsa': 1024,
        'ecdsa': 256,
        'ed25519': 256,
    }

    default_comment = "%s@%s" % (getuser(), gethostname())
    pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    try:
        pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
        if pair.size != default_sizes[pair.key_type] or pair.comment != default_comment:
            result = False
    except Exception as e:
        print(e)
        result = False

    assert result


@pytest.mark.parametrize("keytype,size,passphrase,comment", VALID_USER_KEY_PARAMS)
@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_valid_user_key_params(keytype, size, passphrase, comment):
    result = True

    try:
        pair = OpenSSH_Keypair(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
        if pair.key_type != keytype or pair.size != size or pair.comment != comment:
            result = False
    except Exception as e:
        print(e)
        result = False

    assert result


@pytest.mark.parametrize("keytype,size,passphrase,comment", INVALID_USER_KEY_PARAMS)
@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
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
@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
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


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_valid_comment_update():

    pair = OpenSSH_Keypair()
    new_comment = "comment"
    try:
        pair.comment = new_comment
    except Exception as e:
        print(e)
        pass

    assert pair.comment == new_comment and pair.public_key.split(b' ', 2)[2].decode() == new_comment


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_invalid_comment_update():
    result = False

    pair = OpenSSH_Keypair()
    new_comment = [1, 2, 3]
    try:
        pair.comment = new_comment
    except InvalidCommentError:
        result = True

    assert result


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_valid_passphrase_update():
    result = False

    passphrase = "change_me"

    try:
        tmpdir = mkdtemp()
        keyfilename = os.path.join(tmpdir, "id_rsa")

        pair1 = OpenSSH_Keypair()
        pair1.update_passphrase(passphrase)

        with open(keyfilename, "w+b") as keyfile:
            keyfile.write(pair1.private_key)

        with open(keyfilename + '.pub', "w+b") as pubkeyfile:
            pubkeyfile.write(pair1.public_key)

        pair2 = OpenSSH_Keypair(path=keyfilename, passphrase=passphrase)

        if pair1 == pair2:
            result = True
    finally:
        if os.path.exists(keyfilename):
            remove(keyfilename)
        if os.path.exists(keyfilename + '.pub'):
            remove(keyfilename + '.pub')
        if os.path.exists(tmpdir):
            rmdir(tmpdir)

    assert result


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_invalid_passphrase_update():
    result = False

    passphrase = [1, 2, 3]
    pair = OpenSSH_Keypair()
    try:
        pair.update_passphrase(passphrase)
    except InvalidPassphraseError:
        result = True

    assert result
