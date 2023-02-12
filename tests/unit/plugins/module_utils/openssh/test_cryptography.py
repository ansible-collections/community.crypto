# -*- coding: utf-8 -*-

# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

import os.path
from getpass import getuser
from os import remove, rmdir
from socket import gethostname
from tempfile import mkdtemp

from ansible_collections.community.crypto.plugins.module_utils.openssh.cryptography import (
    HAS_OPENSSH_SUPPORT,
    InvalidCommentError,
    InvalidPrivateKeyFileError,
    InvalidPublicKeyFileError,
    InvalidKeySizeError,
    InvalidKeyTypeError,
    InvalidPassphraseError,
    OpensshKeypair
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
        'change_me'.encode('UTF-8'),
        'comment',
    ),
    (
        'dsa',
        1024,
        'change_me'.encode('UTF-8'),
        'comment',
    ),
    (
        'ecdsa',
        521,
        'change_me'.encode('UTF-8'),
        'comment',
    ),
    (
        'ed25519',
        256,
        'change_me'.encode('UTF-8'),
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
    pair = OpensshKeypair.generate(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    try:
        pair = OpensshKeypair.generate(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
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
        pair = OpensshKeypair.generate(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
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
        OpensshKeypair.generate(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
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
        OpensshKeypair.generate(keytype=keytype, size=size, passphrase=passphrase, comment=comment)
    except InvalidKeySizeError:
        result = True
    except Exception as e:
        print(e)
        pass

    assert result


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_valid_comment_update():

    pair = OpensshKeypair.generate()
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

    pair = OpensshKeypair.generate()
    new_comment = [1, 2, 3]
    try:
        pair.comment = new_comment
    except InvalidCommentError:
        result = True

    assert result


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_valid_passphrase_update():
    result = False

    passphrase = "change_me".encode('UTF-8')

    try:
        tmpdir = mkdtemp()
        keyfilename = os.path.join(tmpdir, "id_rsa")

        pair1 = OpensshKeypair.generate()
        pair1.update_passphrase(passphrase)

        with open(keyfilename, "w+b") as keyfile:
            keyfile.write(pair1.private_key)

        with open(keyfilename + '.pub', "w+b") as pubkeyfile:
            pubkeyfile.write(pair1.public_key)

        pair2 = OpensshKeypair.load(path=keyfilename, passphrase=passphrase)

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
    pair = OpensshKeypair.generate()
    try:
        pair.update_passphrase(passphrase)
    except InvalidPassphraseError:
        result = True

    assert result


@pytest.mark.skipif(not HAS_OPENSSH_SUPPORT, reason="requires cryptography")
def test_invalid_privatekey():
    result = False

    try:
        tmpdir = mkdtemp()
        keyfilename = os.path.join(tmpdir, "id_rsa")

        pair = OpensshKeypair.generate()

        with open(keyfilename, "w+b") as keyfile:
            keyfile.write(pair.private_key[1:])

        with open(keyfilename + '.pub', "w+b") as pubkeyfile:
            pubkeyfile.write(pair.public_key)

        OpensshKeypair.load(path=keyfilename)
    except InvalidPrivateKeyFileError:
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
def test_mismatched_keypair():
    result = False

    try:
        tmpdir = mkdtemp()
        keyfilename = os.path.join(tmpdir, "id_rsa")

        pair1 = OpensshKeypair.generate()
        pair2 = OpensshKeypair.generate()

        with open(keyfilename, "w+b") as keyfile:
            keyfile.write(pair1.private_key)

        with open(keyfilename + '.pub', "w+b") as pubkeyfile:
            pubkeyfile.write(pair2.public_key)

        OpensshKeypair.load(path=keyfilename)
    except InvalidPublicKeyFileError:
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
def test_keypair_comparison():
    assert OpensshKeypair.generate() != OpensshKeypair.generate()
    assert OpensshKeypair.generate() != OpensshKeypair.generate(keytype='dsa')
    assert OpensshKeypair.generate() != OpensshKeypair.generate(keytype='ed25519')
    assert OpensshKeypair.generate(keytype='ed25519') != OpensshKeypair.generate(keytype='ed25519')
    try:
        tmpdir = mkdtemp()

        keys = {
            'rsa': {
                'pair': OpensshKeypair.generate(),
                'filename': os.path.join(tmpdir, "id_rsa"),
            },
            'dsa': {
                'pair': OpensshKeypair.generate(keytype='dsa', passphrase='change_me'.encode('UTF-8')),
                'filename': os.path.join(tmpdir, "id_dsa"),
            },
            'ed25519': {
                'pair': OpensshKeypair.generate(keytype='ed25519'),
                'filename': os.path.join(tmpdir, "id_ed25519"),
            }
        }

        for v in keys.values():
            with open(v['filename'], "w+b") as keyfile:
                keyfile.write(v['pair'].private_key)
            with open(v['filename'] + '.pub', "w+b") as pubkeyfile:
                pubkeyfile.write(v['pair'].public_key)

        assert keys['rsa']['pair'] == OpensshKeypair.load(path=keys['rsa']['filename'])

        loaded_dsa_key = OpensshKeypair.load(path=keys['dsa']['filename'], passphrase='change_me'.encode('UTF-8'))
        assert keys['dsa']['pair'] == loaded_dsa_key

        loaded_dsa_key.update_passphrase('change_me_again'.encode('UTF-8'))
        assert keys['dsa']['pair'] != loaded_dsa_key

        loaded_dsa_key.update_passphrase('change_me'.encode('UTF-8'))
        assert keys['dsa']['pair'] == loaded_dsa_key

        loaded_dsa_key.comment = "comment"
        assert keys['dsa']['pair'] != loaded_dsa_key

        assert keys['ed25519']['pair'] == OpensshKeypair.load(path=keys['ed25519']['filename'])
    finally:
        for v in keys.values():
            if os.path.exists(v['filename']):
                remove(v['filename'])
            if os.path.exists(v['filename'] + '.pub'):
                remove(v['filename'] + '.pub')
        if os.path.exists(tmpdir):
            rmdir(tmpdir)
    assert OpensshKeypair.generate() != []
