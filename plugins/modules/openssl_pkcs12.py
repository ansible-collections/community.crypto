#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Guillaume Delpierre <gde@llew.me>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: openssl_pkcs12
author:
- Guillaume Delpierre (@gdelpierre)
short_description: Generate OpenSSL PKCS#12 archive
description:
    - This module allows one to (re-)generate PKCS#12.
    - The module can use the cryptography Python library, or the pyOpenSSL Python
      library. By default, it tries to detect which one is available, assuming none of the
      I(iter_size) and I(maciter_size) options are used. This can be overridden with the
      I(select_crypto_backend) option.
    # Please note that the C(pyopenssl) backend has been deprecated in community.crypto x.y.0,
    # and will be removed in community.crypto (x+1).0.0.
requirements:
    - PyOpenSSL >= 0.15 or cryptography >= 3.0
options:
    action:
        description:
            - C(export) or C(parse) a PKCS#12.
        type: str
        default: export
        choices: [ export, parse ]
    other_certificates:
        description:
            - List of other certificates to include. Pre Ansible 2.8 this parameter was called I(ca_certificates).
            - Assumes there is one PEM-encoded certificate per file. If a file contains multiple PEM certificates,
              set I(other_certificates_parse_all) to C(true).
        type: list
        elements: path
        aliases: [ ca_certificates ]
    other_certificates_parse_all:
        description:
            - If set to C(true), assumes that the files mentioned in I(other_certificates) can contain more than one
              certificate per file (or even none per file).
        type: bool
        default: false
        version_added: 1.4.0
    certificate_path:
        description:
            - The path to read certificates and private keys from.
            - Must be in PEM format.
        type: path
    force:
        description:
            - Should the file be regenerated even if it already exists.
        type: bool
        default: no
    friendly_name:
        description:
            - Specifies the friendly name for the certificate and private key.
        type: str
        aliases: [ name ]
    iter_size:
        description:
            - Number of times to repeat the encryption step.
            - This is not considered during idempotency checks.
            - This is only used by the C(pyopenssl) backend. When using it, the default is C(2048).
        type: int
    maciter_size:
        description:
            - Number of times to repeat the MAC step.
            - This is not considered during idempotency checks.
            - This is only used by the C(pyopenssl) backend. When using it, the default is C(1).
        type: int
    passphrase:
        description:
            - The PKCS#12 password.
            - "B(Note:) PKCS12 encryption is not secure and should not be used as a security mechanism.
              If you need to store or send a PKCS12 file safely, you should additionally encrypt it
              with something else."
        type: str
    path:
        description:
            - Filename to write the PKCS#12 file to.
        type: path
        required: true
    privatekey_passphrase:
        description:
            - Passphrase source to decrypt any input private keys with.
        type: str
    privatekey_path:
        description:
            - File to read private key from.
        type: path
    state:
        description:
            - Whether the file should exist or not.
              All parameters except C(path) are ignored when state is C(absent).
        choices: [ absent, present ]
        default: present
        type: str
    src:
        description:
            - PKCS#12 file path to parse.
        type: path
    backup:
        description:
            - Create a backup file including a timestamp so you can get the original
              output file back if you overwrote it with a new one by accident.
        type: bool
        default: no
    return_content:
        description:
            - If set to C(yes), will return the (current or generated) PKCS#12's content as I(pkcs12).
        type: bool
        default: no
        version_added: "1.0.0"
    select_crypto_backend:
        description:
            - Determines which crypto backend to use.
            - The default choice is C(auto), which tries to use C(cryptography) if available, and falls back to C(pyopenssl).
              If one of I(iter_size) or I(maciter_size) is used, C(auto) will always result in C(pyopenssl) to be chosen
              for backwards compatibility.
            - If set to C(pyopenssl), will try to use the L(pyOpenSSL,https://pypi.org/project/pyOpenSSL/) library.
            - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
            # - Please note that the C(pyopenssl) backend has been deprecated in community.crypto x.y.0, and will be
            #   removed in community.crypto (x+1).0.0.
            #   From that point on, only the C(cryptography) backend will be available.
        type: str
        default: auto
        choices: [ auto, cryptography, pyopenssl ]
        version_added: 1.7.0
extends_documentation_fragment:
    - files
seealso:
- module: community.crypto.x509_certificate
- module: community.crypto.openssl_csr
- module: community.crypto.openssl_dhparam
- module: community.crypto.openssl_privatekey
- module: community.crypto.openssl_publickey
'''

EXAMPLES = r'''
- name: Generate PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
    # Note that if /opt/certs/ca.pem contains multiple certificates,
    # only the first one will be used. See the other_certificates_parse_all
    # option for changing this behavior.
    state: present

- name: Generate PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates_parse_all: true
    other_certificates:
      - /opt/certs/ca_bundle.pem
        # Since we set other_certificates_parse_all to true, all
        # certificates in the CA bundle are included and not just
        # the first one.
      - /opt/certs/intermediate.pem
        # In case this file has multiple certificates in it,
        # all will be included as well.
    state: present

- name: Change PKCS#12 file permission
  community.crypto.openssl_pkcs12:
    action: export
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
    state: present
    mode: '0600'

- name: Regen PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: export
    src: /opt/certs/ansible.p12
    path: /opt/certs/ansible.p12
    friendly_name: raclette
    privatekey_path: /opt/certs/keys/key.pem
    certificate_path: /opt/certs/cert.pem
    other_certificates: /opt/certs/ca.pem
    state: present
    mode: '0600'
    force: yes

- name: Dump/Parse PKCS#12 file
  community.crypto.openssl_pkcs12:
    action: parse
    src: /opt/certs/ansible.p12
    path: /opt/certs/ansible.pem
    state: present

- name: Remove PKCS#12 file
  community.crypto.openssl_pkcs12:
    path: /opt/certs/ansible.p12
    state: absent
'''

RETURN = r'''
filename:
    description: Path to the generate PKCS#12 file.
    returned: changed or success
    type: str
    sample: /opt/certs/ansible.p12
privatekey:
    description: Path to the TLS/SSL private key the public key was generated from.
    returned: changed or success
    type: str
    sample: /etc/ssl/private/ansible.com.pem
backup_file:
    description: Name of backup file created.
    returned: changed and if I(backup) is C(yes)
    type: str
    sample: /path/to/ansible.com.pem.2019-03-09@11:22~
pkcs12:
    description: The (current or generated) PKCS#12's content Base64 encoded.
    returned: if I(state) is C(present) and I(return_content) is C(yes)
    type: str
    version_added: "1.0.0"
'''

import abc
import base64
import os
import stat
import traceback

from distutils.version import LooseVersion

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes, to_native

from ansible_collections.community.crypto.plugins.module_utils.io import (
    load_file_if_exists,
    write_file,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
    OpenSSLBadPassphraseError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    parse_pkcs12,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    OpenSSLObject,
    load_privatekey,
    load_certificate,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pem import (
    split_pem_list,
)

MINIMAL_CRYPTOGRAPHY_VERSION = '3.0'
MINIMAL_PYOPENSSL_VERSION = '0.15'

PYOPENSSL_IMP_ERR = None
try:
    import OpenSSL
    from OpenSSL import crypto
    PYOPENSSL_VERSION = LooseVersion(OpenSSL.__version__)
except ImportError:
    PYOPENSSL_IMP_ERR = traceback.format_exc()
    PYOPENSSL_FOUND = False
else:
    PYOPENSSL_FOUND = True

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


def load_certificate_set(filename, backend):
    '''
    Load list of concatenated PEM files, and return a list of parsed certificates.
    '''
    with open(filename, 'rb') as f:
        data = f.read().decode('utf-8')
    return [load_certificate(None, content=cert.encode('utf-8'), backend=backend) for cert in split_pem_list(data)]


class PkcsError(OpenSSLObjectError):
    pass


class Pkcs(OpenSSLObject):
    def __init__(self, module, backend):
        super(Pkcs, self).__init__(
            module.params['path'],
            module.params['state'],
            module.params['force'],
            module.check_mode
        )
        self.backend = backend
        self.action = module.params['action']
        self.other_certificates = module.params['other_certificates']
        self.other_certificates_parse_all = module.params['other_certificates_parse_all']
        self.certificate_path = module.params['certificate_path']
        self.friendly_name = module.params['friendly_name']
        self.iter_size = module.params['iter_size'] or 2048
        self.maciter_size = module.params['maciter_size'] or 1
        self.passphrase = module.params['passphrase']
        self.pkcs12 = None
        self.privatekey_passphrase = module.params['privatekey_passphrase']
        self.privatekey_path = module.params['privatekey_path']
        self.pkcs12_bytes = None
        self.return_content = module.params['return_content']
        self.src = module.params['src']

        if module.params['mode'] is None:
            module.params['mode'] = '0400'

        self.backup = module.params['backup']
        self.backup_file = None

        if self.other_certificates:
            if self.other_certificates_parse_all:
                filenames = list(self.other_certificates)
                self.other_certificates = []
                for other_cert_bundle in filenames:
                    self.other_certificates.extend(load_certificate_set(other_cert_bundle, self.backend))
            else:
                self.other_certificates = [
                    load_certificate(other_cert, backend=self.backend) for other_cert in self.other_certificates
                ]

    @abc.abstractmethod
    def generate_bytes(self, module):
        """Generate PKCS#12 file archive."""
        pass

    @abc.abstractmethod
    def parse_bytes(self, pkcs12_content):
        pass

    @abc.abstractmethod
    def _dump_privatekey(self, pkcs12):
        pass

    @abc.abstractmethod
    def _dump_certificate(self, pkcs12):
        pass

    @abc.abstractmethod
    def _dump_other_certificates(self, pkcs12):
        pass

    @abc.abstractmethod
    def _get_friendly_name(self, pkcs12):
        pass

    def check(self, module, perms_required=True):
        """Ensure the resource is in its desired state."""

        state_and_perms = super(Pkcs, self).check(module, perms_required)

        def _check_pkey_passphrase():
            if self.privatekey_passphrase:
                try:
                    load_privatekey(self.privatekey_path, self.privatekey_passphrase, backend=self.backend)
                except OpenSSLObjectError:
                    return False
            return True

        if not state_and_perms:
            return state_and_perms

        if os.path.exists(self.path) and module.params['action'] == 'export':
            dummy = self.generate_bytes(module)
            self.src = self.path
            try:
                pkcs12_privatekey, pkcs12_certificate, pkcs12_other_certificates, pkcs12_friendly_name = self.parse()
            except OpenSSLObjectError:
                return False
            if (pkcs12_privatekey is not None) and (self.privatekey_path is not None):
                expected_pkey = self._dump_privatekey(self.pkcs12)
                if pkcs12_privatekey != expected_pkey:
                    return False
            elif bool(pkcs12_privatekey) != bool(self.privatekey_path):
                return False

            if (pkcs12_certificate is not None) and (self.certificate_path is not None):
                expected_cert = self._dump_certificate(self.pkcs12)
                if pkcs12_certificate != expected_cert:
                    return False
            elif bool(pkcs12_certificate) != bool(self.certificate_path):
                return False

            if (pkcs12_other_certificates is not None) and (self.other_certificates is not None):
                expected_other_certs = self._dump_other_certificates(self.pkcs12)
                if set(pkcs12_other_certificates) != set(expected_other_certs):
                    return False
            elif bool(pkcs12_other_certificates) != bool(self.other_certificates):
                return False

            if pkcs12_privatekey:
                # This check is required because pyOpenSSL will not return a friendly name
                # if the private key is not set in the file
                friendly_name = self._get_friendly_name(self.pkcs12)
                if ((friendly_name is not None) and (pkcs12_friendly_name is not None)):
                    if friendly_name != pkcs12_friendly_name:
                        return False
                elif bool(friendly_name) != bool(pkcs12_friendly_name):
                    return False
        elif module.params['action'] == 'parse' and os.path.exists(self.src) and os.path.exists(self.path):
            try:
                pkey, cert, other_certs, friendly_name = self.parse()
            except OpenSSLObjectError:
                return False
            expected_content = to_bytes(
                ''.join([to_native(pem) for pem in [pkey, cert] + other_certs if pem is not None])
            )
            dumped_content = load_file_if_exists(self.path, ignore_errors=True)
            if expected_content != dumped_content:
                return False
        else:
            return False

        return _check_pkey_passphrase()

    def dump(self):
        """Serialize the object into a dictionary."""

        result = {
            'filename': self.path,
        }
        if self.privatekey_path:
            result['privatekey_path'] = self.privatekey_path
        if self.backup_file:
            result['backup_file'] = self.backup_file
        if self.return_content:
            if self.pkcs12_bytes is None:
                self.pkcs12_bytes = load_file_if_exists(self.path, ignore_errors=True)
            result['pkcs12'] = base64.b64encode(self.pkcs12_bytes) if self.pkcs12_bytes else None

        return result

    def remove(self, module):
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        super(Pkcs, self).remove(module)

    def parse(self):
        """Read PKCS#12 file."""

        try:
            with open(self.src, 'rb') as pkcs12_fh:
                pkcs12_content = pkcs12_fh.read()
            return self.parse_bytes(pkcs12_content)
        except IOError as exc:
            raise PkcsError(exc)

    def generate(self):
        pass

    def write(self, module, content, mode=None):
        """Write the PKCS#12 file."""
        if self.backup:
            self.backup_file = module.backup_local(self.path)
        write_file(module, content, mode)
        if self.return_content:
            self.pkcs12_bytes = content


class PkcsPyOpenSSL(Pkcs):
    def __init__(self, module):
        super(PkcsPyOpenSSL, self).__init__(module, 'pyopenssl')

    def generate_bytes(self, module):
        """Generate PKCS#12 file archive."""
        self.pkcs12 = crypto.PKCS12()

        if self.other_certificates:
            self.pkcs12.set_ca_certificates(self.other_certificates)

        if self.certificate_path:
            self.pkcs12.set_certificate(load_certificate(self.certificate_path, backend=self.backend))

        if self.friendly_name:
            self.pkcs12.set_friendlyname(to_bytes(self.friendly_name))

        if self.privatekey_path:
            try:
                self.pkcs12.set_privatekey(
                    load_privatekey(self.privatekey_path, self.privatekey_passphrase, backend=self.backend))
            except OpenSSLBadPassphraseError as exc:
                raise PkcsError(exc)

        return self.pkcs12.export(self.passphrase, self.iter_size, self.maciter_size)

    def parse_bytes(self, pkcs12_content):
        try:
            p12 = crypto.load_pkcs12(pkcs12_content, self.passphrase)
            pkey = p12.get_privatekey()
            if pkey is not None:
                pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
            crt = p12.get_certificate()
            if crt is not None:
                crt = crypto.dump_certificate(crypto.FILETYPE_PEM, crt)
            other_certs = []
            if p12.get_ca_certificates() is not None:
                other_certs = [crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                       other_cert) for other_cert in p12.get_ca_certificates()]

            friendly_name = p12.get_friendlyname()

            return (pkey, crt, other_certs, friendly_name)
        except crypto.Error as exc:
            raise PkcsError(exc)

    def _dump_privatekey(self, pkcs12):
        pk = pkcs12.get_privatekey()
        return crypto.dump_privatekey(crypto.FILETYPE_PEM, pk) if pk else None

    def _dump_certificate(self, pkcs12):
        cert = pkcs12.get_certificate()
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert) if cert else None

    def _dump_other_certificates(self, pkcs12):
        return [
            crypto.dump_certificate(crypto.FILETYPE_PEM, other_cert)
            for other_cert in pkcs12.get_ca_certificates()
        ]

    def _get_friendly_name(self, pkcs12):
        return pkcs12.get_friendlyname()


class PkcsCryptography(Pkcs):
    def __init__(self, module):
        super(PkcsCryptography, self).__init__(module, 'cryptography')

    def generate_bytes(self, module):
        """Generate PKCS#12 file archive."""
        pkey = None
        if self.privatekey_path:
            try:
                pkey = load_privatekey(self.privatekey_path, self.privatekey_passphrase, backend=self.backend)
            except OpenSSLBadPassphraseError as exc:
                raise PkcsError(exc)

        cert = None
        if self.certificate_path:
            cert = load_certificate(self.certificate_path, backend=self.backend)

        friendly_name = to_bytes(self.friendly_name) if self.friendly_name is not None else None

        # Store fake object which can be used to retrieve the components back
        self.pkcs12 = (pkey, cert, self.other_certificates, friendly_name)

        return serialize_key_and_certificates(
            friendly_name,
            pkey,
            cert,
            self.other_certificates,
            serialization.BestAvailableEncryption(to_bytes(self.passphrase))
            if self.passphrase else serialization.NoEncryption(),
        )

    def parse_bytes(self, pkcs12_content):
        try:
            private_key, certificate, additional_certificates, friendly_name = parse_pkcs12(
                pkcs12_content, self.passphrase)

            pkey = None
            if private_key is not None:
                pkey = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )

            crt = None
            if certificate is not None:
                crt = certificate.public_bytes(serialization.Encoding.PEM)

            other_certs = []
            if additional_certificates is not None:
                other_certs = [
                    other_cert.public_bytes(serialization.Encoding.PEM)
                    for other_cert in additional_certificates
                ]

            return (pkey, crt, other_certs, friendly_name)
        except ValueError as exc:
            raise PkcsError(exc)

    # The following methods will get self.pkcs12 passed, which is computed as:
    #
    #     self.pkcs12 = (pkey, cert, self.other_certificates, self.friendly_name)

    def _dump_privatekey(self, pkcs12):
        return pkcs12[0].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ) if pkcs12[0] else None

    def _dump_certificate(self, pkcs12):
        return pkcs12[1].public_bytes(serialization.Encoding.PEM) if pkcs12[1] else None

    def _dump_other_certificates(self, pkcs12):
        return [other_cert.public_bytes(serialization.Encoding.PEM) for other_cert in pkcs12[2]]

    def _get_friendly_name(self, pkcs12):
        return pkcs12[3]


def select_backend(module, backend):
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)
        can_use_pyopenssl = PYOPENSSL_FOUND and PYOPENSSL_VERSION >= LooseVersion(MINIMAL_PYOPENSSL_VERSION)

        # If no restrictions are provided, first try cryptography, then pyOpenSSL
        if module.params['iter_size'] is not None or module.params['maciter_size'] is not None:
            # If iter_size or maciter_size is specified, use pyOpenSSL backend
            backend = 'pyopenssl'
        elif can_use_cryptography:
            backend = 'cryptography'
        elif can_use_pyopenssl:
            backend = 'pyopenssl'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Can't detect any of the required Python libraries "
                                  "cryptography (>= {0}) or PyOpenSSL (>= {1})").format(
                                      MINIMAL_CRYPTOGRAPHY_VERSION,
                                      MINIMAL_PYOPENSSL_VERSION))

    if backend == 'pyopenssl':
        if not PYOPENSSL_FOUND:
            module.fail_json(msg=missing_required_lib('pyOpenSSL >= {0}'.format(MINIMAL_PYOPENSSL_VERSION)),
                             exception=PYOPENSSL_IMP_ERR)
        # module.deprecate('The module is using the PyOpenSSL backend. This backend has been deprecated',
        #                  version='x.0.0', collection_name='community.crypto')
        return backend, PkcsPyOpenSSL(module)
    elif backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)
        return backend, PkcsCryptography(module)
    else:
        raise ValueError('Unsupported value for backend: {0}'.format(backend))


def main():
    argument_spec = dict(
        action=dict(type='str', default='export', choices=['export', 'parse']),
        other_certificates=dict(type='list', elements='path', aliases=['ca_certificates']),
        other_certificates_parse_all=dict(type='bool', default=False),
        certificate_path=dict(type='path'),
        force=dict(type='bool', default=False),
        friendly_name=dict(type='str', aliases=['name']),
        iter_size=dict(type='int'),
        maciter_size=dict(type='int'),
        passphrase=dict(type='str', no_log=True),
        path=dict(type='path', required=True),
        privatekey_passphrase=dict(type='str', no_log=True),
        privatekey_path=dict(type='path'),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        src=dict(type='path'),
        backup=dict(type='bool', default=False),
        return_content=dict(type='bool', default=False),
        select_crypto_backend=dict(type='str', default='auto', choices=['auto', 'cryptography', 'pyopenssl']),
    )

    required_if = [
        ['action', 'parse', ['src']],
    ]

    module = AnsibleModule(
        add_file_common_args=True,
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    backend, pkcs12 = select_backend(module, module.params['select_crypto_backend'])

    base_dir = os.path.dirname(module.params['path']) or '.'
    if not os.path.isdir(base_dir):
        module.fail_json(
            name=base_dir,
            msg="The directory '%s' does not exist or the path is not a directory" % base_dir
        )

    try:
        changed = False

        if module.params['state'] == 'present':
            if module.check_mode:
                result = pkcs12.dump()
                result['changed'] = module.params['force'] or not pkcs12.check(module)
                module.exit_json(**result)

            if not pkcs12.check(module, perms_required=False) or module.params['force']:
                if module.params['action'] == 'export':
                    if not module.params['friendly_name']:
                        module.fail_json(msg='Friendly_name is required')
                    pkcs12_content = pkcs12.generate_bytes(module)
                    pkcs12.write(module, pkcs12_content, 0o600)
                    changed = True
                else:
                    pkey, cert, other_certs, friendly_name = pkcs12.parse()
                    dump_content = ''.join([to_native(pem) for pem in [pkey, cert] + other_certs if pem is not None])
                    pkcs12.write(module, to_bytes(dump_content))
                    changed = True

            file_args = module.load_file_common_arguments(module.params)
            if module.check_file_absent_if_check_mode(file_args['path']):
                changed = True
            elif module.set_fs_attributes_if_different(file_args, changed):
                changed = True
        else:
            if module.check_mode:
                result = pkcs12.dump()
                result['changed'] = os.path.exists(module.params['path'])
                module.exit_json(**result)

            if os.path.exists(module.params['path']):
                pkcs12.remove(module)
                changed = True

        result = pkcs12.dump()
        result['changed'] = changed
        if os.path.exists(module.params['path']):
            file_mode = "%04o" % stat.S_IMODE(os.stat(module.params['path']).st_mode)
            result['mode'] = file_mode

        module.exit_json(**result)
    except OpenSSLObjectError as exc:
        module.fail_json(msg=to_native(exc))


if __name__ == '__main__':
    main()
