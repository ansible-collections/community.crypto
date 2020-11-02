# -*- coding: utf-8 -*-

# Copyright: (c) 2016-2017, Yanis Guenane <yanis+ansible@guenane.org>
# Copyright: (c) 2017, Markus Teufelberger <mteufelberger+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import abc
import datetime
import time
import os
import tempfile
import traceback

from distutils.version import LooseVersion
from random import randrange

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native, to_bytes, to_text

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.common import ArgumentSpec

from ansible_collections.community.crypto.plugins.module_utils.compat import ipaddress as compat_ipaddress
from ansible_collections.community.crypto.plugins.module_utils.ecs.api import ECSClient, RestOperationException, SessionConfigurationException

from ansible_collections.community.crypto.plugins.module_utils.crypto.basic import (
    OpenSSLObjectError,
    OpenSSLBadPassphraseError,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.support import (
    load_privatekey,
    load_certificate,
    load_certificate_request,
    parse_name_field,
    get_relative_time_option,
    select_message_digest,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_compare_public_keys,
    cryptography_get_name,
    cryptography_name_to_oid,
    cryptography_key_needs_digest_for_signing,
    cryptography_parse_key_usage_params,
    cryptography_serial_number_of_cert,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.pyopenssl_support import (
    pyopenssl_normalize_name_attribute,
)

from ansible_collections.community.crypto.plugins.module_utils.crypto.module_backends.certificate import (
    CertificateError,
    CertificateBackend,
    CertificateProvider,
)

try:
    import OpenSSL
    from OpenSSL import crypto
except ImportError:
    pass

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509 import NameAttribute, Name
    from cryptography.x509.oid import NameOID
except ImportError:
    pass


class AcmeCertificateBackend(CertificateBackend):
    def __init__(self, module, backend):
        super(AcmeCertificateBackend, self).__init__(module, backend)
        self.accountkey_path = module.params['acme_accountkey_path']
        self.challenge_path = module.params['acme_challenge_path']
        self.use_chain = module.params['acme_chain']
        self.acme_directory = module.params['acme_directory']

        if self.csr_content is None and not os.path.exists(self.csr_path):
            raise CertificateError(
                'The certificate signing request file %s does not exist' % self.csr_path
            )

        if not os.path.exists(self.accountkey_path):
            raise CertificateError(
                'The account key %s does not exist' % self.accountkey_path
            )

        if not os.path.exists(self.challenge_path):
            raise CertificateError(
                'The challenge path %s does not exist' % self.challenge_path
            )

        self.acme_tiny_path = self.module.get_bin_path('acme-tiny', required=True)

    def generate_certificate(self):
        """(Re-)Generate certificate."""

        command = [self.acme_tiny_path]
        if self.use_chain:
            command.append('--chain')
        command.extend(['--account-key', self.accountkey_path])
        if self.csr_content is not None:
            # We need to temporarily write the CSR to disk
            fd, tmpsrc = tempfile.mkstemp()
            self.module.add_cleanup_file(tmpsrc)  # Ansible will delete the file on exit
            f = os.fdopen(fd, 'wb')
            try:
                f.write(self.csr_content)
            except Exception as err:
                try:
                    f.close()
                except Exception as dummy:
                    pass
                self.module.fail_json(
                    msg="failed to create temporary CSR file: %s" % to_native(err),
                    exception=traceback.format_exc()
                )
            f.close()
            command.extend(['--csr', tmpsrc])
        else:
            command.extend(['--csr', self.csr_path])
        command.extend(['--acme-dir', self.challenge_path])
        command.extend(['--directory-url', self.acme_directory])

        try:
            self.cert = to_bytes(self.module.run_command(command, check_rc=True)[1])
        except OSError as exc:
            raise CertificateError(exc)

    def get_certificate_data(self):
        """Return bytes for self.cert."""
        return self.cert

    def dump(self, include_certificate):
        result = super(AcmeCertificateBackend, self).dump(include_certificate)
        result['accountkey'] = self.accountkey_path
        return result


class AcmeCertificateProvider(CertificateProvider):
    def validate_module_args(self, module):
        if module.params['acme_accountkey_path'] is None:
            module.fail_json(msg='The acme_accountkey_path option must be specified for the acme provider.')
        if module.params['acme_challenge_path'] is None:
            module.fail_json(msg='The acme_challenge_path option must be specified for the acme provider.')

    def needs_version_two_certs(self, module):
        return False

    def create_backend(self, module, backend):
        return AcmeCertificateBackend(module, backend)


def add_acme_provider_to_argument_spec(argument_spec):
    argument_spec.argument_spec['provider']['choices'].append('acme')
    argument_spec.argument_spec.update(dict(
        acme_accountkey_path=dict(type='path'),
        acme_challenge_path=dict(type='path'),
        acme_chain=dict(type='bool', default=False),
        acme_directory=dict(type='str', default="https://acme-v02.api.letsencrypt.org/directory"),
    ))
