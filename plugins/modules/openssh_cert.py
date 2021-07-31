#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, David Kainz <dkainz@mgit.at> <dave.jokain@gmx.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: openssh_cert
author: "David Kainz (@lolcube)"
short_description: Generate OpenSSH host or user certificates.
description:
    - Generate and regenerate OpenSSH host or user certificates.
requirements:
    - "ssh-keygen"
options:
    state:
        description:
            - Whether the host or user certificate should exist or not, taking action if the state is different
              from what is stated.
        type: str
        default: "present"
        choices: [ 'present', 'absent' ]
    type:
        description:
            - Whether the module should generate a host or a user certificate.
            - Required if I(state) is C(present).
        type: str
        choices: ['host', 'user']
    force:
        description:
            - Should the certificate be regenerated even if it already exists and is valid.
            - Equivalent to I(regenerate=always).
        type: bool
        default: false
    path:
        description:
            - Path of the file containing the certificate.
        type: path
        required: true
    regenerate:
        description:
            - When C(never) the task will fail if a certificate already exists at I(path) and is unreadable.
              Otherwise, a new certificate will only be generated if there is no existing certificate.
            - When C(fail) the task will fail if a certificate already exists at I(path) and does not
              match the module's options.
            - When C(partial_idempotence) an existing certificate will be regenerated based on
              I(serial), I(type), I(valid_from), I(valid_to), I(valid_at), and I(principals).
            - When C(full_idempotence) I(identifier), I(options), I(public_key), and I(signing_key)
              are also considered when compared against an existing certificate.
            - C(always) is equivalent to I(force=true).
        type: str
        choices:
            - never
            - fail
            - partial_idempotence
            - full_idempotence
            - always
        default: partial_idempotence
        version_added: 1.8.0
    signing_key:
        description:
            - The path to the private openssh key that is used for signing the public key in order to generate the certificate.
            - If the private key is on a PKCS#11 token (I(pkcs11_provider)), set this to the path to the public key instead.
            - Required if I(state) is C(present).
        type: path
    pkcs11_provider:
        description:
            - To use a signing key that resides on a PKCS#11 token, set this to the name (or full path) of the shared library to use with the token.
              Usually C(libpkcs11.so).
            - If this is set, I(signing_key) needs to point to a file containing the public key of the CA.
        type: str
        version_added: 1.1.0
    use_agent:
        description:
            - Should the ssh-keygen use a CA key residing in a ssh-agent.
        type: bool
        default: false
        version_added: 1.3.0
    public_key:
        description:
            - The path to the public key that will be signed with the signing key in order to generate the certificate.
            - Required if I(state) is C(present).
        type: path
    valid_from:
        description:
            - "The point in time the certificate is valid from. Time can be specified either as relative time or as absolute timestamp.
               Time will always be interpreted as UTC. Valid formats are: C([+-]timespec | YYYY-MM-DD | YYYY-MM-DDTHH:MM:SS | YYYY-MM-DD HH:MM:SS | always)
               where timespec can be an integer + C([w | d | h | m | s]) (e.g. C(+32w1d2h).
               Note that if using relative time this module is NOT idempotent."
            - Required if I(state) is C(present).
        type: str
    valid_to:
        description:
            - "The point in time the certificate is valid to. Time can be specified either as relative time or as absolute timestamp.
               Time will always be interpreted as UTC. Valid formats are: C([+-]timespec | YYYY-MM-DD | YYYY-MM-DDTHH:MM:SS | YYYY-MM-DD HH:MM:SS | forever)
               where timespec can be an integer + C([w | d | h | m | s]) (e.g. C(+32w1d2h).
               Note that if using relative time this module is NOT idempotent."
            - Required if I(state) is C(present).
        type: str
    valid_at:
        description:
            - "Check if the certificate is valid at a certain point in time. If it is not the certificate will be regenerated.
               Time will always be interpreted as UTC. Mainly to be used with relative timespec for I(valid_from) and / or I(valid_to).
               Note that if using relative time this module is NOT idempotent."
        type: str
    principals:
        description:
            - "Certificates may be limited to be valid for a set of principal (user/host) names.
              By default, generated certificates are valid for all users or hosts."
        type: list
        elements: str
    options:
        description:
            - "Specify certificate options when signing a key. The option that are valid for user certificates are:"
            - "C(clear): Clear all enabled permissions.  This is useful for clearing the default set of permissions so permissions may be added individually."
            - "C(force-command=command): Forces the execution of command instead of any shell or
               command specified by the user when the certificate is used for authentication."
            - "C(no-agent-forwarding): Disable ssh-agent forwarding (permitted by default)."
            - "C(no-port-forwarding): Disable port forwarding (permitted by default)."
            - "C(no-pty): Disable PTY allocation (permitted by default)."
            - "C(no-user-rc): Disable execution of C(~/.ssh/rc) by sshd (permitted by default)."
            - "C(no-x11-forwarding): Disable X11 forwarding (permitted by default)"
            - "C(permit-agent-forwarding): Allows ssh-agent forwarding."
            - "C(permit-port-forwarding): Allows port forwarding."
            - "C(permit-pty): Allows PTY allocation."
            - "C(permit-user-rc): Allows execution of C(~/.ssh/rc) by sshd."
            - "C(permit-x11-forwarding): Allows X11 forwarding."
            - "C(source-address=address_list): Restrict the source addresses from which the certificate is considered valid.
               The C(address_list) is a comma-separated list of one or more address/netmask pairs in CIDR format."
            - "At present, no options are valid for host keys."
        type: list
        elements: str
    identifier:
        description:
            - Specify the key identity when signing a public key. The identifier that is logged by the server when the certificate is used for authentication.
        type: str
    serial_number:
        description:
            - "Specify the certificate serial number.
               The serial number is logged by the server when the certificate is used for authentication.
               The certificate serial number may be used in a KeyRevocationList.
               The serial number may be omitted for checks, but must be specified again for a new certificate.
               Note: The default value set by ssh-keygen is 0."
        type: int

extends_documentation_fragment: files
'''

EXAMPLES = '''
- name: Generate an OpenSSH user certificate that is valid forever and for all users
  community.crypto.openssh_cert:
    type: user
    signing_key: /path/to/private_key
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: always
    valid_to: forever

# Generate an OpenSSH host certificate that is valid for 32 weeks from now and will be regenerated
# if it is valid for less than 2 weeks from the time the module is being run
- name: Generate an OpenSSH host certificate with valid_from, valid_to and valid_at parameters
  community.crypto.openssh_cert:
    type: host
    signing_key: /path/to/private_key
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: +0s
    valid_to: +32w
    valid_at: +2w

- name: Generate an OpenSSH host certificate that is valid forever and only for example.com and examplehost
  community.crypto.openssh_cert:
    type: host
    signing_key: /path/to/private_key
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: always
    valid_to: forever
    principals:
        - example.com
        - examplehost

- name: Generate an OpenSSH host Certificate that is valid from 21.1.2001 to 21.1.2019
  community.crypto.openssh_cert:
    type: host
    signing_key: /path/to/private_key
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: "2001-01-21"
    valid_to: "2019-01-21"

- name: Generate an OpenSSH user Certificate with clear and force-command option
  community.crypto.openssh_cert:
    type: user
    signing_key: /path/to/private_key
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: always
    valid_to: forever
    options:
        - "clear"
        - "force-command=/tmp/bla/foo"

- name: Generate an OpenSSH user certificate using a PKCS#11 token
  community.crypto.openssh_cert:
    type: user
    signing_key: /path/to/ca_public_key.pub
    pkcs11_provider: libpkcs11.so
    public_key: /path/to/public_key.pub
    path: /path/to/certificate
    valid_from: always
    valid_to: forever

'''

RETURN = '''
type:
    description: type of the certificate (host or user)
    returned: changed or success
    type: str
    sample: host
filename:
    description: path to the certificate
    returned: changed or success
    type: str
    sample: /tmp/certificate-cert.pub
info:
    description: Information about the certificate. Output of C(ssh-keygen -L -f).
    returned: change or success
    type: list
    elements: str

'''

import os
from distutils.version import LooseVersion
from sys import version_info

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native, to_text

from ansible_collections.community.crypto.plugins.module_utils.openssh.backends.common import safe_atomic_move

from ansible_collections.community.crypto.plugins.module_utils.openssh.certificate import (
    OpensshCertificate,
    OpensshCertificateTimeParameters,
    parse_option_list,
)

from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    parse_openssh_version,
)

PY27 = version_info[0:2] >= (2, 7)


class Certificate(object):
    def __init__(self, module):
        self.check_mode = module.check_mode
        self.module = module
        self.ssh_keygen = module.get_bin_path('ssh-keygen', True)

        self.force = module.params['force']
        self.identifier = module.params['identifier'] or ""
        self.options = module.params['options'] or []
        self.path = module.params['path']
        self.pkcs11_provider = module.params['pkcs11_provider']
        self.principals = module.params['principals'] or []
        self.public_key = module.params['public_key']
        self.regenerate = module.params['regenerate'] if not self.force else 'always'
        self.serial_number = module.params['serial_number']
        self.signing_key = module.params['signing_key']
        self.state = module.params['state']
        self.type = module.params['type']
        self.use_agent = module.params['use_agent']
        self.valid_at = module.params['valid_at']

        self.changed = False
        self.data = None
        self.original_data = None
        self.time_parameters = None

        if self.state == 'present':
            try:
                self.time_parameters = OpensshCertificateTimeParameters(
                    valid_from=module.params['valid_from'],
                    valid_to=module.params['valid_to'],
                )
            except ValueError as e:
                self.module.fail_json(msg=to_native(e))

        if self.exists():
            try:
                self.original_data = OpensshCertificate.load(self.path)
            except (TypeError, ValueError) as e:
                if self.regenerate in ('never', 'fail'):
                    self.module.fail_json(msg="Unable to read existing certificate: %s" % to_native(e))
                self.module.warn("Unable to read existing certificate: %s" % to_native(e))

        self._validate_parameters()

    def exists(self):
        return os.path.exists(self.path)

    def generate(self):
        if self._should_generate():
            if not self.check_mode:
                temp_cert = self._generate_temp_certificate()

                try:
                    safe_atomic_move(self.module, temp_cert, self.path)
                except OSError as e:
                    self.module.fail_json(msg="Unable to write certificate to %s: %s" % (self.path, to_native(e)))

                try:
                    self.data = OpensshCertificate.load(self.path)
                except (TypeError, ValueError) as e:
                    self.module.fail_json(msg="Unable to read new certificate: %s" % to_native(e))

            self.changed = True

        if self.exists():
            self._update_permissions()

    def remove(self):
        if self.exists():
            if not self.check_mode:
                try:
                    os.remove(self.path)
                except OSError as e:
                    self.module.fail_json(msg="Unable to remove existing certificate: %s" % to_native(e))
            self.changed = True

    @property
    def result(self):
        result = {'changed': self.changed}

        if self.module._diff:
            result['diff'] = {
                'before': get_cert_dict(self.original_data),
                'after': get_cert_dict(self.data)
            }

        if self.state == 'present':
            result.update({
                'type': self.type,
                'filename': self.path,
                'info': format_cert_info(self._get_cert_info()),
            })

        return result

    def _check_if_base_dir(self, path):
        base_dir = os.path.dirname(path) or '.'
        if not os.path.isdir(base_dir):
            self.module.fail_json(
                name=base_dir,
                msg='The directory %s does not exist or the file is not a directory' % base_dir
            )

    def _command_arguments(self, key_copy_path):
        result = [
            self.ssh_keygen,
            '-s', self.signing_key,
            '-P', '',
            '-I', self.identifier,
        ]

        if self.options:
            for option in self.options:
                result.extend(['-O', option])
        if self.pkcs11_provider:
            result.extend(['-D', self.pkcs11_provider])
        if self.principals:
            result.extend(['-n', ','.join(self.principals)])
        if self.serial_number is not None:
            result.extend(['-z', str(self.serial_number)])
        if self.type == 'host':
            result.extend(['-h'])
        if self.use_agent:
            result.extend(['-U'])
        if self.time_parameters.validity_string:
            result.extend(['-V', self.time_parameters.validity_string])
        result.append(key_copy_path)

        return result

    def _compare_options(self):
        try:
            critical_options, extensions = parse_option_list(self.options)
        except ValueError as e:
            return self.module.fail_json(msg=to_native(e))

        return all([
            set(self.original_data.critical_options) == set(critical_options),
            set(self.original_data.extensions) == set(extensions)
        ])

    def _compare_time_parameters(self):
        try:
            original_time_parameters = OpensshCertificateTimeParameters(
                valid_from=self.original_data.valid_after,
                valid_to=self.original_data.valid_before
            )
        except ValueError as e:
            return self.module.fail_json(msg=to_native(e))

        return all([
            original_time_parameters == self.time_parameters,
            original_time_parameters.within_range(self.valid_at)
        ])

    def _generate_temp_certificate(self):
        key_copy = os.path.join(self.module.tmpdir, os.path.basename(self.public_key))

        try:
            self.module.preserved_copy(self.public_key, key_copy)
        except OSError as e:
            self.module.fail_json(msg="Unable to stage temporary key: %s" % to_native(e))
        self.module.add_cleanup_file(key_copy)

        self.module.run_command(self._command_arguments(key_copy), environ_update=dict(TZ="UTC"), check_rc=True)

        temp_cert = os.path.splitext(key_copy)[0] + '-cert.pub'
        self.module.add_cleanup_file(temp_cert)

        return temp_cert

    def _get_cert_info(self):
        return self.module.run_command([self.ssh_keygen, '-Lf', self.path])[1]

    def _get_key_fingerprint(self, path):
        stdout = self.module.run_command([self.ssh_keygen, '-lf', path], check_rc=True)[1]
        return stdout.split()[1]

    def _is_valid(self):
        partial_result = all([
            set(self.original_data.principals) == set(self.principals),
            self.original_data.serial == self.serial_number if self.serial_number is not None else True,
            self.original_data.type == self.type,
            self._compare_time_parameters(),
        ])

        if self.regenerate == 'partial_idempotence':
            return partial_result

        return partial_result and all([
            self._compare_options(),
            self.original_data.key_id == self.identifier,
            self.original_data.public_key == self._get_key_fingerprint(self.public_key),
            self.original_data.signing_key == self._get_key_fingerprint(self.signing_key),
        ])

    def _should_generate(self):
        if self.regenerate == 'never':
            return self.original_data is None
        elif self.regenerate == 'fail':
            if self.original_data and not self._is_valid():
                self.module.fail_json(
                    msg="Certificate does not match the provided options.",
                    cert=get_cert_dict(self.original_data)
                )
            return self.original_data is None
        elif self.regenerate in ('partial_idempotence', 'full_idempotence'):
            return self.original_data is None or not self._is_valid()
        else:
            return True

    def _update_permissions(self):
        file_args = self.module.load_file_common_arguments(self.module.params)
        self.changed = self.module.set_fs_attributes_if_different(file_args, self.changed)

    def _validate_parameters(self):
        self._check_if_base_dir(self.path)

        if self.state == 'present':
            for path in (self.public_key, self.signing_key):
                self._check_if_base_dir(path)

            if self.options and self.type == "host":
                self.module.fail_json(msg="Options can only be used with user certificates.")

        if self.use_agent:
            ssh_version_string = self.module.run_command([self.module.get_bin_path('ssh', True), '-Vq'])[2].strip()
            ssh_version = parse_openssh_version(ssh_version_string)
            if ssh_version is None:
                self.module.fail_json(msg="Failed to parse ssh version from: %s" % ssh_version_string)
            elif LooseVersion(ssh_version) < LooseVersion("7.6"):
                self.module.fail_json(
                    msg="Signing with CA key in ssh agent requires ssh 7.6 or newer." +
                        " Your version is: %s" % ssh_version_string
                )


def format_cert_info(cert_info):
    result = []
    string = ""

    for word in cert_info.split():
        if word in ("Type:", "Public", "Signing", "Key", "Serial:", "Valid:", "Principals:", "Critical", "Extensions:"):
            result.append(string)
            string = word
        else:
            string += " " + word
    result.append(string)
    # Drop the certificate path
    result.pop(0)
    return result


def get_cert_dict(data):
    if data is None:
        return {}

    result = data.to_dict()
    result.pop('nonce')
    return result


def main():
    module = AnsibleModule(
        argument_spec=dict(
            force=dict(type='bool', default=False),
            identifier=dict(type='str'),
            options=dict(type='list', elements='str'),
            path=dict(type='path', required=True),
            pkcs11_provider=dict(type='str'),
            principals=dict(type='list', elements='str'),
            public_key=dict(type='path'),
            regenerate=dict(
                type='str',
                default='partial_idempotence',
                choices=['never', 'fail', 'partial_idempotence', 'full_idempotence', 'always']
            ),
            signing_key=dict(type='path'),
            serial_number=dict(type='int'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            type=dict(type='str', choices=['host', 'user']),
            use_agent=dict(type='bool', default=False),
            valid_at=dict(type='str'),
            valid_from=dict(type='str'),
            valid_to=dict(type='str'),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
        required_if=[('state', 'present', ['type', 'signing_key', 'public_key', 'valid_from', 'valid_to'])],
    )

    certificate = Certificate(module)

    if certificate.state == 'present':
        certificate.generate()
    else:
        certificate.remove()

    module.exit_json(**certificate.result)


if __name__ == '__main__':
    main()
