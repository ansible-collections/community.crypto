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
            - When C(never) the task will fail if a certificate already exists at I(path) and is unreadable
              otherwise a new certificate will only be generated if there is no existing certificate.
            - When C(fail) the task will fail if a certificate already exists at I(path) and does not
              match the module's options.
            - When C(partial_idempotence) an existing certificate will be regenerated based on
              I(serial), I(signature_algorithm), I(type), I(valid_from), I(valid_to), I(valid_at), and I(principals).
              I(valid_from) and I(valid_to) can be excluded by I(ignore_timestamps=true).
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
    signature_algorithm:
        description:
            - As of OpenSSH 8.2 the SHA-1 signature algorithm for RSA keys has been disabled and C(ssh) will refuse
              host certificates signed with the SHA-1 algorithm. OpenSSH 8.1 made C(rsa-sha2-512) the default algorithm
              when acting as a CA and signing certificates with a RSA key. However, for OpenSSH versions less than 8.1
              the SHA-2 signature algorithms, C(rsa-sha2-256) or C(rsa-sha2-512), must be specified using this option
              if compatibility with newer C(ssh) clients is required. Conversely if hosts using OpenSSH version 8.2
              or greater must remain compatible with C(ssh) clients using OpenSSH less than 7.2, then C(ssh-rsa)
              can be used when generating host certificates (a corresponding change to the sshd_config to add C(ssh-rsa)
              to the C(CASignatureAlgorithms) keyword is also required).
            - Using any value for this option with a non-RSA I(signing_key) will cause this module to fail.
            - "Note: OpenSSH versions prior to 7.2 do not support SHA-2 signature algorithms for RSA keys and OpenSSH
               versions prior to 7.3 do not support SHA-2 signature algorithms for certificates."
            - See U(https://www.openssh.com/txt/release-8.2) for more information.
        type: str
        choices:
            - ssh-rsa
            - rsa-sha2-256
            - rsa-sha2-512
        version_added: 1.10.0
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
               where timespec can be an integer + C([w | d | h | m | s]) (for example C(+32w1d2h)).
               Note that if using relative time this module is NOT idempotent."
            - "The value C(always) is only supported for OpenSSH 7.7 and greater, however, the value C(1970-01-01T00:00:01)
               can be used with earlier versions as an equivalent expression."
            - "To ignore this value during comparison with an existing certificate set I(ignore_timestamps=true)."
            - Required if I(state) is C(present).
        type: str
    valid_to:
        description:
            - "The point in time the certificate is valid to. Time can be specified either as relative time or as absolute timestamp.
               Time will always be interpreted as UTC. Valid formats are: C([+-]timespec | YYYY-MM-DD | YYYY-MM-DDTHH:MM:SS | YYYY-MM-DD HH:MM:SS | forever)
               where timespec can be an integer + C([w | d | h | m | s]) (for example C(+32w1d2h)).
               Note that if using relative time this module is NOT idempotent."
            - "To ignore this value during comparison with an existing certificate set I(ignore_timestamps=true)."
            - Required if I(state) is C(present).
        type: str
    valid_at:
        description:
            - "Check if the certificate is valid at a certain point in time. If it is not the certificate will be regenerated.
               Time will always be interpreted as UTC. Mainly to be used with relative timespec for I(valid_from) and / or I(valid_to).
               Note that if using relative time this module is NOT idempotent."
        type: str
    ignore_timestamps:
        description:
            - "Whether the I(valid_from) and I(valid_to) timestamps should be ignored for idempotency checks."
            - "However, the values will still be applied to a new certificate if it meets any other necessary conditions for generation/regeneration."
        type: bool
        default: false
        version_added: 2.2.0
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
    ignore_timestamps: true

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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.openssh.backends.common import (
    KeygenCommand,
    OpensshModule,
    PrivateKey,
)

from ansible_collections.community.crypto.plugins.module_utils.openssh.certificate import (
    OpensshCertificate,
    OpensshCertificateTimeParameters,
    parse_option_list,
)


class Certificate(OpensshModule):
    def __init__(self, module):
        super(Certificate, self).__init__(module)
        self.ssh_keygen = KeygenCommand(self.module)

        self.identifier = self.module.params['identifier'] or ""
        self.options = self.module.params['options'] or []
        self.path = self.module.params['path']
        self.pkcs11_provider = self.module.params['pkcs11_provider']
        self.principals = self.module.params['principals'] or []
        self.public_key = self.module.params['public_key']
        self.regenerate = self.module.params['regenerate'] if not self.module.params['force'] else 'always'
        self.serial_number = self.module.params['serial_number']
        self.signature_algorithm = self.module.params['signature_algorithm']
        self.signing_key = self.module.params['signing_key']
        self.state = self.module.params['state']
        self.type = self.module.params['type']
        self.use_agent = self.module.params['use_agent']
        self.valid_at = self.module.params['valid_at']
        self.ignore_timestamps = self.module.params['ignore_timestamps']

        self._check_if_base_dir(self.path)

        if self.state == 'present':
            self._validate_parameters()

        self.data = None
        self.original_data = None
        if self._exists():
            self._load_certificate()

        self.time_parameters = None
        if self.state == 'present':
            self._set_time_parameters()

    def _validate_parameters(self):
        for path in (self.public_key, self.signing_key):
            self._check_if_base_dir(path)

        if self.options and self.type == "host":
            self.module.fail_json(msg="Options can only be used with user certificates.")

        if self.use_agent:
            self._use_agent_available()

    def _use_agent_available(self):
        ssh_version = self._get_ssh_version()
        if not ssh_version:
            self.module.fail_json(msg="Failed to determine ssh version")
        elif LooseVersion(ssh_version) < LooseVersion("7.6"):
            self.module.fail_json(
                msg="Signing with CA key in ssh agent requires ssh 7.6 or newer." +
                    " Your version is: %s" % ssh_version
            )

    def _exists(self):
        return os.path.exists(self.path)

    def _load_certificate(self):
        try:
            self.original_data = OpensshCertificate.load(self.path)
        except (TypeError, ValueError) as e:
            if self.regenerate in ('never', 'fail'):
                self.module.fail_json(msg="Unable to read existing certificate: %s" % to_native(e))
            self.module.warn("Unable to read existing certificate: %s" % to_native(e))

    def _set_time_parameters(self):
        try:
            self.time_parameters = OpensshCertificateTimeParameters(
                valid_from=self.module.params['valid_from'],
                valid_to=self.module.params['valid_to'],
            )
        except ValueError as e:
            self.module.fail_json(msg=to_native(e))

    def _execute(self):
        if self.state == 'present':
            if self._should_generate():
                self._generate()
                self._update_permissions(self.path)
        else:
            if self._exists():
                self._remove()

    def _should_generate(self):
        if self.regenerate == 'never':
            return self.original_data is None
        elif self.regenerate == 'fail':
            if self.original_data and not self._is_fully_valid():
                self.module.fail_json(
                    msg="Certificate does not match the provided options.",
                    cert=get_cert_dict(self.original_data)
                )
            return self.original_data is None
        elif self.regenerate == 'partial_idempotence':
            return self.original_data is None or not self._is_partially_valid()
        elif self.regenerate == 'full_idempotence':
            return self.original_data is None or not self._is_fully_valid()
        else:
            return True

    def _is_fully_valid(self):
        return self._is_partially_valid() and all([
            self._compare_options() if self.original_data.type == 'user' else True,
            self.original_data.key_id == self.identifier,
            self.original_data.public_key == self._get_key_fingerprint(self.public_key),
            self.original_data.signing_key == self._get_key_fingerprint(self.signing_key),
        ])

    def _is_partially_valid(self):
        return all([
            set(self.original_data.principals) == set(self.principals),
            self.original_data.signature_type == self.signature_algorithm if self.signature_algorithm else True,
            self.original_data.serial == self.serial_number if self.serial_number is not None else True,
            self.original_data.type == self.type,
            self._compare_time_parameters(),
        ])

    def _compare_time_parameters(self):
        try:
            original_time_parameters = OpensshCertificateTimeParameters(
                valid_from=self.original_data.valid_after,
                valid_to=self.original_data.valid_before
            )
        except ValueError as e:
            return self.module.fail_json(msg=to_native(e))

        if self.ignore_timestamps:
            return original_time_parameters.within_range(self.valid_at)

        return all([
            original_time_parameters == self.time_parameters,
            original_time_parameters.within_range(self.valid_at)
        ])

    def _compare_options(self):
        try:
            critical_options, extensions = parse_option_list(self.options)
        except ValueError as e:
            return self.module.fail_json(msg=to_native(e))

        return all([
            set(self.original_data.critical_options) == set(critical_options),
            set(self.original_data.extensions) == set(extensions)
        ])

    def _get_key_fingerprint(self, path):
        private_key_content = self.ssh_keygen.get_private_key(path, check_rc=True)[1]
        return PrivateKey.from_string(private_key_content).fingerprint

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _generate(self):
        try:
            temp_certificate = self._generate_temp_certificate()
            self._safe_secure_move([(temp_certificate, self.path)])
        except OSError as e:
            self.module.fail_json(msg="Unable to write certificate to %s: %s" % (self.path, to_native(e)))

        try:
            self.data = OpensshCertificate.load(self.path)
        except (TypeError, ValueError) as e:
            self.module.fail_json(msg="Unable to read new certificate: %s" % to_native(e))

    def _generate_temp_certificate(self):
        key_copy = os.path.join(self.module.tmpdir, os.path.basename(self.public_key))

        try:
            self.module.preserved_copy(self.public_key, key_copy)
        except OSError as e:
            self.module.fail_json(msg="Unable to stage temporary key: %s" % to_native(e))
        self.module.add_cleanup_file(key_copy)

        self.ssh_keygen.generate_certificate(
            key_copy, self.identifier, self.options, self.pkcs11_provider, self.principals, self.serial_number,
            self.signature_algorithm, self.signing_key, self.type, self.time_parameters, self.use_agent,
            environ_update=dict(TZ="UTC"), check_rc=True
        )

        temp_cert = os.path.splitext(key_copy)[0] + '-cert.pub'
        self.module.add_cleanup_file(temp_cert)

        return temp_cert

    @OpensshModule.trigger_change
    @OpensshModule.skip_if_check_mode
    def _remove(self):
        try:
            os.remove(self.path)
        except OSError as e:
            self.module.fail_json(msg="Unable to remove existing certificate: %s" % to_native(e))

    @property
    def _result(self):
        if self.state != 'present':
            return {}

        certificate_info = self.ssh_keygen.get_certificate_info(self.path)[1]

        return {
            'type': self.type,
            'filename': self.path,
            'info': format_cert_info(certificate_info),
        }

    @property
    def diff(self):
        return {
            'before': get_cert_dict(self.original_data),
            'after': get_cert_dict(self.data)
        }


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
    result['signature_algorithm'] = data.signature_type

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
            signature_algorithm=dict(type='str', choices=['ssh-rsa', 'rsa-sha2-256', 'rsa-sha2-512']),
            signing_key=dict(type='path'),
            serial_number=dict(type='int'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            type=dict(type='str', choices=['host', 'user']),
            use_agent=dict(type='bool', default=False),
            valid_at=dict(type='str'),
            valid_from=dict(type='str'),
            valid_to=dict(type='str'),
            ignore_timestamps=dict(type='bool', default=False),
        ),
        supports_check_mode=True,
        add_file_common_args=True,
        required_if=[('state', 'present', ['type', 'signing_key', 'public_key', 'valid_from', 'valid_to'])],
    )

    Certificate(module).execute()


if __name__ == '__main__':
    main()
