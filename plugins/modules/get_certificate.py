#!/usr/bin/python
# coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: get_certificate
author: "John Westcott IV (@john-westcott-iv)"
short_description: Get a certificate from a host:port
description:
    - Makes a secure connection and returns information about the presented certificate
    - The module uses the cryptography Python library.
    - Support SNI (L(Server Name Indication,https://en.wikipedia.org/wiki/Server_Name_Indication)) only with python >= 2.7.
options:
    host:
      description:
        - The host to get the cert for (IP is fine)
      type: str
      required: true
    ca_cert:
      description:
        - A PEM file containing one or more root certificates; if present, the cert will be validated against these root certs.
        - Note that this only validates the certificate is signed by the chain; not that the cert is valid for the host presenting it.
      type: path
    port:
      description:
        - The port to connect to
      type: int
      required: true
    server_name:
      description:
       - Server name used for SNI (L(Server Name Indication,https://en.wikipedia.org/wiki/Server_Name_Indication)) when hostname
         is an IP or is different from server name.
      type: str
      version_added: 1.4.0
    proxy_host:
      description:
        - Proxy host used when get a certificate.
      type: str
    proxy_port:
      description:
        - Proxy port used when get a certificate.
      type: int
      default: 8080
    starttls:
      description:
        - Requests a secure connection for protocols which require clients to initiate encryption.
        - Only available for C(mysql) currently.
      type: str
      choices:
        - mysql
      version_added: 1.9.0
    timeout:
      description:
        - The timeout in seconds
      type: int
      default: 10
    select_crypto_backend:
      description:
        - Determines which crypto backend to use.
        - The default choice is C(auto), which tries to use C(cryptography) if available.
        - If set to C(cryptography), will try to use the L(cryptography,https://cryptography.io/) library.
      type: str
      default: auto
      choices: [ auto, cryptography ]

notes:
  - When using ca_cert on OS X it has been reported that in some conditions the validate will always succeed.

requirements:
  - "python >= 2.7 when using C(proxy_host)"
  - "cryptography >= 1.6"
'''

RETURN = '''
cert:
    description: The certificate retrieved from the port
    returned: success
    type: str
expired:
    description: Boolean indicating if the cert is expired
    returned: success
    type: bool
extensions:
    description: Extensions applied to the cert
    returned: success
    type: list
    elements: dict
    contains:
        critical:
            returned: success
            type: bool
            description: Whether the extension is critical.
        asn1_data:
            returned: success
            type: str
            description:
              - The Base64 encoded ASN.1 content of the extension.
              - B(Note) that depending on the C(cryptography) version used, it is
                not possible to extract the ASN.1 content of the extension, but only
                to provide the re-encoded content of the extension in case it was
                parsed by C(cryptography). This should usually result in exactly the
                same value, except if the original extension value was malformed.
        name:
            returned: success
            type: str
            description: The extension's name.
issuer:
    description: Information about the issuer of the cert
    returned: success
    type: dict
not_after:
    description: Expiration date of the cert
    returned: success
    type: str
not_before:
    description: Issue date of the cert
    returned: success
    type: str
serial_number:
    description: The serial number of the cert
    returned: success
    type: str
signature_algorithm:
    description: The algorithm used to sign the cert
    returned: success
    type: str
subject:
    description: Information about the subject of the cert (OU, CN, etc)
    returned: success
    type: dict
version:
    description: The version number of the certificate
    returned: success
    type: str
'''

EXAMPLES = '''
- name: Get the cert from an RDP port
  community.crypto.get_certificate:
    host: "1.2.3.4"
    port: 3389
  delegate_to: localhost
  run_once: true
  register: cert

- name: Get a cert from an https port
  community.crypto.get_certificate:
    host: "www.google.com"
    port: 443
  delegate_to: localhost
  run_once: true
  register: cert

- name: How many days until cert expires
  debug:
    msg: "cert expires in: {{ expire_days }} days."
  vars:
    expire_days: "{{ (( cert.not_after | to_datetime('%Y%m%d%H%M%SZ')) - (ansible_date_time.iso8601 | to_datetime('%Y-%m-%dT%H:%M:%SZ')) ).days }}"
'''

import atexit
import base64
import datetime
import traceback

from os.path import isfile
from socket import create_connection, setdefaulttimeout, socket
from ssl import get_server_certificate, DER_cert_to_PEM_cert, CERT_NONE, CERT_REQUIRED

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes

from ansible_collections.community.crypto.plugins.module_utils.version import LooseVersion

from ansible_collections.community.crypto.plugins.module_utils.crypto.cryptography_support import (
    cryptography_oid_to_name,
    cryptography_get_extensions_from_cert,
)

MINIMAL_CRYPTOGRAPHY_VERSION = '1.6'

CREATE_DEFAULT_CONTEXT_IMP_ERR = None
try:
    from ssl import create_default_context
except ImportError:
    CREATE_DEFAULT_CONTEXT_IMP_ERR = traceback.format_exc()
    HAS_CREATE_DEFAULT_CONTEXT = False
else:
    HAS_CREATE_DEFAULT_CONTEXT = True

CRYPTOGRAPHY_IMP_ERR = None
try:
    import cryptography
    import cryptography.exceptions
    import cryptography.x509
    from cryptography.hazmat.backends import default_backend as cryptography_backend
    CRYPTOGRAPHY_VERSION = LooseVersion(cryptography.__version__)
except ImportError:
    CRYPTOGRAPHY_IMP_ERR = traceback.format_exc()
    CRYPTOGRAPHY_FOUND = False
else:
    CRYPTOGRAPHY_FOUND = True


def send_starttls_packet(sock, server_type):
    if server_type == 'mysql':
        ssl_request_packet = (
            b'\x20\x00\x00\x01\x85\xae\x7f\x00' +
            b'\x00\x00\x00\x01\x21\x00\x00\x00' +
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +
            b'\x00\x00\x00\x00\x00\x00\x00\x00' +
            b'\x00\x00\x00\x00'
        )

        sock.recv(8192)  # discard initial handshake from server for this naive implementation
        sock.send(ssl_request_packet)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            ca_cert=dict(type='path'),
            host=dict(type='str', required=True),
            port=dict(type='int', required=True),
            proxy_host=dict(type='str'),
            proxy_port=dict(type='int', default=8080),
            server_name=dict(type='str'),
            timeout=dict(type='int', default=10),
            select_crypto_backend=dict(type='str', choices=['auto', 'cryptography'], default='auto'),
            starttls=dict(type='str', choices=['mysql']),
        ),
    )

    ca_cert = module.params.get('ca_cert')
    host = module.params.get('host')
    port = module.params.get('port')
    proxy_host = module.params.get('proxy_host')
    proxy_port = module.params.get('proxy_port')
    timeout = module.params.get('timeout')
    server_name = module.params.get('server_name')
    start_tls_server_type = module.params.get('starttls')

    backend = module.params.get('select_crypto_backend')
    if backend == 'auto':
        # Detection what is possible
        can_use_cryptography = CRYPTOGRAPHY_FOUND and CRYPTOGRAPHY_VERSION >= LooseVersion(MINIMAL_CRYPTOGRAPHY_VERSION)

        # Try cryptography
        if can_use_cryptography:
            backend = 'cryptography'

        # Success?
        if backend == 'auto':
            module.fail_json(msg=("Cannot detect the required Python library "
                                  "cryptography (>= {0})").format(MINIMAL_CRYPTOGRAPHY_VERSION))

    if backend == 'cryptography':
        if not CRYPTOGRAPHY_FOUND:
            module.fail_json(msg=missing_required_lib('cryptography >= {0}'.format(MINIMAL_CRYPTOGRAPHY_VERSION)),
                             exception=CRYPTOGRAPHY_IMP_ERR)

    result = dict(
        changed=False,
    )

    if timeout:
        setdefaulttimeout(timeout)

    if ca_cert:
        if not isfile(ca_cert):
            module.fail_json(msg="ca_cert file does not exist")

    if not HAS_CREATE_DEFAULT_CONTEXT:
        # Python < 2.7.9
        if proxy_host:
            module.fail_json(msg='To use proxy_host, you must run the get_certificate module with Python 2.7 or newer.',
                             exception=CREATE_DEFAULT_CONTEXT_IMP_ERR)
        try:
            # Note: get_server_certificate does not support SNI!
            cert = get_server_certificate((host, port), ca_certs=ca_cert)
        except Exception as e:
            module.fail_json(msg="Failed to get cert from {0}:{1}, error: {2}".format(host, port, e))
    else:
        # Python >= 2.7.9
        try:
            if proxy_host:
                connect = "CONNECT %s:%s HTTP/1.0\r\n\r\n" % (host, port)
                sock = socket()
                atexit.register(sock.close)
                sock.connect((proxy_host, proxy_port))
                sock.send(connect.encode())
                sock.recv(8192)
            else:
                sock = create_connection((host, port))
                atexit.register(sock.close)

            if ca_cert:
                ctx = create_default_context(cafile=ca_cert)
                ctx.check_hostname = False
                ctx.verify_mode = CERT_REQUIRED
            else:
                ctx = create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = CERT_NONE

            if start_tls_server_type is not None:
                send_starttls_packet(sock, start_tls_server_type)

            cert = ctx.wrap_socket(sock, server_hostname=server_name or host).getpeercert(True)
            cert = DER_cert_to_PEM_cert(cert)
        except Exception as e:
            if proxy_host:
                module.fail_json(msg="Failed to get cert via proxy {0}:{1} from {2}:{3}, error: {4}".format(
                    proxy_host, proxy_port, host, port, e))
            else:
                module.fail_json(msg="Failed to get cert from {0}:{1}, error: {2}".format(host, port, e))

    result['cert'] = cert

    if backend == 'cryptography':
        x509 = cryptography.x509.load_pem_x509_certificate(to_bytes(cert), cryptography_backend())
        result['subject'] = {}
        for attribute in x509.subject:
            result['subject'][cryptography_oid_to_name(attribute.oid, short=True)] = attribute.value

        result['expired'] = x509.not_valid_after < datetime.datetime.utcnow()

        result['extensions'] = []
        for dotted_number, entry in cryptography_get_extensions_from_cert(x509).items():
            oid = cryptography.x509.oid.ObjectIdentifier(dotted_number)
            result['extensions'].append({
                'critical': entry['critical'],
                'asn1_data': base64.b64decode(entry['value']),
                'name': cryptography_oid_to_name(oid, short=True),
            })

        result['issuer'] = {}
        for attribute in x509.issuer:
            result['issuer'][cryptography_oid_to_name(attribute.oid, short=True)] = attribute.value

        result['not_after'] = x509.not_valid_after.strftime('%Y%m%d%H%M%SZ')
        result['not_before'] = x509.not_valid_before.strftime('%Y%m%d%H%M%SZ')

        result['serial_number'] = x509.serial_number
        result['signature_algorithm'] = cryptography_oid_to_name(x509.signature_algorithm_oid)

        # We need the -1 offset to get the same values as pyOpenSSL
        if x509.version == cryptography.x509.Version.v1:
            result['version'] = 1 - 1
        elif x509.version == cryptography.x509.Version.v3:
            result['version'] = 3 - 1
        else:
            result['version'] = "unknown"

    module.exit_json(**result)


if __name__ == '__main__':
    main()
