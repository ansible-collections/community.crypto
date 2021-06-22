# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.crypto.plugins.module_utils.openssh.certificate import (
    OpensshCertificate
)

# Type: ssh-rsa-cert-v01@openssh.com user certificate
# Public key: RSA-CERT SHA256:SvUwwUer4AwsdePYseJR3LcZS8lnKi6BqiL51Dop030
# Signing CA: DSA SHA256:YCdJ2lYU+FSkWUud7zg1SJszprXoRGNU/GVcqXUjgC8
# Key ID: "test"
# Serial: 0
# Valid: forever
# Principals: (none)
# Critical Options: (none)
# Extensions:
#     permit-X11-forwarding
#     permit-agent-forwarding
#     permit-port-forwarding
#     permit-pty
#     permit-user-rc
RSA_CERT_SIGNED_BY_DSA = (
    b'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgY9CvhGpyvBB611Lmx6hHPD+CmeJ0oW' +
    b'SSK1q6K3h5CS4AAAADAQABAAABAQDKYIJtpFaWpTNNifmuV3DM9BBdngMG28jWPy4C/SoZg4EP7mkYUsG6hN+LgjOL17YEF7bKDEWPl9sQS' +
    b'92iD+AuAPrjnHVQ9VG5hbTYiQAaicj6hxqBoNqGQWxDzhZL4B35MgqmoUOBGnzYA/fKgqhRVzOXbWFxKLtzSJzB+Z+kmeoBzq+4MazL4Bko' +
    b'yPZMrIMnvxiluv+kqE9SWeJ/5e7WXdtbYTnSR4WN3gW/BMKEoKQk/UGwuPvCiRq+y8LorJP4B1Wfwlm/meqtbTidXyCcQPR9xWpce3rRjLL' +
    b'T6cimUjWrbx7Q1SlsypdkclgPSTu9Jg457am8tnQUgnL7VdetAAAAAAAAAAAAAAABAAAABHRlc3QAAAAAAAAAAAAAAAD//////////wAAAA' +
    b'AAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0L' +
    b'WZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGxAAAAB3NzaC1kc3MAAACBAPV/' +
    b'b5FknU8e56TWAGLRQ0v3c3f5jAS0txcwqtYLHLulTqyMcLL0MyzWxXv77MpjTMwEjWXLbfNWdk/qmsjfBynzs2nSZ7clVsqt/ZOadcBFEhq' +
    b'ZM0l+1ZCPkhQiqsD2aodGbkVcJgqL5Z5krzB5MTey7c8rlAAxKOjfs70Bg8MPAAAAFQCW466dSEu2Pf0u8AA5SHgH0i/xuwAAAIBc23gfmv' +
    b'GC+oaUAXiak17kH6NvOSJXZBdk/8CyGK6yL+CHKrKyffe6BbiVXwC6sUIa9j4YsFeyYwPFGBtfLuNUmgyKYTJcCM2zJLBykmTIvjSdRaYGN' +
    b'Rkyi8GnzVV2lWxQ+4m4UGeTPbPN/OG4B0NwDbBJGbVJv0xJPq2EBKoUdgAAAIAyrFxGDLtOZFZ2fgONVaKaapEpJ5f3qPhLDXxVQ/BKVUkU' +
    b'RA4AHHyXF2AMiiOOiHLrO5xsEGUyW+OISFm+6m17cEPNixA7G1fBniLvyVv2woyYW3kaY4J9z266kAFzFWVNgwr+T7MY0hEvct8VFA97JMR' +
    b'Q7c8c/tNDaL7uqV46QQAAADcAAAAHc3NoLWRzcwAAAChaQ94wqca+KhkHtbkLpjvGsfu0Gy03SAb0+o11Shk/BXnK7N/cwEVD ' +
    b'ansible@ansible-host'
)
RSA_FINGERPRINT = b'SHA256:SvUwwUer4AwsdePYseJR3LcZS8lnKi6BqiL51Dop030'
# Type: ssh-dss-cert-v01@openssh.com user certificate
# Public key: DSA-CERT SHA256:YCdJ2lYU+FSkWUud7zg1SJszprXoRGNU/GVcqXUjgC8
# Signing CA: ECDSA SHA256:w9lp4zGRJShhm4DzO3ulVm0BEcR0PMjrM6VanQo4C0w
# Key ID: "test"
# Serial: 0
# Valid: forever
# Principals: (none)
# Critical Options: (none)
# Extensions: (none)
DSA_CERT_SIGNED_BY_ECDSA_NO_OPTS = (
    b'ssh-dss-cert-v01@openssh.com AAAAHHNzaC1kc3MtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgsKvMxIv4viCNQX7z8K4/R5jronpZGf' +
    b'ydpoBoh2Cx5dgAAACBAPV/b5FknU8e56TWAGLRQ0v3c3f5jAS0txcwqtYLHLulTqyMcLL0MyzWxXv77MpjTMwEjWXLbfNWdk/qmsjfBynzs' +
    b'2nSZ7clVsqt/ZOadcBFEhqZM0l+1ZCPkhQiqsD2aodGbkVcJgqL5Z5krzB5MTey7c8rlAAxKOjfs70Bg8MPAAAAFQCW466dSEu2Pf0u8AA5' +
    b'SHgH0i/xuwAAAIBc23gfmvGC+oaUAXiak17kH6NvOSJXZBdk/8CyGK6yL+CHKrKyffe6BbiVXwC6sUIa9j4YsFeyYwPFGBtfLuNUmgyKYTJ' +
    b'cCM2zJLBykmTIvjSdRaYGNRkyi8GnzVV2lWxQ+4m4UGeTPbPN/OG4B0NwDbBJGbVJv0xJPq2EBKoUdgAAAIAyrFxGDLtOZFZ2fgONVaKaap' +
    b'EpJ5f3qPhLDXxVQ/BKVUkURA4AHHyXF2AMiiOOiHLrO5xsEGUyW+OISFm+6m17cEPNixA7G1fBniLvyVv2woyYW3kaY4J9z266kAFzFWVNg' +
    b'wr+T7MY0hEvct8VFA97JMRQ7c8c/tNDaL7uqV46QQAAAAAAAAAAAAAAAQAAAAR0ZXN0AAAAAAAAAAAAAAAA//////////8AAAAAAAAAAAAA' +
    b'AAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOf55Wc0yzaJPtxXxBGZKmAUozbYXwxZGFS1c/FaJbwLpq/' +
    b'wvanQKM01uU73swNIt+ZFra9kRSi21xjzgMPn7U0AAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIGmlKa/riG7+EpoW6dTJY6' +
    b'0N8BrEcniKgOxdRM1EPJ2DAAAAIQDnK4stvbvS+Bn0/42Was7uOfJtnLYXs5EuB2L3uejPcQ== ansible@ansible-host'
)
DSA_FINGERPRINT = b'SHA256:YCdJ2lYU+FSkWUud7zg1SJszprXoRGNU/GVcqXUjgC8'
# Type: ecdsa-sha2-nistp256-cert-v01@openssh.com user certificate
# Public key: ECDSA-CERT SHA256:w9lp4zGRJShhm4DzO3ulVm0BEcR0PMjrM6VanQo4C0w
# Signing CA: ED25519 SHA256:NP4JdfkCopbjwMepq0aPrpMz13cNmEd+uDOxC/j9N40
# Key ID: "test"
# Serial: 0
# Valid: forever
# Principals: (none)
# Critical Options:
#     force-command /usr/bin/csh
# Extensions:
#     permit-X11-forwarding
#     permit-agent-forwarding
#     permit-port-forwarding
#     permit-pty
#     permit-user-rc
ECDSA_CERT_SIGNED_BY_ED25519_VALID_OPTS = (
    b'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgtC' +
    b'ips7/sOOOTAgiawGlQhM6pb26t0FfQ1jG60m+tOg0AAAAIbmlzdHAyNTYAAABBBOf55Wc0yzaJPtxXxBGZKmAUozbYXwxZGFS1c/FaJbwLp' +
    b'q/wvanQKM01uU73swNIt+ZFra9kRSi21xjzgMPn7U0AAAAAAAAAAAAAAAEAAAAEdGVzdAAAAAAAAAAAAAAAAP//////////AAAAJQAAAA1m' +
    b'b3JjZS1jb21tYW5kAAAAEAAAAAwvdXNyL2Jpbi9jc2gAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW5' +
    b'0LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLX' +
    b'JjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAII3qYBforim0x87UXpaTDNFnhFTyb+TPCJVQpEAOHTL6AAAAUwAAAAtzc2gtZWQyN' +
    b'TUxOQAAAEAdp3eOLRN5t2wW29TBWbz604uuXg88jH4RA4HDhbRupa/x2rN3j6iZQ4VXPLA4JtdfIslHFkH6HUlxU8XsoJwP ' +
    b'ansible@ansible-host'
)
ECDSA_FINGERPRINT = b'SHA256:w9lp4zGRJShhm4DzO3ulVm0BEcR0PMjrM6VanQo4C0w'
# Type: ssh-ed25519-cert-v01@openssh.com user certificate
# Public key: ED25519-CERT SHA256:NP4JdfkCopbjwMepq0aPrpMz13cNmEd+uDOxC/j9N40
# Signing CA: RSA SHA256:SvUwwUer4AwsdePYseJR3LcZS8lnKi6BqiL51Dop030
# Key ID: "test"
# Serial: 0
# Valid: forever
# Principals: (none)
# Critical Options:
#     test UNKNOWN OPTION (len 13)
# Extensions:
#     test UNKNOWN OPTION (len 0)
ED25519_CERT_SIGNED_BY_RSA_INVALID_OPTS = (
    b'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIP034YpKn6BDcwxqFnVrKt' +
    b'kNX7k6X7hxZ7lADp5LAxHrAAAAII3qYBforim0x87UXpaTDNFnhFTyb+TPCJVQpEAOHTL6AAAAAAAAAAAAAAABAAAABHRlc3QAAAAAAAAAA' +
    b'AAAAAD//////////wAAABkAAAAEdGVzdAAAAA0AAAAJdW5kZWZpbmVkAAAADAAAAAR0ZXN0AAAAAAAAAAAAAAEXAAAAB3NzaC1yc2EAAAAD' +
    b'AQABAAABAQDKYIJtpFaWpTNNifmuV3DM9BBdngMG28jWPy4C/SoZg4EP7mkYUsG6hN+LgjOL17YEF7bKDEWPl9sQS92iD+AuAPrjnHVQ9VG' +
    b'5hbTYiQAaicj6hxqBoNqGQWxDzhZL4B35MgqmoUOBGnzYA/fKgqhRVzOXbWFxKLtzSJzB+Z+kmeoBzq+4MazL4BkoyPZMrIMnvxiluv+kqE' +
    b'9SWeJ/5e7WXdtbYTnSR4WN3gW/BMKEoKQk/UGwuPvCiRq+y8LorJP4B1Wfwlm/meqtbTidXyCcQPR9xWpce3rRjLLT6cimUjWrbx7Q1Slsy' +
    b'pdkclgPSTu9Jg457am8tnQUgnL7VdetAAABDwAAAAdzc2gtcnNhAAABAMZLNacwOMNexYUaFK1nU0JPQTv4fM73QDG3xURtDsIbI6DAcA1y' +
    b'KkvgjJcxlZHx0APJ+i1lWNAvPeOmuPTioymjIEuwxi0VGuAoVKgjmIy6aXH2z3YMxy9cGOq6LNfI4c58iBHR5ejVHAzvIg3rowypVsCGugL' +
    b'7WJpz3eypBJt4TglwRTJpp54IMN2CyDQm0N97x9ris8jQQHlCF2EgZp1u4aOiZJTSJ5d4hapO0uZwXOI9AIWy/lmx0/6jX07MWrs4iXpfiF' +
    b'5T4s6kEn7YW4SaJ0Z7xGp3V0vDOxh+jwHZGD5GM449Il6QxQwDY5BSJq+iMR467yaIjw2g8Kt4ZiU= ansible@ansible-host'
)
ED25519_FINGERPRINT = b'SHA256:NP4JdfkCopbjwMepq0aPrpMz13cNmEd+uDOxC/j9N40'
# garbage
INVALID_DATA = b'yDspTN+BJzvIK2Q+CRD3qBDVSi+YqSxwyz432VEaHKlXbuLURirY0QpuBCqgR6tCtWW5vEGkXKZ3'

VALID_OPTS = [(b'force-command', b'/usr/bin/csh')]
INVALID_OPTS = [(b'test', b'undefined')]
VALID_EXTENSIONS = [
    (b'permit-X11-forwarding', b''),
    (b'permit-agent-forwarding', b''),
    (b'permit-port-forwarding', b''),
    (b'permit-pty', b''),
    (b'permit-user-rc', b''),
]
INVALID_EXTENSIONS = [(b'test', b'')]


def test_rsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_rsa-cert.pub'
    cert_file.write(RSA_CERT_SIGNED_BY_DSA, mode='wb')

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.cert_info.key_id == b'test'
    assert cert.cert_info.serial == 0
    assert cert.cert_info.type_string == b'ssh-rsa-cert-v01@openssh.com'
    assert cert.cert_info.public_key_fingerprint() == RSA_FINGERPRINT
    assert cert.signing_key_fingerprint() == DSA_FINGERPRINT


def test_dsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_dsa-cert.pub'
    cert_file.write(DSA_CERT_SIGNED_BY_ECDSA_NO_OPTS)

    cert = OpensshCertificate.load(str(cert_file))

    assert cert.cert_info.type_string == b'ssh-dss-cert-v01@openssh.com'
    assert cert.cert_info.public_key_fingerprint() == DSA_FINGERPRINT
    assert cert.signing_key_fingerprint() == ECDSA_FINGERPRINT
    assert cert.cert_info.critical_options == []
    assert cert.cert_info.extensions == []


def test_ecdsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_ecdsa-cert.pub'
    cert_file.write(ECDSA_CERT_SIGNED_BY_ED25519_VALID_OPTS)

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.cert_info.type_string == b'ecdsa-sha2-nistp256-cert-v01@openssh.com'
    assert cert.cert_info.public_key_fingerprint() == ECDSA_FINGERPRINT
    assert cert.signing_key_fingerprint() == ED25519_FINGERPRINT
    assert cert.cert_info.critical_options == VALID_OPTS
    assert cert.cert_info.extensions == VALID_EXTENSIONS


def test_ed25519_certificate(tmpdir):
    cert_file = tmpdir / 'id_ed25519-cert.pub'
    cert_file.write(ED25519_CERT_SIGNED_BY_RSA_INVALID_OPTS)

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.cert_info.type_string == b'ssh-ed25519-cert-v01@openssh.com'
    assert cert.cert_info.public_key_fingerprint() == ED25519_FINGERPRINT
    assert cert.signing_key_fingerprint() == RSA_FINGERPRINT
    assert cert.cert_info.critical_options == INVALID_OPTS
    assert cert.cert_info.extensions == INVALID_EXTENSIONS


def test_invalid_data(tmpdir):
    result = False
    cert_file = tmpdir / 'invalid-cert.pub'
    cert_file.write(INVALID_DATA)

    try:
        OpensshCertificate.load(str(cert_file))
    except ValueError:
        result = True
    assert result
