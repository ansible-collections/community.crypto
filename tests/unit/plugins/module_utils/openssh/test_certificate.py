# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import pytest

from ansible_collections.community.crypto.plugins.module_utils.openssh.certificate import (
    OpensshCertificate,
    OpensshCertificateOption,
    OpensshCertificateTimeParameters,
    parse_option_list
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
RSA_FINGERPRINT = 'SHA256:SvUwwUer4AwsdePYseJR3LcZS8lnKi6BqiL51Dop030'
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
DSA_FINGERPRINT = 'SHA256:YCdJ2lYU+FSkWUud7zg1SJszprXoRGNU/GVcqXUjgC8'
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
ECDSA_FINGERPRINT = 'SHA256:w9lp4zGRJShhm4DzO3ulVm0BEcR0PMjrM6VanQo4C0w'
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
ED25519_FINGERPRINT = 'SHA256:NP4JdfkCopbjwMepq0aPrpMz13cNmEd+uDOxC/j9N40'
# garbage
INVALID_DATA = b'yDspTN+BJzvIK2Q+CRD3qBDVSi+YqSxwyz432VEaHKlXbuLURirY0QpuBCqgR6tCtWW5vEGkXKZ3'

VALID_OPTS = [OpensshCertificateOption('critical', 'force-command', '/usr/bin/csh')]
INVALID_OPTS = [OpensshCertificateOption('critical', 'test', 'undefined')]
VALID_EXTENSIONS = [
    OpensshCertificateOption('extension', 'permit-x11-forwarding', ''),
    OpensshCertificateOption('extension', 'permit-agent-forwarding', ''),
    OpensshCertificateOption('extension', 'permit-port-forwarding', ''),
    OpensshCertificateOption('extension', 'permit-pty', ''),
    OpensshCertificateOption('extension', 'permit-user-rc', ''),
]
INVALID_EXTENSIONS = [OpensshCertificateOption('extension', 'test', '')]

VALID_TIME_PARAMETERS = [
    (0, "always", "always", 0,
     0xFFFFFFFFFFFFFFFF, "forever", "forever", 253402300800,
     ""),
    ("always", "always", "always", 0,
     "forever", "forever", "forever", 253402300800,
     ""),
    (315532800, "1980-01-01T00:00:00", "19800101000000", 315532800,
     631152000, "1990-01-01T00:00:00", "19900101000000", 631152000,
     "19800101000000:19900101000000"),
    ("1980-01-01", "1980-01-01T00:00:00", "19800101000000", 315532800,
     "1990-01-01", "1990-01-01T00:00:00", "19900101000000", 631152000,
     "19800101000000:19900101000000"),
    ("1980-01-01 00:00:00", "1980-01-01T00:00:00", "19800101000000", 315532800,
     "1990-01-01 00:00:00", "1990-01-01T00:00:00", "19900101000000", 631152000,
     "19800101000000:19900101000000"),
    ("1980-01-01T00:00:00", "1980-01-01T00:00:00", "19800101000000", 315532800,
     "1990-01-01T00:00:00", "1990-01-01T00:00:00", "19900101000000", 631152000,
     "19800101000000:19900101000000"),
    ("always", "always", "always", 0,
     "1990-01-01T00:00:00", "1990-01-01T00:00:00", "19900101000000", 631152000,
     "always:19900101000000"),
    ("1980-01-01", "1980-01-01T00:00:00", "19800101000000", 315532800,
     "forever", "forever", "forever", 253402300800,
     "19800101000000:forever"),
]

INVALID_TIME_PARAMETERS = [
    (-1, 0xFFFFFFFFFFFFFFFFFF),
    ("never", "ever"),
    ("01-01-1980", "01-01-1990"),
    (1, 0),
]

VALID_VALIDITY_TEST = [
    ("always", "forever", "2000-01-01"),
    ("1999-12-31", "2000-01-02", "2000-01-01"),
    ("1999-12-31 23:59:00", "2000-01-01 00:01:00", "2000-01-01 00:00:00"),
    ("1999-12-31 23:59:59", "2000-01-01 00:00:01", "2000-01-01 00:00:00"),
]

INVALID_VALIDITY_TEST = [
    ("always", "forever", "1969-12-31"),
    ("always", "2000-01-01", "2000-01-02"),
    ("2000-01-01", "forever", "1999-12-31"),
    ("2000-01-01 00:00:00", "2000-01-01 00:00:01", "2000-01-01 00:00:02"),
]

VALID_OPTIONS = [
    ("force-command=/usr/bin/csh", OpensshCertificateOption('critical', 'force-command', '/usr/bin/csh')),
    ("Force-Command=/Usr/Bin/Csh", OpensshCertificateOption('critical', 'force-command', '/Usr/Bin/Csh')),
    ("permit-x11-forwarding", OpensshCertificateOption('extension', 'permit-x11-forwarding', '')),
    ("permit-X11-forwarding", OpensshCertificateOption('extension', 'permit-x11-forwarding', '')),
    ("critical:foo=bar", OpensshCertificateOption('critical', 'foo', 'bar')),
    ("extension:foo", OpensshCertificateOption('extension', 'foo', '')),
]

INVALID_OPTIONS = [
    "foobar",
    "foo=bar",
    'foo:bar=baz',
    [],
]


def test_rsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_rsa-cert.pub'
    cert_file.write(RSA_CERT_SIGNED_BY_DSA, mode='wb')

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.key_id == 'test'
    assert cert.serial == 0
    assert cert.type_string == 'ssh-rsa-cert-v01@openssh.com'
    assert cert.public_key == RSA_FINGERPRINT
    assert cert.signing_key == DSA_FINGERPRINT


def test_dsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_dsa-cert.pub'
    cert_file.write(DSA_CERT_SIGNED_BY_ECDSA_NO_OPTS)

    cert = OpensshCertificate.load(str(cert_file))

    assert cert.type_string == 'ssh-dss-cert-v01@openssh.com'
    assert cert.public_key == DSA_FINGERPRINT
    assert cert.signing_key == ECDSA_FINGERPRINT
    assert cert.critical_options == []
    assert cert.extensions == []


def test_ecdsa_certificate(tmpdir):
    cert_file = tmpdir / 'id_ecdsa-cert.pub'
    cert_file.write(ECDSA_CERT_SIGNED_BY_ED25519_VALID_OPTS)

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.type_string == 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
    assert cert.public_key == ECDSA_FINGERPRINT
    assert cert.signing_key == ED25519_FINGERPRINT
    assert cert.critical_options == VALID_OPTS
    assert cert.extensions == VALID_EXTENSIONS


def test_ed25519_certificate(tmpdir):
    cert_file = tmpdir / 'id_ed25519-cert.pub'
    cert_file.write(ED25519_CERT_SIGNED_BY_RSA_INVALID_OPTS)

    cert = OpensshCertificate.load(str(cert_file))
    assert cert.type_string == 'ssh-ed25519-cert-v01@openssh.com'
    assert cert.public_key == ED25519_FINGERPRINT
    assert cert.signing_key == RSA_FINGERPRINT
    assert cert.critical_options == INVALID_OPTS
    assert cert.extensions == INVALID_EXTENSIONS


def test_invalid_data(tmpdir):
    result = False
    cert_file = tmpdir / 'invalid-cert.pub'
    cert_file.write(INVALID_DATA)

    try:
        OpensshCertificate.load(str(cert_file))
    except ValueError:
        result = True
    assert result


@pytest.mark.parametrize(
    "valid_from,valid_from_hr,valid_from_openssh,valid_from_timestamp," +
    "valid_to,valid_to_hr,valid_to_openssh,valid_to_timestamp," +
    "validity_string",
    VALID_TIME_PARAMETERS
)
def test_valid_time_parameters(valid_from, valid_from_hr, valid_from_openssh, valid_from_timestamp,
                               valid_to, valid_to_hr, valid_to_openssh, valid_to_timestamp,
                               validity_string):
    time_parameters = OpensshCertificateTimeParameters(
        valid_from=valid_from,
        valid_to=valid_to
    )
    assert time_parameters.valid_from(date_format="human_readable") == valid_from_hr
    assert time_parameters.valid_from(date_format="openssh") == valid_from_openssh
    assert time_parameters.valid_from(date_format="timestamp") == valid_from_timestamp
    assert time_parameters.valid_to(date_format="human_readable") == valid_to_hr
    assert time_parameters.valid_to(date_format="openssh") == valid_to_openssh
    assert time_parameters.valid_to(date_format="timestamp") == valid_to_timestamp
    assert time_parameters.validity_string == validity_string


@pytest.mark.parametrize("valid_from,valid_to", INVALID_TIME_PARAMETERS)
def test_invalid_time_parameters(valid_from, valid_to):
    with pytest.raises(ValueError):
        OpensshCertificateTimeParameters(valid_from, valid_to)


@pytest.mark.parametrize("valid_from,valid_to,valid_at", VALID_VALIDITY_TEST)
def test_valid_validity_test(valid_from, valid_to, valid_at):
    assert OpensshCertificateTimeParameters(valid_from, valid_to).within_range(valid_at)


@pytest.mark.parametrize("valid_from,valid_to,valid_at", INVALID_VALIDITY_TEST)
def test_invalid_validity_test(valid_from, valid_to, valid_at):
    assert not OpensshCertificateTimeParameters(valid_from, valid_to).within_range(valid_at)


@pytest.mark.parametrize("option_string,option_object", VALID_OPTIONS)
def test_valid_options(option_string, option_object):
    assert OpensshCertificateOption.from_string(option_string) == option_object


@pytest.mark.parametrize("option_string", INVALID_OPTIONS)
def test_invalid_options(option_string):
    with pytest.raises(ValueError):
        OpensshCertificateOption.from_string(option_string)


def test_parse_option_list():
    critical_options, extensions = parse_option_list(['force-command=/usr/bin/csh'])

    critical_option_objects = [
        OpensshCertificateOption.from_string('force-command=/usr/bin/csh'),
    ]

    extension_objects = [
        OpensshCertificateOption.from_string('permit-x11-forwarding'),
        OpensshCertificateOption.from_string('permit-agent-forwarding'),
        OpensshCertificateOption.from_string('permit-port-forwarding'),
        OpensshCertificateOption.from_string('permit-user-rc'),
        OpensshCertificateOption.from_string('permit-pty'),
    ]

    assert set(critical_options) == set(critical_option_objects)
    assert set(extensions) == set(extension_objects)


def test_parse_option_list_with_directives():
    critical_options, extensions = parse_option_list(['clear', 'no-pty', 'permit-pty', 'permit-user-rc'])

    extension_objects = [
        OpensshCertificateOption.from_string('permit-user-rc'),
        OpensshCertificateOption.from_string('permit-pty'),
    ]

    assert set(critical_options) == set()
    assert set(extensions) == set(extension_objects)


def test_parse_option_list_case_sensitivity():
    critical_options, extensions = parse_option_list(['CLEAR', 'no-X11-forwarding', 'permit-X11-forwarding'])

    extension_objects = [
        OpensshCertificateOption.from_string('permit-x11-forwarding'),
    ]

    assert set(critical_options) == set()
    assert set(extensions) == set(extension_objects)
