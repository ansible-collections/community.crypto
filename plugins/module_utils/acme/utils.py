# -*- coding: utf-8 -*-

# Copyright (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import base64
import datetime
import re
import textwrap
import traceback

from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.six.moves.urllib.parse import unquote
from ansible_collections.community.crypto.plugins.module_utils.acme.errors import (
    ModuleFailException,
)
from ansible_collections.community.crypto.plugins.module_utils.crypto.math import (
    convert_int_to_bytes,
)
from ansible_collections.community.crypto.plugins.module_utils.time import (
    get_now_datetime,
)


def nopad_b64(data):
    return base64.urlsafe_b64encode(data).decode("utf8").replace("=", "")


def der_to_pem(der_cert):
    """
    Convert the DER format certificate in der_cert to a PEM format certificate and return it.
    """
    return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----\n""".format(
        "\n".join(textwrap.wrap(base64.b64encode(der_cert).decode("utf8"), 64))
    )


def pem_to_der(pem_filename=None, pem_content=None):
    """
    Load PEM file, or use PEM file's content, and convert to DER.

    If PEM contains multiple entities, the first entity will be used.
    """
    certificate_lines = []
    if pem_content is not None:
        lines = pem_content.splitlines()
    elif pem_filename is not None:
        try:
            with open(pem_filename, "rt") as f:
                lines = list(f)
        except Exception as err:
            raise ModuleFailException(
                "cannot load PEM file {0}: {1}".format(pem_filename, to_native(err)),
                exception=traceback.format_exc(),
            )
    else:
        raise ModuleFailException(
            "One of pem_filename and pem_content must be provided"
        )
    header_line_count = 0
    for line in lines:
        if line.startswith("-----"):
            header_line_count += 1
            if header_line_count == 2:
                # If certificate file contains other certs appended
                # (like intermediate certificates), ignore these.
                break
            continue
        certificate_lines.append(line.strip())
    return base64.b64decode("".join(certificate_lines))


def process_links(info, callback):
    """
    Process link header, calls callback for every link header with the URL and relation as options.

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
    """
    if "link" in info:
        link = info["link"]
        for url, relation in re.findall(r'<([^>]+)>;\s*rel="(\w+)"', link):
            callback(unquote(url), relation)


def parse_retry_after(value, relative_with_timezone=True, now=None):
    """
    Parse the value of a Retry-After header and return a timestamp.

    https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
    """
    # First try a number of seconds
    try:
        delta = datetime.timedelta(seconds=int(value))
        if now is None:
            now = get_now_datetime(relative_with_timezone)
        return now + delta
    except ValueError:
        pass

    try:
        return datetime.datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT")
    except ValueError:
        pass

    raise ValueError("Cannot parse Retry-After header value %s" % repr(value))


def compute_cert_id(
    backend,
    cert_info=None,
    cert_filename=None,
    cert_content=None,
    none_if_required_information_is_missing=False,
):
    # Obtain certificate info if not provided
    if cert_info is None:
        cert_info = backend.get_cert_information(
            cert_filename=cert_filename, cert_content=cert_content
        )

    # Convert Authority Key Identifier to string
    if cert_info.authority_key_identifier is None:
        if none_if_required_information_is_missing:
            return None
        raise ModuleFailException(
            "Certificate has no Authority Key Identifier extension"
        )
    aki = to_native(
        base64.urlsafe_b64encode(cert_info.authority_key_identifier)
    ).replace("=", "")

    # Convert serial number to string
    serial_bytes = convert_int_to_bytes(cert_info.serial_number)
    if ord(serial_bytes[:1]) >= 128:
        serial_bytes = b"\x00" + serial_bytes
    serial = to_native(base64.urlsafe_b64encode(serial_bytes)).replace("=", "")

    # Compose cert ID
    return "{aki}.{serial}".format(aki=aki, serial=serial)
