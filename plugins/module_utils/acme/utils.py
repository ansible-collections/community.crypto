# -*- coding: utf-8 -*-

# Copyright: (c) 2016 Michael Gruener <michael.gruener@chaosmoon.net>
# Copyright: (c) 2021 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


import base64
import re
import traceback

from ansible.module_utils._text import to_native
from ansible.module_utils.six.moves.urllib.parse import unquote

from ansible_collections.community.crypto.plugins.module_utils.acme.errors import ModuleFailException


def nopad_b64(data):
    return base64.urlsafe_b64encode(data).decode('utf8').replace("=", "")


def pem_to_der(pem_filename, pem_content=None):
    '''
    Load PEM file, or use PEM file's content, and convert to DER.

    If PEM contains multiple entities, the first entity will be used.
    '''
    certificate_lines = []
    if pem_content is not None:
        lines = pem_content.splitlines()
    else:
        try:
            with open(pem_filename, "rt") as f:
                lines = list(f)
        except Exception as err:
            raise ModuleFailException("cannot load PEM file {0}: {1}".format(pem_filename, to_native(err)), exception=traceback.format_exc())
    header_line_count = 0
    for line in lines:
        if line.startswith('-----'):
            header_line_count += 1
            if header_line_count == 2:
                # If certificate file contains other certs appended
                # (like intermediate certificates), ignore these.
                break
            continue
        certificate_lines.append(line.strip())
    return base64.b64decode(''.join(certificate_lines))


def process_links(info, callback):
    '''
    Process link header, calls callback for every link header with the URL and relation as options.
    '''
    if 'link' in info:
        link = info['link']
        for url, relation in re.findall(r'<([^>]+)>;\s*rel="(\w+)"', link):
            callback(unquote(url), relation)
