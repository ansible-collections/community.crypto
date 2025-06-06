# Copyright (c) Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from sys import argv
from subprocess import Popen, PIPE, STDOUT

p = Popen(["openssl", "s_client", "-host", argv[1], "-port", "443", "-prexit", "-showcerts"], stdin=PIPE, stdout=PIPE, stderr=STDOUT)
stdout = p.communicate(input=b'\n')[0]
data = stdout.decode()

certs = []
cert = ""
capturing = False
for line in data.split('\n'):
    if line == '-----BEGIN CERTIFICATE-----':
        capturing = True

    if capturing:
        cert = "{0}{1}\n".format(cert, line)

    if line == '-----END CERTIFICATE-----':
        capturing = False
        certs.append(cert)
        cert = ""

with open(argv[2], 'w') as f:
    for cert in set(certs):
        f.write(cert)
