#!/usr/bin/env python

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import os
import subprocess
import sys


CONTAINER = 'quay.io/ansible/default-test-container:1.12'


def main():
    root = os.path.abspath(os.environ['HOME'])

    command = ['docker', 'run', '--rm', '-t']
    command.extend(['-v', '{0}:{1}'.format(root, root)])
    command.extend(['-w', os.path.abspath(os.getcwd())])
    command.extend(['-u', '{0}:{1}'.format(os.getuid(), os.getgid())])
    command.extend([CONTAINER])
    # command.extend(['/bin/sh', '-c', 'ls -lah ; pwd'])
    command.extend(['python3.7', 'tests/sanity/runner.py'])
    command.extend(sys.argv[1:])
    sys.stdout.write('[RUN] {0}\n'.format(' '.join(command)))
    sys.stdout.flush()
    rc = subprocess.call(command)
    sys.exit(rc)


if __name__ == '__main__':
    main()
