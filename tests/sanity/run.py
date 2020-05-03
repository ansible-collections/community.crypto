#!/usr/bin/env python

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import os
import subprocess
import sys


CONTAINER = 'quay.io/ansible/default-test-container:1.12'


def run(command):
    sys.stdout.write('[RUN] {0}\n'.format(' '.join(command)))
    sys.stdout.flush()
    return subprocess.call(command)


def main():
    root = os.path.abspath(os.environ['HOME'])

    base_command = ['docker', 'run', '--rm', '-t']
    base_command.extend(['-v', '{0}:{1}'.format(root, root)])
    base_command.extend(['-w', os.path.abspath(os.getcwd())])
    base_command.extend(['-u', '{0}:{1}'.format(os.getuid(), os.getgid())])
    base_command.extend([CONTAINER])

    run(base_command + ['/bin/sh', '-c', 'ls -lah ; pwd'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah /root'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah /root/.ansible'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah /root/.ansible/ansible_collections'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah /root/.ansible/ansible_collections/community'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah /root/.ansible/ansible_collections/community/crypto'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah tests/'])
    run(base_command + ['/bin/sh', '-c', 'ls -lah tests/sanity/'])

    sys.exit(run(base_command + ['python3.7', 'tests/sanity/runner.py'] + sys.argv[1:]))


if __name__ == '__main__':
    main()
