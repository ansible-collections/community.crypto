#!/usr/bin/env python

# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import os
import random
import subprocess
import sys


CONTAINER = 'quay.io/ansible/default-test-container:1.12'


def run(command):
    sys.stdout.write('[RUN] {0}\n'.format(' '.join(command)))
    sys.stdout.flush()
    return subprocess.call(command)


def get_common_parent(*directories):
    parent = directories[0]
    for dir in directories[1:]:
        while os.path.relpath(dir, parent).startswith('..'):
            old_parent, parent = parent, os.path.dirname(parent)
            if old_parent == parent:
                break
    return parent


def main():
    root = os.getcwd()
    try:
        root = get_common_parent(root, __file__)
    except Exception as e:
        pass

    container_name = 'ansible-test-{0}'.format(random.getrandbits(64))

    result = -1
    run(['docker', 'run', '--detach', '--workdir', os.path.abspath(os.getcwd()), '--user', '{0}:{1}'.format(os.getuid(), os.getgid()), '--name', container_name, CONTAINER, '/bin/sh', '-c', 'sleep 50m'])
    try:
        run(['docker', 'cp', root, '{0}:{1}'.format(container_name, os.path.dirname(root))])
        run(['docker', 'exec', container_name, '/bin/sh', '-c', 'ls -lah ; pwd'])
        run(['docker', 'exec', container_name, 'python3.7', 'tests/sanity/runner.py'] + sys.argv[1:])
    finally:
        run(['docker', 'rm', '-f', container_name])
    sys.exit(result)


if __name__ == '__main__':
    main()
