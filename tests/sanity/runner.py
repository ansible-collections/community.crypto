# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import subprocess
import sys


SEPARATOR = '=========================================================================='


def setup(python_version):
    print('Installing requirements')
    subprocess.check_call([
        'pip{0}'.format(python_version),
        'install',
        'https://github.com/felixfontein/ansible-changelog/archive/master.tar.gz',
        '--disable-pip-version-check',
    ])


def run(failed_tests, errors, test, command):
    new_errors = []
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        if stdout:
            stdout = stdout.decode('utf-8').splitlines()
            for line in stdout:
                new_errors.append((test, '{0}'.format(line)))
        if stderr:
            stderr = stderr.decode('utf-8').splitlines()
            for line in stderr:
                new_errors.append((test, '[stderr] {0}'.format(line)))
        if int(p.returncode) != 0:
            new_errors.append((test, '[command returned {0}]'.format(p.returncode)))
    except Exception as e:
        new_errors.append((test, '[internal error] {0}'.format(e)))

    if new_errors:
        print(SEPARATOR)
        print('Test "{0}" failed with the following {1} errors:'.format(test, len(new_errors)))
        failed_tests.append(test)
        for dummy, line in new_errors:
            print(line)
        errors.extend(new_errors)
    else:
        print(SEPARATOR)
        print('Test "{0}" succeeded.'.format(test))


def main(argv):
    python_version = '3.7'
    if '--python' in argv:
        python_version = argv[argv.index('--python') + 1]
    if '--install-requirements' in argv:
        setup(python_version)

    errors = []
    failed_tests = []

    run(failed_tests, errors, 'changelog', ['ansible-changelog', 'lint'])
    run(failed_tests, errors, 'bundled', ['python{0}'.format(python_version), 'tests/sanity/code-smell/update-bundled.py', 'plugins/module_utils/compat/ipaddress.py'])

    if not errors:
        print(SEPARATOR)
        sys.exit(0)

    print(SEPARATOR)
    print('Total of {0} errors in the following tests:'.format(len(errors)))
    for test in failed_tests:
        print(test)
    print(SEPARATOR)
    sys.exit(-1)


if __name__ == '__main__':
    main(sys.argv[2:])
