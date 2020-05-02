#!/usr/bin/env python

import subprocess
import sys


SEPARATOR = '=========================================================================='


def run(failed_tests, errors, test, command):
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        new_errors = []
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
        for _, line in new_errors:
            print(line)
        errors.extend(new_errors)
    else:
        print(SEPARATOR)
        print('Test "{0}" succeeded.'.format(test))

def main():
    errors = []
    failed_tests = []

    run(errors, failed_tests, 'changelog', ['ansible-changelog', 'lint'])
    run(errors, failed_tests, 'bundled', ['tests/sanity/code-smell/update-bundled.py', 'plugins/module_utils/compat/ipaddress.py'])

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
    main()
