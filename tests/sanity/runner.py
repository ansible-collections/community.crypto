# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import json
import subprocess
import sys


SEPARATOR = '=========================================================================='


def setup(python_version):
    print('Installing requirements')
    subprocess.check_call([
        'pip{0}'.format(python_version),
        'install',
        '--disable-pip-version-check',
        'https://github.com/felixfontein/ansible-changelog/archive/master.tar.gz',
        'requests',
    ])


def run(result, test, command):
    print(SEPARATOR)
    print('Running {0}'.format(' '.join(command)))

    errors = []
    failed = False
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        if stdout:
            stdout = stdout.decode('utf-8').splitlines()
            for line in stdout:
                errors.append(('', 0, 0, '{0}'.format(line)))
                failed = True
        if stderr:
            stderr = stderr.decode('utf-8').splitlines()
            for line in stderr:
                print('[stderr] {0}'.format(line))
            failed = True
        if int(p.returncode) != 0:
            failed = True
            print('[command returned {0}]'.format(p.returncode))
    except Exception as e:
        errors.append((test, '[internal error] {0}'.format(e)))

    if failed:
        if errors:
            print('Test "{0}" failed with the following {1} errors:'.format(test, len(errors)))
            for path, line, col, message in errors:
                print('{0}:{1}:{2}:{3}'.format(path, line, col, message))
        else:
            print('Test "{0}" failed.')
        result[test] = dict(
            success=False,
            errors=errors,
        )
    else:
        print('Test "{0}" succeeded.'.format(test))
        result[test] = dict(
            success=True,
        )


def main(argv):
    print(argv)
    python_version = '3.7'
    output = 'output.json'
    if '--output' in argv:
        i = argv.index('--output')
        output = argv[i + 1]
        argv = argv[:i] + argv[i + 1:]

    setup(python_version)

    result = dict()

    run(result, 'changelog',
        ['ansible-changelog', 'lint'])
    run(result, 'bundled',
        ['python{0}'.format(python_version), 'tests/sanity/code-smell/update-bundled.py', 'plugins/module_utils/compat/ipaddress.py'])

    print(SEPARATOR)

    print('Writing results to {0}'.format(output))
    with open(output, 'wb') as output_f:
        output_f.write(json.dumps(result, sort_keys=True, indent=2).encode('utf-8'))


if __name__ == '__main__':
    main(sys.argv[1:])
