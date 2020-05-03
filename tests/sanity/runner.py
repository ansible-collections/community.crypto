# Copyright: (c) Ansible Project
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import argparse
import glob
import json
import os
import shlex
import shutil
import subprocess


SEPARATOR = '=========================================================================='
DEFAULT_PYTHON = '3.7'


# Copied from test/lib/_internal/util.py in ansible/ansible
def is_subdir(candidate_path, path):  # type: (str, str) -> bool
    """Returns true if candidate_path is path or a subdirectory of path."""
    if not path.endswith(os.path.sep):
        path += os.path.sep

    if not candidate_path.endswith(os.path.sep):
        candidate_path += os.path.sep

    return candidate_path.startswith(path)


# Copied from test/lib/_internal/util.py in ansible/ansible
def is_binary_file(path):
    """
    :type path: str
    :rtype: bool
    """
    assume_text = set([
        '.cfg',
        '.conf',
        '.crt',
        '.cs',
        '.css',
        '.html',
        '.ini',
        '.j2',
        '.js',
        '.json',
        '.md',
        '.pem',
        '.ps1',
        '.psm1',
        '.py',
        '.rst',
        '.sh',
        '.txt',
        '.xml',
        '.yaml',
        '.yml',
    ])

    assume_binary = set([
        '.bin',
        '.eot',
        '.gz',
        '.ico',
        '.iso',
        '.jpg',
        '.otf',
        '.p12',
        '.png',
        '.pyc',
        '.rpm',
        '.ttf',
        '.woff',
        '.woff2',
        '.zip',
    ])

    ext = os.path.splitext(path)[1]

    if ext in assume_text:
        return False

    if ext in assume_binary:
        return True

    with open_binary_file(path) as path_fd:
        # noinspection PyTypeChecker
        return b'\0' in path_fd.read(1024)


class Test:
    # Copied in parts from test/lib/_internal/sanity/__init__.py in ansible/ansible
    def __init__(self, name, data, data_path, executable):
        self.name = name
        self.data_path = data_path
        self.executable = executable
        self.python = data.get('python', DEFAULT_PYTHON)
        self.output_format = data.get('output', 'path-line-column-message').split('-')
        self.requirements = data.get('requirements', [])

        self.extensions = data.get('extensions')  # type: t.List[str]
        self.prefixes = data.get('prefixes')  # type: t.List[str]
        self.files = data.get('files')  # type: t.List[str]
        self.text = data.get('text')  # type: t.Optional[bool]
        self.ignore_self = data.get('ignore_self')  # type: bool

        self.all_targets = data.get('all_targets')  # type: bool
        self.no_targets = data.get('no_targets')  # type: bool
        self.include_directories = data.get('include_directories')  # type: bool
        self.include_symlinks = data.get('include_symlinks')  # type: bool

    # Copied in parts from test/lib/_internal/sanity/__init__.py in ansible/ansible
    def _filter_targets(self, targets):
        if self.no_targets:
            return []

        if self.text is not None:
            if self.text:
                targets = [target for target in targets if not is_binary_file(target)]
            else:
                targets = [target for target in targets if is_binary_file(target)]

        if self.extensions:
            targets = [target for target in targets if os.path.splitext(target)[1] in self.extensions
                       or (is_subdir(target, 'bin') and '.py' in self.extensions)]

        if self.prefixes:
            targets = [target for target in targets if any(target.startswith(pre) for pre in self.prefixes)]

        if self.files:
            targets = [target for target in targets if os.path.basename(target) in self.files]

        if self.ignore_self:
            relative_self_path = os.path.relpath(self.data_path, '.')
            targets = [target for target in targets if target != relative_self_path]

        return targets

    def should_run(self, targets):
        if self.no_targets:
            return True
        targets = self._filter_targets(targets)
        return bool(targets)

    def compose_command(self, targets):
        targets = self._filter_targets(targets)
        return ['python{0}'.format(self.python), self.executable] + targets

    def _parse_output_line(self, line):
        result = ['', 0, 0, '']
        parts = line.split(':', len(self.output_format) - 1)
        for what, part in zip(self.output_format, parts):
            if what == 'path':
                result[0] = part
            if what == 'line':
                result[1] = part
            if what == 'column':
                result[2] = part
            if what == 'message':
                result[3] = part
        return result

    def parse_output(self, stdout_lines):
        errors = []
        for line in stdout_lines:
            errors.append(self._parse_output_line(line))
        return errors


def collect_tests(path='tests/sanity/extra'):
    tests = []
    for filepath in glob.glob(os.path.join(path, '*.json')):
        dir, filename = os.path.split(filepath)
        basename, ext = os.path.splitext(filename)
        try:
            with open(filepath, 'rb') as filepath_f:
                data = json.load(filepath_f)
            executable = os.path.join(dir, basename + '.py')
            if os.path.exists(executable):
                tests.append(Test(basename, data, filepath, executable))
            else:
                print('ERROR: {0} does not exist'.format(executable))
        except Exception as e:
            print('ERROR while processing {0}: {1}'.format(filename, e))
    return tests


def join_command(command):
    return ' '.join([shlex.quote(part) for part in command])


def run(result, test, targets, skip=False):
    print(SEPARATOR)
    result_record = result[test.name] = dict(
        skipped=True,
    )

    if skip:
        print('Test "{0}" skipped.'.format(test.name))
        return

    command = test.compose_command(targets)
    if not command:
        print('Test "{0}" skipped.'.format(test.name))
        return

    del result_record['skipped']
    result_record['success'] = False

    errors = []
    failed = False
    try:
        print('Running {0}: {1}'.format(test.name, join_command(command)))
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()

        if stdout:
            stdout = stdout.decode('utf-8').splitlines()
            errors = test.parse_output(stdout)
            if errors:
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
        errors.append(('', 0, 0, '[internal error] {0}'.format(e)))
        failed = True

    if failed:
        if errors:
            result_record['errors'] = errors
            print('Test "{0}" failed with the following {1} errors:'.format(test.name, len(errors)))
            for path, line, col, message in errors:
                print('{0}:{1}:{2}:{3}'.format(path, line, col, message))
        else:
            print('Test "{0}" failed.'.format(test.name))
    else:
        result_record['success'] = True
        print('Test "{0}" succeeded.'.format(test.name))


def setup(tests):
    requirements = dict()
    for test in tests:
        if test.requirements:
            reqs = requirements.get(test.python)
            if reqs is None:
                reqs = []
                requirements[test.python] = reqs
            reqs.extend(test.requirements)
    if requirements:
        print('Installing requirements')
    for python_version, reqs in sorted(requirements.items()):
        command = [
            'pip{0}'.format(python_version),
            'install',
            '--disable-pip-version-check'
        ] + reqs
        print('Running {0}'.format(join_command(command)))
        subprocess.check_call(command)


def main():
    parser = argparse.ArgumentParser(description='Extra sanity test runner.')
    parser.add_argument('--output',
                        default='output.json',
                        help='output file name')
    parser.add_argument('--install-requirements',
                        action='store_true',
                        help='install necessary requirements')
    parser.add_argument('--cleanup',
                        action='store_true',
                        help='cleanup before running tests')
    parser.add_argument('targets',
                        metavar='TARGET',
                        nargs='*',
                        help='targets')

    args = parser.parse_args()

    tests = collect_tests()
    tests = sorted(tests, key=lambda test: test.name)

    # Cleanup
    if args.cleanup:
        for dirpath, dirnames, filenames in os.walk('.'):
            for dirname in dirnames:
                if dirname == '__pycache__':
                    shutil.rmtree(os.path.join(dirpath, dirname), ignore_errors=True)
            for filename in filenames:
                if filename.endswith('.pyc'):
                    shutil.rmdir(os.path.join(dirpath, filename))

    # Collect targets
    targets = list(args.targets)
    if not targets:
        print('No targets provided; scanning for targets...')
        for dirpath, dirnames, filenames in os.walk('.'):
            dirpath = os.path.relpath(dirpath, '.')
            if dirpath == '.git' or dirpath.startswith('.git/'):
                continue
            for filename in filenames:
                targets.append(os.path.join(dirpath, filename))
    else:
        print('Considering the following targets:')
        for target in targets:
            print(' - {0}'.format(target))
    print('Considering {0} targets'.format(len(targets)))

    # Restrict tests for these targets
    tests_to_run = [test for test in tests if test.should_run(targets)]

    # Setup tests
    if args.install_requirements:
        setup(tests_to_run)

    # Run tests
    result = dict()
    for test in tests:
        run(result, test, targets, skip=test not in tests_to_run)

    print(SEPARATOR)
    print('Writing results to {0}'.format(args.output))
    with open(args.output, 'wb') as output_f:
        output_f.write(json.dumps(result, sort_keys=True, indent=2).encode('utf-8'))


if __name__ == '__main__':
    main()
