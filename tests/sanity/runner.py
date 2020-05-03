# Copyright: (c) Ansible Project
# Copyright: (c) 2020, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import glob
import json
import os
import shlex
import shutil
import subprocess
import sys


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
    def _filter_targets(self, paths):
        if self.no_targets:
            return []

        targets = paths

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

    def should_run(self, paths):
        if self.no_targets:
            return True
        targets = self._filter_targets(paths)
        return bool(targets)

    def compose_command(self, paths):
        targets = self._filter_targets(paths)
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


def run(result, test, paths, skip=False):
    print(SEPARATOR)
    result_record = result[test.name] = dict(
        skipped=True,
    )

    if skip:
        print('Test "{0}" skipped.'.format(test.name))
        return

    command = test.compose_command(paths)
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


def main(argv):
    python_version = '3.7'
    output = 'output.json'
    install_requirements = False
    cleanup = False
    if '--output' in argv:
        i = argv.index('--output')
        output = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    if '--install-requirements' in argv:
        i = argv.index('--install-requirements')
        install_requirements = True
        argv = argv[:i] + argv[i + 1:]
    if '--cleanup' in argv:
        i = argv.index('--cleanup')
        cleanup = True
        argv = argv[:i] + argv[i + 1:]

    tests = collect_tests()
    tests = sorted(tests, key=lambda test: test.name)

    # Cleanup
    if cleanup:
        for dirpath, dirnames, filenames in os.walk('.'):
            for dirname in dirnames:
                if dirname == '__pycache__':
                    shutil.rmtree(os.path.join(dirpath, dirname), ignore_errors=True)
            for filename in filenames:
                if filename.endswith('.pyc'):
                    shutil.rmdir(os.path.join(dirpath, filename))

    # Collect paths
    paths = list(argv)
    if not paths:
        print('No changed paths provided, scanning directories')
        for dirpath, dirnames, filenames in os.walk('.'):
            dirpath = os.path.relpath(dirpath, '.')
            if dirpath == '.git' or dirpath.startswith('.git/'):
                continue
            for filename in filenames:
                paths.append(os.path.join(dirpath, filename))
    print('Considering {0} paths'.format(len(paths)))

    # Restrict tests for these paths
    tests_to_run = [test for test in tests if test.should_run(paths)]

    # Setup tests
    if install_requirements:
        setup(tests_to_run)

    # Run tests
    result = dict()
    for test in tests:
        run(result, test, paths, skip=test not in tests_to_run)

    print(SEPARATOR)
    print('Writing results to {0}'.format(output))
    with open(output, 'wb') as output_f:
        output_f.write(json.dumps(result, sort_keys=True, indent=2).encode('utf-8'))


if __name__ == '__main__':
    main(sys.argv[1:])
