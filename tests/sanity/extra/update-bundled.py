#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
This test checks whether the libraries we're bundling are out of date and need to be synced with
a newer upstream release.
"""


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import re
import sys
from distutils.version import LooseVersion

import packaging.specifiers

import requests


BUNDLED_RE = re.compile(b'\\b_BUNDLED_METADATA\\b')


def get_bundled_libs(paths):
    """
    Return the set of known bundled libraries

    :arg paths: The paths which the test has been instructed to check
    :returns: The list of all files which we know to contain bundled libraries.  If a bundled
        library consists of multiple files, this should be the file which has metadata included.
    """
    bundled_libs = set()
    bundled_libs.add('plugins/module_utils/compat/ipaddress.py')

    return bundled_libs


def get_files_with_bundled_metadata(paths):
    """
    Search for any files which have bundled metadata inside of them

    :arg paths: Iterable of filenames to search for metadata inside of
    :returns: A set of pathnames which contained metadata
    """

    with_metadata = set()
    for path in paths:
        with open(path, 'rb') as f:
            body = f.read()

        if BUNDLED_RE.search(body):
            with_metadata.add(path)

    return with_metadata


def get_bundled_metadata(filename):
    """
    Retrieve the metadata about a bundled library from a python file

    :arg filename: The filename to look inside for the metadata
    :raises ValueError: If we're unable to extract metadata from the file
    :returns: The metadata from the python file
    """
    with open(filename, 'r') as module:
        for line in module:
            if line.strip().startswith('_BUNDLED_METADATA'):
                data = line[line.index('{'):].strip()
                break
        else:
            raise ValueError('Unable to check bundled library for update.  Please add'
                             ' _BUNDLED_METADATA dictionary to the library file with'
                             ' information on pypi name and bundled version.')
        metadata = json.loads(data)
    return metadata


def get_latest_applicable_version(pypi_data, constraints=None):
    """Get the latest pypi version of the package that we allow

    :arg pypi_data: Pypi information about the data as returned by
        ``https://pypi.org/pypi/{pkg_name}/json``
    :kwarg constraints: version constraints on what we're allowed to use as specified by
        the bundled metadata
    :returns: The most recent version on pypi that are allowed by ``constraints``
    """
    latest_version = "0"
    if constraints:
        version_specification = packaging.specifiers.SpecifierSet(constraints)
        for version in pypi_data['releases']:
            if version in version_specification:
                if LooseVersion(version) > LooseVersion(latest_version):
                    latest_version = version
    else:
        latest_version = pypi_data['info']['version']

    return latest_version


def main():
    """Entrypoint to the script"""

    paths = sys.argv[1:] or sys.stdin.read().splitlines()

    bundled_libs = get_bundled_libs(paths)
    files_with_bundled_metadata = get_files_with_bundled_metadata(paths)

    for filename in files_with_bundled_metadata.difference(bundled_libs):
        print('{0}: ERROR: File contains _BUNDLED_METADATA but needs to be added to'
              ' test/sanity/code-smell/update-bundled.py'.format(filename))

    for filename in bundled_libs:
        try:
            metadata = get_bundled_metadata(filename)
        except ValueError as e:
            print('{0}: ERROR: {1}'.format(filename, e))
            continue
        except (IOError, OSError) as e:
            if e.errno == 2:
                print('{0}: ERROR: {1}.  Perhaps the bundled library has been removed'
                      ' or moved and the bundled library test needs to be modified as'
                      ' well?'.format(filename, e))

        pypi_r = requests.get('https://pypi.org/pypi/{0}/json'.format(metadata['pypi_name']))
        pypi_data = pypi_r.json()

        constraints = metadata.get('version_constraints', None)
        latest_version = get_latest_applicable_version(pypi_data, constraints)

        if LooseVersion(metadata['version']) < LooseVersion(latest_version):
            print('{0}: UPDATE {1} from {2} to {3} {4}'.format(
                filename,
                metadata['pypi_name'],
                metadata['version'],
                latest_version,
                'https://pypi.org/pypi/{0}/json'.format(metadata['pypi_name'])))


if __name__ == '__main__':
    main()
