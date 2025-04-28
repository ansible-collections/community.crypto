# -*- coding: utf-8 -*-
#
# Copyright (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

import abc
import os
import stat
import traceback

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.community.crypto.plugins.module_utils.openssh.utils import (
    parse_openssh_version,
)


def restore_on_failure(f):
    def backup_and_restore(module, path, *args, **kwargs):
        backup_file = module.backup_local(path) if os.path.exists(path) else None

        try:
            f(module, path, *args, **kwargs)
        except Exception:
            if backup_file is not None:
                module.atomic_move(os.path.abspath(backup_file), os.path.abspath(path))
            raise
        else:
            module.add_cleanup_file(backup_file)

    return backup_and_restore


@restore_on_failure
def safe_atomic_move(module, path, destination):
    module.atomic_move(os.path.abspath(path), os.path.abspath(destination))


def _restore_all_on_failure(f):
    def backup_and_restore(self, sources_and_destinations, *args, **kwargs):
        backups = [
            (d, self.module.backup_local(d))
            for s, d in sources_and_destinations
            if os.path.exists(d)
        ]

        try:
            f(self, sources_and_destinations, *args, **kwargs)
        except Exception:
            for destination, backup in backups:
                self.module.atomic_move(
                    os.path.abspath(backup), os.path.abspath(destination)
                )
            raise
        else:
            for destination, backup in backups:
                self.module.add_cleanup_file(backup)

    return backup_and_restore


@six.add_metaclass(abc.ABCMeta)
class OpensshModule(object):
    def __init__(self, module):
        self.module = module

        self.changed = False
        self.check_mode = self.module.check_mode

    def execute(self):
        try:
            self._execute()
        except Exception as e:
            self.module.fail_json(
                msg="unexpected error occurred: %s" % to_native(e),
                exception=traceback.format_exc(),
            )

        self.module.exit_json(**self.result)

    @abc.abstractmethod
    def _execute(self):
        pass

    @property
    def result(self):
        result = self._result

        result["changed"] = self.changed

        if self.module._diff:
            result["diff"] = self.diff

        return result

    @property
    @abc.abstractmethod
    def _result(self):
        pass

    @property
    @abc.abstractmethod
    def diff(self):
        pass

    @staticmethod
    def skip_if_check_mode(f):
        def wrapper(self, *args, **kwargs):
            if not self.check_mode:
                f(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def trigger_change(f):
        def wrapper(self, *args, **kwargs):
            f(self, *args, **kwargs)
            self.changed = True

        return wrapper

    def _check_if_base_dir(self, path):
        base_dir = os.path.dirname(path) or "."
        if not os.path.isdir(base_dir):
            self.module.fail_json(
                name=base_dir,
                msg="The directory %s does not exist or the file is not a directory"
                % base_dir,
            )

    def _get_ssh_version(self):
        ssh_bin = self.module.get_bin_path("ssh")
        if not ssh_bin:
            return ""
        return parse_openssh_version(
            self.module.run_command([ssh_bin, "-V", "-q"], check_rc=True)[2].strip()
        )

    @_restore_all_on_failure
    def _safe_secure_move(self, sources_and_destinations):
        """Moves a list of files from 'source' to 'destination' and restores 'destination' from backup upon failure.
        If 'destination' does not already exist, then 'source' permissions are preserved to prevent
        exposing protected data ('atomic_move' uses the 'destination' base directory mask for
        permissions if 'destination' does not already exists).
        """
        for source, destination in sources_and_destinations:
            if os.path.exists(destination):
                self.module.atomic_move(
                    os.path.abspath(source), os.path.abspath(destination)
                )
            else:
                self.module.preserved_copy(source, destination)

    def _update_permissions(self, path):
        file_args = self.module.load_file_common_arguments(self.module.params)
        file_args["path"] = path

        if not self.module.check_file_absent_if_check_mode(path):
            self.changed = self.module.set_fs_attributes_if_different(
                file_args, self.changed
            )
        else:
            self.changed = True


class KeygenCommand(object):
    def __init__(self, module):
        self._bin_path = module.get_bin_path("ssh-keygen", True)
        self._run_command = module.run_command

    def generate_certificate(
        self,
        certificate_path,
        identifier,
        options,
        pkcs11_provider,
        principals,
        serial_number,
        signature_algorithm,
        signing_key_path,
        type,
        time_parameters,
        use_agent,
        **kwargs
    ):
        args = [self._bin_path, "-s", signing_key_path, "-P", "", "-I", identifier]

        if options:
            for option in options:
                args.extend(["-O", option])
        if pkcs11_provider:
            args.extend(["-D", pkcs11_provider])
        if principals:
            args.extend(["-n", ",".join(principals)])
        if serial_number is not None:
            args.extend(["-z", str(serial_number)])
        if type == "host":
            args.extend(["-h"])
        if use_agent:
            args.extend(["-U"])
        if time_parameters.validity_string:
            args.extend(["-V", time_parameters.validity_string])
        if signature_algorithm:
            args.extend(["-t", signature_algorithm])
        args.append(certificate_path)

        return self._run_command(args, **kwargs)

    def generate_keypair(self, private_key_path, size, type, comment, **kwargs):
        args = [
            self._bin_path,
            "-q",
            "-N",
            "",
            "-b",
            str(size),
            "-t",
            type,
            "-f",
            private_key_path,
            "-C",
            comment or "",
        ]

        # "y" must be entered in response to the "overwrite" prompt
        data = "y" if os.path.exists(private_key_path) else None

        return self._run_command(args, data=data, **kwargs)

    def get_certificate_info(self, certificate_path, **kwargs):
        return self._run_command(
            [self._bin_path, "-L", "-f", certificate_path], **kwargs
        )

    def get_matching_public_key(self, private_key_path, **kwargs):
        return self._run_command(
            [self._bin_path, "-P", "", "-y", "-f", private_key_path], **kwargs
        )

    def get_private_key(self, private_key_path, **kwargs):
        return self._run_command(
            [self._bin_path, "-l", "-f", private_key_path], **kwargs
        )

    def update_comment(
        self, private_key_path, comment, force_new_format=True, **kwargs
    ):
        if os.path.exists(private_key_path) and not os.access(
            private_key_path, os.W_OK
        ):
            try:
                os.chmod(private_key_path, stat.S_IWUSR + stat.S_IRUSR)
            except (IOError, OSError) as e:
                raise e(
                    "The private key at %s is not writeable preventing a comment update"
                    % private_key_path
                )

        command = [self._bin_path, "-q"]
        if force_new_format:
            command.append("-o")
        command.extend(["-c", "-C", comment, "-f", private_key_path])
        return self._run_command(command, **kwargs)


class PrivateKey(object):
    def __init__(self, size, key_type, fingerprint, format=""):
        self._size = size
        self._type = key_type
        self._fingerprint = fingerprint
        self._format = format

    @property
    def size(self):
        return self._size

    @property
    def type(self):
        return self._type

    @property
    def fingerprint(self):
        return self._fingerprint

    @property
    def format(self):
        return self._format

    @classmethod
    def from_string(cls, string):
        properties = string.split()

        return cls(
            size=int(properties[0]),
            key_type=properties[-1][1:-1].lower(),
            fingerprint=properties[1],
        )

    def to_dict(self):
        return {
            "size": self._size,
            "type": self._type,
            "fingerprint": self._fingerprint,
            "format": self._format,
        }


class PublicKey(object):
    def __init__(self, type_string, data, comment):
        self._type_string = type_string
        self._data = data
        self._comment = comment

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented

        return all(
            [
                self._type_string == other._type_string,
                self._data == other._data,
                (
                    (self._comment == other._comment)
                    if self._comment is not None and other._comment is not None
                    else True
                ),
            ]
        )

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        return "%s %s" % (self._type_string, self._data)

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, value):
        self._comment = value

    @property
    def data(self):
        return self._data

    @property
    def type_string(self):
        return self._type_string

    @classmethod
    def from_string(cls, string):
        properties = string.strip("\n").split(" ", 2)

        return cls(
            type_string=properties[0],
            data=properties[1],
            comment=properties[2] if len(properties) > 2 else "",
        )

    @classmethod
    def load(cls, path):
        try:
            with open(path, "r") as f:
                properties = f.read().strip(" \n").split(" ", 2)
        except (IOError, OSError):
            raise

        if len(properties) < 2:
            return None

        return cls(
            type_string=properties[0],
            data=properties[1],
            comment="" if len(properties) <= 2 else properties[2],
        )

    def to_dict(self):
        return {
            "comment": self._comment,
            "public_key": self._data,
        }


def parse_private_key_format(path):
    with open(path, "r") as file:
        header = file.readline().strip()

    if header == "-----BEGIN OPENSSH PRIVATE KEY-----":
        return "SSH"
    elif header == "-----BEGIN PRIVATE KEY-----":
        return "PKCS8"
    elif header == "-----BEGIN RSA PRIVATE KEY-----":
        return "PKCS1"

    return ""
