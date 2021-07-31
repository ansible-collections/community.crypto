# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, Andrew Pantuso (@ajpantuso) <ajpantuso@gmail.com>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os


def restore_on_failure(f):
    def backup_and_restore(module, path, *args, **kwargs):
        backup_file = module.backup_local(path) if os.path.exists(path) else None

        try:
            f(module, path, *args, **kwargs)
        except Exception:
            if backup_file is not None:
                module.atomic_move(backup_file, path)
            raise
        else:
            module.add_cleanup_file(backup_file)

    return backup_and_restore


@restore_on_failure
def safe_atomic_move(module, path, destination):
    module.atomic_move(path, destination)
