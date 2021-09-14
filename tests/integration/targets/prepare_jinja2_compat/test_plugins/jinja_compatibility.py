from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def compatibility_equalto_test(a, b):
    return a == b


def compatibility_in_test(a, b):
    return a in b


class TestModule:
    ''' Ansible math jinja2 tests '''

    def tests(self):
        return {
            'equalto': compatibility_equalto_test,
            'in': compatibility_in_test,
        }
